package bayern.kickner.kovexy.incus

import bayern.kickner.kovexy.config.parseIpLiteral
import java.net.NetworkInterface
import java.net.InetAddress
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.IncusConfig
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.LocationConfig
import bayern.kickner.kovexy.config.SiteConfig
import bayern.kickner.kovexy.config.Target
import bayern.kickner.kovexy.config.UpstreamConfig
import bayern.kickner.kovexy.config.UpstreamServerConfig
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.config.isValidHostName
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.notify.EventSink
import bayern.kickner.kovexy.stats.IncusDecisionTable
import bayern.kickner.kovexy.stats.Storage
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.prepareGet
import io.ktor.client.request.unixSocket
import io.ktor.client.statement.bodyAsChannel
import io.ktor.utils.io.readRemaining
import kotlinx.io.readByteArray
import io.ktor.http.isSuccess
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.upsert
import kotlin.time.Duration.Companion.seconds

private const val TAG = "Incus"

/** Prefix of the keys Kovexy reads from an instance's own config. */
const val INCUS_KEY_PREFIX = "user.kovexy."

/** Prefix of the upstream groups Kovexy creates for approved instances, never valid in `kovexy.json`. */
const val INCUS_UPSTREAM_PREFIX = "incus:"

/** Retry delay after the connection to Incus broke. */
private val RECONNECT_DELAY = 10.seconds

/** A running instance with claims but no address yet (DHCP after the start) is fetched again after this time. */
private val ADDRESS_RETRY = 5.seconds

/**
 * One instance as Incus reports it.
 *
 * @property project Incus project.
 * @property name Instance name.
 * @property running Whether its status is `Running`.
 * @property keys The `user.kovexy.*` keys of the instance's own config (not of its profiles), without the prefix.
 * @property address First global IPv4 address of the configured interface, `null` if none.
 */
data class IncusInstance(val project: String, val name: String, val running: Boolean, val keys: Map<String, String>, val address: String?)

/**
 * Reads the answer of `GET /1.0/instances?recursion=2&project=<name>`.
 *
 * Only the instance's own `config` counts, not `expanded_config`: keys from a profile would apply to every instance of
 * the profile at once.
 */
fun parseInstances(body: String, networkInterface: String): List<IncusInstance> {
    val root = Json.parseToJsonElement(body).jsonObject
    val list = root["metadata"] as? JsonArray ?: return emptyList()
    return list.mapNotNull { element ->
        val instance = element as? JsonObject ?: return@mapNotNull null
        val name = instance.text("name") ?: return@mapNotNull null
        val config = (instance["config"] as? JsonObject).orEmpty()
        val keys = config.filterKeys { it.startsWith(INCUS_KEY_PREFIX) }
            .mapNotNull { (k, v) -> v.jsonPrimitive.contentOrNull?.let { k.removePrefix(INCUS_KEY_PREFIX) to it } }.toMap()
        val addresses = runCatching {
            (instance["state"] as? JsonObject)?.get("network")?.jsonObject?.get(networkInterface)?.jsonObject?.get("addresses")?.jsonArray
        }.getOrNull().orEmpty()
        val address = addresses.map { it.jsonObject }.firstOrNull { it.text("family") == "inet" && it.text("scope") == "global" }?.text("address")
        IncusInstance(instance.text("project") ?: "default", name, instance.text("status") == "Running", keys, address)
    }
}

private fun JsonObject.text(key: String): String? = (this[key] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull

private fun JsonObject?.orEmpty(): Map<String, JsonElement> = this ?: emptyMap()

/** What the admin decided about an instance. */
enum class IncusState { DETECTED, APPROVED, REJECTED }

/**
 * An instance with `user.kovexy.*` keys and what Kovexy makes of it.
 *
 * @property domains From `user.kovexy.domains`, comma separated.
 * @property port From `user.kovexy.port`, `0` if missing or invalid.
 * @property tls From `user.kovexy.tls`.
 * @property access From `user.kovexy.access`.
 * @property state Decision of the admin. An approval only counts for exactly the approved domains.
 * @property approvedDomains Domains of the stored decision.
 * @property problems Why the instance gets no route even though approved and running, shown in the admin UI.
 * @property live Whether it has a route right now.
 */
data class IncusClaim(
    val instance: IncusInstance,
    val domains: List<String>,
    val port: Int,
    val tls: Boolean,
    val access: String?,
    val state: IncusState,
    val approvedDomains: List<String>,
    val problems: List<String>,
    val live: Boolean,
) {
    /** `project/name`. */
    val id: String get() = "${instance.project}/${instance.name}"

    /** Name of the upstream group of this instance. */
    val upstreamName: String get() = "$INCUS_UPSTREAM_PREFIX$id"

    /** What an approval is bound to besides the domains, see [incusTarget]. */
    val target: String get() = incusTarget(instance.address, port, tls, access)
}

/** A stored decision. */
data class IncusDecision(val project: String, val instance: String, val domains: List<String>, val approved: Boolean, val decidedAt: Long, val target: String = "")

/** Address, port, HTTPS and access profile of a claim as one text, what an approval is bound to besides the domains. */
fun incusTarget(address: String?, port: Int, tls: Boolean, access: String?): String =
    "${address ?: "?"}:$port${if (tls) " https" else ""} access=${access ?: "-"}"

/**
 * Whether a reported instance address may be a proxy target: an IPv4 literal that is not loopback, link-local,
 * wildcard, multicast or an address of the host itself. A guest controls the addresses Incus reports for it, it must
 * not point a public domain at a service of the host. Tests replace it, their fake containers live on loopback.
 */
internal var incusAddressAllowed: (String) -> Boolean = { text ->
    val bytes = if (Regex("""\d{1,3}(\.\d{1,3}){3}""").matches(text)) parseIpLiteral(text) else null
    val ip = bytes?.let { InetAddress.getByAddress(it) }
    ip != null && ip.isLoopbackAddress.not() && ip.isLinkLocalAddress.not() && ip.isAnyLocalAddress.not() && ip.isMulticastAddress.not() &&
        runCatching { NetworkInterface.getByInetAddress(ip) == null }.getOrDefault(false)
}

/**
 * Turns instances and decisions into claims. Rules: only instances of the configured projects, an approval only
 * for exactly the stored domains (new domains need a new click), a rejection counts for the instance whatever its
 * domains are, a manual site wins over a container, two approved running containers with the same domain both get no
 * route for it. A container that is not approved only gets a warning, it never takes an approved route offline.
 */
fun buildClaims(instances: List<IncusInstance>, decisions: List<IncusDecision>, config: KovexyConfig): List<IncusClaim> {
    val manualDomains = config.sites.flatMap { it.domains }.toSet()
    val profiles = config.accessProfiles.map { it.name }.toSet()
    val byKey = decisions.associateBy { it.project to it.instance }
    val relevant = instances.filter { it.project in config.incus.projects && it.keys.isNotEmpty() }
    // Only approved, running containers can take a route offline: an unapproved or rejected container claiming the same
    // domain must not disable a route the admin approved (audit run-2)
    fun approvedNow(instance: IncusInstance): Boolean {
        val decision = byKey[instance.project to instance.name] ?: return false
        val port = instance.keys["port"].orEmpty().trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: 0
        val access = instance.keys["access"]?.trim()?.takeIf { it.isNotEmpty() }
        val tls = instance.keys["tls"]?.trim()?.lowercase() == "true"
        return decision.approved && decision.domains.sorted() == domainsOf(instance).sorted() && decision.target == incusTarget(instance.address, port, tls, access)
    }
    val approvedCount = relevant.filter { it.running && approvedNow(it) }.flatMap { domainsOf(it) }.groupingBy { it }.eachCount()
    val runningCount = relevant.filter { it.running }.flatMap { domainsOf(it) }.groupingBy { it }.eachCount()
    return relevant.sortedWith(compareBy({ it.project }, { it.name })).map { instance ->
        val domains = domainsOf(instance)
        val portText = instance.keys["port"].orEmpty().trim()
        val port = portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: 0
        val access = instance.keys["access"]?.trim()?.takeIf { it.isNotEmpty() }
        val tls = instance.keys["tls"]?.trim()?.lowercase() == "true"
        val decision = byKey[instance.project to instance.name]
        // An approval covers exactly what the admin saw: domains, address, port, HTTPS and access profile
        val state = when {
            decision == null -> IncusState.DETECTED
            decision.approved.not() -> IncusState.REJECTED
            approvedNow(instance) -> IncusState.APPROVED
            else -> IncusState.DETECTED
        }
        val problems = buildList {
            if (domains.isEmpty()) add("user.kovexy.domains is missing")
            // The decision stores the domains in a column of 1000 characters
            if (domains.joinToString(",").length > 1000) add("user.kovexy.domains is longer than 1000 characters")
            domains.filter { isValidHostName(it).not() }.forEach { add("\"$it\" is not a valid domain") }
            if (port == 0) add(if (portText.isEmpty()) "user.kovexy.port is missing" else "user.kovexy.port \"$portText\" is not a port")
            if (access != null && access !in profiles) add("access profile \"$access\" does not exist")
            domains.filter { it in manualDomains }.forEach { add("$it belongs to a site set up by hand, that site wins") }
            // An approved route only yields to another approved one, an unapproved claim only gets the warning
            val counts = if (state == IncusState.APPROVED) approvedCount else runningCount
            domains.filter { (counts[it] ?: 0) > 1 }.forEach { add("$it is claimed by another container too") }
            if (instance.running && instance.address == null) add("no IPv4 address on ${config.incus.`interface`} yet")
            instance.address?.let { if (incusAddressAllowed(it).not()) add("address $it is not allowed as a target (loopback, link-local or the host itself)") }
        }
        IncusClaim(
            instance, domains, port, tls, access, state,
            decision?.domains.orEmpty(), problems, live = state == IncusState.APPROVED && instance.running && problems.isEmpty(),
        )
    }
}

private fun domainsOf(instance: IncusInstance): List<String> =
    instance.keys["domains"].orEmpty().split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()

/**
 * The config the proxy works with: `kovexy.json` plus one site and one upstream group per live claim. The site
 * listens on both listeners with the HTTPS redirect, like a new site in the admin UI.
 *
 * A container that speaks HTTPS is reached by its IP address, which no public certificate names, so the certificate
 * is not checked. The traffic stays on the Incus bridge of the host.
 */
fun withIncusRoutes(config: KovexyConfig, claims: List<IncusClaim>): KovexyConfig {
    val live = claims.filter { it.live }
    if (live.isEmpty()) return config
    return config.copy(
        sites = config.sites + live.map { claim ->
            SiteConfig(domains = claim.domains, access = claim.access, locations = listOf(LocationConfig("/", target = Target.Upstream(claim.upstreamName))))
        },
        upstreams = config.upstreams + live.map { claim ->
            val host = claim.instance.address.orEmpty()
            UpstreamConfig(claim.upstreamName, listOf(UpstreamServerConfig("$host:${claim.port}", tls = claim.tls, skipCertVerify = claim.tls)))
        },
    )
}

/** Decisions in SQLite, not in `kovexy.json` (decided on 17.11.2026). */
class IncusDecisions(private val storage: Storage, private val clock: () -> Long) {
    fun all(): List<IncusDecision> = storage.tx {
        IncusDecisionTable.selectAll().map {
            IncusDecision(
                it[IncusDecisionTable.project], it[IncusDecisionTable.instance],
                it[IncusDecisionTable.domains].split(',').filter { d -> d.isNotEmpty() }, it[IncusDecisionTable.approved], it[IncusDecisionTable.decidedAt],
                it[IncusDecisionTable.target],
            )
        }
    }

    fun decide(project: String, instance: String, domains: List<String>, approved: Boolean, target: String = "") {
        storage.tx {
            IncusDecisionTable.upsert {
                it[IncusDecisionTable.project] = project
                it[IncusDecisionTable.instance] = instance
                it[IncusDecisionTable.domains] = domains.joinToString(",")
                it[IncusDecisionTable.approved] = approved
                it[IncusDecisionTable.target] = target
                it[decidedAt] = clock()
            }
        }
    }

    fun remove(project: String, instance: String) {
        storage.tx { IncusDecisionTable.deleteWhere { (IncusDecisionTable.project eq project) and (IncusDecisionTable.instance eq instance) } }
    }
}

/** Largest answer of the Incus API Kovexy reads for one project. */
const val MAX_INCUS_ANSWER_BYTES = 16L * 1024 * 1024

/** Waiting containers Kovexy remembers as announced by webhook at most. */
const val MAX_INCUS_ANNOUNCED = 1000

/** Largest lifecycle event frame Kovexy reads from Incus. */
const val MAX_INCUS_EVENT_BYTES = 1L * 1024 * 1024

/**
 * Talks to the Incus API over its unix socket, only reading.
 *
 * @param socket Path of the socket.
 */
class IncusApi(private val socket: String) : AutoCloseable {
    private val client = HttpClient(CIO) {
        // Lifecycle events are small, a big frame would be reserved in full as soon as its header arrives
        install(WebSockets) { maxFrameSize = MAX_INCUS_EVENT_BYTES }
        // No request timeout for everything, the events WebSocket stays open for good
        install(HttpTimeout) { connectTimeoutMillis = 10_000 }
        expectSuccess = false
    }

    /**
     * Every instance of the [projects] with config and state, one request per project. Only the configured projects
     * are read, and each answer may have at most [MAX_INCUS_ANSWER_BYTES]: users of any project choose what goes into
     * the answer, and it is parsed as a whole (audit run-2). A larger answer is an error for that project.
     *
     * @return per project its instances or why they could not be read, one broken project does not hide the others.
     */
    suspend fun instances(networkInterface: String, projects: List<String>): Map<String, Result<List<IncusInstance>>> = projects.associateWith { project ->
        try {
            Result.success(instancesOf(networkInterface, project))
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private suspend fun instancesOf(networkInterface: String, project: String): List<IncusInstance> =
        client.prepareGet("http://incus/1.0/instances?recursion=2&project=" + java.net.URLEncoder.encode(project, Charsets.UTF_8)) {
            unixSocket(socket)
            timeout { requestTimeoutMillis = 30_000 }
        }.execute { response ->
            val bytes = response.bodyAsChannel().readRemaining(MAX_INCUS_ANSWER_BYTES + 1).readByteArray()
            check(bytes.size <= MAX_INCUS_ANSWER_BYTES) { "Incus answered more than ${MAX_INCUS_ANSWER_BYTES / 1024 / 1024} MiB for project $project" }
            val body = bytes.decodeToString()
            if (response.status.isSuccess().not()) error("Incus answered ${response.status.value}: ${body.take(200)}")
            // Everything in this answer belongs to the project asked for
            parseInstances(body, networkInterface).map { it.copy(project = project) }
        }

    /**
     * Listens to lifecycle events of all projects until the connection ends. [onConnected] runs once the WebSocket is
     * open, so nothing between subscribing and the full fetch gets lost.
     */
    suspend fun events(onConnected: suspend () -> Unit, onEvent: suspend () -> Unit) {
        client.webSocket(urlString = "ws://incus/1.0/events?type=lifecycle&all-projects=true", request = { unixSocket(socket) }) {
            onConnected()
            for (frame in incoming) {
                if (frame is Frame.Text && isInstanceEvent(frame.readText())) onEvent()
            }
        }
    }

    override fun close() = client.close()
}

/** Whether a lifecycle event is about an instance, its source starts with `/1.0/instances/`. */
internal fun isInstanceEvent(text: String): Boolean = runCatching {
    Json.parseToJsonElement(text).jsonObject["metadata"]?.jsonObject?.get("source")?.jsonPrimitive?.contentOrNull.orEmpty().startsWith("/1.0/instances/")
}.getOrDefault(false)

/**
 * Discovery: subscribes to the events, then fetches the full list, then fetches again on every instance event. After
 * a broken connection it starts over, Incus does not resend missed events. Never creates a route on its own, see
 * [buildClaims].
 *
 * @param config The active config.
 * @param api Creates the API client for a socket path, tests pass their own socket.
 * @param onChange Called with the new claims after every change, the proxy rebuilds its routing table.
 */
class IncusDiscovery(
    private val config: () -> KovexyConfig,
    private val decisions: IncusDecisions,
    private val events: EventSink,
    private val clock: () -> Long,
    private val api: (String) -> IncusApi = ::IncusApi,
    private val onChange: (List<IncusClaim>) -> Unit,
) {
    /** Current claims, empty while discovery is off. */
    @Volatile
    var claims: List<IncusClaim> = emptyList()
        private set

    /** Last error talking to Incus, `null` while connected. */
    @Volatile
    var lastError: String? = null
        private set

    /** Whether the events WebSocket is open. */
    @Volatile
    var connected: Boolean = false
        private set

    @Volatile
    private var instances: List<IncusInstance> = emptyList()
    private val announced = HashSet<String>()
    private val wakeUp = Channel<Unit>(Channel.CONFLATED)
    private var job: Job? = null
    private var running: IncusConfig? = null

    /** Starts or stops discovery to match the config, also on every config change. */
    @Synchronized
    fun reconcile(scope: CoroutineScope) {
        val wanted = config().incus.takeIf { it.enabled }
        if (wanted == running) {
            recompute()
            return
        }
        job?.cancel()
        job = null
        running = wanted
        connected = false
        if (wanted == null) {
            instances = emptyList()
            lastError = null
            recompute()
            return
        }
        job = scope.launch { loop(wanted) }
    }

    private suspend fun loop(settings: IncusConfig) {
        while (true) {
            val client = api(settings.socket)
            try {
                // Events only ask for a fetch, a separate coroutine fetches, so a slow fetch never holds up the stream
                // (Incus drops listeners that fall behind)
                coroutineScope {
                    val fetcher = launch { fetchOnRequest(client, settings) }
                    client.events(
                        onConnected = {
                            connected = true
                            lastError = null
                            wakeUp.trySend(Unit)
                            staticLog(KLogger.Level.INFO, TAG) { "Connected to Incus at ${settings.socket}" }
                        },
                        onEvent = { wakeUp.trySend(Unit) },
                    )
                    fetcher.cancel()
                }
                lastError = "Incus closed the event stream"
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Throwable) {
                lastError = e.message ?: e.javaClass.simpleName
                staticLog(KLogger.Level.WARN, TAG) { "Incus at ${settings.socket} not reachable: $lastError" }
            } finally {
                connected = false
                runCatching { client.close() }
            }
            delay(RECONNECT_DELAY)
        }
    }

    /** Fetches the list whenever [wakeUp] asks for it. */
    private suspend fun fetchOnRequest(client: IncusApi, settings: IncusConfig) = coroutineScope {
        var addressTries = 0
        for (request in wakeUp) {
            val fetched = client.instances(settings.`interface`, settings.projects)
            // A project that could not be read keeps its last known instances, the others are current
            val previous = instances.groupBy { it.project }
            instances = settings.projects.flatMap { project -> fetched[project]?.getOrNull() ?: previous[project].orEmpty() }
            val failed = fetched.filterValues { it.isFailure }.mapValues { it.value.exceptionOrNull()?.message ?: "unknown error" }
            lastError = failed.entries.takeIf { it.isNotEmpty() }?.joinToString("; ") { (project, why) -> "project $project: $why" }
            if (failed.isNotEmpty()) staticLog(KLogger.Level.WARN, TAG) { "Incus: $lastError" }
            recompute()
            // A container that just started often has no address yet, ask again until it has one
            val waiting = claims.any { it.state == IncusState.APPROVED && it.instance.running && it.instance.address == null }
            if (waiting.not()) addressTries = 0
            else if (addressTries++ < 12) launch {
                delay(ADDRESS_RETRY)
                wakeUp.trySend(Unit)
            }
        }
    }

    /** Builds the claims anew from the last list, after a fetch, a decision or a config change. */
    @Synchronized
    fun recompute() {
        val next = buildClaims(instances, decisions.all(), config())
        val detected = next.filter { it.state == IncusState.DETECTED && it.instance.running }
        // Only what still waits stays announced, and at most MAX_INCUS_ANNOUNCED: a project user changing keys again and
        // again must not grow it forever. A cleared entry is announced again once, which is harmless
        val waiting = detected.map { it.id + "|" + it.domains.sorted().joinToString(",") }.toSet()
        announced.retainAll(waiting)
        detected.forEach { claim ->
            val key = claim.id + "|" + claim.domains.sorted().joinToString(",")
            if (announced.size < MAX_INCUS_ANNOUNCED && announced.add(key)) {
                events.emit(Event(WebhookEvent.INCUS_DETECTED, "Incus container ${claim.id} wants ${claim.domains.joinToString(", ")}", "Approve it under Incus in the admin UI.", time = clock()))
            }
        }
        if (next != claims) {
            claims = next
            onChange(next)
        }
    }

    /**
     * Approves [id], the route goes live at once. With [domains] and [target] only if the container still claims
     * exactly those, the admin approves what the page showed.
     */
    fun approve(id: String, domains: List<String>? = null, target: String? = null): Boolean = decide(id, approved = true, domains, target)

    /** Rejects [id], it no longer shows up as detected. */
    fun reject(id: String): Boolean = decide(id, approved = false)

    /** Removes the decision of [id]: an approved route is gone at once, a rejected one shows up as detected again. */
    fun remove(id: String): Boolean {
        val claim = claims.firstOrNull { it.id == id }
        val project = claim?.instance?.project ?: id.substringBefore('/')
        val name = claim?.instance?.name ?: id.substringAfter('/')
        decisions.remove(project, name)
        if (claim?.state == IncusState.APPROVED) events.emit(Event(WebhookEvent.INCUS_REMOVED, "Incus container $id removed", claim.domains.joinToString(", "), time = clock()))
        recompute()
        return true
    }

    private fun decide(id: String, approved: Boolean, domains: List<String>? = null, target: String? = null): Boolean {
        val claim = claims.firstOrNull { it.id == id } ?: return false
        // What the admin saw, it may have changed since the page was shown
        if (domains != null && claim.domains != domains) return false
        if (target != null && claim.target != target) return false
        decisions.decide(claim.instance.project, claim.instance.name, claim.domains, approved, claim.target)
        if (approved) events.emit(Event(WebhookEvent.INCUS_APPROVED, "Incus container $id approved", claim.domains.joinToString(", "), time = clock()))
        recompute()
        return true
    }

    /** Running instances of the configured projects without any `user.kovexy.*` key, for the copy-ready commands. */
    fun withoutKeys(): List<IncusInstance> =
        instances.filter { it.running && it.keys.isEmpty() && it.project in config().incus.projects }.sortedWith(compareBy({ it.project }, { it.name }))

    /** Stops discovery. */
    fun stop() {
        job?.cancel()
    }
}

/** The `incus config set` command for an instance, with `--project` outside the default project. */
fun incusSetCommand(instance: IncusInstance, domain: String, port: String): String = buildString {
    append("incus config set ")
    if (instance.project != "default") append("--project ").append(instance.project).append(' ')
    append(instance.name).append(" user.kovexy.domains=").append(domain).append(" user.kovexy.port=").append(port)
}
