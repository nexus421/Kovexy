package bayern.kickner.kovexy.proxy

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.HostPort
import bayern.kickner.kovexy.config.BackendConfig
import bayern.kickner.kovexy.config.BackendServerConfig
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.notify.EventSink
import bayern.kickner.kovexy.sha256Hex
import kotlinx.coroutines.sync.Semaphore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

private const val TAG = "Backends"

/** Prefix of the sticky session cookie, followed by a short hash of the backend name. */
const val STICKY_COOKIE_PREFIX = "kovexy_sticky_"

/** Lifetime of the sticky session cookie, one day like Zoraxy. */
const val STICKY_COOKIE_MAX_AGE_SECONDS = 86400

/**
 * Runtime state of one backend server. Survives config changes as long as the group keeps the server.
 *
 * @property group Name of the backend.
 * @property address Parsed address.
 */
class BackendServer(val group: String, val address: HostPort, config: BackendServerConfig) {
    /** Settings of the current config version. */
    @Volatile
    var config: BackendServerConfig = config
        internal set

    /** Whether the server is considered up. Starts up, like Caddy and Zoraxy. */
    @Volatile
    var healthy: Boolean = true
        private set

    /** Unix milliseconds of the last change of [healthy], `null` before the first. */
    @Volatile
    var changedAt: Long? = null
        private set

    /** Reason of the last failure, `null` while healthy. */
    @Volatile
    var lastError: String? = null
        private set

    /** Requests currently running against this server. */
    val active = AtomicInteger()

    @Volatile
    private var limit: Pair<Int, Semaphore>? = null

    /** Stable id of the server for the sticky cookie, does not reveal the address. */
    val stickyId: String = sha256Hex("$group|$address").take(16)

    /** The concurrency limit, `null` if unlimited. Recreated when [BackendServerConfig.maxConnections] changes. */
    fun semaphore(): Semaphore? {
        val max = config.maxConnections
        if (max <= 0) return null
        val current = limit
        if (current != null && current.first == max) return current.second
        // Synchronized, so two first requests share one semaphore and the limit holds
        return synchronized(this) {
            limit?.takeIf { it.first == max }?.second ?: Semaphore(max).also { limit = max to it }
        }
    }

    /**
     * Records a health result. A change of state is logged and reported as webhook event.
     *
     * @return whether the state changed.
     */
    fun markHealth(up: Boolean, reason: String?, now: Long, events: EventSink): Boolean {
        synchronized(this) {
            if (up == healthy) {
                if (up.not()) lastError = reason
                return false
            }
            healthy = up
            changedAt = now
            lastError = if (up) null else reason
        }
        if (up) {
            staticLog(KLogger.Level.INFO, TAG) { "Backend $address of \"$group\" is up again" }
            events.emit(Event(WebhookEvent.BACKEND_UP, "Backend $address is up again", "Backend server $address of backend \"$group\" answers again.", time = now, item = address.toString()))
        } else {
            staticLog(KLogger.Level.WARN, TAG) { "Backend $address of \"$group\" is down: $reason" }
            events.emit(Event(WebhookEvent.BACKEND_DOWN, "Backend $address is down", "Backend server $address of backend \"$group\" is down: $reason", time = now, item = address.toString()))
        }
        return true
    }
}

/**
 * A backend group of one config version.
 *
 * @property config The group from the config.
 * @property servers State of every server, in config order.
 */
class BackendGroup(val config: BackendConfig, val servers: List<BackendServer>) {
    /** Name of the sticky cookie of this group. */
    val stickyCookie: String = STICKY_COOKIE_PREFIX + sha256Hex(config.name).take(8)

    /**
     * Picks a server like Zoraxy:
     *
     * - a group with one server always uses it, even when it is down, so a restarting backend does not lead to an
     *   error page of Kovexy,
     * - otherwise only servers that are up are candidates,
     * - with sticky sessions the server from the cookie is used while it is up,
     * - otherwise weighted random among servers with a weight above 0, and only if there is none of those, randomly
     *   among the backup servers with weight 0.
     *
     * @param stickyId Value of the sticky cookie, if any.
     * @return the server, `null` if none is up.
     */
    fun pick(stickyId: String?, random: Random = Random.Default): BackendServer? {
        if (servers.size == 1) return servers.first()
        val online = servers.filter { it.healthy }
        if (online.isEmpty()) return null
        if (config.stickySession && stickyId != null) online.firstOrNull { it.stickyId == stickyId }?.let { return it }

        val weighted = online.filter { it.config.weight > 0 }
        if (weighted.isEmpty()) return online[random.nextInt(online.size)]
        var roll = random.nextInt(weighted.sumOf { it.config.weight })
        weighted.forEach { server ->
            if (roll < server.config.weight) return server
            roll -= server.config.weight
        }
        return weighted.last()
    }
}

/**
 * All backends. Server state (health, running requests) is kept across config changes for every server that
 * stays in its group, a changed or new server starts as up.
 */
class BackendPool {
    private val states = ConcurrentHashMap<String, BackendServer>()

    @Volatile
    private var groups: Map<String, BackendGroup> = emptyMap()

    /** Builds the groups of a new config version. */
    fun reconcile(configs: List<BackendConfig>) {
        val keep = mutableSetOf<String>()
        groups = configs.associate { group ->
            val servers = group.servers.mapNotNull { server ->
                val address = HostPort.parse(server.address) ?: return@mapNotNull null
                val key = "${group.name}|${server.address}|${server.tls}"
                keep += key
                states.getOrPut(key) { BackendServer(group.name, address, server) }.also { it.config = server }
            }
            group.name to BackendGroup(group, servers)
        }
        states.keys.retainAll(keep)
    }

    /** The group named [name] of the current config version. */
    fun group(name: String): BackendGroup? = groups[name]

    /** Every group of the current config version. */
    fun all(): List<BackendGroup> = groups.values.sortedBy { it.config.name }
}
