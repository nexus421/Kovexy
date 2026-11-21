package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.config.HostPort
import bayern.kickner.kovexy.notify.EventSink
import io.ktor.client.request.prepareGet
import io.ktor.client.request.header
import io.ktor.http.HttpHeaders
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.seconds

/** Time between two passive checks of a server that is down, like Zoraxy. */
val PASSIVE_RECHECK_INTERVAL = 30.seconds

/** Time a passive check may take to connect. */
private val PASSIVE_CHECK_TIMEOUT = 5.seconds

/**
 * Checks backend servers:
 *
 * - **active** (Caddy) only for groups with `healthCheck.path`: a `GET` to every server every `interval`, a status
 *   other than `expectStatus` or no answer within `timeout` marks it down, one good answer marks it up again,
 * - **passive** (Zoraxy) for everything: a connection error during a request marks the server down (done by the
 *   proxy), a server that is down and has no active check is tried with a TCP connect every
 *   [PASSIVE_RECHECK_INTERVAL] and marked up when it accepts.
 *
 * @param pool The backends.
 * @param clients HTTP clients for the active checks.
 * @param events Receives up and down events.
 * @param clock Unix milliseconds.
 */
class HealthChecker(
    private val pool: BackendPool,
    private val clients: () -> BackendClients,
    private val events: EventSink,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /** Next due time per server, by identity. */
    private val due = ConcurrentHashMap<BackendServer, Long>()
    private val running = ConcurrentHashMap.newKeySet<BackendServer>()

    /** Starts the check loop in [scope]. */
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (isActive) {
            val now = clock()
            val current = pool.all()
            val alive = current.flatMap { it.servers }.toSet()
            due.keys.retainAll(alive)
            current.forEach { group ->
                val check = group.config.healthCheck
                group.servers.forEach { server ->
                    val active = check.path.isNotEmpty()
                    if (active.not() && server.healthy) {
                        due.remove(server)
                        return@forEach
                    }
                    // A server that just went down is tried again only after the passive interval
                    val next = due[server] ?: if (active) null else ((server.changedAt ?: now) + PASSIVE_RECHECK_INTERVAL.inWholeMilliseconds).also { due[server] = it }
                    if (next != null && now < next) return@forEach
                    if (running.add(server).not()) return@forEach
                    val interval = if (active) check.interval else PASSIVE_RECHECK_INTERVAL
                    due[server] = now + interval.inWholeMilliseconds
                    launch {
                        try {
                            if (active) activeCheck(group, server) else passiveCheck(server)
                        } finally {
                            running.remove(server)
                        }
                    }
                }
            }
            delay(1000)
        }
    }

    private suspend fun activeCheck(group: BackendGroup, server: BackendServer) {
        val check = group.config.healthCheck
        val scheme = if (server.config.tls) "https" else "http"
        val result = runCatching {
            withTimeout(check.timeout) {
                // Streamed: only the status counts, the body is never read into memory (audit run-2)
                clients().forServer(server.config.skipCertVerify, server.address.host).prepareGet("$scheme://${server.address}${check.path}") {
                    header(HttpHeaders.Host, server.address.toString())
                }.execute { it.status.value }
            }
        }
        val status = result.getOrNull()
        val up = status == check.expectStatus
        val reason = when {
            status != null -> "health check answered $status, expected ${check.expectStatus}"
            else -> "health check failed: ${result.exceptionOrNull()?.reason()}"
        }
        server.markHealth(up, reason, clock(), events)
    }

    private fun passiveCheck(server: BackendServer) {
        val up = canConnect(server.address)
        if (up) server.markHealth(true, null, clock(), events)
    }

    /** Tries a TCP connection within [PASSIVE_CHECK_TIMEOUT]. */
    private fun canConnect(address: HostPort): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(address.host, address.port), PASSIVE_CHECK_TIMEOUT.inWholeMilliseconds.toInt()) }
    }.isSuccess
}
