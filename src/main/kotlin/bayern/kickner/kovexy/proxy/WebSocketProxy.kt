package bayern.kickner.kovexy.proxy

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.cio.webSocketRawSession
import io.ktor.client.request.header
import io.ktor.client.request.url
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.util.AttributeKey
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import io.ktor.server.websocket.WebSocketUpgrade
import kotlinx.coroutines.cancel
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.close
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private const val TAG = "WebSocketProxy"


/**
 * Largest WebSocket frame Kovexy relays from an upstream to a visitor. A larger frame closes the connection (close code
 * 1009). Upstreams are chosen by the admin, apps send big frames mostly in this direction.
 */
const val MAX_WEBSOCKET_FRAME_BYTES = 16L * 1024 * 1024

/**
 * Largest WebSocket frame a visitor may send. The reader reserves the whole frame as soon as its header arrives, so
 * this bounds what a visitor can make Kovexy hold per WebSocket (audit run-2). A larger frame closes the connection.
 */
const val MAX_VISITOR_WEBSOCKET_FRAME_BYTES = 1L * 1024 * 1024

/** Open WebSockets in total. One more gets 503. Together with [MAX_VISITOR_WEBSOCKET_FRAME_BYTES] it bounds the memory. */
const val MAX_WEBSOCKETS = 128

/** IPv6 prefix for [MAX_WEBSOCKETS_PER_ADDRESS], wider than the /64 of bans: one attacker usually has a /56 or /48. */
const val WEBSOCKET_IPV6_PREFIX = 56

/** Open WebSockets of one visitor address (IPv6 per /56, a whole household or VPS). One more gets 503. */
const val MAX_WEBSOCKETS_PER_ADDRESS = 16

/** Frames a relayed WebSocket buffers per direction and side before reading pauses (backpressure). */
const val WEBSOCKET_QUEUE_FRAMES = 1

/** Marks the handshake request to an upstream, so a refusal can be told apart from other errors. */
val WebSocketHandshakeKey = AttributeKey<Unit>("kovexy.websocket.handshake")

/**
 * The upstream answered the WebSocket handshake with [status] instead of `101`. The visitor gets the same status, so
 * an app sees the real reason (for example 403 when not logged in).
 */
class WebSocketRefusedException(val status: HttpStatusCode) : Exception("Upstream refused the WebSocket with $status")

/** Headers the WebSocket client creates itself for the handshake with the upstream. */
private val HANDSHAKE_HEADERS = setOf(
    "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "sec-websocket-accept", "host",
    "content-length", "content-type",
)

/**
 * What a relayed WebSocket was admitted for, so a later revocation can find it.
 *
 * @property domain The site domain of the handshake.
 * @property upstream The upstream server address it is relayed to.
 * @property clientKey The ban key of the visitor's address ([addressKey]), `null` if unknown.
 * @property viaSite Whether a site served it, `false` for the default site. Only those depend on a site's route.
 */
data class WebSocketTag(val domain: String, val upstream: String, val clientKey: String?, val viaSite: Boolean = true)

/**
 * The proxied WebSockets that are open, and the streamed HTTP responses that are being sent. After a config change the
 * WebSockets are closed, like Caddy does. Revocations outside the config (an Incus route removed, an address banned)
 * close the affected WebSockets and cut the affected responses through [closeWhere].
 */
class WebSocketRegistry {
    private class Open(val visitor: WebSocketSession, val upstream: WebSocketSession, val job: Job, val tag: WebSocketTag)

    private val open = ConcurrentHashMap.newKeySet<Open>()

    /** Streamed HTTP responses that are being copied, so a ban or a removed Incus route ends them too. */
    private val streams = ConcurrentHashMap<Job, WebSocketTag>()

    /** Number of open WebSockets. */
    val count: Int get() = open.size

    private val reservedTotal = java.util.concurrent.atomic.AtomicInteger()
    private val reservedBy = ConcurrentHashMap<String, Int>()

    /**
     * Takes one of the [MAX_WEBSOCKETS] places, and one of the [MAX_WEBSOCKETS_PER_ADDRESS] places of [key], before the
     * handshake, so parallel handshakes cannot get past the limits. `false` if one is full. Every `true` needs a
     * [release].
     */
    internal fun reserve(key: String?): Boolean {
        if (reservedTotal.incrementAndGet() > MAX_WEBSOCKETS) {
            reservedTotal.decrementAndGet()
            return false
        }
        if (key == null) return true
        var taken = true
        reservedBy.compute(key) { _, count ->
            val next = (count ?: 0) + 1
            if (next > MAX_WEBSOCKETS_PER_ADDRESS) count.also { taken = false } else next
        }
        if (taken.not()) reservedTotal.decrementAndGet()
        return taken
    }

    /** Gives back a place taken with [reserve]. */
    internal fun release(key: String?) {
        reservedTotal.decrementAndGet()
        if (key != null) reservedBy.compute(key) { _, count -> count?.minus(1)?.takeIf { it > 0 } }
    }

    internal fun add(visitor: WebSocketSession, upstream: WebSocketSession, job: Job, tag: WebSocketTag): Any =
        Open(visitor, upstream, job, tag).also { open += it }

    internal fun remove(handle: Any) {
        open.remove(handle)
    }

    /** Runs [copy], the body of a streamed HTTP response, so that [closeWhere] can cancel it. */
    internal suspend fun stream(tag: WebSocketTag, copy: suspend () -> Unit) {
        val job = currentCoroutineContext()[Job]
        if (job != null) streams[job] = tag
        try {
            copy()
        } finally {
            if (job != null) streams.remove(job)
        }
    }

    /** Closes every open WebSocket after [delay] with `1001 Going Away` on both sides. */
    fun closeAll(scope: CoroutineScope, delay: Duration) =
        close(scope, open.toList(), delay, CloseReason(CloseReason.Codes.GOING_AWAY, "Kovexy configuration changed"), "after the config change")

    /**
     * Closes at once, with `1008 Policy Violation`, every open WebSocket [predicate] picks, and cancels the streamed
     * HTTP responses it picks (the visitor sees a cut off body).
     */
    fun closeWhere(scope: CoroutineScope, why: String, predicate: (WebSocketTag) -> Boolean) {
        val cut = streams.filterValues(predicate).keys
        cut.forEach { it.cancel() }
        if (cut.isNotEmpty()) staticLog(KLogger.Level.INFO, TAG) { "Cut ${cut.size} streamed response(s) $why" }
        close(scope, open.filter { predicate(it.tag) }, Duration.ZERO, CloseReason(CloseReason.Codes.VIOLATED_POLICY, why), why)
    }

    private fun close(scope: CoroutineScope, sockets: List<Open>, delay: Duration, reason: CloseReason, why: String) {
        if (sockets.isEmpty()) return
        scope.launch {
            delay(delay)
            sockets.forEach { ws ->
                runCatching { ws.visitor.close(reason) }
                runCatching { ws.upstream.close(reason) }
                withTimeoutOrNull(5.seconds) { ws.job.cancelAndJoin() }
            }
            staticLog(KLogger.Level.INFO, TAG) { "Closed ${sockets.size} WebSocket(s) $why" }
        }
    }
}

/**
 * Bytes relayed in each direction.
 *
 * @property toUpstream Payload bytes from the visitor to the upstream.
 * @property toVisitor Payload bytes from the upstream to the visitor.
 */
class WebSocketTraffic(val toUpstream: AtomicLong = AtomicLong(), val toVisitor: AtomicLong = AtomicLong())

/**
 * Proxies a WebSocket. The handshake with the upstream happens first, only when it succeeds the visitor's request
 * is upgraded, with the subprotocol the upstream chose. Then frames are relayed unchanged in both directions,
 * pings and close frames included, until one side closes.
 *
 * There is no time limit for an active WebSocket. One without any traffic for 60 minutes is closed by Jetty (Ktor
 * sets that idle time for upgraded connections), so forgotten connections clean up after themselves. Apps that keep
 * a WebSocket open longer send their own pings, which pass through.
 *
 * @param url `ws://` or `wss://` URL of the upstream.
 * @param headers Request headers for the upstream, already cleaned and with `X-Forwarded-*`.
 * @param hostHeader `Host` for the upstream.
 * @param tag What the WebSocket was admitted for, for a later revocation.
 * @throws WebSocketRefusedException if the upstream answered the handshake with another status than `101`, nothing
 *   was sent to the visitor yet.
 * @throws Exception from connecting, for the caller to report the upstream as failed.
 */
suspend fun ApplicationCall.proxyWebSocket(
    client: HttpClient,
    url: String,
    headers: HeaderList,
    hostHeader: String,
    registry: WebSocketRegistry,
    traffic: WebSocketTraffic,
    tag: WebSocketTag,
) {
    val upstream = client.webSocketRawSession(HttpMethod.Get) {
        url(url)
        attributes.put(WebSocketHandshakeKey, Unit)
        header("Host", hostHeader)
        headers.entries.filter { it.first.lowercase() !in HANDSHAKE_HEADERS && it.first.lowercase() !in HOP_BY_HOP_HEADERS }
            .forEach { (name, value) -> header(name, value) }
    }
    val protocol = upstream.call.response.headers["Sec-WebSocket-Protocol"]
    // If the visitor's upgrade fails, nothing else would close the upstream session
    try {
        upgrade(protocol, upstream, registry, traffic, tag)
    } catch (e: Throwable) {
        upstream.cancel()
        throw e
    }
}

private suspend fun ApplicationCall.upgrade(protocol: String?, upstream: WebSocketSession, registry: WebSocketRegistry, traffic: WebSocketTraffic, tag: WebSocketTag) {
    respond(WebSocketUpgrade(this, protocol) {
        val visitor = this
        coroutineScope {
            val relay = coroutineContext[Job]!!
            val handle = registry.add(visitor, upstream, relay, tag)
            try {
                val down = launch { pump(upstream, visitor, traffic.toVisitor) }
                val up = launch { pump(visitor, upstream, traffic.toUpstream) }
                // Whichever direction ends first ends the other
                kotlinx.coroutines.selects.select {
                    down.onJoin { }
                    up.onJoin { }
                }
                // A side that stopped reading would block a flush forever
                withTimeoutOrNull(5.seconds) { runCatching { upstream.flush() } }
                withTimeoutOrNull(5.seconds) { runCatching { visitor.flush() } }
                down.cancel()
                up.cancel()
                runCatching { upstream.outgoing.close() }
                runCatching { visitor.outgoing.close() }
            } finally {
                registry.remove(handle)
                // Ends the upstream connection even when its writer is stuck, its buffered frames are freed with it
                upstream.cancel()
            }
        }
    })
}

/**
 * Relays frames from [from] to [to] until [from] closes. A close frame is forwarded and ends the relay.
 */
private suspend fun pump(from: WebSocketSession, to: WebSocketSession, counter: AtomicLong) {
    runCatching {
        for (frame in from.incoming) {
            counter.addAndGet(frame.data.size.toLong())
            to.outgoing.send(frame.copy())
            // Waits until the frame is written, so a side that does not read stops the relay from reading the
            // other side (backpressure down to TCP) instead of frames piling up in memory
            to.flush()
            if (frame is Frame.Close) break
        }
    }.onFailure { staticLog(KLogger.Level.DEBUG, TAG) { "WebSocket relay ended: ${it.message}" } }
}
