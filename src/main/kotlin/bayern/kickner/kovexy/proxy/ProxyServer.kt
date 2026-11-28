package bayern.kickner.kovexy.proxy

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.AdminConfig
import bayern.kickner.kovexy.access.addressKey
import bayern.kickner.kovexy.config.Cidr
import bayern.kickner.kovexy.config.LISTENER_HTTP
import bayern.kickner.kovexy.config.LISTENER_HTTPS
import bayern.kickner.kovexy.config.LimitsConfig
import bayern.kickner.kovexy.randomToken
import bayern.kickner.kovexy.site.neutralPage
import bayern.kickner.kovexy.tls.CertificateBundle
import bayern.kickner.kovexy.tls.DynamicKeyManager
import bayern.kickner.kovexy.tls.FALLBACK_ALIAS
import io.ktor.server.application.Application
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.jetty.jakarta.Jetty
import io.ktor.server.jetty.jakarta.JettyApplicationEngine
import io.ktor.server.jetty.jakarta.JettyApplicationEngineBase
import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http.HttpHeader
import org.eclipse.jetty.http.HttpStatus
import org.eclipse.jetty.http2.server.AbstractHTTP2ServerConnectionFactory
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.HttpConnectionFactory
import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.Response
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.SslConnectionFactory
import org.eclipse.jetty.server.handler.ErrorHandler
import org.eclipse.jetty.util.Callback
import org.eclipse.jetty.util.ssl.SslContextFactory
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.net.ssl.SSLContext

private const val TAG = "Server"

/**
 * Ports of the proxy listeners. Always 80 and 443 in a real deployment, tests and `devRun` pass others in code.
 *
 * @property http Plain HTTP port.
 * @property https TLS port.
 */
data class Ports(val http: Int = 80, val https: Int = 443)

/**
 * The Jetty server behind Ktor, with three kinds of connectors:
 *
 * - plain HTTP on [Ports.http] and TLS on [Ports.https], both on every interface,
 * - the admin UI on `admin.host:admin.port`, plain HTTP, added after the start and moved while running when the
 *   config changes (Jetty's public `addConnector`/`removeConnector`, tested in the PoC).
 *
 * TLS uses the [DynamicKeyManager] through an own `SSLContext` set on Jetty's `SslContextFactory` via Ktor's hook
 * `configureServer` (variant `jetty-km`). Jetty's SNI host check is off like Caddy's `strict_sni_host`, unknown names
 * get the fallback certificate and the fallback.
 *
 * @param ports Proxy ports.
 * @param keyManager Certificates.
 * @param fallback The fallback certificate, Ktor's API needs a key store with one entry.
 * @param limits Initial limits.
 * @param module The Ktor module for every request.
 */
class ProxyServer(
    private val ports: Ports,
    private val keyManager: DynamicKeyManager,
    private val fallback: CertificateBundle,
    limits: LimitsConfig,
    private val module: Application.() -> Unit,
) {
    private lateinit var jetty: Server
    private val engine: EmbeddedServer<JettyApplicationEngine, JettyApplicationEngineBase.Configuration>

    @Volatile
    private var admin: Pair<AdminConfig, ServerConnector>? = null

    /** Port the admin UI listens on, `-1` before it opened. */
    @Volatile
    var adminPort: Int = -1
        private set

    init {
        val password = randomToken(18).toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry(FALLBACK_ALIAS, fallback.key, password, fallback.chain)
        }
        val sslContext = SSLContext.getInstance("TLS").apply { init(arrayOf(keyManager), null, null) }
        engine = embeddedServer(Jetty, configure = {
            connector { port = ports.http }
            // Ktor's Netty engine overwrites the password array, Jetty does not, but copies cost nothing
            sslConnector(keyStore, FALLBACK_ALIAS, { password.copyOf() }, { password.copyOf() }) { port = ports.https }
            idleTimeout = limits.clientIdleTimeout
            httpConfiguration = { requestHeaderSize = limits.maxRequestHeaderBytes }
            secureRequestCustomizer = { isSniHostCheck = false }
            configureServer = {
                jetty = this
                // Set before the start, like every other bean
                errorHandler = NeutralErrorHandler()
                connectors.filterIsInstance<ServerConnector>().forEach { connector ->
                    // Every interface, IPv4 and IPv6, instead of Ktor's 0.0.0.0
                    connector.host = null
                    connector.connectionFactories.filterIsInstance<SslConnectionFactory>().forEach {
                        (it.sslContextFactory as SslContextFactory.Server).sslContext = sslContext
                    }
                    // Without extended CONNECT browsers open WebSockets over HTTP/1.1, which the proxy relays
                    connector.connectionFactories.filterIsInstance<AbstractHTTP2ServerConnectionFactory>().forEach {
                        it.isConnectProtocolEnabled = false
                    }
                }
                // The gate exists from the start and only its values change later. Jetty's ConnectionLimit is not used:
                // it counts every connection object of an endpoint, and with TLS and ALPN those counts cancel out, so a
                // TLS connection counted as zero (measured on 18.11.2026)
                val proxyConnectors = connectors.filterIsInstance<ServerConnector>()
                gate = ConnectionGate(proxyConnectors).also { g ->
                    g.maxConnections = limits.maxConnections
                    g.acceptsPerSecond = limits.maxAcceptsPerSecond
                    g.maxPerAddress = limits.maxConnectionsPerAddress
                    proxyConnectors.forEach { it.addBean(g) }
                }
            }
        }, module = module)
    }

    /**
     * Starts the proxy connectors and the admin connector. Throws if a proxy port or the admin address cannot be bound,
     * Kovexy then does not start and systemd shows why (decided on 19.11.2026). Later moves of the admin address that
     * fail keep the old one, see [updateAdmin].
     */
    fun start(adminConfig: AdminConfig, limits: LimitsConfig) {
        engine.start(wait = false)
        runCatching { openAdmin(adminConfig) }.onFailure {
            runCatching { engine.stop(0, 1000) }
            throw IllegalStateException("Cannot open the admin UI on ${adminConfig.host}:${adminConfig.port}: ${it.message}. Fix admin.host or admin.port in kovexy.json", it)
        }
        updateLimits(limits)
    }

    private lateinit var gate: ConnectionGate

    /** Open connections on the proxy ports, for the status page. */
    val proxyConnections: Int get() = proxyConnectors().sumOf { it.connectedEndPoints.size }

    private fun proxyConnectors(): List<ServerConnector> = jetty.connectors.filterIsInstance<ServerConnector>().filter { it != admin?.second }

    /** Stops everything. */
    fun stop() {
        engine.stop(1000, 5000)
    }

    /** The listener name for a local port, `null` for the admin port. */
    fun listenerFor(port: Int): String? = when (port) {
        ports.http -> LISTENER_HTTP
        ports.https -> LISTENER_HTTPS
        else -> null
    }

    /** Port of the TLS listener. */
    val httpsPort: Int get() = ports.https

    /**
     * Moves the admin connector when host or port changed. The new one opens before the old one closes, so a failed
     * bind leaves the admin UI where it was.
     *
     * @return `null` on success, else the error.
     */
    fun updateAdmin(config: AdminConfig): String? {
        val current = admin
        if (current != null && current.first.host == config.host && current.first.port == config.port) {
            admin = config to current.second
            return null
        }
        return runCatching {
            openAdmin(config)
            current?.second?.let { old ->
                old.stop()
                jetty.removeConnector(old)
            }
        }.exceptionOrNull()?.let {
            val message = "Cannot open the admin UI on ${config.host}:${config.port}: ${it.message}"
            staticLog(KLogger.Level.ERROR, TAG) { "$message. It stays on ${current?.first?.host}:${current?.first?.port}" }
            message
        }
    }

    private fun openAdmin(config: AdminConfig) {
        val connector = ServerConnector(jetty, HttpConnectionFactory(HttpConfiguration().apply {
            sendServerVersion = false
            sendDateHeader = false
        })).apply {
            host = config.host
            port = config.port
        }
        jetty.addConnector(connector)
        try {
            connector.start()
        } catch (e: Exception) {
            jetty.removeConnector(connector)
            throw e
        }
        admin = config to connector
        adminPort = connector.localPort
        staticLog(KLogger.Level.INFO, TAG) { "Admin UI on http://${config.host}:${connector.localPort}" }
    }

    /** Applies new limits to the proxy connectors, for new connections and requests. */
    fun updateLimits(limits: LimitsConfig) {
        val connectors = proxyConnectors()
        connectors.forEach { connector ->
            connector.idleTimeout = limits.clientIdleTimeout.inWholeMilliseconds
            connector.getConnectionFactory(HttpConnectionFactory::class.java)?.httpConfiguration?.requestHeaderSize = limits.maxRequestHeaderBytes
        }
        gate.maxConnections = limits.maxConnections
        gate.acceptsPerSecond = limits.maxAcceptsPerSecond
        gate.maxPerAddress = limits.maxConnectionsPerAddress
    }

    /** Addresses the per address limit does not apply to, from `trustedProxies`. */
    fun updateTrustedProxies(trusted: List<Cidr>) {
        gate.trusted = trusted
    }

    /** Turns the loopback exemption of the per address limit off, for tests. */
    internal fun limitLoopbackForTests() {
        gate.exemptLoopback = false
    }

    /** The active connection limit, `null` if unlimited, for tests. */
    internal val activeConnectionLimit: Int? get() = gate.maxConnections.takeIf { it > 0 }
}

/**
 * Limits connections on the proxy connectors, both values can change while running:
 *
 * - [maxConnections]: open connections in total (Jetty `connectedEndPoints`, one per TCP connection, TLS included).
 *   A new connection above the limit is closed at once, like Jetty's `ConnectionLimit` does.
 * - [acceptsPerSecond]: new connections per second, like Jetty's `AcceptRateLimit`. Above the rate the connectors stop
 *   accepting until the next second starts, waiting connections stay in the backlog of the operating system.
 * - [maxPerAddress]: open connections of one address (IPv6 per /64). Counted when a connection arrives by going
 *   through the open ones, a few thousand at most. Loopback and [trusted] proxies are not limited.
 *
 * `0` turns a limit off.
 *
 * @param connectors The proxy connectors.
 */
class ConnectionGate(private val connectors: List<org.eclipse.jetty.server.AbstractConnector>) : org.eclipse.jetty.io.SelectorManager.AcceptListener {
    /** Open connections in total, `0` is unlimited. */
    @Volatile
    var maxConnections: Int = 0

    /** Open connections of one address, `0` is unlimited. */
    @Volatile
    var maxPerAddress: Int = 0

    /** Peers the per address limit does not apply to. */
    @Volatile
    var trusted: List<Cidr> = emptyList()

    /** Whether loopback peers are exempt from the per address limit, only tests turn it off. */
    @Volatile
    internal var exemptLoopback = true

    /** New connections per second, `0` is off. */
    @Volatile
    var acceptsPerSecond: Int = 0
        set(value) {
            field = value
            if (value <= 0) resume()
        }

    private var second = 0L
    private var count = 0
    private var paused = false
    private val timer = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "connection-gate").apply { isDaemon = true } }

    override fun onAccepting(channel: java.nio.channels.SelectableChannel) {
        val max = maxConnections
        if (max > 0 && connectors.sumOf { it.connectedEndPoints.size } >= max) {
            runCatching { channel.close() }
            return
        }
        val perAddress = maxPerAddress
        if (perAddress > 0) {
            val peer = ((channel as? java.nio.channels.SocketChannel)?.remoteAddress as? java.net.InetSocketAddress)?.address
            if (peer != null && (exemptLoopback.not() || peer.isLoopbackAddress.not()) && trusted.none { it.contains(peer) }) {
                val key = addressKey(peer)
                val open = connectors.sumOf { connector ->
                    connector.connectedEndPoints.count { endPoint -> (endPoint.remoteSocketAddress as? java.net.InetSocketAddress)?.address?.let(::addressKey) == key }
                }
                if (open >= perAddress) {
                    runCatching { channel.close() }
                    return
                }
            }
        }
        val rate = acceptsPerSecond
        if (rate <= 0) return
        synchronized(this) {
            val now = System.currentTimeMillis()
            if (now / 1000 != second) {
                second = now / 1000
                count = 0
            }
            count++
            if (count >= rate && paused.not()) {
                paused = true
                connectors.forEach { it.isAccepting = false }
                timer.schedule({ resume() }, 1000 - now % 1000, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
        }
    }

    private fun resume() = synchronized(this) {
        if (paused) {
            paused = false
            connectors.forEach { it.isAccepting = true }
        }
    }
}

/**
 * Answers the errors Jetty handles itself, before Ktor sees the request (a broken request target like `/%`, a bad
 * header), with Kovexy's neutral page. Jetty's own page names the server and repeats the request.
 */
internal class NeutralErrorHandler : ErrorHandler() {
    override fun generateResponse(request: Request, response: Response, code: Int, message: String?, cause: Throwable?, callback: Callback) {
        response.headers.put(HttpHeader.CONTENT_TYPE, NEUTRAL_CONTENT_TYPE)
        response.write(true, ByteBuffer.wrap(page(code)), callback)
    }

    override fun badMessageError(status: Int, reason: String?, fields: HttpFields.Mutable): ByteBuffer {
        fields.put(HttpHeader.CONTENT_TYPE, NEUTRAL_CONTENT_TYPE)
        return ByteBuffer.wrap(page(status))
    }

    private fun page(code: Int): ByteArray =
        neutralPage(code, HttpStatus.getMessage(code), "This request cannot be answered.").toByteArray(Charsets.UTF_8)

    private companion object {
        const val NEUTRAL_CONTENT_TYPE = "text/html;charset=utf-8"
    }
}
