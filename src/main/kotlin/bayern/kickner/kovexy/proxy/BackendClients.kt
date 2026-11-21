package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.config.LimitsConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpResponseValidator
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.websocket.ChannelOverflow
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import bayern.kickner.kovexy.config.parseIpLiteral
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.time.Duration.Companion.hours

/** Accepts every server certificate, only for backend servers with `skipCertVerify`. */
private object TrustAll : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/** The JVM's default trust manager (the system CAs), the same one Ktor would pick. */
private val systemTrust: X509TrustManager by lazy {
    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as KeyStore?) }
        .trustManagers.filterIsInstance<X509TrustManager>().first()
}

/**
 * Checks the chain against the system CAs and the server certificate against [host], the configured address of the
 * backend. Ktor's CIO client checks the name only loosely: a certificate without names of the matching kind passes,
 * and for an IP address it compares a reverse DNS name (audit run-2). Here an IP address needs the same IP in the
 * certificate's subject alternative names, a name needs a matching DNS name. The common name is not used, like in
 * browsers.
 */
internal class HostCheckingTrustManager(private val host: String, private val trust: X509TrustManager = systemTrust) : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = trust.checkClientTrusted(chain, authType)
    override fun getAcceptedIssuers(): Array<X509Certificate> = trust.acceptedIssuers

    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
        trust.checkServerTrusted(chain, authType)
        val certificate = chain.firstOrNull() ?: throw CertificateException("No server certificate")
        if (certificateMatchesHost(certificate, host).not()) throw CertificateException("Certificate does not belong to $host")
    }
}

/** Whether [certificate] names [host] in its subject alternative names: IP for an IP literal, DNS (with `*.`) otherwise. */
internal fun certificateMatchesHost(certificate: X509Certificate, host: String): Boolean {
    val names = runCatching { certificate.subjectAlternativeNames }.getOrNull().orEmpty()
    val ip = parseIpLiteral(host.removePrefix("[").removeSuffix("]"))
    if (ip != null) return names.any { it.size >= 2 && it[0] == 7 && (it[1] as? String)?.let(::parseIpLiteral)?.contentEquals(ip) == true }
    val name = host.lowercase().trimEnd('.')
    return names.any { it.size >= 2 && it[0] == 2 && (it[1] as? String)?.let { pattern -> dnsNameMatches(pattern.lowercase().trimEnd('.'), name) } == true }
}

/** RFC 6125 matching: exact, or `*.` as the whole leftmost label standing for exactly one label. */
private fun dnsNameMatches(pattern: String, name: String): Boolean {
    if (pattern.startsWith("*.").not()) return pattern == name
    val rest = pattern.removePrefix("*.")
    val first = name.substringBefore('.', "")
    return first.isNotEmpty() && '*' !in rest && name == "$first.$rest"
}

/**
 * HTTP clients for backend servers, Ktor client with the CIO engine. Servers with `skipCertVerify` share one client
 * that accepts any certificate. Every other HTTPS server host gets its own client whose trust manager also checks
 * the certificate against that host ([HostCheckingTrustManager]). Plain HTTP servers use the client of their host
 * too, it simply never does TLS. No client follows redirects, retries, decodes or adds content: what the backend
 * sends goes to the visitor as it is.
 *
 * @property insecure Accepts any certificate.
 * @property limits The limits the clients were built for.
 */
class BackendClients private constructor(val insecure: HttpClient, val limits: LimitsConfig) {
    private val strict = ConcurrentHashMap<String, HttpClient>()

    @Volatile
    private var closed = false

    /** The client for a server on [host] (its configured address, name or IP). */
    fun forServer(skipCertVerify: Boolean, host: String): HttpClient {
        if (skipCertVerify) return insecure
        val key = host.lowercase()
        return strict.computeIfAbsent(key) { build(limits, key) }.also { if (closed) it.close() }
    }

    /** Closes and forgets the per host clients of hosts not in [hosts]. */
    fun retainHosts(hosts: Set<String>) {
        val keep = hosts.map { it.lowercase() }.toSet()
        strict.keys.filter { it !in keep }.forEach { host -> strict.remove(host)?.close() }
    }

    /** Closes every client. */
    fun close() {
        closed = true
        insecure.close()
        strict.values.forEach { it.close() }
    }

    companion object {
        /** The clients for [limits], the per host ones are created on first use. */
        fun create(limits: LimitsConfig): BackendClients = BackendClients(build(limits, null), limits)

        /**
         * Connections a client may open, in total and per server address. Ktor's defaults (1000 and 100) let one
         * visitor with 100 slow requests make other domains wait for the pool, and a wait for the pool ended as connect
         * timeout and marked the server down (audit run-2). The proxy ports already limit connections
         * (`limits.maxConnections`), a server's own `maxConnections` limits per server.
         */
        private const val POOL_CONNECTIONS = 100_000

        /** [host] `null` builds the client that accepts every certificate. */
        private fun build(limits: LimitsConfig, host: String?): HttpClient = HttpClient(CIO) {
            followRedirects = false
            expectSuccess = false
            // Default transformers would turn bodies into strings or byte arrays, the proxy only streams them
            useDefaultTransformers = false
            install(WebSockets) {
                maxFrameSize = MAX_WEBSOCKET_FRAME_BYTES
                channels {
                    incoming = bounded(WEBSOCKET_QUEUE_FRAMES, ChannelOverflow.SUSPEND)
                    outgoing = bounded(WEBSOCKET_QUEUE_FRAMES, ChannelOverflow.SUSPEND)
                }
            }
            // A refused WebSocket handshake carries its status to the visitor, see WebSocketRefusedException
            HttpResponseValidator {
                validateResponse { response ->
                    if (response.call.request.attributes.contains(WebSocketHandshakeKey) && response.status != HttpStatusCode.SwitchingProtocols) {
                        throw WebSocketRefusedException(response.status)
                    }
                }
            }
            engine {
                // No total time limit: waiting for the response headers and the body are unlimited, like Caddy
                requestTimeout = 0
                maxConnectionsCount = POOL_CONNECTIONS
                endpoint.apply {
                    maxConnectionsPerRoute = POOL_CONNECTIONS
                    connectTimeout = limits.backendConnectTimeout.inWholeMilliseconds
                    keepAliveTime = limits.backendKeepAlive.inWholeMilliseconds
                    connectAttempts = 1
                }
                https {
                    if (host == null) {
                        trustManager = TrustAll
                    } else {
                        trustManager = HostCheckingTrustManager(host)
                        // A name goes into SNI as configured. For an IP address Ktor keeps its own behavior, an IP is
                        // no valid SNI value
                        if (parseIpLiteral(host.removePrefix("[").removeSuffix("]")) == null) serverName = host
                    }
                }
            }
        }
    }
}

/**
 * Holds the current [BackendClients] and replaces them when the limits change. Replaced clients are closed after an
 * hour, so running transfers can finish.
 */
class BackendClientHolder(limits: LimitsConfig, private val scope: CoroutineScope) {
    @Volatile
    var current: BackendClients = BackendClients.create(limits)
        private set

    /** Rebuilds the clients if [limits] changed. */
    fun update(limits: LimitsConfig) {
        val old = current
        if (old.limits.backendConnectTimeout == limits.backendConnectTimeout && old.limits.backendKeepAlive == limits.backendKeepAlive) return
        current = BackendClients.create(limits)
        scope.launch {
            delay(1.hours)
            old.close()
        }
    }

    /** Closes the current clients. */
    fun close() = current.close()
}
