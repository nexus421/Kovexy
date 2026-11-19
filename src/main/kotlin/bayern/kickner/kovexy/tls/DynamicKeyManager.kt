package bayern.kickner.kovexy.tls

import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager

/** Alias of the fallback certificate. */
const val FALLBACK_ALIAS = "fallback"

/**
 * Time a replaced certificate stays readable. A handshake chooses the alias and reads the key in two separate steps,
 * removing the old entry at once made single handshakes fail under load (measured in the PoC).
 */
const val REPLACED_CERT_GRACE_SECONDS = 30L

/**
 * Picks the certificate for every TLS handshake by the SNI name, and lets certificates be added and replaced while
 * running without any reload of Jetty (variant `jetty-km` of the PoC, 0 errors in 4500 requests with 300 swaps).
 *
 * Unknown names and handshakes without SNI get the fallback certificate.
 *
 * @param fallbackKey Key of the fallback certificate.
 * @param fallbackChain Chain of the fallback certificate.
 */
class DynamicKeyManager(fallbackKey: PrivateKey, fallbackChain: Array<X509Certificate>) : X509ExtendedKeyManager() {

    private class Entry(val key: PrivateKey, val chain: Array<X509Certificate>)

    private val counter = AtomicLong()

    /** Unique alias to certificate. */
    private val entries = ConcurrentHashMap<String, Entry>()

    /** Domain to its current alias. */
    private val current = ConcurrentHashMap<String, String>()

    private val cleanup = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "cert-cleanup").apply { isDaemon = true } }

    init {
        entries[FALLBACK_ALIAS] = Entry(fallbackKey, fallbackChain)
    }

    /**
     * Installs or replaces the certificate of [domain]. New handshakes use it at once, the replaced one stays readable
     * for [REPLACED_CERT_GRACE_SECONDS] for handshakes that already chose it.
     */
    fun install(domain: String, key: PrivateKey, chain: Array<X509Certificate>) {
        val id = "${domain.lowercase()}#${counter.incrementAndGet()}"
        entries[id] = Entry(key, chain)
        val old = current.put(domain.lowercase(), id)
        if (old != null) scheduleRemoval(old)
    }

    /** Removes the certificate of [domain] from memory, handshakes for it get the fallback again. */
    fun remove(domain: String) {
        current.remove(domain.lowercase())?.let(::scheduleRemoval)
    }

    /** Domains with an installed certificate. */
    fun domains(): Set<String> = current.keys.toSet()

    /** The leaf certificate installed for [domain], `null` if there is none. */
    fun certificateOf(domain: String): X509Certificate? = current[domain.lowercase()]?.let { entries[it] }?.chain?.firstOrNull()

    private fun scheduleRemoval(alias: String) {
        cleanup.schedule({ entries.remove(alias) }, REPLACED_CERT_GRACE_SECONDS, TimeUnit.SECONDS)
    }

    private fun pick(keyType: String?, session: SSLSession?): String? {
        val sni = (session as? ExtendedSSLSession)?.requestedServerNames
            ?.filterIsInstance<SNIHostName>()?.firstOrNull()?.asciiName?.lowercase()
        val id = sni?.let { current[it] } ?: FALLBACK_ALIAS
        val algorithm = entries[id]?.key?.algorithm ?: return null
        val wanted = when (keyType) {
            "EC", "EC_EC", "ECDHE_ECDSA" -> "EC"
            "RSA", "RSASSA-PSS", "ECDHE_RSA" -> "RSA"
            else -> keyType
        }
        return if (wanted == null || algorithm == wanted) id else null
    }

    override fun chooseEngineServerAlias(keyType: String?, issuers: Array<Principal>?, engine: SSLEngine?): String? =
        pick(keyType, engine?.handshakeSession)

    override fun chooseServerAlias(keyType: String?, issuers: Array<Principal>?, socket: Socket?): String? =
        pick(keyType, (socket as? SSLSocket)?.handshakeSession)

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = entries[alias]?.chain

    override fun getPrivateKey(alias: String?): PrivateKey? = entries[alias]?.key

    override fun getServerAliases(keyType: String?, issuers: Array<Principal>?): Array<String> = entries.keys.toTypedArray()

    override fun getClientAliases(keyType: String?, issuers: Array<Principal>?): Array<String>? = null

    override fun chooseClientAlias(keyType: Array<String>?, issuers: Array<Principal>?, socket: Socket?): String? = null
}
