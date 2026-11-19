package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.config.Cidr
import bayern.kickner.kovexy.config.HeaderAction
import bayern.kickner.kovexy.config.HeaderRule
import bayern.kickner.kovexy.config.parseIpLiteral
import java.net.InetAddress

/**
 * Hop-by-hop headers, they describe one connection and are never forwarded (RFC 9110 and Caddy). `Upgrade` only
 * passes as part of a WebSocket handshake, which the WebSocket proxy builds itself.
 */
val HOP_BY_HOP_HEADERS: Set<String> = setOf(
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade",
)

/** The headers Kovexy sets itself towards the upstream. */
const val X_FORWARDED_FOR = "X-Forwarded-For"
const val X_FORWARDED_PROTO = "X-Forwarded-Proto"
const val X_FORWARDED_HOST = "X-Forwarded-Host"

/**
 * An ordered, case-insensitive header list that keeps repeated headers and the original spelling of names.
 */
class HeaderList(entries: List<Pair<String, String>> = emptyList()) {
    private val items = entries.toMutableList()

    /** Every name and value in order. */
    val entries: List<Pair<String, String>> get() = items

    /** All values of [name]. */
    fun all(name: String): List<String> = items.filter { it.first.equals(name, ignoreCase = true) }.map { it.second }

    /** The first value of [name]. */
    operator fun get(name: String): String? = items.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    /**
     * Removes every value of [name], also under spellings that differ only in other characters than letters and digits.
     * CGI style servers (WSGI, Rack, PHP) turn every such character into `_`, so they read `X_Forwarded_User` and
     * `X.Forwarded.User` as `X-Forwarded-User`. A visitor must not get around the removal that way (audit run-1 and 2).
     */
    fun remove(name: String) {
        val key = foldName(name)
        items.removeAll { foldName(it.first) == key }
    }

    private fun foldName(name: String): String = name.filter { it.isLetterOrDigit() }.lowercase()

    /** Replaces every value of [name] with [value]. */
    fun set(name: String, value: String) {
        remove(name)
        items += name to value
    }

    /** Adds a value to [name]. */
    fun add(name: String, value: String) {
        items += name to value
    }

    /**
     * Removes the cookies [names] from every `Cookie` header and drops a header that ends up empty. The other cookies
     * keep their order and spelling.
     */
    fun removeCookies(names: Set<String>) {
        val values = all("Cookie")
        if (values.isEmpty()) return
        remove("Cookie")
        values.forEach { value ->
            val kept = value.split(';').map { it.trim() }.filter { it.isNotEmpty() && it.substringBefore('=').trim() !in names }
            if (kept.isNotEmpty()) add("Cookie", kept.joinToString("; "))
        }
    }

    /** Applies the rules of a location in order. */
    fun apply(rules: List<HeaderRule>) {
        rules.forEach { rule ->
            when (rule.action) {
                HeaderAction.SET -> set(rule.name, rule.value)
                HeaderAction.ADD -> add(rule.name, rule.value)
                HeaderAction.REMOVE -> remove(rule.name)
            }
        }
    }

    /**
     * Removes the hop-by-hop headers and every header the `Connection` header names.
     *
     * @param keepUpgrade Keeps `Upgrade` and `Connection` for a WebSocket handshake.
     */
    fun removeHopByHop(keepUpgrade: Boolean = false) {
        val named = all("Connection").flatMap { it.split(',') }.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
        val keep = if (keepUpgrade) setOf("upgrade", "connection") else emptySet()
        items.removeAll { (name, _) ->
            val lower = name.lowercase()
            lower !in keep && (lower in HOP_BY_HOP_HEADERS || lower in named)
        }
    }
}

/**
 * Whether the client address belongs to a trusted proxy, whose `X-Forwarded-*` headers are believed.
 */
fun isTrusted(clientIp: String, trusted: List<Cidr>): Boolean {
    if (trusted.isEmpty()) return false
    val bytes = parseIpLiteral(clientIp) ?: return false
    val address = InetAddress.getByAddress(bytes)
    return trusted.any { it.contains(address) }
}

/**
 * Sets the `X-Forwarded-*` headers like Caddy. From a trusted proxy the incoming values stay and the client address
 * is appended to `X-Forwarded-For`, from anybody else incoming values are replaced, so a client cannot fake its
 * address or the scheme. Other headers (`Forwarded`, `X-Real-IP`, the remaining `X-Forwarded-*`) pass unchanged like
 * in Caddy (decided on 19.11.2026), apps take the visitor's address from `X-Forwarded-For`.
 *
 * @param clientIp Address of the direct peer.
 * @param scheme `http` or `https` of the incoming connection.
 * @param host The `Host` the client asked for.
 * @param trusted Whether the peer is a trusted proxy.
 */
fun HeaderList.setForwarded(clientIp: String, scheme: String, host: String, trusted: Boolean) {
    if (trusted) {
        val prior = all(X_FORWARDED_FOR).joinToString(", ").ifBlank { null }
        set(X_FORWARDED_FOR, if (prior == null) clientIp else "$prior, $clientIp")
        if (get(X_FORWARDED_PROTO) == null) set(X_FORWARDED_PROTO, scheme)
        if (get(X_FORWARDED_HOST) == null) set(X_FORWARDED_HOST, host)
    } else {
        set(X_FORWARDED_FOR, clientIp)
        set(X_FORWARDED_PROTO, scheme)
        set(X_FORWARDED_HOST, host)
    }
}

/**
 * The real visitor address: the direct peer, or the last address in `X-Forwarded-For` that is not a trusted proxy
 * when the peer is one.
 */
fun visitorIp(peer: String, forwardedFor: List<String>, trusted: List<Cidr>): String {
    if (isTrusted(peer, trusted).not()) return peer
    val chain = forwardedFor.flatMap { it.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }
    return chain.lastOrNull { isTrusted(it, trusted).not() && parseIpLiteral(it) != null } ?: peer
}
