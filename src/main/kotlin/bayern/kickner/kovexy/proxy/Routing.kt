package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.Cidr
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.RouteConfig
import bayern.kickner.kovexy.config.MatchType
import bayern.kickner.kovexy.config.DomainConfig
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * A domain ready for matching.
 *
 * @property config The domain from the config.
 * @property name Display name, the first domain.
 * @property routes Enabled routes, most specific first.
 */
class CompiledDomain(val config: DomainConfig) {
    val name: String = config.names.first()

    val routes: List<RouteConfig> = config.routes
        .filter { it.enabled }
        .sortedWith(compareByDescending<RouteConfig> { it.path.length }.thenBy { if (it.match == MatchType.EXACT) 0 else 1 })

    /**
     * The most specific route for [path], like Caddy: longer paths before shorter ones, at equal length exact
     * before prefix. The order in the config does not matter.
     *
     * @param path The normalized request path, see [normalizePath].
     */
    fun routeFor(path: String): RouteConfig? = routes.firstOrNull { matches(it, path) }
}

/**
 * Whether [route] matches [path]. A prefix matches only at path boundaries: `/api` matches `/api` and
 * `/api/users`, never `/apix`. A deliberate deviation from Zoraxy and Caddy, a rule for `/admin` must not hit
 * `/administrator`.
 */
fun matches(route: RouteConfig, path: String): Boolean = when (route.match) {
    MatchType.EXACT -> path == route.path
    MatchType.PREFIX -> route.path == "/" || path == route.path || path.startsWith(route.path + "/")
}

/**
 * Everything the proxy needs from one config version, built once per change and swapped in one step. Requests that
 * already run keep the version they started with.
 *
 * @property config The config.
 * @property trustedProxies Parsed [KovexyConfig.trustedProxies].
 */
class RoutingTable(val config: KovexyConfig) {
    /** Domain to domain, only enabled domains. */
    private val byDomain: Map<String, CompiledDomain> = buildMap {
        config.domains.filter { it.enabled }.forEach { domain ->
            val compiled = CompiledDomain(domain)
            domain.names.forEach { put(it, compiled) }
        }
    }

    val trustedProxies: List<Cidr> = config.trustedProxies.mapNotNull(Cidr::parse)

    private val profiles: Map<String, AccessProfile> = config.accessProfiles.associateBy { it.name }

    /** The access profile named [name]. */
    fun profile(name: String): AccessProfile? = profiles[name]

    /** The domain for [domain], `null` if none serves it. */
    fun domain(domain: String): CompiledDomain? = byDomain[domain]

    /** The access profile that applies to [path] on [domain], `null` without a domain or a profile. [path] is already normalized. */
    fun profileFor(domain: String, path: String): AccessProfile? {
        val domain = byDomain[domain] ?: return null
        return (domain.routeFor(path)?.access ?: domain.config.access)?.let { profiles[it] }
    }

    /** Whether an enabled domain serves [domain]. */
    fun servesDomain(domain: String): Boolean = domain in byDomain

    /** Every domain that needs a certificate: domains of enabled domains. */
    fun tlsDomains(): Set<String> = byDomain.keys
}

/**
 * Whether [rawPath] can be checked at all: it starts with `/`, has a valid percent encoding and no NUL. Requests with
 * another path get 400, matching them on the raw text would let them pass rules they should hit.
 */
fun isValidPath(rawPath: String): Boolean {
    // `OPTIONS *` and other request targets that are no path would become a broken backend URL (audit run-3)
    if (rawPath.startsWith("/").not()) return false
    val decoded = runCatching { decodePath(rawPath) }.getOrNull() ?: return false
    return '\u0000' !in decoded
}

private fun decodePath(rawPath: String): String = URLDecoder.decode(rawPath.replace("+", "%2B"), StandardCharsets.UTF_8)

/**
 * The request path as rules see it: percent-decoded, path parameters (`;x`) dropped, `.` and `..` segments resolved,
 * repeated slashes collapsed. Matching on the decoded and cleaned path means `/a/../admin`, `//admin`, `/%61dmin` and
 * `/admin;x` all hit a rule for `/admin`, like Tomcat and Spring read them. The request still goes to the backend
 * with its original path. Call [isValidPath] first, an invalid encoding is matched on the raw text here.
 */
fun normalizePath(rawPath: String): String {
    val decoded = runCatching { decodePath(rawPath) }.getOrDefault(rawPath)
    val out = ArrayList<String>()
    decoded.split('/').map { it.substringBefore(';') }.forEach { segment ->
        when (segment) {
            "", "." -> Unit
            ".." -> if (out.isNotEmpty()) out.removeAt(out.size - 1)
            else -> out += segment
        }
    }
    val trailing = decoded.length > 1 && decoded.endsWith("/") && out.isNotEmpty()
    return "/" + out.joinToString("/") + if (trailing) "/" else ""
}

/**
 * The part of [path] below [route], always starting with `/`: for `/api` and `/api/users` it is `/users`, for
 * `/api` itself `/`. For the root route it is the whole path.
 */
fun pathBelow(route: RouteConfig, path: String): String {
    if (route.match == MatchType.EXACT || route.path == "/") return if (route.match == MatchType.EXACT) "/" else path
    val rest = path.removePrefix(route.path)
    return if (rest.isEmpty()) "/" else rest
}

/**
 * The raw path for the backend with the route prefix removed. Uses the raw path when it starts with the prefix
 * literally, so encoded characters further down stay untouched. Otherwise the normalized path, encoded again, so
 * the backend never decodes a second time what Kovexy already decoded (`%2561dmin` must not become `/admin`).
 */
fun stripPrefix(route: RouteConfig, rawPath: String, normalizedPath: String): String {
    if (route.path == "/") return rawPath
    val prefix = route.path
    val source = if (rawPath == prefix || rawPath.startsWith("$prefix/")) rawPath else encodePath(normalizedPath)
    val rest = source.removePrefix(encodePath(prefix))
    return if (rest.isEmpty()) "/" else rest
}

/** Characters a path segment may carry unencoded (RFC 3986 unreserved, sub-delims, `:` and `@`). */
private const val PATH_SAFE = "-._~!$&'()*+,;=:@"

/** Percent-encodes every segment of a decoded [path], `/` stays. `?`, `#` and `%` are always encoded. */
fun encodePath(path: String): String = path.split('/').joinToString("/") { segment ->
    buildString {
        segment.toByteArray(StandardCharsets.UTF_8).forEach { byte ->
            val c = byte.toInt() and 0xff
            if (c < 0x80 && (c.toChar().isLetterOrDigit() || c.toChar() in PATH_SAFE)) append(c.toChar())
            else append('%').append("%02X".format(c))
        }
    }
}
