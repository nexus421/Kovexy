package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.Cidr
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.LocationConfig
import bayern.kickner.kovexy.config.MatchType
import bayern.kickner.kovexy.config.SiteConfig
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * A site ready for matching.
 *
 * @property config The site from the config.
 * @property name Display name, the first domain.
 * @property locations Enabled locations, most specific first.
 */
class CompiledSite(val config: SiteConfig) {
    val name: String = config.domains.first()

    val locations: List<LocationConfig> = config.locations
        .filter { it.enabled }
        .sortedWith(compareByDescending<LocationConfig> { it.path.length }.thenBy { if (it.match == MatchType.EXACT) 0 else 1 })

    /**
     * The most specific location for [path], like Caddy: longer paths before shorter ones, at equal length exact
     * before prefix. The order in the config does not matter.
     *
     * @param path The normalized request path, see [normalizePath].
     */
    fun locationFor(path: String): LocationConfig? = locations.firstOrNull { matches(it, path) }
}

/**
 * Whether [location] matches [path]. A prefix matches only at path boundaries: `/api` matches `/api` and
 * `/api/users`, never `/apix`. A deliberate deviation from Zoraxy and Caddy, a rule for `/admin` must not hit
 * `/administrator`.
 */
fun matches(location: LocationConfig, path: String): Boolean = when (location.match) {
    MatchType.EXACT -> path == location.path
    MatchType.PREFIX -> location.path == "/" || path == location.path || path.startsWith(location.path + "/")
}

/**
 * Everything the proxy needs from one config version, built once per change and swapped in one step. Requests that
 * already run keep the version they started with.
 *
 * @property config The config.
 * @property trustedProxies Parsed [KovexyConfig.trustedProxies].
 */
class RoutingTable(val config: KovexyConfig) {
    /** Domain to site, only enabled sites. */
    private val byDomain: Map<String, CompiledSite> = buildMap {
        config.sites.filter { it.enabled }.forEach { site ->
            val compiled = CompiledSite(site)
            site.domains.forEach { put(it, compiled) }
        }
    }

    val trustedProxies: List<Cidr> = config.trustedProxies.mapNotNull(Cidr::parse)

    private val profiles: Map<String, AccessProfile> = config.accessProfiles.associateBy { it.name }

    /** The access profile named [name]. */
    fun profile(name: String): AccessProfile? = profiles[name]

    /** The site for [domain], `null` if none serves it. */
    fun site(domain: String): CompiledSite? = byDomain[domain]

    /** The access profile that applies to [path] on [domain], `null` without a site or a profile. [path] is already normalized. */
    fun profileFor(domain: String, path: String): AccessProfile? {
        val site = byDomain[domain] ?: return null
        return (site.locationFor(path)?.access ?: site.config.access)?.let { profiles[it] }
    }

    /** Whether an enabled site serves [domain]. */
    fun servesDomain(domain: String): Boolean = domain in byDomain

    /** Every domain that needs a certificate: domains of enabled sites. */
    fun tlsDomains(): Set<String> = byDomain.keys
}

/**
 * Whether [rawPath] can be checked at all: valid percent encoding and no NUL. Requests with another path get 400,
 * matching them on the raw text would let them pass rules they should hit.
 */
fun isValidPath(rawPath: String): Boolean {
    val decoded = runCatching { decodePath(rawPath) }.getOrNull() ?: return false
    return '\u0000' !in decoded
}

private fun decodePath(rawPath: String): String = URLDecoder.decode(rawPath.replace("+", "%2B"), StandardCharsets.UTF_8)

/**
 * The request path as rules see it: percent-decoded, path parameters (`;x`) dropped, `.` and `..` segments resolved,
 * repeated slashes collapsed. Matching on the decoded and cleaned path means `/a/../admin`, `//admin`, `/%61dmin` and
 * `/admin;x` all hit a rule for `/admin`, like Tomcat and Spring read them. The request still goes to the upstream
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
 * The part of [path] below [location], always starting with `/`: for `/api` and `/api/users` it is `/users`, for
 * `/api` itself `/`. For the root location it is the whole path.
 */
fun pathBelow(location: LocationConfig, path: String): String {
    if (location.match == MatchType.EXACT || location.path == "/") return if (location.match == MatchType.EXACT) "/" else path
    val rest = path.removePrefix(location.path)
    return if (rest.isEmpty()) "/" else rest
}

/**
 * The raw path for the upstream with the location prefix removed. Uses the raw path when it starts with the prefix
 * literally, so encoded characters further down stay untouched. Otherwise the normalized path, encoded again, so
 * the upstream never decodes a second time what Kovexy already decoded (`%2561dmin` must not become `/admin`).
 */
fun stripPrefix(location: LocationConfig, rawPath: String, normalizedPath: String): String {
    if (location.path == "/") return rawPath
    val prefix = location.path
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
