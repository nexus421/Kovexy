package bayern.kickner.kovexy.access

import bayern.kickner.kovexy.config.AiCrawlersConfig
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.InetAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Patterns of the exploit filter, taken from Nginx Proxy Manager's `block-exploits.conf`
 * (https://github.com/NginxProxyManager/nginx-proxy-manager, MIT license, see NOTICE). Zoraxy uses the same ones,
 * but its code is AGPL and nothing is taken from there. Like in nginx (`~`) the patterns are case sensitive and are
 * checked against the query string.
 */
private val QUERY_PATTERNS: List<Pair<String, Regex>> = listOf(
    // Block file injections
    "file injection" to """[a-zA-Z0-9_]=http://""",
    // NPM writes these two with a repeated group, `(\.\.//?)+` and `/([a-z0-9_.]//?)+`. For "contains" one repetition
    // decides the same, and the repeated group overflowed the stack on a long query (audit run-2)
    "file injection" to """[a-zA-Z0-9_]=\.\./""",
    "file injection" to """[a-zA-Z0-9_]=/[a-z0-9_.]/""",
    // Block common exploits
    "common exploit" to """GLOBALS(=|\[|%[0-9A-Z]{0,2})""",
    "common exploit" to """_REQUEST(=|\[|%[0-9A-Z]{0,2})""",
    "common exploit" to """proc/self/environ""",
    "common exploit" to """mosConfig_[a-zA-Z_]{1,21}(=|%3D)""",
    // Block spam
    "spam" to """\b(ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo)\b""",
    "spam" to """\b(erections|hoodia|huronriveracres|impotence|levitra|libido)\b""",
    "spam" to """\b(ambien|blue\spill|cialis|cocaine|ejaculation|erectile)\b""",
    "spam" to """\b(lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby)\b""",
).map { (name, pattern) -> name to pattern.toRegex() }

/**
 * NPM's patterns of the form `a.*b.*c` as ordered parts, each a list of alternatives. A backtracking regex needs cubic
 * time for them on a long query (seconds per request), [containsInOrder] finds the same matches in linear time.
 */
private val ORDERED_PATTERNS: List<Pair<String, List<List<String>>>> = listOf(
    // Block SQL injections: union.*select.*\(   union.*all.*select.*   concat.*\(
    "sql injection" to listOf(listOf("union"), listOf("select"), listOf("(")),
    "sql injection" to listOf(listOf("union"), listOf("all"), listOf("select")),
    "sql injection" to listOf(listOf("concat"), listOf("(")),
    // Block common exploits: (<|%3C).*script.*(>|%3E)   base64_(en|de)code\(.*\)
    "common exploit" to listOf(listOf("<", "%3C"), listOf("script"), listOf(">", "%3E")),
    "common exploit" to listOf(listOf("base64_encode(", "base64_decode("), listOf(")")),
)

/** Characters `.` of a regex does not match, so the ordered parts must be found within one line, like the regex. */
private val LINE_BREAKS = charArrayOf('\n', '\r', '\u0085', '\u2028', '\u2029')

/**
 * Whether every group of [parts] occurs in [text] in this order on one line, like the regex `a.*b.*c`. Taking the
 * earliest occurrence of each part is enough: if any order fits, the earliest one does.
 */
internal fun containsInOrder(text: String, parts: List<List<String>>): Boolean = text.split(*LINE_BREAKS).any { line ->
    var from = 0
    parts.all { alternatives ->
        val hit = alternatives.mapNotNull { a -> line.indexOf(a, from).takeIf { it >= 0 }?.let { it + a.length } }.minOrNull()
        if (hit != null) from = hit
        hit != null
    }
}

/** User agents of NPM's "Block user agents" section: old download tools and hacking tools. */
private val USER_AGENT_PATTERNS: List<String> = listOf(
    "Indy Library", "libwww-perl", "GetRight", "GetWeb!", "Go!Zilla", "Download Demon", "Go-Ahead-Got-It", "TurnitinBot", "GrabNet",
)

/**
 * Checks a request against the common exploit patterns. The query is checked raw and percent-decoded, so an encoded
 * attack does not slip through.
 *
 * @return the name of the matching group, `null` if nothing matches.
 */
fun matchCommonExploit(rawQuery: String, userAgent: String): String? {
    if (rawQuery.isNotEmpty()) {
        val decoded = runCatching { URLDecoder.decode(rawQuery.replace("+", "%2B"), StandardCharsets.UTF_8) }.getOrDefault(rawQuery)
        ORDERED_PATTERNS.firstOrNull { (_, parts) -> containsInOrder(rawQuery, parts) || containsInOrder(decoded, parts) }?.let { return it.first }
        QUERY_PATTERNS.firstOrNull { (_, regex) -> regex.containsMatchIn(rawQuery) || regex.containsMatchIn(decoded) }?.let { return it.first }
    }
    if (USER_AGENT_PATTERNS.any { it in userAgent }) return "known tool"
    return null
}

/**
 * Names of AI crawlers from ai.robots.txt (https://github.com/ai-robots-txt/ai.robots.txt, MIT license, see NOTICE),
 * shipped as `ai-bots/robots.json`. Only the keys are used, keys starting with `__` are metadata.
 */
val AI_BOT_NAMES: List<String> by lazy {
    val text = object {}.javaClass.getResourceAsStream("/ai-bots/robots.json")?.use { it.readBytes().decodeToString() } ?: return@lazy emptyList()
    Json.parseToJsonElement(text).jsonObject.keys.filter { it.startsWith("__").not() && it.isNotBlank() }.map { it.lowercase() }
}

/** The shipped crawler names, lower case, for the admin UI. */
val shippedAiBotNames: List<String> get() = AI_BOT_NAMES

@Volatile
private var effective: Pair<AiCrawlersConfig, List<String>>? = null

/** The shipped list without the ignored names plus the added ones, lower case. Remembered for the last config. */
fun aiBotNames(changes: AiCrawlersConfig): List<String> {
    effective?.takeIf { it.first == changes }?.let { return it.second }
    val ignored = changes.ignore.map { it.trim().lowercase() }.toSet()
    val names = (AI_BOT_NAMES.filter { it !in ignored } + changes.add.map { it.trim().lowercase() }.filter { it.isNotEmpty() }).distinct()
    effective = changes to names
    return names
}

/** The AI crawler named in [userAgent], `null` if none. Case insensitive substring, see [aiBotNames]. */
fun matchAiBot(userAgent: String, changes: AiCrawlersConfig = AiCrawlersConfig()): String? {
    if (userAgent.isEmpty()) return null
    val lower = userAgent.lowercase()
    return aiBotNames(changes).firstOrNull { it in lower }
}

/** Whether [address] is private, loopback or link local (IPv4 RFC 1918, IPv6 `fc00::/7`), for `allowLocal`. */
fun isLocalAddress(address: InetAddress): Boolean {
    if (address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress) return true
    val bytes = address.address
    return bytes.size == 16 && (bytes[0].toInt() and 0xFE) == 0xFC
}

/**
 * The key an address is counted and banned under: IPv4 addresses as they are, IPv6 addresses reduced to their first
 * [ipv6Prefix] bits, because one household or server usually gets a whole /64.
 */
fun addressKey(address: InetAddress, ipv6Prefix: Int = 64): String {
    val bytes = address.address
    if (bytes.size == 4) return address.hostAddress
    val masked = bytes.copyOf()
    for (bit in ipv6Prefix until 128) masked[bit / 8] = (masked[bit / 8].toInt() and (0x80 ushr (bit % 8)).inv()).toByte()
    return InetAddress.getByAddress(masked).hostAddress.let { normalizeV6(it) } + "/$ipv6Prefix"
}

/** Java prints IPv6 without shortening, this gives the usual short form for display. */
private fun normalizeV6(text: String): String {
    val groups = text.split(':').map { it.trimStart('0').ifEmpty { "0" } }
    var bestStart = -1
    var bestLength = 0
    var i = 0
    while (i < groups.size) {
        if (groups[i] == "0") {
            var j = i
            while (j < groups.size && groups[j] == "0") j++
            if (j - i > bestLength && j - i > 1) {
                bestStart = i
                bestLength = j - i
            }
            i = j
        } else i++
    }
    if (bestStart < 0) return groups.joinToString(":")
    val head = groups.subList(0, bestStart).joinToString(":")
    val tail = groups.subList(bestStart + bestLength, groups.size).joinToString(":")
    return "$head::$tail"
}
