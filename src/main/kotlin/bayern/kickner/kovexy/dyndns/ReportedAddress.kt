package bayern.kickner.kovexy.dyndns

import bayern.kickner.kovexy.ResultOf2
import bayern.kickner.kovexy.config.parseIpLiteral

/** Smallest IPv6 prefix a client may report, a /48 is what one site gets at most. */
const val MIN_REPORTED_V6_PREFIX = 48

/**
 * An address a DynDNS client reported, validated and with its host bits cleared.
 *
 * @property text Canonical `address/prefix`, what goes into the allow list of a profile.
 * @property isV4 Whether this is an IPv4 address.
 * @property display The plain address for a single host (what dyndns2 answers), `address/prefix` for a prefix.
 */
class ReportedAddress internal constructor(val text: String, val isV4: Boolean, val display: String)

private val dottedQuad = """\d{1,3}(\.\d{1,3}){3}""".toRegex()

/** IPv4 ranges that are not publicly routable, as network bytes and prefix. */
private val blockedV4 = listOf(
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
).map(::network)

/** The IPv6 documentation range, not routable. */
private val documentationV6 = network("2001:db8::/32")

private fun network(cidr: String) = parseIpLiteral(cidr.substringBefore('/'))!! to cidr.substringAfter('/').toInt()

/**
 * Checks an address reported by a DynDNS client: a public IPv4 host or a global IPv6 host or prefix (/48 to /128).
 * Only literals, so parsing never asks DNS.
 *
 * @return the address, or the reason why it is refused.
 */
fun parseReported(raw: String): ResultOf2<ReportedAddress, String> {
    val text = raw.trim()
    if (text.isEmpty()) return ResultOf2.Failure("empty address")
    if ('%' in text) return ResultOf2.Failure("scoped addresses are not allowed")
    val addressPart = text.substringBefore('/')
    val prefixPart = text.substringAfter('/', "")
    // ofLiteral also accepts legacy forms like "1.2.3", only plain dotted quads are allowed
    if (':' !in addressPart && dottedQuad.matches(addressPart).not()) return ResultOf2.Failure("not an IP literal: $addressPart")
    val address = parseIpLiteral(addressPart) ?: return ResultOf2.Failure("not an IP literal: $addressPart")
    val v4 = address.size == 4
    val prefix = if (prefixPart.isEmpty()) address.size * 8 else prefixPart.toIntOrNull() ?: return ResultOf2.Failure("invalid prefix length: $prefixPart")
    if (v4 && prefix != 32) return ResultOf2.Failure("IPv4 must be a single address (/32)")
    if (v4.not() && prefix !in MIN_REPORTED_V6_PREFIX..128) return ResultOf2.Failure("IPv6 prefix must be /$MIN_REPORTED_V6_PREFIX to /128")
    if (isPublic(address).not()) return ResultOf2.Failure("not a publicly routable address: $addressPart")
    val bytes = mask(address, prefix)
    val plain = format(bytes)
    return ResultOf2.Success(ReportedAddress("$plain/$prefix", v4, if (prefix == bytes.size * 8) plain else "$plain/$prefix"))
}

/**
 * Collects the reported addresses from the query parameters `myip` (IPv4 and IPv6, comma separated), `myipv4` and `ip`
 * (IPv4), `myipv6`, `myip6` and `ipv6` (IPv6).
 *
 * @return IPv4 first, then IPv6. `null` if no known parameter has a value, the caller then uses the source address.
 *   A failure for an invalid address, the wrong family for an alias or more than one address of a family.
 */
fun addressesFromQuery(query: Map<String, String>): ResultOf2<List<ReportedAddress>?, String> {
    val v4Only = listOf("myipv4", "ip")
    val v6Only = listOf("myipv6", "myip6", "ipv6")
    val found = mutableListOf<Pair<String, ReportedAddress>>()
    for (name in listOf("myip") + v4Only + v6Only) {
        for (value in query[name].orEmpty().split(',').map(String::trim).filter(String::isNotEmpty)) {
            when (val parsed = parseReported(value)) {
                is ResultOf2.Success -> found += name to parsed.value
                is ResultOf2.Failure -> return ResultOf2.Failure(parsed.value)
            }
        }
    }
    if (found.isEmpty()) return ResultOf2.Success(null)
    found.forEach { (name, address) ->
        if (name in v4Only && address.isV4.not()) return ResultOf2.Failure("$name expects an IPv4 address")
        if (name in v6Only && address.isV4) return ResultOf2.Failure("$name expects an IPv6 address")
    }
    val addresses = found.map { it.second }
    if (addresses.count { it.isV4 } > 1 || addresses.count { it.isV4.not() } > 1) return ResultOf2.Failure("expected at most one IPv4 and one IPv6 address")
    return ResultOf2.Success(addresses.sortedBy { if (it.isV4) 0 else 1 })
}

private fun mask(bytes: ByteArray, prefix: Int): ByteArray {
    val out = bytes.copyOf()
    for (i in out.indices) {
        val keep = (prefix - i * 8).coerceIn(0, 8)
        out[i] = (out[i].toInt() and (0xFF shl (8 - keep)) and 0xFF).toByte()
    }
    return out
}

private fun isPublic(bytes: ByteArray): Boolean {
    if (bytes.size == 4) return blockedV4.none { inRange(bytes, it) }
    // Only global unicast 2000::/3, minus the documentation range
    return (bytes[0].toInt() and 0xE0) == 0x20 && inRange(bytes, documentationV6).not()
}

private fun inRange(bytes: ByteArray, network: Pair<ByteArray, Int>): Boolean = mask(bytes, network.second).contentEquals(network.first)

/** IPv4 dotted, IPv6 in the compressed form of RFC 5952 (the JDK writes it uncompressed, one spelling keeps entries comparable). */
private fun format(bytes: ByteArray): String {
    if (bytes.size == 4) return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
    val groups = IntArray(8) { ((bytes[it * 2].toInt() and 0xFF) shl 8) or (bytes[it * 2 + 1].toInt() and 0xFF) }
    var bestStart = -1
    var bestLength = 0
    var i = 0
    while (i < 8) {
        if (groups[i] != 0) {
            i++
            continue
        }
        var j = i
        while (j < 8 && groups[j] == 0) j++
        if (j - i > bestLength && j - i >= 2) {
            bestStart = i
            bestLength = j - i
        }
        i = j
    }
    val hex = groups.map { Integer.toHexString(it) }
    if (bestStart < 0) return hex.joinToString(":")
    return hex.subList(0, bestStart).joinToString(":") + "::" + hex.subList(bestStart + bestLength, 8).joinToString(":")
}
