package bayern.kickner.kovexy.config

import java.net.InetAddress
import java.net.URI

/**
 * An IP range in CIDR notation, e.g. `192.168.1.0/24` or `fd00::/8`. A single address without suffix is a range of
 * exactly that address.
 *
 * @property network The address bytes of the range start.
 * @property prefix Number of leading bits that must match.
 */
class Cidr private constructor(private val network: ByteArray, private val prefix: Int) {

    /** Whether [address] lies in this range. IPv4 and IPv6 never match each other. */
    fun contains(address: InetAddress): Boolean {
        val bytes = address.address
        if (bytes.size != network.size) return false
        val fullBytes = prefix / 8
        for (i in 0 until fullBytes) if (bytes[i] != network[i]) return false
        val rest = prefix % 8
        if (rest == 0) return true
        val mask = (0xFF shl (8 - rest)) and 0xFF
        return (bytes[fullBytes].toInt() and mask) == (network[fullBytes].toInt() and mask)
    }

    companion object {
        /**
         * Parses `address` or `address/prefix`. Only literal IP addresses, never host names, so parsing never asks DNS.
         *
         * @return the range, `null` if [text] is no valid range.
         */
        fun parse(text: String): Cidr? {
            val address = text.substringBefore('/')
            val bytes = parseIpLiteral(address) ?: return null
            val maxPrefix = bytes.size * 8
            val prefix = if ('/' in text) text.substringAfter('/').toIntOrNull() ?: return null else maxPrefix
            if (prefix !in 0..maxPrefix) return null
            return Cidr(bytes, prefix)
        }
    }
}

private val ipv4Literal = """\d{1,3}(\.\d{1,3}){3}""".toRegex()
private val ipv6Literal = """[0-9a-fA-F:.]+""".toRegex()

/**
 * A peer address without the brackets Jetty puts around IPv6 and without the zone of a link-local address:
 * `[::1]` becomes `::1`, `fe80::1%eth0` becomes `fe80::1`.
 */
fun plainAddress(text: String): String = text.removePrefix("[").removeSuffix("]").substringBefore('%')

/**
 * The bytes of a literal IPv4 or IPv6 address, without any DNS lookup.
 *
 * @return the bytes, `null` if [text] is no IP literal.
 */
fun parseIpLiteral(text: String): ByteArray? {
    val plain = text.removePrefix("[").removeSuffix("]")
    val isV4 = ipv4Literal.matches(plain) && plain.split('.').all { it.toInt() in 0..255 }
    val isV6 = ':' in plain && ipv6Literal.matches(plain)
    if (isV4.not() && isV6.not()) return null
    // With a literal, getByName only parses and never resolves
    return runCatching { InetAddress.getByName(plain).address }.getOrNull()
}

/**
 * Host and port of a backend server.
 *
 * @property host Host name or IP, IPv6 without brackets.
 * @property port TCP port.
 */
data class HostPort(val host: String, val port: Int) {
    /** `host:port`, IPv6 in brackets, as used in URLs and the `Host` header. */
    override fun toString(): String = if (':' in host) "[$host]:$port" else "$host:$port"

    companion object {
        /**
         * Parses `host:port` or `[ipv6]:port`.
         *
         * @return the address, `null` if [text] has no valid host or port.
         */
        fun parse(text: String): HostPort? {
            val (host, portText) = when {
                text.startsWith("[") -> {
                    val end = text.indexOf("]:")
                    if (end < 0) return null
                    text.substring(1, end) to text.substring(end + 2)
                }

                text.count { it == ':' } == 1 -> text.substringBefore(':') to text.substringAfter(':')
                else -> return null
            }
            val port = portText.toIntOrNull() ?: return null
            if (port !in 1..65535 || host.isBlank()) return null
            if (text.startsWith("[") && parseIpLiteral(host) == null) return null
            if (text.startsWith("[").not() && isValidHostName(host).not() && parseIpLiteral(host) == null) return null
            return HostPort(host, port)
        }
    }
}

private val hostLabel = """[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?""".toRegex()

/**
 * Whether [name] is a valid lower case DNS name (letters, digits, hyphens, punycode for international names), at
 * most 253 characters. No wildcards, no trailing dot, no port.
 */
fun isValidHostName(name: String): Boolean =
    name.length in 1..253 && name.split('.').all { hostLabel.matches(it) }

/**
 * The domain a request is meant for: the `Host` header without port and trailing dot, in lower case.
 *
 * @return the domain, `null` for an empty or malformed header.
 */
fun domainOfHostHeader(host: String?): String? {
    if (host.isNullOrBlank()) return null
    val withoutPort = when {
        host.startsWith("[") -> host.substringBefore("]") + "]"
        else -> host.substringBefore(':')
    }
    return withoutPort.trimEnd('.').lowercase().ifEmpty { null }
}

/** True for host names that never leave the machine. */
fun isLoopbackHost(host: String): Boolean =
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1" || host.endsWith(".localhost")

/**
 * Checks that [value] is an absolute `https` URL, or `http` where [allowHttp] says so.
 *
 * @return an error message, `null` if the URL is fine.
 */
fun checkAbsoluteUrl(name: String, value: String, allowHttp: (host: String) -> Boolean = ::isLoopbackHost): String? {
    val uri = runCatching { URI(value) }.getOrNull()
    val host = uri?.host
    val valid = host != null && (uri.scheme == "https" || (uri.scheme == "http" && allowHttp(host)))
    // Only scheme and host are repeated: a webhook URL carries its token in the path or query, and this message goes
    // into the log and to every webhook (audit run-2)
    val shown = if (uri?.scheme != null && host != null) "${uri.scheme}://$host/..." else "not a URL"
    return if (valid) null else "$name must be an absolute https URL${if (allowHttp("example.com")) " or http URL" else " (http only for localhost)"}, is $shown"
}
