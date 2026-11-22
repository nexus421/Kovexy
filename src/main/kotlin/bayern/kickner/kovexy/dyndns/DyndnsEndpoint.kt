package bayern.kickner.kovexy.dyndns

import bayern.kickner.kovexy.ResultOf2
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.sha256Hex
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64

/** The only path a domain with `dyndns` answers. */
const val DYNDNS_UPDATE_PATH = "/nic/update"

/**
 * The answer to an update request.
 *
 * @property status HTTP status.
 * @property body The dyndns2 answer, plain text.
 * @property reason For the access log, never holds a password or a query value.
 * @property authFailed Whether the login was wrong, the proxy then adds `WWW-Authenticate` and marks the request as a
 *   failed Basic Auth login in the access log.
 */
data class DyndnsAnswer(val status: Int, val body: String, val reason: String, val authFailed: Boolean = false)

/**
 * The dyndns2 endpoint of a domain with `dyndns`: `GET /nic/update` with Basic Auth (client name and password) and the
 * address in `myip` and the other parameters of [addressesFromQuery]. Without an address parameter the source address of
 * the request counts. Each update replaces all addresses of the client. The access profile of the domain has already
 * run when this is called.
 *
 * @param config The active config.
 * @param store Where the reports are kept.
 * @param onChange Called when the reported addresses of a client changed, the routing table is rebuilt there.
 * @param onFailedLogin Called with the client IP and the domain for a wrong login, it becomes a security event there.
 */
class DyndnsEndpoint(
    private val config: () -> KovexyConfig,
    private val store: DyndnsStore,
    private val onChange: () -> Unit,
    private val onFailedLogin: (clientIp: String, domain: String) -> Unit = { _, _ -> },
) {
    /**
     * Answers one request. Never throws. [rawQuery] is the query string as sent, without `?`, [domain] the name of the
     * domain for the security events.
     */
    fun answer(method: String, authorization: String?, rawQuery: String, clientIp: String, domain: String = ""): DyndnsAnswer {
        if (method != "GET") return DyndnsAnswer(405, "badrequest", "dyndns wrong method")
        val client = authenticate(authorization) ?: run {
            onFailedLogin(clientIp, domain)
            return DyndnsAnswer(401, "badauth", "dyndns wrong login", authFailed = true)
        }
        val query = parseQuery(rawQuery) ?: return DyndnsAnswer(400, "badrequest invalid query", "dyndns invalid query")
        val reported = when (val found = addressesFromQuery(query)) {
            is ResultOf2.Failure -> return DyndnsAnswer(400, "badrequest ${clean(found.value)}", "dyndns invalid address")
            is ResultOf2.Success -> found.value
        }
        // dyndns2: without an address parameter the source address of the request is used
        val addresses = reported ?: when (val source = parseReported(clientIp)) {
            is ResultOf2.Failure -> return DyndnsAnswer(400, "badrequest ${clean(source.value)}", "dyndns invalid source address")
            is ResultOf2.Success -> listOf(source.value)
        }
        // 911 is the dyndns2 answer for a problem on the server side
        val changed = when (val stored = store.report(client, addresses)) {
            is ResultOf2.Failure -> return DyndnsAnswer(500, "911", "dyndns ${stored.value}")
            is ResultOf2.Success -> stored.value
        }
        if (changed) onChange()
        val shown = addresses.joinToString(",") { it.display }
        return if (changed) DyndnsAnswer(200, "good $shown", "dyndns good") else DyndnsAnswer(200, "nochg $shown", "dyndns nochg")
    }

    /** The name of the client whose name and password [authorization] carries, `null` if there is none. */
    private fun authenticate(authorization: String?): String? {
        val encoded = authorization?.takeIf { it.startsWith("Basic ", ignoreCase = true) }?.substring(6)?.trim() ?: return null
        val text = runCatching { String(Base64.getDecoder().decode(encoded), Charsets.UTF_8) }.getOrNull() ?: return null
        val name = text.substringBefore(':')
        val password = text.substringAfter(':', "")
        val client = config().dyndnsClients.firstOrNull { it.name == name }
        // Compared against a fixed value for an unknown name too, so the answer time does not tell which names exist
        val expected = client?.passwordHash ?: "0".repeat(64)
        val same = MessageDigest.isEqual(sha256Hex(password).toByteArray(), expected.toByteArray())
        return if (client != null && same) client.name else null
    }

    /** The decoded query, the last value of a name wins. `null` for broken percent encoding. */
    private fun parseQuery(raw: String): Map<String, String>? = runCatching {
        raw.split('&').filter { it.isNotEmpty() }.associate { pair ->
            URLDecoder.decode(pair.substringBefore('='), Charsets.UTF_8) to URLDecoder.decode(pair.substringAfter('=', ""), Charsets.UTF_8)
        }
    }.getOrNull()

    /** Drops control characters from a reason, the answer is one line. */
    private fun clean(text: String): String = text.filter { it.code in 32..126 }
}
