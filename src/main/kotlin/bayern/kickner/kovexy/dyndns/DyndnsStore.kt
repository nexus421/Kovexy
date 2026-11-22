package bayern.kickner.kovexy.dyndns

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.ResultOf2
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.writeAtomically
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

private const val TAG = "Dyndns"

/**
 * The allow list entry a profile with DynDNS clients gets while none of them has an address and the profile has no
 * `allowIps` of its own: it names no address a visitor can come from (no TCP connection starts at 0.0.0.0), so the
 * profile lets nobody in by IP instead of everybody. It only exists in the routing table, never in the config.
 */
const val NOBODY_ALLOW_ENTRY = "0.0.0.0/32"

/** Name of the state file in the data directory. */
const val DYNDNS_STATE_FILE = "dyndns-state.json"

/**
 * What a client reported last.
 *
 * @property ipv4 The IPv4 address as `address/32`, `null` if none was reported.
 * @property ipv6 The IPv6 host or prefix as `address/prefix`, `null` if none was reported.
 * @property updated Unix milliseconds of the last report.
 */
@Serializable
data class ClientReport(val ipv4: String? = null, val ipv6: String? = null, val updated: Long = 0)

@Serializable
private data class DyndnsState(val clients: Map<String, ClientReport> = emptyMap())

private val stateJson = Json { prettyPrint = true; ignoreUnknownKeys = true }

/**
 * The last report of every DynDNS client, kept in `<dataDir>/dyndns-state.json` (owner only, written atomically). It
 * is runtime state and not part of the config, so a router update never changes the config version, the backups or
 * the audit log. A missing or broken file means nobody has reported yet.
 *
 * @param file The state file.
 * @param clock Unix milliseconds.
 */
class DyndnsStore(private val file: File, private val clock: () -> Long = System::currentTimeMillis) {
    @Volatile
    private var reports: Map<String, ClientReport> = load()

    private fun load(): Map<String, ClientReport> = runCatching {
        if (file.isFile.not()) emptyMap() else stateJson.decodeFromString<DyndnsState>(file.readText()).clients
    }.getOrElse {
        staticLog(KLogger.Level.WARN, TAG) { "The DynDNS state file could not be read, starting without reported addresses: ${it.javaClass.simpleName}" }
        emptyMap()
    }

    /** The last report of [client], `null` if it never reported. */
    fun lastReport(client: String): ClientReport? = reports[client]

    /**
     * Stores what [client] reports. Each update replaces all addresses of the client. The file is written first, so
     * what is kept in memory is always on disk too.
     *
     * @return whether the addresses differ from the last report (only then the allow lists change), or the reason
     *   why the state file could not be written. Nothing changes then.
     */
    @Synchronized
    fun report(client: String, addresses: List<ReportedAddress>): ResultOf2<Boolean, String> {
        val before = reports[client]
        val report = ClientReport(addresses.firstOrNull { it.isV4 }?.text, addresses.firstOrNull { it.isV4.not() }?.text, clock())
        val next = reports + (client to report)
        runCatching { writeAtomically(file, stateJson.encodeToString(DyndnsState(next))) }.onFailure {
            staticLog(KLogger.Level.WARN, TAG) { "The DynDNS state file could not be written, the report of $client is dropped: ${it.javaClass.simpleName}" }
            return ResultOf2.Failure("state file not written")
        }
        reports = next
        return ResultOf2.Success(before?.ipv4 != report.ipv4 || before?.ipv6 != report.ipv6)
    }

    /**
     * Forgets the reports of every client not in [clients], so a client that is deleted and added again under the
     * same name starts without addresses.
     */
    @Synchronized
    fun retain(clients: Set<String>) {
        val next = reports.filterKeys { it in clients }
        if (next.size == reports.size) return
        // Memory is cleaned in any case, a report left on disk belongs to no client and is dropped at the next start
        reports = next
        runCatching { writeAtomically(file, stateJson.encodeToString(DyndnsState(next))) }.onFailure {
            staticLog(KLogger.Level.WARN, TAG) { "The DynDNS state file could not be written after removing clients: ${it.javaClass.simpleName}" }
        }
    }

    /** The addresses of every client that uses [profile] and is still in [config], as allow list entries. */
    fun allowIpsFor(config: KovexyConfig, profile: String): List<String> =
        config.dyndnsClients.filter { profile in it.profiles }.flatMap { client -> reports[client.name]?.let { listOfNotNull(it.ipv4, it.ipv6) }.orEmpty() }
}

/** Names of the DynDNS clients in this config. */
fun KovexyConfig.dyndnsClientNames(): Set<String> = dyndnsClients.map { it.name }.toSet()

/**
 * [config] with the reported addresses added to the `allowIps` of the profiles of their clients. The result is only
 * used for the routing table and never written, so the entries in the config stay as the admin wrote them. An address
 * that two clients report stays while one of them still does. A profile that DynDNS clients use but that ends up
 * with no address at all (nobody reported yet, the state file was lost, no `allowIps` of its own) gets
 * [NOBODY_ALLOW_ENTRY], so it fails closed: only its countries and `allowLocal` still let visitors in.
 */
fun withDyndnsAllowIps(config: KovexyConfig, store: DyndnsStore): KovexyConfig {
    if (config.dyndnsClients.isEmpty()) return config
    return config.copy(accessProfiles = config.accessProfiles.map { profile ->
        if (config.dyndnsClients.none { profile.name in it.profiles }) return@map profile
        val allow = (profile.allowIps + store.allowIpsFor(config, profile.name)).distinct()
        profile.copy(allowIps = allow.ifEmpty { listOf(NOBODY_ALLOW_ENTRY) })
    })
}
