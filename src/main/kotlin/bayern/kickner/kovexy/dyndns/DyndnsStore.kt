package bayern.kickner.kovexy.dyndns

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.writeAtomically
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

private const val TAG = "Dyndns"

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
     * Stores what [client] reports. Each update replaces all addresses of the client.
     *
     * @return whether the addresses differ from the last report, only then the allow lists change.
     */
    @Synchronized
    fun report(client: String, addresses: List<ReportedAddress>): Boolean {
        val before = reports[client]
        val report = ClientReport(addresses.firstOrNull { it.isV4 }?.text, addresses.firstOrNull { it.isV4.not() }?.text, clock())
        val changed = before?.ipv4 != report.ipv4 || before?.ipv6 != report.ipv6
        reports = reports + (client to report)
        writeAtomically(file, stateJson.encodeToString(DyndnsState(reports)))
        return changed
    }

    /** The addresses of every client that uses [profile] and is still in [config], as allow list entries. */
    fun allowIpsFor(config: KovexyConfig, profile: String): List<String> =
        config.dyndnsClients.filter { profile in it.profiles }.flatMap { client -> reports[client.name]?.let { listOfNotNull(it.ipv4, it.ipv6) }.orEmpty() }
}

/**
 * [config] with the reported addresses added to the `allowIps` of the profiles of their clients. The result is only
 * used for the routing table and never written, so the entries in the config stay as the admin wrote them. An address
 * that two clients report stays while one of them still does.
 */
fun withDyndnsAllowIps(config: KovexyConfig, store: DyndnsStore): KovexyConfig {
    if (config.dyndnsClients.isEmpty()) return config
    return config.copy(accessProfiles = config.accessProfiles.map { profile ->
        val extra = store.allowIpsFor(config, profile.name)
        if (extra.isEmpty()) profile else profile.copy(allowIps = (profile.allowIps + extra).distinct())
    })
}
