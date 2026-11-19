package bayern.kickner.kovexy.access

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.audit.SecurityEvents
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.notify.EventSink
import bayern.kickner.kovexy.stats.BanTable
import bayern.kickner.kovexy.stats.Storage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.upsert
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration

private const val TAG = "Bans"

/**
 * An active ban.
 *
 * @property key The address, for IPv6 the /64 prefix.
 * @property reason Why, e.g. the trap path.
 * @property site The site whose trap fired.
 * @property createdAt Unix milliseconds.
 * @property expiresAt Unix milliseconds.
 */
data class Ban(val key: String, val reason: String, val site: String, val createdAt: Long, val expiresAt: Long)

/**
 * Bans from trap paths. They are checked first for every proxy request (concept section 3.3, step 2), for all
 * sites. Stored in SQLite so they survive a restart, kept in memory for the check, removed automatically when they
 * expire.
 *
 * @param clock Unix milliseconds.
 * @param onBan Called with the ban key of every new ban, to end what the address already has open.
 */
class BanStore(
    private val storage: Storage,
    private val events: EventSink,
    private val security: SecurityEvents,
    private val clock: () -> Long = System::currentTimeMillis,
    private val onBan: (String) -> Unit = {},
) {
    private val active = ConcurrentHashMap<String, Ban>()

    /** Database writes, one after the other in their order, so the proxy path never waits for SQLite. */
    private val writes = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))

    init {
        reload()
    }

    /** Loads the bans from the database, at start and after a restored backup. */
    fun reload() {
        val stored = storage.tx {
            BanTable.selectAll().associate { row ->
                row[BanTable.key] to Ban(row[BanTable.key], row[BanTable.reason], row[BanTable.site], row[BanTable.createdAt], row[BanTable.expiresAt])
            }
        }
        active.keys.retainAll(stored.keys)
        active.putAll(stored)
    }

    /** The active ban of [address], `null` if it may pass. An expired ban is removed on the way. */
    fun banOf(address: InetAddress): Ban? {
        if (active.isEmpty()) return null
        val ban = active[addressKey(address)] ?: return null
        if (ban.expiresAt <= clock()) {
            expire(ban)
            return null
        }
        return ban
    }

    /** Bans [address] for [duration], or extends an existing ban. */
    fun ban(address: InetAddress, duration: Duration, reason: String, site: String) {
        val now = clock()
        val key = addressKey(address)
        val ban = Ban(key, reason.take(300), site.take(253), now, now + duration.inWholeMilliseconds)
        val isNew = active.put(key, ban) == null
        writes.launch {
            runCatching {
                storage.tx {
                    BanTable.upsert {
                        it[BanTable.key] = key
                        it[BanTable.reason] = ban.reason
                        it[BanTable.site] = ban.site
                        it[createdAt] = ban.createdAt
                        it[expiresAt] = ban.expiresAt
                    }
                }
            }.onFailure { staticLog(KLogger.Level.ERROR, TAG) { "Cannot store the ban of $key: ${it.message}" } }
        }
        if (isNew.not()) return
        onBan(key)
        staticLog(KLogger.Level.WARN, TAG) { "Banned $key until ${formatTimestamp(ban.expiresAt)}: $reason" }
        security.record(SecurityEventType.IP_BANNED, key, site, reason)
        events.emit(Event(WebhookEvent.IP_BANNED, "IP $key banned", "$key was banned until ${formatTimestamp(ban.expiresAt)}: $reason", site, now, item = key))
    }

    /** Lifts the ban of [key] before it expires. @return whether there was one. */
    fun lift(key: String): Boolean {
        val ban = active.remove(key) ?: return false
        writes.launch { runCatching { storage.tx { BanTable.deleteWhere { BanTable.key eq key } } } }
        security.record(SecurityEventType.BAN_ENDED, key, ban.site, "lifted by hand")
        return true
    }

    /** Every active ban, newest first. */
    fun list(): List<Ban> {
        val now = clock()
        active.values.filter { it.expiresAt <= now }.forEach(::expire)
        return active.values.sortedByDescending { it.createdAt }
    }

    /** Removes expired bans, called regularly. */
    fun purgeExpired() {
        val now = clock()
        active.values.filter { it.expiresAt <= now }.forEach(::expire)
        storage.tx { BanTable.deleteWhere { expiresAt less now } }
    }

    private fun expire(ban: Ban) {
        if (active.remove(ban.key, ban).not()) return
        writes.launch { runCatching { storage.tx { BanTable.deleteWhere { BanTable.key eq ban.key } } } }
        security.record(SecurityEventType.BAN_ENDED, ban.key, ban.site, "expired")
    }
}
