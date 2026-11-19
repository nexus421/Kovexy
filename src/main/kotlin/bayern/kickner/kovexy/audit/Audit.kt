package bayern.kickner.kovexy.audit

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.stats.AuditTable
import bayern.kickner.kovexy.stats.SecurityEventTable
import bayern.kickner.kovexy.stats.Storage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.jdbc.andWhere
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration

private const val TAG = "Audit"

/** Longest stored detail of an audit entry, a config diff is cut there. */
private const val MAX_AUDIT_DETAIL = 20_000

/**
 * Who did something.
 *
 * @property sub Stable ID: the OIDC `sub`, `local` for the local password, `system` for Kovexy itself, `file` for a
 *   change of `kovexy.json` on disk (by hand or by a command line action).
 * @property name Display name.
 * @property ip Address, empty for the system.
 */
data class Actor(val sub: String, val name: String, val ip: String = "") {
    companion object {
        /** Kovexy itself, e.g. an issued certificate. */
        val SYSTEM = Actor("system", "Kovexy")

        /** `kovexy.json` changed on disk, by hand or by a command line action such as `reset-password`. */
        val FILE = Actor("file", "File on disk")
    }
}

/** Actions in the audit log. */
enum class AuditAction(val label: String) {
    LOGIN("Login"),
    LOGOUT("Logout"),
    LOGIN_FAILED("Failed login"),
    CONFIG_CHANGED("Configuration changed"),
    CERT_ISSUED("Certificate issued"),
    CERT_REMOVED("Expired certificate removed"),
    BACKUP_DOWNLOADED("Backup downloaded"),
    BACKUP_RESTORED("Backup restored"),
    PASSWORD_CHANGED("Password changed"),
    SESSIONS_ENDED("Other sessions ended"),
    BAN_LIFTED("Ban lifted"),
    INCUS_APPROVED("Incus container approved"),
    INCUS_REJECTED("Incus container rejected"),
    INCUS_REMOVED("Incus decision removed"),
}

/**
 * One audit entry.
 *
 * @property detail Free text, for config changes the diff with secrets as `***`.
 */
data class AuditEntry(val time: Long, val actor: Actor, val action: AuditAction, val target: String, val detail: String)

/**
 * The audit log in SQLite (Dirl's audit log, stored like the other runtime data). Never holds passwords, hashes,
 * secrets or keys.
 *
 * @param clock Unix milliseconds.
 */
class AuditLog(private val storage: Storage, private val clock: () -> Long = System::currentTimeMillis) {

    /** Records an action. Blocking, but small and rare. */
    fun record(actor: Actor, action: AuditAction, target: String = "", detail: String = "") {
        runCatching {
            storage.tx {
                AuditTable.insert {
                    it[time] = clock()
                    it[actorSub] = actor.sub.take(256)
                    it[actorName] = actor.name.take(100)
                    it[ip] = actor.ip.take(64)
                    it[AuditTable.action] = action.name
                    it[AuditTable.target] = target.take(300)
                    it[AuditTable.detail] = detail.take(MAX_AUDIT_DETAIL)
                }
            }
        }.onFailure { staticLog(KLogger.Level.ERROR, TAG) { "Cannot write the audit log: ${it.message}" } }
    }

    /** The newest entries, newest first, optionally only of [action]. */
    fun latest(action: AuditAction? = null, limit: Int = 200): List<AuditEntry> = storage.tx {
        val query = AuditTable.selectAll()
        action?.let { a -> query.andWhere { AuditTable.action eq a.name } }
        query.orderBy(AuditTable.id, SortOrder.DESC).limit(limit).mapNotNull { row ->
            val a = runCatching { AuditAction.valueOf(row[AuditTable.action]) }.getOrNull() ?: return@mapNotNull null
            AuditEntry(row[AuditTable.time], Actor(row[AuditTable.actorSub], row[AuditTable.actorName], row[AuditTable.ip]), a, row[AuditTable.target], row[AuditTable.detail])
        }
    }

    /** Deletes entries older than [retention]. */
    suspend fun applyRetention(retention: Duration, now: Long) = storage.writeLock.withLock {
        storage.tx { AuditTable.deleteWhere { time less (now - retention.inWholeMilliseconds) } }
    }
}

/** Kinds of security events. */
enum class SecurityEventType(val label: String) {
    IP_BANNED("IP banned"),
    BAN_ENDED("Ban ended or lifted"),
    RATE_LIMITED("Rate limit exceeded"),
    EXPLOIT_BLOCKED("Exploit pattern"),
    AI_BOT_BLOCKED("AI crawler"),
    ACCESS_DENIED("Denied by profile"),
    METHOD_DENIED("Method not allowed"),
    BASIC_AUTH_FAILED("Basic Auth failed"),
    ADMIN_LOGIN_FAILED("Admin login failed"),
}

/**
 * One security event.
 *
 * @property ip Visitor address.
 * @property site Site of the request, empty if none.
 * @property detail Short description, e.g. the path or the matched pattern group.
 */
data class SecurityEvent(val time: Long, val type: SecurityEventType, val ip: String, val site: String, val detail: String)

/**
 * Security events in SQLite, written in the background like the access log so the proxy never waits. Rate limit
 * events are recorded at most once per IP and minute.
 *
 * @param clock Unix milliseconds.
 */
class SecurityEvents(private val storage: Storage, private val clock: () -> Long = System::currentTimeMillis) {
    private val queue = Channel<SecurityEvent>(10_000, BufferOverflow.DROP_LATEST)
    private val rateLimited = ConcurrentHashMap<String, Long>()

    /** Queues an event, returns at once. */
    fun record(type: SecurityEventType, ip: String, site: String = "", detail: String = "") {
        val now = clock()
        if (type == SecurityEventType.RATE_LIMITED) {
            val minute = now / 60_000
            if (rateLimited.put("$ip|$site", minute) == minute) return
            if (rateLimited.size > 10_000) rateLimited.clear()
        }
        queue.trySend(SecurityEvent(now, type, ip, site, detail))
    }

    /** Starts the writer in [scope]. */
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (true) {
            val batch = mutableListOf(queue.receive())
            withTimeoutOrNull(1000) { while (batch.size < 500) batch += queue.receive() }
            runCatching { write(batch) }.onFailure { staticLog(KLogger.Level.ERROR, TAG) { "Writing security events failed: ${it.message}" } }
        }
    }

    /** Writes everything still queued, for tests. */
    suspend fun flush() {
        val batch = mutableListOf<SecurityEvent>()
        while (true) batch += queue.tryReceive().getOrNull() ?: break
        if (batch.isNotEmpty()) write(batch)
    }

    private suspend fun write(batch: List<SecurityEvent>) = storage.writeLock.withLock {
        storage.tx {
            SecurityEventTable.batchInsert(batch, shouldReturnGeneratedValues = false) { e ->
                this[SecurityEventTable.time] = e.time
                this[SecurityEventTable.type] = e.type.name
                this[SecurityEventTable.ip] = e.ip.take(64)
                this[SecurityEventTable.site] = e.site.take(253)
                this[SecurityEventTable.detail] = e.detail.take(500)
            }
        }
    }

    /** The newest events, newest first, optionally only of [type]. */
    fun latest(type: SecurityEventType? = null, limit: Int = 200): List<SecurityEvent> = storage.tx {
        val query = SecurityEventTable.selectAll()
        type?.let { t -> query.andWhere { SecurityEventTable.type eq t.name } }
        query.orderBy(SecurityEventTable.id, SortOrder.DESC).limit(limit).mapNotNull { row ->
            val t = runCatching { SecurityEventType.valueOf(row[SecurityEventTable.type]) }.getOrNull() ?: return@mapNotNull null
            SecurityEvent(row[SecurityEventTable.time], t, row[SecurityEventTable.ip], row[SecurityEventTable.site], row[SecurityEventTable.detail])
        }
    }

    /** Deletes events older than [retention]. */
    suspend fun applyRetention(retention: Duration, now: Long) = storage.writeLock.withLock {
        storage.tx { SecurityEventTable.deleteWhere { time less (now - retention.inWholeMilliseconds) } }
    }
}
