package bayern.kickner.kovexy.stats

import bayern.kickner.kovexy.restrictToOwner
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.JdbcTransaction
import org.jetbrains.exposed.v1.jdbc.SchemaUtils
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.sql.Connection
import java.sql.DriverManager

/** Name of the database file in the data directory. */
const val DATABASE_FILE_NAME = "kovexy.db"

/** One line per request. */
object AccessLogTable : Table("access_log") {
    val id = long("id").autoIncrement()
    val time = long("time").index()
    val clientIp = varchar("client_ip", 64)
    val method = varchar("method", 16)
    val domain = varchar("domain", 253)
    val path = varchar("path", 2048)
    val status = integer("status")
    val bytesIn = long("bytes_in")
    val bytesOut = long("bytes_out")
    val durationMs = long("duration_ms")
    val site = varchar("site", 253).index()
    val location = varchar("location", 512)
    val upstream = varchar("upstream", 300)
    val userAgent = varchar("user_agent", 512)
    val reason = varchar("reason", 200)
    override val primaryKey = PrimaryKey(id)
}

/** Columns shared by the hourly and the daily statistics. */
abstract class StatsTable(name: String) : Table(name) {
    val site = varchar("site", 253)
    val bucket = long("bucket")
    val requests = long("requests")
    val status2xx = long("status_2xx")
    val status3xx = long("status_3xx")
    val status4xx = long("status_4xx")
    val status5xx = long("status_5xx")
    val bytesIn = long("bytes_in")
    val bytesOut = long("bytes_out")
    val durationSum = long("duration_sum_ms")
    val durationMax = long("duration_max_ms")
    override val primaryKey = PrimaryKey(site, bucket)
}

/** Statistics per site and hour. `bucket` is the start of the hour in Unix milliseconds. */
object StatsHourlyTable : StatsTable("stats_hourly")

/** Statistics per site and day. `bucket` is the start of the day in the host's time zone, Unix milliseconds. */
object StatsDailyTable : StatsTable("stats_daily")

/** Admin sessions. Only the SHA-256 of the token is stored, a copy of the database opens no session. */
object SessionTable : Table("sessions") {
    val tokenHash = varchar("token_hash", 64)
    val id = varchar("id", 32)
    val createdAt = long("created_at")
    val lastSeen = long("last_seen")
    val userAgent = varchar("user_agent", 200)
    val ip = varchar("ip", 64)
    val sub = varchar("sub", 256).default("local")
    val name = varchar("name", 100).default("admin")
    override val primaryKey = PrimaryKey(tokenHash)
}

/** IP bans from trap paths. `key` is the address, or the /64 prefix for IPv6. */
object BanTable : Table("bans") {
    val key = varchar("key", 64)
    val reason = varchar("reason", 300)
    val site = varchar("site", 253)
    val createdAt = long("created_at")
    val expiresAt = long("expires_at").index()
    override val primaryKey = PrimaryKey(key)
}

/** The audit log: who changed what and when. */
object AuditTable : Table("audit") {
    val id = long("id").autoIncrement()
    val time = long("time").index()
    val actorSub = varchar("actor_sub", 256)
    val actorName = varchar("actor_name", 100)
    val ip = varchar("ip", 64)
    val action = varchar("action", 40)
    val target = varchar("target", 300)
    val detail = text("detail")
    override val primaryKey = PrimaryKey(id)
}

/** Security events: bans, blocked requests, failed logins. */
object SecurityEventTable : Table("security_events") {
    val id = long("id").autoIncrement()
    val time = long("time").index()
    val type = varchar("type", 40)
    val ip = varchar("ip", 64)
    val site = varchar("site", 253)
    val detail = varchar("detail", 500)
    override val primaryKey = PrimaryKey(id)
}

/** Sessions of the OIDC login before apps, per domain. Only the SHA-256 of the token is stored. */
object AppSessionTable : Table("app_sessions") {
    val tokenHash = varchar("token_hash", 64)
    val domain = varchar("domain", 253)
    val sub = varchar("sub", 256)
    val name = varchar("name", 100)
    val email = varchar("email", 200)
    val preferredUsername = varchar("preferred_username", 100)
    val createdAt = long("created_at")
    val lastSeen = long("last_seen")
    override val primaryKey = PrimaryKey(tokenHash)
}

/** Decisions about discovered Incus containers: approved or rejected, for exactly these domains. */
object IncusDecisionTable : Table("incus_decisions") {
    val project = varchar("project", 100)
    val instance = varchar("instance", 100)
    val domains = varchar("domains", 1000)
    val approved = bool("approved")
    val decidedAt = long("decided_at")
    /** Address, port, HTTPS and profile the approval covers ([bayern.kickner.kovexy.incus.incusTarget]). */
    val target = varchar("target", 600).default("")
    override val primaryKey = PrimaryKey(project, instance)
}

/** Daily top lists per site (Zoraxy `DailySummary`), at most 100 keys per list and day. */
object StatsTopTable : Table("stats_top") {
    val site = varchar("site", 253)
    val day = long("day")
    val kind = varchar("kind", 20)
    val key = varchar("key", 512)
    val count = long("count")
    override val primaryKey = PrimaryKey(site, day, kind, key)
}

/** Response time histogram per site and hour, counts per bucket as comma separated text. */
object LatencyTable : Table("stats_latency") {
    val site = varchar("site", 253)
    val bucket = long("bucket")
    val histogram = varchar("histogram", 1000)
    override val primaryKey = PrimaryKey(site, bucket)
}

/** Every table, created on start. */
private val ALL_TABLES = arrayOf(
    AccessLogTable, StatsHourlyTable, StatsDailyTable, SessionTable, BanTable, AuditTable, SecurityEventTable,
    AppSessionTable, IncusDecisionTable, StatsTopTable, LatencyTable,
)

/**
 * The SQLite database `<dataDir>/kovexy.db` with access log, statistics and sessions. Opened through Exposed, every
 * transaction gets its own connection, so the file can be swapped between transactions (backup restore).
 *
 * @param file The database file.
 */
class Storage(val file: File) {
    /** Serializes writers with a file swap. */
    val writeLock = Mutex()

    /** The Exposed database. */
    val db: Database

    init {
        file.absoluteFile.parentFile.mkdirs()
        if (file.exists().not()) {
            file.createNewFile()
            restrictToOwner(file)
        }
        db = Database.connect(
            url = "jdbc:sqlite:${file.absolutePath}",
            driver = "org.sqlite.JDBC",
            setupConnection = { connection ->
                connection.createStatement().use {
                    it.execute("PRAGMA busy_timeout = 5000")
                    it.execute("PRAGMA synchronous = NORMAL")
                }
            },
            databaseConfig = org.jetbrains.exposed.v1.core.DatabaseConfig {
                defaultIsolationLevel = Connection.TRANSACTION_SERIALIZABLE
            },
        )
        // Journal mode and VACUUM cannot run inside a transaction, Exposed always opens one
        rawSql("PRAGMA journal_mode = WAL")
        transaction(db) { SchemaUtils.create(*ALL_TABLES) }
        addMissingColumns()
    }

    /**
     * Adds columns that newer versions brought to existing tables. SQLite only knows `ALTER TABLE ADD COLUMN`, which
     * is all that is needed while columns are only added, never changed.
     */
    private fun addMissingColumns() {
        val added = listOf(
            Triple("sessions", "sub", "VARCHAR(256) NOT NULL DEFAULT 'local'"),
            Triple("sessions", "name", "VARCHAR(100) NOT NULL DEFAULT 'admin'"),
            Triple("incus_decisions", "target", "VARCHAR(600) NOT NULL DEFAULT ''"),
        )
        DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}").use { connection ->
            added.forEach { (table, column, definition) ->
                val existing = connection.createStatement().use { st ->
                    st.executeQuery("PRAGMA table_info($table)").use { rs -> buildSet { while (rs.next()) add(rs.getString("name")) } }
                }
                if (column !in existing) connection.createStatement().use { it.execute("ALTER TABLE $table ADD COLUMN $column $definition") }
            }
        }
    }

    /** Runs one statement on its own connection, outside of any transaction. */
    private fun rawSql(sql: String) {
        DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}").use { connection ->
            connection.createStatement().use { it.execute(sql) }
        }
    }

    /** Runs [block] in a transaction. */
    fun <T> tx(block: JdbcTransaction.() -> T): T = transaction(db) { block() }

    /**
     * Writes a consistent copy of the database to [target] (`VACUUM INTO`), for the backup. The target must not exist.
     */
    fun copyTo(target: File) {
        rawSql("VACUUM INTO '${target.absolutePath.replace("'", "''")}'")
        restrictToOwner(target)
    }

    /**
     * Replaces the content of the database with [source], for restoring a backup. SQLite's backup API copies it page
     * by page under SQLite's own locks, so writers that run at the same time wait instead of corrupting the file.
     */
    fun restoreFrom(source: File) {
        rawSql("restore from '${source.absolutePath.replace("'", "''")}'")
        tx { SchemaUtils.create(*ALL_TABLES) }
        addMissingColumns()
    }
}
