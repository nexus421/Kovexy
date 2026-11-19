package bayern.kickner.kovexy.auth

import bayern.kickner.kovexy.randomToken
import bayern.kickner.kovexy.sha256Hex
import bayern.kickner.kovexy.stats.SessionTable
import bayern.kickner.kovexy.stats.Storage
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.core.neq
import org.jetbrains.exposed.v1.core.notInList
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.jdbc.deleteAll
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import bayern.kickner.kovexy.access.addressKey
import bayern.kickner.kovexy.config.parseIpLiteral
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration

/** A session is marked as used in the database at most this often, every request would otherwise write. */
private const val TOUCH_INTERVAL_MILLIS = 60_000L

/**
 * A logged-in browser.
 *
 * @property id Random ID to show and end the session in the UI, never the token.
 * @property createdAt Unix milliseconds of the login.
 * @property lastSeen Unix milliseconds of the latest request.
 * @property userAgent The browser's `User-Agent` at login.
 * @property ip Address of the login.
 * @property sub Who: the OIDC `sub`, `local` for the local password.
 * @property name Display name.
 */
data class Session(
    val id: String,
    val createdAt: Long,
    val lastSeen: Long,
    val userAgent: String,
    val ip: String,
    val sub: String = "local",
    val name: String = "admin",
)

/**
 * Admin sessions in SQLite, so a restart does not log anybody out. Only the SHA-256 of the token is stored.
 *
 * @param storage The database.
 * @param limits Idle timeout and maximum age, read on every check so a config change applies at once.
 * @param clock Unix milliseconds.
 */
class SessionStore(
    private val storage: Storage,
    private val limits: () -> Pair<Duration, Duration>,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /** Last time each session was written as used, to limit writes. */
    private val touched = ConcurrentHashMap<String, Long>()

    /**
     * Creates a session.
     *
     * @return the token for the cookie and the session.
     */
    fun create(userAgent: String, ip: String, sub: String = "local", name: String = "admin"): Pair<String, Session> {
        purgeExpired()
        val token = randomToken()
        val now = clock()
        val session = Session(randomToken(9), now, now, userAgent.take(200), ip.take(64), sub.take(256), name.take(100))
        storage.tx {
            SessionTable.insert {
                it[tokenHash] = sha256Hex(token)
                it[id] = session.id
                it[createdAt] = now
                it[lastSeen] = now
                it[SessionTable.userAgent] = session.userAgent
                it[SessionTable.ip] = session.ip
                it[SessionTable.sub] = session.sub
                it[SessionTable.name] = session.name
            }
        }
        return token to session
    }

    /**
     * The valid session for [token], marked as used unless [touch] is `false`. `null` if unknown or expired.
     *
     * @param touch `false` for background checks such as the live status stream, they must not keep an idle session alive.
     */
    fun get(token: String?, touch: Boolean = true): Session? {
        if (token.isNullOrBlank()) return null
        val hash = sha256Hex(token)
        val now = clock()
        val session = storage.tx {
            SessionTable.selectAll().where { SessionTable.tokenHash eq hash }.firstOrNull()?.let {
                Session(it[SessionTable.id], it[SessionTable.createdAt], it[SessionTable.lastSeen], it[SessionTable.userAgent], it[SessionTable.ip], it[SessionTable.sub], it[SessionTable.name])
            }
        }?.let { it.copy(lastSeen = maxOf(it.lastSeen, touched[hash] ?: 0)) } ?: return null
        if (isExpired(session, now)) {
            remove(token)
            return null
        }
        if (touch.not()) return session
        if (now - session.lastSeen >= TOUCH_INTERVAL_MILLIS) {
            touched[hash] = now
            storage.tx { SessionTable.update({ SessionTable.tokenHash eq hash }) { it[lastSeen] = now } }
        }
        return session.copy(lastSeen = now)
    }

    /** Ends the session of [token]. */
    fun remove(token: String?) {
        if (token.isNullOrBlank()) return
        val hash = sha256Hex(token)
        touched.remove(hash)
        storage.tx { SessionTable.deleteWhere { tokenHash eq hash } }
    }

    /** Ends every session except the one of [token], e.g. after the password was changed. */
    fun removeAllExcept(token: String) {
        val keep = sha256Hex(token)
        touched.keys.retainAll(setOf(keep))
        storage.tx { SessionTable.deleteWhere { tokenHash neq keep } }
    }

    /** Ends every session whose subject is not in [allowed]. Password sessions have the subject `local`. */
    fun removeSubjectsNotIn(allowed: Set<String>) {
        touched.clear()
        storage.tx { SessionTable.deleteWhere { sub notInList allowed } }
    }

    /** Ends every session. */
    fun removeAll() {
        touched.clear()
        storage.tx { SessionTable.deleteAll() }
    }

    /** All valid sessions, newest first. */
    fun list(): List<Session> {
        purgeExpired()
        return storage.tx {
            SessionTable.selectAll().map {
                Session(it[SessionTable.id], it[SessionTable.createdAt], it[SessionTable.lastSeen], it[SessionTable.userAgent], it[SessionTable.ip], it[SessionTable.sub], it[SessionTable.name])
            }
        }.sortedByDescending { it.createdAt }
    }

    private fun purgeExpired() {
        val (idle, maxAge) = limits()
        val now = clock()
        storage.tx {
            SessionTable.deleteWhere {
                (lastSeen less (now - idle.inWholeMilliseconds)) or (createdAt less (now - maxAge.inWholeMilliseconds))
            }
        }
    }

    private fun isExpired(session: Session, now: Long): Boolean {
        val (idle, maxAge) = limits()
        return now - session.lastSeen > idle.inWholeMilliseconds || now - session.createdAt > maxAge.inWholeMilliseconds
    }
}

/** Failed logins from one address before it is locked out. */
const val LOGIN_MAX_FAILURES = 5

/** Length of the lockout. */
const val LOGIN_LOCKOUT_MILLIS = 15L * 60 * 1000

/**
 * Locks an address out after [LOGIN_MAX_FAILURES] failed logins for [LOGIN_LOCKOUT_MILLIS]. IPv6 addresses count per
 * /64, a household gets a whole /64. In memory, a restart forgets it.
 *
 * Every attempt counts as failure before the password is checked ([begin]) and only a success clears it, so parallel
 * requests cannot get more guesses than allowed.
 */
class LoginThrottle(private val clock: () -> Long = System::currentTimeMillis) {
    private class State(val failures: Int, val first: Long, val lockedUntil: Long)

    private val states = ConcurrentHashMap<String, State>()

    /**
     * Unix milliseconds until which [ip] is locked out, `null` if it may try. Counts nothing.
     *
     * @param scope Separates independent lockouts, e.g. one per Basic Auth profile, empty for the admin login.
     */
    fun lockedUntil(ip: String, scope: String = ""): Long? = states[key(ip, scope)]?.lockedUntil?.takeIf { it > clock() }

    /**
     * Starts an attempt of [ip]: counts it as failure unless [success] follows.
     *
     * @return Unix milliseconds until which [ip] is locked out, then the attempt must not run, `null` if it may.
     */
    fun begin(ip: String, scope: String = ""): Long? {
        val now = clock()
        // Not on every attempt, a full scan per request would cost more than the attempt itself
        if (states.size > 10_000 && now - lastPurge > PURGE_INTERVAL_MILLIS) {
            lastPurge = now
            states.values.removeIf { now - it.first > LOGIN_LOCKOUT_MILLIS && it.lockedUntil <= now }
        }
        var locked: Long? = null
        states.compute(key(ip, scope)) { _, old ->
            if (old != null && old.lockedUntil > now) return@compute old.also { locked = it.lockedUntil }
            val fresh = old == null || now - old.first > LOGIN_LOCKOUT_MILLIS
            val failures = if (fresh) 1 else old.failures + 1
            val first = if (fresh) now else old.first
            State(failures, first, if (failures >= LOGIN_MAX_FAILURES) now + LOGIN_LOCKOUT_MILLIS else 0)
        }
        return locked
    }

    /** Forgets the failures of [ip] after a successful login. */
    fun success(ip: String, scope: String = "") {
        states.remove(key(ip, scope))
    }

    @Volatile
    private var lastPurge = 0L

    private fun key(ip: String, scope: String): String = (parseIpLiteral(ip)?.let { addressKey(InetAddress.getByAddress(it)) } ?: ip) + "|" + scope

    private companion object {
        const val PURGE_INTERVAL_MILLIS = 30_000L
    }
}
