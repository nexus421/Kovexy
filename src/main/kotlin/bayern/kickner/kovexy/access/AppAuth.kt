package bayern.kickner.kovexy.access

import bayern.kickner.kovexy.auth.IdTokenClaims
import bayern.kickner.kovexy.auth.OidcClient
import bayern.kickner.kovexy.config.AppAuthConfig
import bayern.kickner.kovexy.config.OidcConfig
import bayern.kickner.kovexy.randomToken
import bayern.kickner.kovexy.sha256Hex
import bayern.kickner.kovexy.stats.AppSessionTable
import bayern.kickner.kovexy.stats.Storage
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.jdbc.deleteAll
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog

private const val TAG = "AppAuth"

/** Cookie of the app login, per domain. Lax, so the return from the provider brings it along. */
const val APP_AUTH_COOKIE = "__Host-kovexy-auth"

/** Cookie of a login in progress (Dirl's signed attempt). */
const val APP_LOGIN_COOKIE = "__Host-kovexy-applogin"

/** Cookie with the address to return to after the login. */
const val APP_RETURN_COOKIE = "__Host-kovexy-return"

/** A session without requests for this long expires (Dirl's value). */
const val APP_SESSION_IDLE_MILLIS = 60L * 60 * 1000

/** A session expires this long after the login (Dirl's value). */
const val APP_SESSION_MAX_MILLIS = 12L * 60 * 60 * 1000

/** Headers Kovexy sets towards the upstream for a logged in user, removed from every incoming request. */
val APP_USER_HEADERS = listOf("X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Preferred-Username")

/**
 * A user logged in through the app login.
 *
 * @property sub Stable ID at the provider.
 * @property name Display name.
 * @property email Mail address, empty if none.
 * @property preferredUsername User name, empty if none.
 */
data class AppUser(val sub: String, val name: String, val email: String, val preferredUsername: String) {
    /**
     * `X-Forwarded-User` like oauth2-proxy: always `sub`, the only claim that is unique and stable at the provider
     * (decided on 19.11.2026). The name goes in `X-Forwarded-Preferred-Username`.
     */
    val forwardedUser: String get() = sub
}

/** A session as kept in memory. [lastSeen] changes while it is used. */
private class AppSession(val domain: String, val user: AppUser, val createdAt: Long, @Volatile var lastSeen: Long, @Volatile var storedSeen: Long)

/**
 * The OIDC login before apps, like oauth2-proxy, with Dirl's OIDC client. One client per protected domain, because the
 * callback `https://<domain>/.kovexy/auth/callback` differs per domain.
 *
 * Sessions live in memory and in SQLite (only the hash of the token), so a restart does not log anybody out. The
 * proxy path only reads the memory: a request with an unknown cookie never reaches the database, and the last use
 * is written at most once a minute in the background.
 *
 * @param scope Runs the background writes.
 * @param clock Unix milliseconds.
 */
class AppAuthService(
    private val storage: Storage,
    private val clock: () -> Long = System::currentTimeMillis,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    @Volatile
    private var config: AppAuthConfig? = null
    private val clients = ConcurrentHashMap<String, OidcClient>()
    private val sessions = ConcurrentHashMap<String, AppSession>()

    init {
        reload()
    }

    /** Loads the app sessions from the database at start. */
    fun reload() {
        runCatching {
            val now = clock()
            val stored = HashMap<String, AppSession>()
            storage.tx {
                AppSessionTable.selectAll().forEach { row ->
                    val user = AppUser(row[AppSessionTable.sub], row[AppSessionTable.name], row[AppSessionTable.email], row[AppSessionTable.preferredUsername])
                    val seen = row[AppSessionTable.lastSeen]
                    val session = AppSession(row[AppSessionTable.domain], user, row[AppSessionTable.createdAt], seen, seen)
                    if (session.expired(now).not()) stored[row[AppSessionTable.tokenHash]] = session
                }
            }
            sessions.keys.retainAll(stored.keys)
            sessions.putAll(stored)
        }.onFailure { staticLog(KLogger.Level.ERROR, TAG) { "Loading the app sessions failed: ${it.message}" } }
    }

    /** Takes a new `appAuth`, dropping the clients of the old one. */
    fun configure(appAuth: AppAuthConfig?) {
        if (appAuth == config) return
        config = appAuth
        clients.clear()
    }

    /** The OIDC client for [domain], `null` without `appAuth`. */
    fun client(domain: String): OidcClient? {
        val auth = config ?: return null
        return clients.computeIfAbsent(domain) {
            OidcClient(OidcConfig(auth.issuer, auth.clientId, auth.clientSecret, emptyList(), auth.forceReauth, auth.scopes), callbackUrl(domain), clock = clock)
        }
    }

    /** The callback URL to register at the provider for [domain]. */
    fun callbackUrl(domain: String) = "https://$domain/.kovexy/auth/callback"

    /** Creates a session on [domain] and returns the token for the cookie. Blocks for one database write. */
    fun createSession(domain: String, claims: IdTokenClaims): String {
        val now = clock()
        sessions.entries.removeIf { it.value.expired(now) }
        val token = randomToken()
        val hash = sha256Hex(token)
        val user = AppUser(claims.sub.take(256), claims.name.take(100), claims.email.orEmpty().take(200), claims.preferredUsername.orEmpty().take(100))
        // Written at once, only after a login at the provider, so a restart right after it keeps the session
        storage.tx {
            AppSessionTable.deleteWhere { (lastSeen less (now - APP_SESSION_IDLE_MILLIS)) or (createdAt less (now - APP_SESSION_MAX_MILLIS)) }
            AppSessionTable.insert {
                it[tokenHash] = hash
                it[AppSessionTable.domain] = domain
                it[sub] = user.sub
                it[name] = user.name
                it[email] = user.email
                it[preferredUsername] = user.preferredUsername
                it[createdAt] = now
                it[lastSeen] = now
            }
        }
        sessions[hash] = AppSession(domain, user, now, now, now)
        return token
    }

    /** The user of a valid session on [domain], marked as used. `null` if unknown, expired or of another domain. */
    fun user(token: String?, domain: String): AppUser? {
        if (token.isNullOrBlank()) return null
        val hash = sha256Hex(token)
        val session = sessions[hash] ?: return null
        if (session.domain != domain) return null
        val now = clock()
        if (session.expired(now)) {
            remove(token)
            return null
        }
        session.lastSeen = now
        if (now - session.storedSeen > 60_000) {
            session.storedSeen = now
            scope.launch {
                runCatching { storage.tx { AppSessionTable.update({ AppSessionTable.tokenHash eq hash }) { it[AppSessionTable.lastSeen] = now } } }
            }
        }
        return session.user
    }

    /** Ends every app login, in memory and in the database, e.g. after a restored backup. */
    fun removeAll() {
        sessions.clear()
        runCatching { storage.tx { AppSessionTable.deleteAll() } }
    }

    /** Ends the session of [token]. */
    fun remove(token: String?) {
        if (token.isNullOrBlank()) return
        val hash = sha256Hex(token)
        if (sessions.remove(hash) == null) return
        scope.launch { runCatching { storage.tx { AppSessionTable.deleteWhere { tokenHash eq hash } } } }
    }

    private fun AppSession.expired(now: Long) = now - lastSeen > APP_SESSION_IDLE_MILLIS || now - createdAt > APP_SESSION_MAX_MILLIS
}
