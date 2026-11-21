package bayern.kickner.kovexy.config

import kotlinx.serialization.KSerializer
import bayern.kickner.kovexy.i18n.DEFAULT_LANGUAGE
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * A duration written as text like `"30s"`, `"5m"`, `"12h"` or `"90d"` ([Duration.parse] syntax). Combinations such as
 * `"1h 30m"` and the ISO form `"PT30S"` work as well.
 */
typealias TextDuration = @Serializable(with = DurationAsTextSerializer::class) Duration

/** Reads and writes a [Duration] as text, see [TextDuration]. */
object DurationAsTextSerializer : KSerializer<Duration> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("bayern.kickner.kovexy.TextDuration", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Duration) = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): Duration {
        val text = decoder.decodeString()
        return runCatching { Duration.parse(text) }
            .getOrElse { throw SerializationException("Invalid duration \"$text\", use for example \"30s\", \"5m\", \"12h\" or \"90d\"") }
    }
}

/** Name of the plain HTTP listener. */
const val LISTENER_HTTP = "http"

/** Name of the TLS listener. */
const val LISTENER_HTTPS = "https"

/** The two listeners of phase 1. They cannot be changed in the file, additional ports are deferred. */
val DEFAULT_LISTENERS: List<ListenerConfig> = listOf(
    ListenerConfig(LISTENER_HTTP, 80, tls = false),
    ListenerConfig(LISTENER_HTTPS, 443, tls = true),
)

/** Let's Encrypt production, the default ACME directory. */
const val LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

/** Let's Encrypt staging. Certificates are not trusted by browsers, the rate limits are much higher. */
const val LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"

/**
 * The whole configuration, stored in `<dataDir>/kovexy.json`. The admin UI writes it, changes by hand are picked up
 * as well. Every change is validated completely and applied while running, an invalid file changes nothing.
 *
 * Missing fields take their default. When Kovexy writes the file it leaves out every value that equals its default.
 *
 * @property admin Admin UI and login.
 * @property acme Certificates from an ACME CA.
 * @property listeners Ports the proxy listens on. Fixed to 80 and 443 in phase 1.
 * @property trustedProxies IPs or CIDR ranges whose `X-Forwarded-*` headers are believed.
 * @property fallback What happens for a domain no domain serves.
 * @property accessProfiles Reusable access profiles for domains and routes.
 * @property aiCrawlers Changes to the shipped AI crawler list, for every profile.
 * @property incus Discovery of Incus containers.
 * @property backends Reusable groups of backend servers.
 * @property domains Domains with their names and routes.
 * @property webhooks Webhook targets for notifications.
 * @property limits Timeouts and size limits.
 * @property retention How long the access log and the statistics are kept.
 * @property updateCheck Asks GitHub for a newer release while somebody uses the admin UI.
 * @property webSocketCloseDelay Time open WebSockets get after a config change before they are closed.
 * @property language Language of the admin UI, a key of [bayern.kickner.kovexy.i18n.LANGUAGES].
 */
@Serializable
data class KovexyConfig(
    val admin: AdminConfig = AdminConfig(),
    val acme: AcmeConfig = AcmeConfig(),
    val listeners: List<ListenerConfig> = DEFAULT_LISTENERS,
    val trustedProxies: List<String> = emptyList(),
    val fallback: Fallback = Fallback.Static(),
    val accessProfiles: List<AccessProfile> = emptyList(),
    val aiCrawlers: AiCrawlersConfig = AiCrawlersConfig(),
    val incus: IncusConfig = IncusConfig(),
    val backends: List<BackendConfig> = emptyList(),
    val domains: List<DomainConfig> = emptyList(),
    val webhooks: List<WebhookConfig> = emptyList(),
    val limits: LimitsConfig = LimitsConfig(),
    val retention: RetentionConfig = RetentionConfig(),
    val updateCheck: Boolean = true,
    val webSocketCloseDelay: TextDuration = Duration.ZERO,
    val language: String = DEFAULT_LANGUAGE,
)

/**
 * Changes to the shipped AI crawler list (ai.robots.txt), the same for every access profile with
 * `exploitFilter.aiBots`. Matching stays a case insensitive substring of the user agent.
 *
 * @property add Extra user agent parts that count as AI crawler.
 * @property ignore Names of the shipped list that no longer count.
 */
@Serializable
data class AiCrawlersConfig(val add: List<String> = emptyList(), val ignore: List<String> = emptyList())

/** Longest entry of [AiCrawlersConfig]. */
const val MAX_AI_CRAWLER_ENTRY = 200

/**
 * The admin UI. It runs in the same Jetty server as the proxy, on its own connector.
 *
 * @property host Address the admin UI binds to, loopback by default.
 * @property port Port of the admin UI.
 * @property publicUrl URL in the browser when the admin UI is reached through a domain, e.g. `https://proxy.example.com`.
 *   The only accepted `Origin` besides the local address. Empty when the admin UI is only used locally.
 * @property loginMode How admins log in. OIDC needs [oidc] and [publicUrl].
 * @property passwordHash Argon2id hash of the admin password in PHC format. Empty on the first start, Kovexy then
 *   creates a password and prints it once to the log.
 * @property oidc OpenID Connect settings for [LoginMode.OIDC] and [LoginMode.BOTH].
 * @property session Lifetime of admin sessions.
 */
@Serializable
data class AdminConfig(
    val host: String = "127.0.0.1",
    val port: Int = 8000,
    val publicUrl: String = "",
    val loginMode: LoginMode = LoginMode.PASSWORD,
    val passwordHash: String = "",
    val oidc: OidcConfig? = null,
    val session: SessionConfig = SessionConfig(),
)

/** How admins log in. */
@Serializable
enum class LoginMode {
    /** Only the local password. Kovexy shows a warning on every page in this mode. */
    @SerialName("password")
    PASSWORD,

    /** Only OpenID Connect. */
    @SerialName("oidc")
    OIDC,

    /** OpenID Connect first, then the password, as a second barrier in case the provider has a hole. */
    @SerialName("both")
    BOTH,
}

/**
 * OpenID Connect settings for the admin login. Same fields as Dirl. The callback is `<publicUrl>/auth/callback`.
 *
 * @property issuer Issuer URL exactly as the provider reports it.
 * @property clientId Client ID registered in the provider.
 * @property clientSecret Secret of the confidential client.
 * @property allowedSubjects `sub` claims that may log in. Empty means everybody the provider lets through, then the
 *   group restriction at the provider is the only barrier.
 * @property forceReauth Sends `prompt=login` on every login.
 * @property scopes Requested scopes, `openid` is mandatory.
 */
@Serializable
data class OidcConfig(
    val issuer: String,
    val clientId: String,
    val clientSecret: String,
    val allowedSubjects: List<String> = emptyList(),
    val forceReauth: Boolean = true,
    val scopes: List<String> = listOf("openid", "profile"),
)

/**
 * Lifetime of admin sessions.
 *
 * @property idleTimeout A session without requests for this long expires.
 * @property maxAge A session expires this long after the login, active or not.
 */
@Serializable
data class SessionConfig(
    val idleTimeout: TextDuration = 60.minutes,
    val maxAge: TextDuration = 12.hours,
)

/**
 * ACME settings. Using ACME means agreeing to the terms of service of the CA.
 *
 * @property directory URL of the ACME directory.
 * @property staging Uses Let's Encrypt staging instead of [directory].
 * @property email Optional contact address for the account at the CA.
 */
@Serializable
data class AcmeConfig(
    val directory: String = LETS_ENCRYPT_PRODUCTION,
    val staging: Boolean = false,
    val email: String = "",
) {
    /** The directory orders go to. */
    val effectiveDirectory: String get() = if (staging) LETS_ENCRYPT_STAGING else directory
}

/**
 * A port the proxy listens on.
 *
 * @property name Referenced by [DomainConfig.listeners].
 * @property port TCP port.
 * @property tls Whether the port speaks TLS.
 */
@Serializable
data class ListenerConfig(
    val name: String,
    val port: Int,
    val tls: Boolean,
)

/**
 * A reusable group of backend servers.
 *
 * @property name Unique name, referenced by targets.
 * @property servers The servers of the group.
 * @property stickySession Sends a visitor to the same server again, through a cookie.
 * @property healthCheck Active health check, off without a path.
 */
@Serializable
data class BackendConfig(
    val name: String,
    val servers: List<BackendServerConfig>,
    val stickySession: Boolean = false,
    val healthCheck: HealthCheckConfig = HealthCheckConfig(),
)

/**
 * One backend server.
 *
 * @property address `host:port`, IPv6 addresses in brackets.
 * @property tls Talks HTTPS to the server.
 * @property skipCertVerify Accepts any certificate of the server, e.g. a self signed one.
 * @property weight Share of the requests. `0` makes it a backup that only gets requests when no other server is up.
 * @property maxConnections Concurrent requests to this server, more wait. `0` is unlimited.
 */
@Serializable
data class BackendServerConfig(
    val address: String,
    val tls: Boolean = false,
    val skipCertVerify: Boolean = false,
    val weight: Int = 1,
    val maxConnections: Int = 0,
)

/**
 * Active health check of every server of a group. Without [path] servers are only checked passively: a connection
 * error marks a server as down, it is tried again every 30 seconds.
 *
 * @property path Path of a `GET` request, e.g. `/health`. Empty turns the active check off.
 * @property interval Time between two checks.
 * @property timeout Time a check may take.
 * @property expectStatus Status code of a healthy answer.
 */
@Serializable
data class HealthCheckConfig(
    val path: String = "",
    val interval: TextDuration = 30.seconds,
    val timeout: TextDuration = 5.seconds,
    val expectStatus: Int = 200,
)

/**
 * A domain: one or more domains with their routes. Always reachable over HTTPS only, plain HTTP on port 80 is
 * redirected for every host and never reaches a domain.
 *
 * @property names Exact domain names, e.g. `example.com` and `www.example.com`. Each gets its own certificate.
 * @property access Name of an access profile for the whole domain.
 * @property routes Path rules. The most specific matching one wins, the order does not matter.
 * @property enabled A disabled domain is treated as if it did not exist.
 * @property accessLog Writes requests of this domain to the access log.
 */
@Serializable
data class DomainConfig(
    val names: List<String>,
    val access: String? = null,
    val routes: List<RouteConfig> = emptyList(),
    val enabled: Boolean = true,
    val accessLog: Boolean = true,
)

/** How a route path is compared with the request path. */
@Serializable
enum class MatchType {
    /** The path and everything below it, only at path boundaries: `/api` matches `/api` and `/api/x`, not `/apix`. */
    @SerialName("prefix")
    PREFIX,

    /** Only exactly this path. */
    @SerialName("exact")
    EXACT,
}

/**
 * A path rule of a domain.
 *
 * @property path Path starting with `/`.
 * @property match Prefix or exact match.
 * @property stripPrefix Removes the matched prefix before the request goes to a backend.
 * @property target What answers the request.
 * @property access Name of an access profile that replaces the one of the domain completely.
 * @property requestHeaders Header changes for the request to the backend.
 * @property responseHeaders Header changes for the response to the visitor.
 * @property enabled A disabled route is ignored.
 */
@Serializable
data class RouteConfig(
    val path: String,
    val match: MatchType = MatchType.PREFIX,
    val stripPrefix: Boolean = false,
    val target: Target,
    val access: String? = null,
    val requestHeaders: List<HeaderRule> = emptyList(),
    val responseHeaders: List<HeaderRule> = emptyList(),
    val enabled: Boolean = true,
)

/** What answers a request of a route. */
@Serializable
sealed interface Target {
    /**
     * Forwards to a backend.
     *
     * @property backend Name of the backend.
     */
    @Serializable
    @SerialName("backend")
    data class Backend(val backend: String) : Target

    /**
     * Serves files from a directory.
     *
     * @property root Directory, absolute or relative to the data directory.
     * @property directoryListing Lists directories without an index file.
     */
    @Serializable
    @SerialName("static")
    data class Static(val root: String, val directoryListing: Boolean = false) : Target

    /**
     * Redirects to another address.
     *
     * @property url Absolute target URL.
     * @property status `307` (temporary) or `301` (permanent).
     * @property keepPath Appends the rest of the path after the route and the query to [url].
     */
    @Serializable
    @SerialName("redirect")
    data class Redirect(val url: String, val status: Int = 307, val keepPath: Boolean = true) : Target

    /**
     * Blocks the path.
     *
     * @property status Status code of the answer.
     * @property html Optional HTML page sent with it, otherwise a neutral page.
     */
    @Serializable
    @SerialName("deny")
    data class Deny(val status: Int = 404, val html: String = "") : Target
}

/** What happens for a domain no domain serves. */
@Serializable
sealed interface Fallback {
    /**
     * Serves files, by default the neutral page in `<dataDir>/www`.
     *
     * @property root Directory, absolute or relative to the data directory. Empty means `<dataDir>/www`.
     * @property directoryListing Lists directories without an index file.
     */
    @Serializable
    @SerialName("static")
    data class Static(val root: String = "", val directoryListing: Boolean = false) : Fallback

    /**
     * Forwards to a backend.
     *
     * @property backend Name of the backend.
     */
    @Serializable
    @SerialName("backend")
    data class Backend(val backend: String) : Fallback

    /**
     * Redirects to a fixed address. A redirect to the requested domain itself is refused, it would loop.
     *
     * @property url Absolute target URL.
     * @property status `307` or `301`.
     * @property keepPath Appends the requested path and query to [url].
     */
    @Serializable
    @SerialName("redirect")
    data class Redirect(val url: String, val status: Int = 307, val keepPath: Boolean = true) : Fallback

    /** Answers with a neutral 404 page. */
    @Serializable
    @SerialName("notFound")
    data object NotFound : Fallback

    /**
     * Answers with an empty `204` and closes the connection, so the visitor learns nothing about the server. No real
     * close without answer: Ktor offers no public way to do that (decided on 18.11.2026).
     */
    @Serializable
    @SerialName("noResponse")
    data object NoResponse : Fallback
}

/** What a [HeaderRule] does. */
@Serializable
enum class HeaderAction {
    /** Replaces every value of the header. */
    @SerialName("set")
    SET,

    /** Adds a value, existing ones stay. */
    @SerialName("add")
    ADD,

    /** Removes the header. */
    @SerialName("remove")
    REMOVE,
}

/**
 * One header change.
 *
 * @property action Set, add or remove.
 * @property name Header name.
 * @property value Value for set and add, empty for remove.
 */
@Serializable
data class HeaderRule(
    val action: HeaderAction,
    val name: String,
    val value: String = "",
)

/** Events a webhook can be sent for. */
@Serializable
enum class WebhookEvent(val label: String) {
    @SerialName("certIssued")
    CERT_ISSUED("Certificate issued or renewed"),

    @SerialName("certFailed")
    CERT_FAILED("Certificate failed"),

    @SerialName("backendDown")
    BACKEND_DOWN("Backend server down"),

    @SerialName("backendUp")
    BACKEND_UP("Backend server up again"),

    @SerialName("ipBanned")
    IP_BANNED("IP banned"),

    @SerialName("adminLoginFailed")
    ADMIN_LOGIN_FAILED("Failed admin login"),

    @SerialName("configChanged")
    CONFIG_CHANGED("Configuration changed"),

    @SerialName("configInvalid")
    CONFIG_INVALID("Configuration file invalid"),

    @SerialName("incusDetected")
    INCUS_DETECTED("Incus container detected"),

    @SerialName("incusApproved")
    INCUS_APPROVED("Incus container approved"),

    @SerialName("incusRemoved")
    INCUS_REMOVED("Incus container domain removed"),
}

/** Default body of a webhook, every placeholder as JSON field. */
const val DEFAULT_WEBHOOK_TEMPLATE =
    """{"event": "{{event}}", "subject": "{{subject}}", "body": "{{body}}", "time": "{{time}}", "domain": "{{domain}}"}"""

/** Body of the KNot preset. */
const val KNOT_WEBHOOK_TEMPLATE = """{"subject": "{{subject}}", "body": "{{body}}"}"""

/**
 * A webhook target. Kovexy sends a `POST` with the filled [template] for every selected event.
 *
 * @property name Unique name.
 * @property url Target URL.
 * @property headers Extra request headers, e.g. `X-API-Key` for KNot. Without `Content-Type` Kovexy sends
 *   `application/json`.
 * @property template Body with placeholders `{{event}}`, `{{subject}}`, `{{body}}`, `{{time}}` and `{{domain}}`.
 * @property events Events this target receives.
 * @property bundleWindow Events that can come in large numbers (IP banned, failed admin login) are sent at once the
 *   first time, further ones of the same kind within this window are collected into one message.
 */
@Serializable
data class WebhookConfig(
    val name: String,
    val url: String,
    val headers: Map<String, String> = emptyMap(),
    val template: String = DEFAULT_WEBHOOK_TEMPLATE,
    val events: List<WebhookEvent> = WebhookEvent.entries,
    val bundleWindow: TextDuration = 60.seconds,
)

/**
 * Timeouts and size limits. Not listed and therefore unlimited: waiting for the response headers of a backend,
 * the request body and the lifetime of a WebSocket.
 *
 * @property backendConnectTimeout Time to connect to a backend server.
 * @property backendKeepAlive Time an idle connection to a backend server stays open for reuse.
 * @property clientIdleTimeout Time a client connection may be idle. Jetty has no separate timeout for reading the
 *   request headers, this one covers a client that stops sending them.
 * @property maxRequestHeaderBytes Size of the request headers.
 * @property maxConnections Concurrent connections on the proxy ports in total (Jetty `ConnectionLimit`), `0` is
 *   unlimited. Keeps a connection flood from filling the memory.
 * @property maxAcceptsPerSecond New connections per second on the proxy ports (Jetty `AcceptRateLimit`), `0` is off.
 *   Off by default, the limit is shared by everybody and would lock normal visitors out during an attack.
 * @property maxConnectionsPerAddress Open connections on the proxy ports of one address (IPv6 per /64), `0` is
 *   unlimited. Keeps a single host from taking all [maxConnections] (decided on 19.11.2026). Loopback and
 *   `trustedProxies` are not limited, every visitor comes from them.
 */
@Serializable
data class LimitsConfig(
    val backendConnectTimeout: TextDuration = 3.seconds,
    val backendKeepAlive: TextDuration = 2.minutes,
    val clientIdleTimeout: TextDuration = 5.minutes,
    val maxRequestHeaderBytes: Int = 16 * 1024,
    val maxConnections: Int = 10_000,
    val maxAcceptsPerSecond: Int = 0,
    val maxConnectionsPerAddress: Int = 256,
)

/**
 * How long data is kept. Daily statistics are kept forever.
 *
 * @property accessLog Entries of the access log.
 * @property hourlyStats Hourly statistics.
 * @property audit Audit log entries.
 * @property securityEvents Security events.
 */
@Serializable
data class RetentionConfig(
    val accessLog: TextDuration = 90.days,
    val hourlyStats: TextDuration = 90.days,
    val audit: TextDuration = 90.days,
    val securityEvents: TextDuration = 90.days,
)

/** Paths that only scanners call, default of [TrapPathsConfig.paths]. */
val DEFAULT_TRAP_PATHS: List<String> = listOf(
    "/.env", "/.git/", "/.aws/", "/.ssh/", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/", "/pma/",
    "/vendor/phpunit/", "/cgi-bin/", "/HNAP1", "/boaform/", "/actuator/", "/server-status",
)

/**
 * A reusable access profile. It hangs on a domain or a route, a route with its own profile replaces the one of
 * the domain completely. The checks run in this order (Zoraxy): block lists, allow lists, exploit filter and trap paths,
 * rate limit, allowed methods, basic auth.
 *
 * @property name Unique name.
 * @property denyIps IPs and CIDR ranges that are blocked.
 * @property denyCountries ISO 3166 country codes that are blocked.
 * @property allowIps If this or [allowCountries] is not empty, only matching visitors get in.
 * @property allowCountries Like [allowIps], for countries.
 * @property allowLocal Private and loopback addresses get in despite the allow lists.
 * @property exploitFilter Pattern checks against typical attacks and AI crawlers.
 * @property trapPaths Paths that ban the visitor.
 * @property rateLimit Requests per second and IP, off without it.
 * @property allowedMethods Allowed HTTP methods, empty allows all. Others get 405.
 * @property basicAuth HTTP Basic Auth, off without it.
 * @property captcha Captcha before the domain, off without it.
 */
@Serializable
data class AccessProfile(
    val name: String,
    val denyIps: List<String> = emptyList(),
    val denyCountries: List<String> = emptyList(),
    val allowIps: List<String> = emptyList(),
    val allowCountries: List<String> = emptyList(),
    val allowLocal: Boolean = false,
    val exploitFilter: ExploitFilterConfig = ExploitFilterConfig(),
    val trapPaths: TrapPathsConfig = TrapPathsConfig(),
    val rateLimit: RateLimitConfig? = null,
    val allowedMethods: List<String> = emptyList(),
    val basicAuth: BasicAuthConfig? = null,
    val captcha: CaptchaConfig? = null,
) {
    /** Whether the profile uses country rules. */
    val usesCountries: Boolean get() = denyCountries.isNotEmpty() || allowCountries.isNotEmpty()
}

/** What a request gets that the exploit filter catches. */
@Serializable
enum class ExploitResponse(val status: Int) {
    @SerialName("notFound")
    NOT_FOUND(404),

    @SerialName("forbidden")
    FORBIDDEN(403),

    @SerialName("badRequest")
    BAD_REQUEST(400),

    /** An empty `204` and the connection closed, like the fallback `noResponse`. */
    @SerialName("drop")
    DROP(204),
}

/**
 * The exploit filter.
 *
 * @property commonExploits Checks query and user agent against the patterns of Nginx Proxy Manager (SQL and file
 *   injection, common exploits, spam, known tools).
 * @property aiBots Recognizes AI crawlers by their user agent (list of ai.robots.txt).
 * @property response What a caught request gets.
 */
@Serializable
data class ExploitFilterConfig(
    val commonExploits: Boolean = false,
    val aiBots: Boolean = false,
    val response: ExploitResponse = ExploitResponse.FORBIDDEN,
)

/**
 * Trap paths: whoever calls one is banned for all domains.
 *
 * @property enabled Traps on or off.
 * @property paths Path prefixes that trigger a ban.
 * @property banDuration How long the ban lasts.
 */
@Serializable
data class TrapPathsConfig(
    val enabled: Boolean = false,
    val paths: List<String> = DEFAULT_TRAP_PATHS,
    val banDuration: TextDuration = 1.hours,
)

/**
 * Rate limit per IP in fixed one second windows (Zoraxy). Counted per profile.
 *
 * @property requestsPerSecond Allowed requests per second and IP, more get 429.
 * @property ipv6Prefix IPv6 addresses are counted per prefix of this length, a household usually has a whole /64.
 */
@Serializable
data class RateLimitConfig(
    val requestsPerSecond: Int,
    val ipv6Prefix: Int = 64,
)

/**
 * HTTP Basic Auth.
 *
 * @property users Users with their bcrypt (cost 14, like Caddy) or Argon2id hash.
 * @property realm Shown by the browser.
 * @property exceptions Requests that need no login.
 */
@Serializable
data class BasicAuthConfig(
    val users: List<BasicAuthUser>,
    val realm: String = "Restricted",
    val exceptions: List<BasicAuthException> = emptyList(),
)

/**
 * A Basic Auth user.
 *
 * @property name User name.
 * @property hash bcrypt or Argon2id hash of the password, never the password.
 */
@Serializable
data class BasicAuthUser(val name: String, val hash: String)

/**
 * A request that needs no Basic Auth login, exactly one field is set (Zoraxy `BasicAuthExceptionRule`).
 *
 * @property pathPrefix Paths below this prefix, at path boundaries like routes.
 * @property cidr Visitors from this IP or range.
 */
@Serializable
data class BasicAuthException(val pathPrefix: String? = null, val cidr: String? = null)

/** reCAPTCHA versions. */
@Serializable
enum class RecaptchaVersion {
    /** The checkbox. */
    @SerialName("v2")
    V2,

    /** Invisible, with a score. */
    @SerialName("v3")
    V3,
}

/**
 * A Google reCAPTCHA before the domain (Zoraxy `captcha.Config`). A solved captcha is valid for [sessionDuration], kept
 * only in memory like Zoraxy, a restart asks once more.
 *
 * @property siteKey Google site key.
 * @property secretKey Google secret key.
 * @property recaptchaVersion v2 or v3.
 * @property recaptchaScore Lowest accepted score of v3.
 * @property sessionDuration How long a solved captcha counts.
 * @property protectedPaths Only these path prefixes, empty protects everything.
 * @property exceptions Requests that never see the captcha.
 */
@Serializable
data class CaptchaConfig(
    val siteKey: String = "",
    val secretKey: String = "",
    val recaptchaVersion: RecaptchaVersion = RecaptchaVersion.V2,
    val recaptchaScore: Double = 0.5,
    val sessionDuration: TextDuration = 1.hours,
    val protectedPaths: List<String> = emptyList(),
    val exceptions: List<BasicAuthException> = emptyList(),
)

/**
 * Discovery of Incus containers. Kovexy only reads, it never changes an instance and never creates a route on its own:
 * a container with `user.kovexy.*` keys shows up in the admin UI and needs a click to go live.
 *
 * @property enabled Turns discovery on. Needs root, otherwise the config is rejected.
 * @property socket The Incus API socket.
 * @property projects Incus projects whose instances count. In restricted projects non-admins may create instances.
 * @property interface Network interface whose first global IPv4 address is the target.
 */
@Serializable
data class IncusConfig(
    val enabled: Boolean = false,
    val socket: String = "/var/lib/incus/unix.socket",
    val projects: List<String> = listOf("default"),
    val `interface`: String = "eth0",
)
