package bayern.kickner.kovexy.access

import bayern.kickner.kovexy.config.AiCrawlersConfig
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.audit.SecurityEvents
import bayern.kickner.kovexy.auth.LoginThrottle
import bayern.kickner.kovexy.auth.hashBcrypt
import bayern.kickner.kovexy.auth.verifyBasicAuthHash
import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.BasicAuthConfig
import bayern.kickner.kovexy.config.BasicAuthUser
import bayern.kickner.kovexy.config.CaptchaConfig
import bayern.kickner.kovexy.config.Cidr
import bayern.kickner.kovexy.config.ExploitResponse
import bayern.kickner.kovexy.sha256Hex
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** How long a successful Basic Auth check is remembered, bcrypt with cost 14 takes about a second. */
const val BASIC_AUTH_CACHE_MILLIS = 10L * 60 * 1000

/**
 * What the access checks need from a request.
 *
 * @property address Visitor address (after trusted proxies).
 * @property domain Domain name, for events.
 * @property path Normalized request path.
 * @property rawQuery Query string as sent, without `?`.
 * @property method HTTP method.
 * @property userAgent The `User-Agent`.
 * @property authorization The `Authorization` header.
 * @property exactRoute Whether a route with `match: "exact"` serves exactly this path, then traps do not fire.
 * @property domain Requested domain, a solved captcha counts for one domain.
 * @property captchaCookie Value of the captcha cookie.
 * @property isWebSocket Whether the request is a WebSocket upgrade, which cannot follow a redirect.
 * @property foreignInitiated Whether a browser sent the request on behalf of another site (see [isForeignInitiated]).
 *   Such a request never bans the address, any web page could otherwise get its visitors banned.
 */
data class AccessRequest(
    val address: InetAddress,
    val domain: String,
    val path: String,
    val rawQuery: String,
    val method: String,
    val userAgent: String,
    val authorization: String?,
    val exactRoute: Boolean,
    val host: String = "",
    val captchaCookie: String? = null,
    val isWebSocket: Boolean = false,
    val foreignInitiated: Boolean = false,
)

/**
 * Whether a browser may have sent a request because another site told it to (an image, a script, a form or a link on
 * a foreign page): `Sec-Fetch-Site` other than `none` and `same-origin`, or an `Origin` or `Referer` with another host
 * than [domain]. Browsers send `Sec-Fetch-Site` only over HTTPS and a page can suppress the `Referer`, so over plain
 * HTTP a browser like `Accept` (pages or images) counts too.
 *
 * This is best effort for trap paths: such a request is only refused, never banned. A scanner that sends these
 * headers avoids the ban, the trap still refuses it.
 */
fun isForeignInitiated(domain: String, secFetchSite: String?, origin: String?, referer: String?, https: Boolean = true, accept: String? = null): Boolean {
    if (secFetchSite != null && secFetchSite.lowercase() !in setOf("none", "same-origin")) return true
    if (https.not() && accept != null && ("text/html" in accept || "image/" in accept)) return true
    fun foreign(url: String?): Boolean {
        if (url.isNullOrBlank() || url == "null") return url == "null"
        val host = runCatching { java.net.URI(url).host?.lowercase() }.getOrNull() ?: return true
        return host.removePrefix("[").removeSuffix("]") != domain.removePrefix("[").removeSuffix("]")
    }
    return foreign(origin) || foreign(referer)
}

/** Result of the access checks. */
sealed interface AccessResult {
    /**
     * The request may pass.
     *
     * @property basicAuthUser The Basic Auth user, if Basic Auth let it in. The proxy then removes the
     *   `Authorization` header, so the password does not reach the backend.
     */
    data class Allow(val basicAuthUser: String? = null) : AccessResult

    /**
     * Refused.
     *
     * @property status Status code, `204` with a closed connection for the exploit response `drop`.
     * @property reason For the access log, never shown to the visitor.
     * @property allow Value of the `Allow` header for 405.
     */
    data class Deny(val status: Int, val reason: String, val allow: String? = null) : AccessResult

    /**
     * Basic Auth needed: `401` with `WWW-Authenticate`.
     *
     * @property realm Realm of the profile.
     * @property reason For the access log.
     */
    data class Challenge(val realm: String, val reason: String) : AccessResult

    /**
     * The captcha of the profile has to be solved first (403 with the captcha page, like Zoraxy).
     *
     * @property profile Name of the profile.
     * @property config Its captcha.
     */
    data class CaptchaRequired(val profile: String, val config: CaptchaConfig) : AccessResult
}

/**
 * Rate limit per profile and address in fixed one second windows, like Zoraxy. Counted per profile instead of
 * globally, so domains do not influence each other.
 */
class RateLimiter(private val clock: () -> Long = System::currentTimeMillis) {
    private class Window(@Volatile var second: Long, val count: AtomicInteger = AtomicInteger())

    private val windows = ConcurrentHashMap<String, Window>()

    /** Counts a request and tells whether it is above [limit] in the current second. */
    fun exceeded(profile: String, key: String, limit: Int): Boolean {
        val second = clock() / 1000
        if (windows.size > 100_000) windows.values.removeIf { it.second < second }
        val window = windows.computeIfAbsent("$profile|$key") { Window(second) }
        synchronized(window) {
            if (window.second != second) {
                window.second = second
                window.count.set(0)
            }
        }
        return window.count.incrementAndGet() > limit
    }
}

/** Result of one Basic Auth check. */
internal sealed interface BasicResult {
    data class Ok(val user: String) : BasicResult
    data object Missing : BasicResult
    data object Wrong : BasicResult
    data object Locked : BasicResult
    data object Busy : BasicResult
}

/** Basic Auth hash checks that may run at the same time, for all profiles together. */
const val BASIC_AUTH_CONCURRENT_CHECKS = 4

/** How long a Basic Auth check waits for a free slot before the request gets 503. */
const val BASIC_AUTH_SLOT_WAIT_MILLIS = 2_000L

/**
 * Basic Auth like Caddy: bcrypt (or Argon2id) hashes, unknown users are checked against a fixed fake hash so the
 * answer time tells nothing, successful checks are remembered for [BASIC_AUTH_CACHE_MILLIS] under a hash of user,
 * password and stored hash (never the password itself).
 *
 * - A remembered login passes before anything else, wrong attempts of others from the same address cannot lock it out.
 *   Every use extends it, and parallel requests with the same login wait for one check.
 * - Five failures from one address lock it out of that profile for 15 minutes. Other profiles are not affected, a
 *   low-value domain cannot lock its users out of another one.
 * - At most [BASIC_AUTH_CONCURRENT_CHECKS] hash checks run at once, for all profiles. A request that finds no free slot
 *   within [BASIC_AUTH_SLOT_WAIT_MILLIS] gets 503 and does not count as a failure.
 */
class BasicAuthChecker(private val clock: () -> Long = System::currentTimeMillis) {
    private val remembered = ConcurrentHashMap<String, Long>()
    private val throttle = LoginThrottle(clock)
    private val checks = Semaphore(BASIC_AUTH_CONCURRENT_CHECKS)

    /** Checks that are running, by profile and credentials, so the same login sent in parallel is checked once. */
    private val checking = ConcurrentHashMap<String, CompletableDeferred<BasicResult>>()

    @Volatile
    private var lastPurge = 0L

    /** A hash nobody has the password of, created once on first use. */
    private val fakeHash: String by lazy { hashBcrypt(sha256Hex(System.nanoTime().toString())) }

    /** Checks the `Authorization` header of a request from [ip] against [config] of the profile [profile]. */
    internal suspend fun check(config: BasicAuthConfig, authorization: String?, ip: String, profile: String = ""): BasicResult {
        val decoded = decode(authorization)
        val user = decoded?.let { (name, _) -> config.users.firstOrNull { it.name == name } }
        val key = decoded?.let { (name, password) -> sha256Hex("$name\u0000$password\u0000${user?.hash ?: ""}") }
        val now = clock()
        if (user != null && key != null && (remembered[key] ?: 0) > now) {
            // Sliding: an active user does not hit a full check burst every 10 minutes
            remembered[key] = now + BASIC_AUTH_CACHE_MILLIS
            return BasicResult.Ok(user.name)
        }
        if (throttle.lockedUntil(ip, profile) != null) return BasicResult.Locked
        val (name, password) = decoded ?: return BasicResult.Missing
        // A page fires many requests with the same login at once, one hash check answers all of them
        val running = CompletableDeferred<BasicResult>()
        val coalesceKey = "$profile\u0000${key!!}"
        val first = checking.putIfAbsent(coalesceKey, running)
        if (first != null) return first.await()
        val result = try {
            verify(user, name, password, ip, profile, key, now)
        } catch (e: Throwable) {
            running.completeExceptionally(e)
            throw e
        } finally {
            checking.remove(coalesceKey, running)
        }
        running.complete(result)
        return result
    }

    private suspend fun verify(user: BasicAuthUser?, name: String, password: String, ip: String, profile: String, key: String, now: Long): BasicResult {
        // The slot first: a refusal for lack of a slot is no wrong password and must not count against the address
        // The flag, not the block's result: a timeout right after acquire() would otherwise lose the permit
        var acquired = false
        withTimeoutOrNull(BASIC_AUTH_SLOT_WAIT_MILLIS) { checks.acquire(); acquired = true }
        if (acquired.not()) return BasicResult.Busy
        val valid = try {
            if (throttle.begin(ip, profile) != null) return BasicResult.Locked
            withContext(Dispatchers.Default) { verifyBasicAuthHash(password, user?.hash ?: fakeHash) } && user != null
        } finally {
            checks.release()
        }
        if (valid.not()) return BasicResult.Wrong
        throttle.success(ip, profile)
        if (remembered.size > 10_000 && now - lastPurge > 30_000) {
            lastPurge = now
            remembered.values.removeIf { it <= now }
        }
        remembered[key] = now + BASIC_AUTH_CACHE_MILLIS
        return BasicResult.Ok(name)
    }

    private fun decode(header: String?): Pair<String, String>? {
        if (header == null || header.startsWith("Basic ", ignoreCase = true).not()) return null
        val text = runCatching { Base64.getDecoder().decode(header.substring(6).trim()).decodeToString() }.getOrNull() ?: return null
        if (':' !in text) return null
        return text.substringBefore(':') to text.substringAfter(':')
    }
}

/**
 * Runs the checks of an access profile in Zoraxy's order (specification phase 2, section 1.2):
 *
 * 1. block lists (IPs always, countries only when the country is known),
 * 2. allow lists (with `allowLocal`, an unknown country passes when only countries are listed),
 * 3. exploit filter and trap paths,
 * 4. rate limit,
 * 5. allowed methods,
 * 6. captcha,
 * 7. Basic Auth.
 *
 * Every refusal is a security event, the reason goes to the access log, the visitor only sees a neutral page.
 */
class AccessChecker(
    private val geo: Geo,
    private val bans: BanStore,
    private val security: SecurityEvents,
    private val rateLimiter: RateLimiter,
    private val basicAuth: BasicAuthChecker,
    private val captcha: CaptchaService,
    private val aiCrawlers: () -> AiCrawlersConfig = { AiCrawlersConfig() },
) {
    suspend fun check(profile: AccessProfile, request: AccessRequest): AccessResult {
        val ip = request.address.hostAddress
        val country by lazy { if (profile.usesCountries) geo.country(request.address) else null }

        // 1. Block lists
        if (profile.denyIps.any { cachedCidr(it)?.contains(request.address) == true }) return deny(403, "blocked IP", SecurityEventType.ACCESS_DENIED, request)
        if (profile.denyCountries.isNotEmpty() && country != null && country in profile.denyCountries) {
            return deny(403, "blocked country $country", SecurityEventType.ACCESS_DENIED, request)
        }

        // 2. Allow lists
        if (profile.allowIps.isNotEmpty() || profile.allowCountries.isNotEmpty()) {
            val byIp = profile.allowsIp(request.address)
            val byCountry = profile.allowCountries.isNotEmpty() && when (val c = country) {
                null -> profile.allowIps.isEmpty()
                else -> c in profile.allowCountries
            }
            val byLocal = profile.allowLocal && isLocalAddress(request.address)
            if (byIp.not() && byCountry.not() && byLocal.not()) return deny(403, "not on the allow list" + (country?.let { " ($it)" } ?: ""), SecurityEventType.ACCESS_DENIED, request)
        }

        // 3. Exploit filter and trap paths
        val filter = profile.exploitFilter
        if (filter.commonExploits) matchCommonExploit(request.rawQuery, request.userAgent)?.let { group ->
            security.record(SecurityEventType.EXPLOIT_BLOCKED, request.address.hostAddress, request.domain, "exploit filter: $group: ${request.method} ${request.path}")
            return AccessResult.Deny(filter.response.status, "exploit filter: $group")
        }
        if (filter.aiBots) matchAiBot(request.userAgent, aiCrawlers())?.let { bot ->
            security.record(SecurityEventType.AI_BOT_BLOCKED, request.address.hostAddress, request.domain, "AI crawler: $bot: ${request.method} ${request.path}")
            return AccessResult.Deny(filter.response.status, "AI crawler: $bot")
        }
        val traps = profile.trapPaths
        if (traps.enabled && request.exactRoute.not()) traps.paths.firstOrNull { request.path.startsWith(it) }?.let { trap ->
            // A foreign page could make every visitor's browser load a trap path, that only gets refused
            if (request.foreignInitiated) return deny(403, "trap path $trap, not banned (sent for another site)", SecurityEventType.ACCESS_DENIED, request)
            // An address on the allow list of the profile is never banned (decided on 20.11.2026), the request is still refused
            if (profile.allowsIp(request.address)) return deny(403, "trap path $trap, not banned (on the allow list)", SecurityEventType.ACCESS_DENIED, request)
            bans.ban(request.address, traps.banDuration, "trap path $trap", request.domain)
            return AccessResult.Deny(403, "trap path $trap")
        }

        // 4. Rate limit
        if (rateLimitExceeded(profile, request.address, request.domain, "${request.method} ${request.path}")) return AccessResult.Deny(429, "rate limit")

        // 5. Allowed methods
        if (profile.allowedMethods.isNotEmpty() && request.method !in profile.allowedMethods) {
            return deny(405, "method ${request.method} not allowed", SecurityEventType.METHOD_DENIED, request, allow = profile.allowedMethods.joinToString(", "))
        }

        // 6. Captcha
        val solved = profile.captcha != null && captcha.sessions.isValid(request.captchaCookie, captcha.scope(profile.name, request.host))
        profile.captcha?.let { config ->
            val excepted = config.exceptions.any { e ->
                e.pathPrefix?.let { p -> p == "/" || request.path == p.trimEnd('/') || request.path.startsWith(p.trimEnd('/') + "/") } == true ||
                    e.cidr?.let { cachedCidr(it)?.contains(request.address) } == true
            }
            if (solved.not() && captchaApplies(config, request.path, excepted)) return AccessResult.CaptchaRequired(profile.name, config)
        }

        // 7. Basic Auth
        val auth = profile.basicAuth ?: return AccessResult.Allow()
        val excepted = auth.exceptions.any { e ->
            e.pathPrefix?.let { p -> p == "/" || request.path == p.trimEnd('/') || request.path.startsWith(p.trimEnd('/') + "/") } == true ||
                e.cidr?.let { cachedCidr(it)?.contains(request.address) } == true
        }
        if (excepted) return AccessResult.Allow()
        return when (val result = basicAuth.check(auth, request.authorization, ip, profile.name)) {
            is BasicResult.Ok -> AccessResult.Allow(result.user)
            BasicResult.Missing -> AccessResult.Challenge(auth.realm, "basic auth required")
            BasicResult.Locked -> deny(429, "basic auth locked out", SecurityEventType.BASIC_AUTH_FAILED, request)
            BasicResult.Busy -> AccessResult.Deny(503, "basic auth busy")
            BasicResult.Wrong -> {
                security.record(SecurityEventType.BASIC_AUTH_FAILED, ip, request.domain, request.path)
                AccessResult.Challenge(auth.realm, "basic auth failed")
            }
        }
    }

    /**
     * Counts a request against the rate limit of [profile] and records a security event when it is exceeded. Also used
     * alone for Kovexy's own paths under `/.kovexy/`, which are answered before the profile runs (decided on 18.11.2026).
     *
     * @param what Method and path for the security event.
     */
    fun rateLimitExceeded(profile: AccessProfile, address: InetAddress, domain: String, what: String): Boolean {
        val limit = profile.rateLimit ?: return false
        if (rateLimiter.exceeded(profile.name, addressKey(address, limit.ipv6Prefix), limit.requestsPerSecond).not()) return false
        security.record(SecurityEventType.RATE_LIMITED, address.hostAddress, domain, "rate limit: $what")
        return true
    }

    private fun deny(status: Int, reason: String, type: SecurityEventType, request: AccessRequest, allow: String? = null): AccessResult.Deny {
        security.record(type, request.address.hostAddress, request.domain, "$reason: ${request.method} ${request.path}")
        return AccessResult.Deny(status, reason, allow)
    }
}

private val cidrCache = ConcurrentHashMap<String, java.util.Optional<Cidr>>()

/**
 * Whether [address] is named in [AccessProfile.allowIps]. Only the IP list counts, not the countries and not
 * `allowLocal`, so an address that is trusted by name can never be banned, wherever it ends up.
 */
fun AccessProfile.allowsIp(address: InetAddress): Boolean = allowIps.any { cachedCidr(it)?.contains(address) == true }

/** [Cidr.parse] with a cache, profiles are checked on every request. */
private fun cachedCidr(text: String): Cidr? {
    if (cidrCache.size > 10_000) cidrCache.clear()
    return cidrCache.computeIfAbsent(text) { java.util.Optional.ofNullable(Cidr.parse(it)) }.orElse(null)
}

/** Whether a deny status means the `drop` response of the exploit filter. */
val AccessResult.Deny.isDrop: Boolean get() = status == ExploitResponse.DROP.status
