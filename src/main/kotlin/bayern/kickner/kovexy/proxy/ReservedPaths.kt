package bayern.kickner.kovexy.proxy

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.access.APP_AUTH_COOKIE
import bayern.kickner.kovexy.access.APP_LOGIN_COOKIE
import bayern.kickner.kovexy.access.APP_RETURN_COOKIE
import bayern.kickner.kovexy.access.APP_SESSION_MAX_MILLIS
import bayern.kickner.kovexy.access.AppAuthService
import bayern.kickner.kovexy.access.CaptchaService
import bayern.kickner.kovexy.access.CAPTCHA_COOKIE
import bayern.kickner.kovexy.access.safeReturnPath
import bayern.kickner.kovexy.access.addressKey
import bayern.kickner.kovexy.auth.LoginError
import bayern.kickner.kovexy.config.parseIpLiteral
import java.net.InetAddress
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.audit.SecurityEvents
import bayern.kickner.kovexy.config.CaptchaConfig
import bayern.kickner.kovexy.config.CaptchaProvider
import bayern.kickner.kovexy.config.RecaptchaVersion
import bayern.kickner.kovexy.site.captchaPage
import bayern.kickner.kovexy.site.neutralPage
import io.ktor.http.ContentType
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import bayern.kickner.kovexy.receiveForm
import bayern.kickner.kovexy.MAX_PUBLIC_FORM_BYTES
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotnexlib.ResultOf2

private const val TAG = "Reserved"

/** Prefix of Kovexy's own paths on every domain. Never forwarded to an upstream. */
const val RESERVED_PREFIX = "/.kovexy/"

/** The captcha script, read once from the JAR. */
private val CAPTCHA_SCRIPT: ByteArray by lazy {
    object {}.javaClass.getResourceAsStream("/kovexy-captcha.js")!!.use { it.readBytes() }
}

/** Status and reason of an answer to a reserved path, for the access log. */
data class ReservedResult(val status: Int, val reason: String)

/**
 * Answers the reserved paths `/.kovexy/...` of a site: the captcha script and its verification, and the app login
 * (start, callback, logout). They run before the locations, nothing of it reaches an upstream.
 */
class ReservedPaths(
    private val captcha: CaptchaService,
    private val appAuth: AppAuthService,
    private val security: SecurityEvents,
) {
    /** Answers the reserved [path] (cleaned, without query). */
    suspend fun handle(call: ApplicationCall, table: RoutingTable, site: CompiledSite, domain: String, path: String, clientIp: String, https: Boolean): ReservedResult =
        when (path) {
            "/.kovexy/captcha.js" -> {
                call.response.headers.append(HttpHeaders.CacheControl, "public, max-age=3600")
                call.respondBytes(CAPTCHA_SCRIPT, ContentType.Application.JavaScript)
                ReservedResult(200, "captcha script")
            }

            "/.kovexy/captcha/verify" -> verifyCaptcha(call, table, domain, clientIp, https)
            "/.kovexy/auth/start" -> startLogin(call, domain, https)
            "/.kovexy/auth/callback" -> callback(call, domain, clientIp, site.name, admittedSubjects(table, site))
            "/.kovexy/auth/logout" -> logout(call)
            else -> page(call, 404, "Not Found", "There is nothing at this address.", "unknown reserved path")
        }

    /** Answers with the captcha page of [config] for the profile [profile]. */
    suspend fun challenge(call: ApplicationCall, profile: String, config: CaptchaConfig, domain: String, returnTo: String, error: String? = null) {
        val token = captcha.pageToken(profile, domain, safeReturnPath(returnTo))
        val html = when {
            config.provider == CaptchaProvider.POW -> captchaPage(token, "pow", captcha.pow.task(config.powDifficulty), config.powDifficulty, error = error)
            config.recaptchaVersion == RecaptchaVersion.V2 -> captchaPage(token, "recaptcha2", siteKey = config.siteKey, error = error)
            else -> captchaPage(token, "recaptcha3", siteKey = config.siteKey, error = error)
        }
        call.response.headers.append(HttpHeaders.CacheControl, "no-store")
        call.response.headers.append("Content-Security-Policy", captchaPolicy(config.provider == CaptchaProvider.GOOGLE))
        call.respondText(html, ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.Forbidden)
    }

    private suspend fun verifyCaptcha(call: ApplicationCall, table: RoutingTable, domain: String, clientIp: String, https: Boolean): ReservedResult {
        if (call.request.httpMethod != HttpMethod.Post) return page(call, 405, "Method Not Allowed", "Only for the captcha form.", "captcha verify method")
        if (https.not()) return page(call, 400, "HTTPS needed", "The check only works over HTTPS.", "captcha over http")
        val params = call.receiveForm(MAX_PUBLIC_FORM_BYTES)
        val (profileName, tokenDomain, returnTo) = captcha.readPageToken(params["token"].orEmpty())
            ?: return page(call, 400, "Expired", "This page is too old. Please load the address again.", "captcha token invalid")
        val config = table.profile(profileName)?.captcha
        if (config == null || tokenDomain != domain) return page(call, 400, "Expired", "This page is too old. Please load the address again.", "captcha token for another site")
        val valid = when (config.provider) {
            CaptchaProvider.POW -> captcha.pow.verify(params["task"].orEmpty(), params["nonce"].orEmpty(), config.powDifficulty)
            CaptchaProvider.GOOGLE -> captcha.google.verifyLimited(config, params["g-recaptcha-response"].orEmpty(), clientIp)
                ?: return page(call, 503, "Busy", "A check from this address is still running. Please try again in a moment.", "captcha check busy")
        }
        if (valid.not() && config.provider == CaptchaProvider.POW && captcha.pow.full) {
            return page(call, 503, "Busy", "Too many visitors right now. Please try again in a few minutes.", "captcha task list full")
        }
        if (valid.not()) {
            security.record(SecurityEventType.ACCESS_DENIED, clientIp, domain, "captcha failed")
            challenge(call, profileName, config, domain, returnTo, "That did not work, please try again.")
            return ReservedResult(403, "captcha failed")
        }
        val lifetime = config.sessionDuration.inWholeMilliseconds
        val id = captcha.sessions.create(captcha.scope(profileName, domain), lifetime)
        // Like Zoraxy HttpOnly and Lax, Secure because the captcha only runs over HTTPS
        call.response.cookies.append(Cookie(CAPTCHA_COOKIE, id, maxAge = (lifetime / 1000).toInt(), path = "/", secure = true, httpOnly = true, extensions = mapOf("SameSite" to "Lax")))
        call.respondRedirect(returnTo)
        return ReservedResult(302, "captcha solved")
    }

    private suspend fun startLogin(call: ApplicationCall, domain: String, https: Boolean): ReservedResult {
        val client = appAuth.client(domain) ?: return page(call, 404, "Not Found", "There is nothing at this address.", "app login not set up")
        if (https.not()) return page(call, 400, "HTTPS needed", "The login only works over HTTPS.", "app login over http")
        val returnTo = safeReturnPath(call.request.queryParameters["rd"])
        return when (val start = withContext(Dispatchers.IO) { client.startLogin() }) {
            is ResultOf2.Success -> {
                call.response.cookies.append(laxCookie(APP_LOGIN_COOKIE, start.value.cookie, 600))
                call.response.cookies.append(laxCookie(APP_RETURN_COOKIE, returnTo, 600))
                call.respondRedirect(start.value.redirectUrl)
                ReservedResult(302, "app login start")
            }

            is ResultOf2.Failure -> {
                staticLog(KLogger.Level.ERROR, TAG) { "Cannot start the app login for $domain: ${start.value}" }
                page(call, 503, "Login unavailable", "The login service is not reachable. Please try again in a moment.", "app login provider unavailable")
            }
        }
    }

    /**
     * The subjects any OIDC profile of [site] admits, `null` if one of them admits everybody, empty without any. A login of somebody else
     * would only create a session that never opens anything (audit run-2).
     */
    private fun admittedSubjects(table: RoutingTable, site: CompiledSite): Set<String>? {
        val profiles = (listOf(site.config.access) + site.config.locations.filter { it.enabled }.map { it.access }).mapNotNull { name -> name?.let(table::profile)?.oidc }
        if (profiles.isEmpty()) return emptySet()
        if (profiles.any { it.allowedSubjects.isEmpty() }) return null
        return profiles.flatMap { it.allowedSubjects }.toSet()
    }

    private suspend fun callback(call: ApplicationCall, domain: String, clientIp: String, site: String, admitted: Set<String>?): ReservedResult {
        val client = appAuth.client(domain) ?: return page(call, 404, "Not Found", "There is nothing at this address.", "app login not set up")
        val q = call.request.queryParameters
        val attempt = call.request.cookies[APP_LOGIN_COOKIE]
        val returnTo = safeReturnPath(call.request.cookies[APP_RETURN_COOKIE])
        call.response.cookies.append(laxCookie(APP_LOGIN_COOKIE, "", 0))
        call.response.cookies.append(laxCookie(APP_RETURN_COOKIE, "", 0))
        val clientKey = parseIpLiteral(clientIp)?.let { addressKey(InetAddress.getByAddress(it)) }
        val result = withContext(Dispatchers.IO) { client.finishLogin(attempt, q["state"], q["code"], q["error"], q["error_description"], clientKey) }
        val claims = when (result) {
            is ResultOf2.Success -> result.value
            is ResultOf2.Failure -> {
                if (result.value == LoginError.Busy) return page(call, 503, "Busy", "Another login from this address is running. Please start again in a moment.", "app login busy")
                staticLog(KLogger.Level.WARN, TAG) { "App login on $domain failed: ${result.value}" }
                security.record(SecurityEventType.ACCESS_DENIED, clientIp, site, "app login failed")
                return page(call, 403, "Login failed", "The login did not work. Please start again.", "app login failed")
            }
        }
        if (admitted != null && claims.sub !in admitted) {
            security.record(SecurityEventType.ACCESS_DENIED, clientIp, site, "oidc user ${claims.sub} not allowed")
            return page(call, 403, "Forbidden", "Access to this address is not allowed.", "oidc user not allowed")
        }
        val token = appAuth.createSession(domain, claims)
        call.response.cookies.append(laxCookie(APP_AUTH_COOKIE, token, (APP_SESSION_MAX_MILLIS / 1000).toInt()))
        // The cookie is Lax, a top level redirect back to the app brings it along
        call.respondRedirect(returnTo)
        return ReservedResult(302, "app login")
    }

    private suspend fun logout(call: ApplicationCall): ReservedResult {
        appAuth.remove(call.request.cookies[APP_AUTH_COOKIE])
        call.response.cookies.append(laxCookie(APP_AUTH_COOKIE, "", 0))
        return page(call, 200, "Logged out", "You are logged out.", "app logout")
    }

    private suspend fun page(call: ApplicationCall, status: Int, title: String, text: String, reason: String): ReservedResult {
        call.respondText(neutralPage(status, title, text), ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.fromValue(status))
        return ReservedResult(status, reason)
    }

    private fun laxCookie(name: String, value: String, maxAge: Int) =
        Cookie(name, value, maxAge = maxAge, path = "/", secure = true, httpOnly = true, extensions = mapOf("SameSite" to "Lax"))
}

/**
 * The content security policy of the captcha page. Only this page allows Google's scripts and frames, and only with
 * reCAPTCHA. The inline style is the neutral page style, scripts only come from the same origin.
 */
internal fun captchaPolicy(google: Boolean): String {
    val googleScripts = if (google) " https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/" else ""
    val frames = if (google) "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/" else "'none'"
    return "default-src 'none'; script-src 'self'$googleScripts; style-src 'unsafe-inline'; img-src 'self' data:; " +
        "frame-src $frames; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}
