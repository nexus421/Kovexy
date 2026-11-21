package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.access.CAPTCHA_COOKIE
import bayern.kickner.kovexy.access.CaptchaService
import bayern.kickner.kovexy.access.safeReturnPath
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.audit.SecurityEvents
import bayern.kickner.kovexy.config.CaptchaConfig
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

/** Prefix of Kovexy's own paths on every domain. Never forwarded to a backend. */
const val RESERVED_PREFIX = "/.kovexy/"

/** The captcha script, read once from the JAR. */
private val CAPTCHA_SCRIPT: ByteArray by lazy {
    object {}.javaClass.getResourceAsStream("/kovexy-captcha.js")!!.use { it.readBytes() }
}

/** Status and reason of an answer to a reserved path, for the access log. */
data class ReservedResult(val status: Int, val reason: String)

/**
 * Answers the reserved paths `/.kovexy/...` of a domain: the captcha script and the verification of its answer. They
 * run before the routes, nothing of it reaches a backend.
 */
class ReservedPaths(
    private val captcha: CaptchaService,
    private val security: SecurityEvents,
) {
    /** Answers the reserved [path] (cleaned, without query). */
    suspend fun handle(call: ApplicationCall, table: RoutingTable, domain: String, path: String, clientIp: String, https: Boolean): ReservedResult =
        when (path) {
            "/.kovexy/captcha.js" -> {
                call.response.headers.append(HttpHeaders.CacheControl, "public, max-age=3600")
                call.respondBytes(CAPTCHA_SCRIPT, ContentType.Application.JavaScript)
                ReservedResult(200, "captcha script")
            }

            "/.kovexy/captcha/verify" -> verifyCaptcha(call, table, domain, clientIp, https)
            else -> page(call, 404, "Not Found", "There is nothing at this address.", "unknown reserved path")
        }

    /** Answers with the captcha page of [config] for the profile [profile]. */
    suspend fun challenge(call: ApplicationCall, profile: String, config: CaptchaConfig, domain: String, returnTo: String, error: String? = null) {
        val token = captcha.pageToken(profile, domain, safeReturnPath(returnTo))
        val provider = if (config.recaptchaVersion == RecaptchaVersion.V2) "recaptcha2" else "recaptcha3"
        call.response.headers.append(HttpHeaders.CacheControl, "no-store")
        call.response.headers.append("Content-Security-Policy", CAPTCHA_POLICY)
        call.respondText(captchaPage(token, provider, config.siteKey, error), ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.Forbidden)
    }

    private suspend fun verifyCaptcha(call: ApplicationCall, table: RoutingTable, domain: String, clientIp: String, https: Boolean): ReservedResult {
        if (call.request.httpMethod != HttpMethod.Post) return page(call, 405, "Method Not Allowed", "Only for the captcha form.", "captcha verify method")
        if (https.not()) return page(call, 400, "HTTPS needed", "The check only works over HTTPS.", "captcha over http")
        val params = call.receiveForm(MAX_PUBLIC_FORM_BYTES)
        val (profileName, tokenDomain, returnTo) = captcha.readPageToken(params["token"].orEmpty())
            ?: return page(call, 400, "Expired", "This page is too old. Please load the address again.", "captcha token invalid")
        val config = table.profile(profileName)?.captcha
        if (config == null || tokenDomain != domain) return page(call, 400, "Expired", "This page is too old. Please load the address again.", "captcha token for another site")
        val valid = captcha.google.verifyLimited(config, params["g-recaptcha-response"].orEmpty(), clientIp)
            ?: return page(call, 503, "Busy", "A check from this address is still running. Please try again in a moment.", "captcha check busy")
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

    private suspend fun page(call: ApplicationCall, status: Int, title: String, text: String, reason: String): ReservedResult {
        call.respondText(neutralPage(status, title, text), ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.fromValue(status))
        return ReservedResult(status, reason)
    }
}

/**
 * The content security policy of the captcha page. Only this page allows Google's scripts and frames, for reCAPTCHA.
 * The inline style is the neutral page style, scripts only come from the same origin.
 */
internal const val CAPTCHA_POLICY = "default-src 'none'; script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; " +
    "style-src 'unsafe-inline'; img-src 'self' data:; frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; " +
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
