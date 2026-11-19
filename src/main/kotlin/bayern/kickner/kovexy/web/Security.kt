package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.config.plainAddress
import bayern.kickner.kovexy.proxy.ADMIN_RELAY_HEADER
import bayern.kickner.kovexy.proxy.ADMIN_RELAY_SECRET
import bayern.kickner.kovexy.proxy.isLoopbackHost
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.auth.Session
import bayern.kickner.kovexy.config.AdminConfig
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.util.AttributeKey
import java.net.URI

/** Name of the session cookie. The `__Host-` prefix makes the browser reject it unless Secure, host-only and `Path=/`. */
const val SESSION_COOKIE = "__Host-kovexy-session"

/**
 * Content Security Policy for every admin response: no inline scripts, no inline styles, no `eval`, nothing from
 * other origins. htmx is configured not to inject styles (see `Layout.kt`).
 */
const val CONTENT_SECURITY_POLICY = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
    "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

/**
 * Paths reachable without a session, matched exactly. Everything else requires a login, so a new route is protected
 * by default.
 */
private val publicPaths = setOf("/login", "/auth/start", "/auth/callback", "/healthz")

/** The only public prefix: the static files the login page needs. */
private const val STATIC_PREFIX = "/static/"

/** Key of the [Session] in the call attributes, set by [checkAdminRequest] for every protected path. */
val SessionKey = AttributeKey<Session>("kovexy.session")

/** Key of the session token in the call attributes. */
val SessionTokenKey = AttributeKey<String>("kovexy.session.token")

/** The session of the current call. Only valid on protected paths. */
val ApplicationCall.session: Session get() = attributes[SessionKey]

/**
 * The origins the admin UI accepts for form posts: the local address of the admin connector (with `localhost` and
 * `127.0.0.1` both when it listens on loopback) and the origin of `publicUrl`.
 */
fun allowedOrigins(admin: AdminConfig, port: Int): Set<String> = buildSet {
    val host = admin.host
    when (host) {
        // A wildcard bind is reached locally through loopback, from outside only through the public URL
        "127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "::", "[::]" -> {
            add("http://127.0.0.1:$port")
            add("http://localhost:$port")
            add("http://[::1]:$port")
        }

        else -> add("http://${if (':' in host) "[$host]" else host}:$port")
    }
    if (admin.publicUrl.isNotEmpty()) runCatching { URI(admin.publicUrl) }.getOrNull()?.let { add("${it.scheme}://${it.rawAuthority}") }
}

/**
 * The visitor's address. When the admin UI is reached through a site of Kovexy itself, the request comes from
 * loopback and Kovexy's proxy hands over the visitor it resolved (trusted proxies included) in [ADMIN_RELAY_HEADER]
 * with the per-process secret. `X-Forwarded-For` is never believed here, any local process could set it.
 */
val ApplicationCall.adminClientIp: String
    get() {
        val peer = plainAddress(request.local.remoteAddress)
        if (isLoopbackHost(peer).not()) return peer
        val relay = request.headers[ADMIN_RELAY_HEADER] ?: return peer
        if (relay.substringBefore(' ') != ADMIN_RELAY_SECRET) return peer
        return relay.substringAfter(' ', "").ifEmpty { peer }
    }

/**
 * Security checks before routing, for every admin request:
 *
 * 1. Security headers (CSP, `nosniff`, referrer only same-origin, no caching, no framing, HSTS behind https).
 * 2. Origin check: requests other than GET and HEAD must come from an [allowedOrigins] origin. Together with
 *    `SameSite=Strict` this is the CSRF protection.
 * 3. Login check: no valid session leads to `/login` (pages) or 401.
 *
 * @return `true` if the request may continue, `false` if it was answered already.
 */
suspend fun ApplicationCall.checkAdminRequest(kovexy: Kovexy): Boolean {
    val admin = kovexy.config.admin
    val headers = response.headers
    headers.append("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    headers.append("X-Content-Type-Options", "nosniff")
    // Not no-referrer: with it, browsers send "Origin: null" on form posts and the origin check rejects them
    headers.append("Referrer-Policy", "same-origin")
    headers.append("X-Frame-Options", "DENY")
    headers.append(HttpHeaders.CacheControl, "no-store")
    headers.append("Cross-Origin-Opener-Policy", "same-origin")
    headers.append("Cross-Origin-Resource-Policy", "same-origin")
    headers.append("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
    if (admin.publicUrl.startsWith("https://")) headers.append("Strict-Transport-Security", "max-age=31536000")

    val method = request.httpMethod
    val needsOrigin = method != HttpMethod.Get && method != HttpMethod.Head
    if (needsOrigin && request.headers[HttpHeaders.Origin] !in allowedOrigins(admin, kovexy.server.adminPort)) {
        respond(HttpStatusCode.Forbidden, "Origin not allowed")
        return false
    }

    val path = request.path()
    if (path in publicPaths || path.startsWith(STATIC_PREFIX)) return true

    val token = sessionToken
    val session = kovexy.sessions.get(token)
    if (session == null) {
        if (method == HttpMethod.Get) respondRedirect("/login")
        else errorPage(HttpStatusCode.Unauthorized, "Logged out", "Your session ended, the change was not saved. Log in again and repeat it.")
        return false
    }
    attributes.put(SessionKey, session)
    attributes.put(SessionTokenKey, token!!)
    return true
}

/** The session token from the cookie, `null` if missing or not decodable (a broken cookie is no session, not an error). */
val ApplicationCall.sessionToken: String? get() = runCatching { request.cookies[SESSION_COOKIE] }.getOrNull()

/** The session cookie: Secure, HttpOnly, `SameSite=Strict`, `Path=/`, no domain. */
fun sessionCookie(value: String, maxAgeSeconds: Int): Cookie = Cookie(
    name = SESSION_COOKIE,
    value = value,
    maxAge = maxAgeSeconds,
    path = "/",
    secure = true,
    httpOnly = true,
    extensions = mapOf("SameSite" to "Strict"),
)
