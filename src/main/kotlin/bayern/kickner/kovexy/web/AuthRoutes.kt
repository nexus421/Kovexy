package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.t
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.PASSWORD_ONLY_WARNING
import bayern.kickner.kovexy.audit.Actor
import bayern.kickner.kovexy.audit.AuditAction
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.auth.IdTokenClaims
import bayern.kickner.kovexy.auth.LoginError
import bayern.kickner.kovexy.auth.verifyPassword
import bayern.kickner.kovexy.cleanText
import bayern.kickner.kovexy.config.LoginMode
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.secureRandom
import bayern.kickner.kovexy.toBase64Url
import io.ktor.http.Cookie
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import bayern.kickner.kovexy.access.addressKey
import bayern.kickner.kovexy.config.parseIpLiteral
import java.net.InetAddress
import kotlin.time.Duration.Companion.seconds
import kotlinx.html.FormMethod
import kotlinx.html.form
import kotlinx.html.h2
import kotlinx.html.p
import bayern.kickner.kovexy.ResultOf2
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val TAG = "Login"


/** Admin password checks that may run at the same time. */
private val passwordChecks = Semaphore(2)

/** How long a password login waits for a free check before it gets 503. */
private val PASSWORD_SLOT_WAIT = 5.seconds

/** Short-lived cookie that ties the OIDC callback to the login attempt (Dirl). */
const val LOGIN_COOKIE = "__Host-kovexy-login"

/** Short-lived cookie between OIDC and password in the login mode `both`. */
const val PENDING_COOKIE = "__Host-kovexy-pending"

/** Time between the OIDC step and the password step in the login mode `both`. */
private const val PENDING_SECONDS = 300

/** Signs the pending cookie. New on every start, a restart only ends logins that are half done. */
private val pendingKey = SecretKeySpec(ByteArray(32).also(secureRandom::nextBytes), "HmacSHA256")

private fun hmac(data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").apply { init(pendingKey) }.doFinal(data)

/** The pending cookie for [claims]: `payload.signature`, both Base64url. */
private fun signPending(claims: IdTokenClaims, expiresAt: Long): String {
    val payload = "${claims.sub}\u0000${claims.name}\u0000$expiresAt".toByteArray()
    return payload.toBase64Url() + "." + hmac(payload).toBase64Url()
}

/** The identity from a pending cookie, `null` if it is missing, forged or expired. */
private fun verifyPending(cookie: String?, now: Long): IdTokenClaims? = runCatching {
    val (payloadPart, signaturePart) = cookie?.split('.')?.takeIf { it.size == 2 } ?: return null
    val payload = Base64.getUrlDecoder().decode(payloadPart)
    if (MessageDigest.isEqual(hmac(payload), Base64.getUrlDecoder().decode(signaturePart)).not()) return null
    val fields = payload.decodeToString().split('\u0000')
    if (fields.size != 3 || fields[2].toLong() < now) return null
    IdTokenClaims(fields[0], fields[1])
}.getOrNull()

/** A login cookie: Secure, HttpOnly, `Path=/`, the given SameSite. */
private fun shortCookie(name: String, value: String, maxAge: Int, sameSite: String) =
    Cookie(name = name, value = value, maxAge = maxAge, path = "/", secure = true, httpOnly = true, extensions = mapOf("SameSite" to sameSite))

/**
 * Login and logout in the three modes of the concept:
 *
 * - `password`: only the local password, every page warns about it,
 * - `oidc`: only OpenID Connect (Dirl's flow: PKCE, state, nonce, signed login cookie, no server state),
 * - `both`: OpenID Connect first, then the password, as a second barrier in case the provider has a hole.
 *
 * `GET /login` shows a link for OIDC, not a form, because `form-action 'self'` in the CSP would block a form that
 * redirects to the provider.
 */
fun Route.authRoutes(kovexy: Kovexy) {
    get("/login") {
        if (kovexy.sessions.get(call.sessionToken) != null) return@get call.respondRedirect("/")
        call.loginPage(kovexy, null)
    }

    get("/auth/start") {
        val oidc = kovexy.oidc
        if (kovexy.config.admin.loginMode == LoginMode.PASSWORD || oidc == null) return@get call.respondRedirect("/login")
        when (val start = withContext(Dispatchers.IO) { oidc.startLogin() }) {
            is ResultOf2.Success -> {
                // Lax, so the cookie survives the top-level navigation back from the provider
                call.response.cookies.append(shortCookie(LOGIN_COOKIE, start.value.cookie, 600, "Lax"))
                call.respondRedirect(start.value.redirectUrl)
            }

            is ResultOf2.Failure -> {
                staticLog(KLogger.Level.ERROR, TAG) { "Cannot start the OIDC login: ${start.value}" }
                call.loginPage(kovexy, "The identity provider is not reachable. Try again in a moment.", HttpStatusCode.ServiceUnavailable)
            }
        }
    }

    get("/auth/callback") {
        val oidc = kovexy.oidc ?: return@get call.respondRedirect("/login")
        // A login started before a switch to password only must not end in a session
        if (kovexy.config.admin.loginMode == LoginMode.PASSWORD) {
            call.response.cookies.append(shortCookie(LOGIN_COOKIE, "", 0, "Lax"))
            return@get call.respondRedirect("/login")
        }
        val q = call.request.queryParameters
        val loginCookie = call.request.cookies[LOGIN_COOKIE]
        call.response.cookies.append(shortCookie(LOGIN_COOKIE, "", 0, "Lax"))
        val clientKey = parseIpLiteral(call.adminClientIp)?.let { addressKey(InetAddress.getByAddress(it)) }
        val result = withContext(Dispatchers.IO) { oidc.finishLogin(loginCookie, q["state"], q["code"], q["error"], q["error_description"], clientKey) }
        val claims = when (result) {
            is ResultOf2.Success -> result.value
            is ResultOf2.Failure -> {
                // Busy is nobody's failed login, it is no event and no webhook
                if (result.value == LoginError.Busy) return@get call.loginPage(kovexy, loginErrorText(result.value), HttpStatusCode.ServiceUnavailable)
                staticLog(KLogger.Level.WARN, TAG) { "OIDC login failed: ${result.value}" }
                call.failedLogin(kovexy, Actor("unknown", "unknown", call.adminClientIp), "OIDC: ${result.value::class.simpleName}")
                return@get call.loginPage(kovexy, loginErrorText(result.value), HttpStatusCode.Forbidden)
            }
        }
        // The token exchange takes a while, the login mode or the provider may have changed meanwhile (audit run-2)
        if (kovexy.config.admin.loginMode == LoginMode.PASSWORD || kovexy.oidc !== oidc) {
            staticLog(KLogger.Level.WARN, TAG) { "Dropped OIDC login of '${claims.name}', the login settings changed during the login" }
            return@get call.loginPage(kovexy, "The login settings changed during the login. Please start again.", HttpStatusCode.Forbidden)
        }
        val allowed = kovexy.config.admin.oidc?.allowedSubjects.orEmpty()
        if (allowed.isNotEmpty() && claims.sub !in allowed) {
            staticLog(KLogger.Level.WARN, TAG) { "Rejected OIDC login of '${claims.name}' (${claims.sub}), not in allowedSubjects" }
            call.failedLogin(kovexy, Actor(claims.sub, claims.name, call.adminClientIp), "not in allowedSubjects")
            return@get call.loginPage(kovexy, "This account may not use the Kovexy admin UI.", HttpStatusCode.Forbidden)
        }
        if (kovexy.config.admin.loginMode == LoginMode.BOTH) {
            call.response.cookies.append(shortCookie(PENDING_COOKIE, signPending(claims, kovexy.clock() + PENDING_SECONDS * 1000L), PENDING_SECONDS, "Strict"))
            // A same-site refresh, the Strict cookie is not sent on the cross-site navigation from the provider
            return@get call.page("Password", null, frame = PageFrame.CENTER, refresh = "0; url=/login") {
                card { p { +t("Signed in as {0}. Now the password.", claims.name) } }
            }
        }
        call.startSession(kovexy, claims.sub, claims.name)
    }

    post("/login") {
        val ip = call.adminClientIp
        val mode = kovexy.config.admin.loginMode
        val pending = verifyPending(call.request.cookies[PENDING_COOKIE], kovexy.clock())
        if (mode == LoginMode.OIDC || (mode == LoginMode.BOTH && pending == null)) return@post call.respondRedirect("/login")
        // The OIDC step may be older than a change of allowedSubjects (audit run-2)
        val allowed = kovexy.config.admin.oidc?.allowedSubjects.orEmpty()
        if (pending != null && allowed.isNotEmpty() && pending.sub !in allowed) {
            call.response.cookies.append(shortCookie(PENDING_COOKIE, "", 0, "Strict"))
            return@post call.loginPage(kovexy, "This account may not use the Kovexy admin UI.", HttpStatusCode.Forbidden)
        }
        val password = call.receiveForm()["password"].orEmpty()
        val lockedText = { until: Long -> t("Too many failed attempts. Try again after {0}.", formatTimestamp(until)) }
        kovexy.loginThrottle.lockedUntil(ip)?.let { return@post call.loginPage(kovexy, lockedText(it), HttpStatusCode.TooManyRequests) }
        // Argon2 takes a moment and 64 MiB, so at most two checks run at once, a burst cannot fill the heap. The slot
        // comes before the attempt is counted: a busy server is no wrong password (audit run-2)
        // The flag, not the block's result: a timeout right after acquire() would otherwise lose the permit
        var acquired = false
        withTimeoutOrNull(PASSWORD_SLOT_WAIT) { passwordChecks.acquire(); acquired = true }
        if (acquired.not()) return@post call.loginPage(kovexy, "The server is busy, try again in a moment.", HttpStatusCode.ServiceUnavailable)
        val hash = kovexy.config.admin.passwordHash
        val valid = try {
            kovexy.loginThrottle.begin(ip)?.let { return@post call.loginPage(kovexy, lockedText(it), HttpStatusCode.TooManyRequests) }
            hash.isNotEmpty() && withContext(Dispatchers.Default) { verifyPassword(password, hash) }
        } finally {
            passwordChecks.release()
        }
        val actor = Actor(pending?.sub ?: "local", pending?.name ?: "admin", ip)
        if (valid.not()) {
            staticLog(KLogger.Level.WARN, TAG) { "Failed admin login from $ip" }
            call.failedLogin(kovexy, actor, "wrong password")
            return@post call.loginPage(kovexy, "Wrong password.", HttpStatusCode.Unauthorized)
        }
        kovexy.loginThrottle.success(ip)
        if (pending != null) call.response.cookies.append(shortCookie(PENDING_COOKIE, "", 0, "Strict"))
        call.startSession(kovexy, actor.sub, actor.name)
    }

    post("/logout") {
        val token = call.sessionToken
        kovexy.sessions.get(token)?.let { kovexy.audit.record(Actor(it.sub, it.name, call.adminClientIp), AuditAction.LOGOUT) }
        kovexy.sessions.remove(token)
        call.response.cookies.append(sessionCookie("", 0))
        call.respondRedirect("/login?done=logged-out")
    }
}

/** Creates the session after a complete login and goes to the status page. */
private suspend fun ApplicationCall.startSession(kovexy: Kovexy, sub: String, name: String) {
    val ip = adminClientIp
    val userAgent = cleanText(request.headers[HttpHeaders.UserAgent].orEmpty(), 200).orEmpty()
    val (token, _) = kovexy.sessions.create(userAgent, ip, sub, name)
    response.cookies.append(sessionCookie(token, kovexy.config.admin.session.maxAge.inWholeSeconds.toInt()))
    kovexy.audit.record(Actor(sub, name, ip), AuditAction.LOGIN)
    staticLog(KLogger.Level.INFO, TAG) { "Admin '$name' logged in from $ip" }
    // A redirect after the OIDC callback would still belong to the cross-site navigation from the provider, the
    // browser would not send the SameSite=Strict cookie with it. A same-site refresh does.
    page("Signed in", null, frame = PageFrame.CENTER, refresh = "0; url=/") {
        card {
            p { +t("Signed in as {0}.", name) }
            linkButton("/", "Continue", "primary block")
        }
    }
}

/** Records a failed login everywhere it belongs: audit log, security events, webhook (bundled). */
private fun ApplicationCall.failedLogin(kovexy: Kovexy, actor: Actor, reason: String) {
    kovexy.audit.record(actor, AuditAction.LOGIN_FAILED, detail = reason)
    kovexy.security.record(SecurityEventType.ADMIN_LOGIN_FAILED, actor.ip, detail = reason)
    kovexy.webhooks.emit(Event(WebhookEvent.ADMIN_LOGIN_FAILED, "Failed admin login from ${actor.ip}", "Admin login from ${actor.ip} failed: $reason", time = kovexy.clock(), item = actor.ip))
}

private suspend fun ApplicationCall.loginPage(kovexy: Kovexy, error: String?, status: HttpStatusCode = HttpStatusCode.OK) {
    val mode = kovexy.config.admin.loginMode
    val pending = verifyPending(request.cookies[PENDING_COOKIE], kovexy.clock())
    page("Log in", null, frame = PageFrame.CENTER, status = status) {
        card {
            h2 { +t("Log in") }
            p("muted") { +t("Admin interface of this Kovexy reverse proxy.") }
            if (kovexy.passwordOnly) notice("warn", PASSWORD_ONLY_WARNING)
            if (error != null) notice("error", error)
            val showPassword = mode == LoginMode.PASSWORD || (mode == LoginMode.BOTH && pending != null)
            if (showPassword) {
                if (pending != null) p { +t("Signed in as {0}. Step 2 of 2: the password.", pending.name) }
                form(action = "/login", method = FormMethod.post, classes = "form") {
                    passwordField("Password", "password", "current-password")
                    submit("Log in", "primary block")
                }
            } else {
                if (mode == LoginMode.BOTH) p("muted small") { +t("Step 1 of 2: the identity provider, then the password.") }
                linkButton("/auth/start", "Continue with the identity provider", "primary block")
            }
        }
    }
}

/** User-facing text for a failed OIDC login. Details stay in the log. */
private fun loginErrorText(error: LoginError): String = when (error) {
    is LoginError.Denied -> t("The identity provider denied the login: {0}", error.description)
    LoginError.UnknownAttempt -> "The login took too long or was started in another browser. Please start again."
    LoginError.StateMismatch -> "The login response did not belong to this browser. Please start again."
    is LoginError.ProviderUnavailable -> "The identity provider is not reachable."
    is LoginError.InvalidToken -> "The identity provider's answer could not be verified."
    LoginError.Busy -> "Another login from this address is running. Please start again in a moment."
}
