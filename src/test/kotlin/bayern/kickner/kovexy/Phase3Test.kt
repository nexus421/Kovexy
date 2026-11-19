package bayern.kickner.kovexy

import bayern.kickner.kovexy.access.CaptchaService
import bayern.kickner.kovexy.access.GoogleVerifier
import bayern.kickner.kovexy.access.ProofOfWork
import bayern.kickner.kovexy.access.Signer
import bayern.kickner.kovexy.access.leadingZeroBits
import bayern.kickner.kovexy.access.safeReturnPath
import bayern.kickner.kovexy.audit.configDiff
import bayern.kickner.kovexy.config.AppAuthConfig
import bayern.kickner.kovexy.config.CaptchaConfig
import bayern.kickner.kovexy.config.CaptchaProvider
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.RecaptchaVersion
import bayern.kickner.kovexy.config.rootCheck
import bayern.kickner.kovexy.config.validateConfig
import bayern.kickner.kovexy.dev.MockOidcProvider
import bayern.kickner.kovexy.dev.MockUser
import bayern.kickner.kovexy.incus.IncusDecision
import bayern.kickner.kovexy.incus.incusTarget
import bayern.kickner.kovexy.incus.IncusState
import bayern.kickner.kovexy.incus.buildClaims
import bayern.kickner.kovexy.incus.isInstanceEvent
import bayern.kickner.kovexy.incus.parseInstances
import bayern.kickner.kovexy.incus.withIncusRoutes
import bayern.kickner.kovexy.proxy.refererWithoutQuery
import bayern.kickner.kovexy.stats.AccessLog
import bayern.kickner.kovexy.stats.AccessRecord
import bayern.kickner.kovexy.stats.Storage
import bayern.kickner.kovexy.stats.TOP_LIST_SIZE
import bayern.kickner.kovexy.stats.TopKind
import bayern.kickner.kovexy.stats.histogramQuantile
import bayern.kickner.kovexy.stats.latencyBucket
import bayern.kickner.kovexy.stats.latencyHistograms
import bayern.kickner.kovexy.stats.topLists
import com.sun.net.httpserver.HttpServer
import io.ktor.server.cio.CIO
import io.ktor.server.cio.unixConnector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.application.install
import io.ktor.websocket.close
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.DefaultWebSocketServerSession
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.http.ContentType
import io.ktor.websocket.Frame
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetSocketAddress
import java.net.URLEncoder
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Solves a proof of work task like the browser script does. */
fun solvePow(task: String, difficulty: Int): String {
    val digest = MessageDigest.getInstance("SHA-256")
    var nonce = 0L
    while (leadingZeroBits(digest.digest("$task:$nonce".toByteArray())) < difficulty) nonce++
    return nonce.toString()
}

private fun form(vararg pairs: Pair<String, String>) = pairs.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, Charsets.UTF_8)}" }.toByteArray()

private val formHeader = "Content-Type" to "application/x-www-form-urlencoded"

/** Captcha building blocks without a server. */
class CaptchaUnitTest {
    @Test
    fun proofOfWorkIsCheckedOnceAndOnlyWithEnoughWork() {
        var now = 1_000_000L
        val pow = ProofOfWork(Signer()) { now }
        val task = pow.task(10)
        val nonce = solvePow(task, 10)
        assertFalse(pow.verify(task, nonce, 12), "A task easier than the profile asks for does not count")
        val failing = generateSequence(0L) { it + 1 }.first { leadingZeroBits(MessageDigest.getInstance("SHA-256").digest("$task:$it".toByteArray())) < 10 }
        assertFalse(pow.verify(task, failing.toString(), 10), "Not enough zero bits")
        assertTrue(pow.verify(task, nonce, 10))
        assertFalse(pow.verify(task, nonce, 10), "Every task counts once")
        assertFalse(pow.verify(task.dropLast(2) + "xx", nonce, 10), "A changed signature is refused")
        val old = pow.task(8)
        val oldNonce = solvePow(old, 8)
        now += 6 * 60_000
        assertFalse(pow.verify(old, oldNonce, 8), "Expired after five minutes")
        assertFalse(pow.verify(pow.task(8), "12a", 8), "Only digits")
    }

    @Test
    fun captchaPagesRender() {
        listOf("pow", "recaptcha2", "recaptcha3").forEach { provider ->
            val html = bayern.kickner.kovexy.site.captchaPage("tok", provider, "task", 10, "site-key")
            assertTrue(html.contains("kovexy-captcha") && html.contains("/.kovexy/captcha.js"), provider)
        }
        assertTrue(bayern.kickner.kovexy.proxy.captchaPolicy(true).contains("https://www.gstatic.com/recaptcha/"))
    }

    @Test
    fun pageTokensAndReturnPaths() {
        var now = 0L
        val service = CaptchaService(clock = { now })
        val token = service.pageToken("p", "a.test", "/x?y=1")
        assertEquals(Triple("p", "a.test", "/x?y=1"), service.readPageToken(token))
        assertNull(service.readPageToken(token.substringBeforeLast('.') + "x." + token.substringAfterLast('.')), "A changed payload is refused")
        now += 11 * 60_000
        assertNull(service.readPageToken(token), "Expired")
        assertEquals("/", safeReturnPath("//evil.test/"))
        assertEquals("/", safeReturnPath("https://evil.test/"))
        assertEquals("/", safeReturnPath("/\\evil"))
        assertEquals("/ok?a=1", safeReturnPath("/ok?a=1"))
        val id = service.sessions.create("p|a.test", 1000)
        assertTrue(service.sessions.isValid(id, "p|a.test"))
        assertFalse(service.sessions.isValid(id, "p|b.test"), "A session counts for one domain only")
        now += 2000
        assertFalse(service.sessions.isValid(id, "p|a.test"))
    }

    @Test
    fun googleAnswersAreCheckedOnTheServer(): Unit = runBlocking {
        val received = CopyOnWriteArrayList<String>()
        var answer = """{"success": true, "score": 0.9}"""
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/siteverify") { ex ->
            received += ex.requestBody.readBytes().decodeToString()
            val bytes = answer.toByteArray()
            ex.sendResponseHeaders(200, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }
        server.start()
        try {
            val verifier = GoogleVerifier("http://127.0.0.1:${server.address.port}/siteverify")
            val v2 = CaptchaConfig(CaptchaProvider.GOOGLE, "site", "the secret")
            val v3 = v2.copy(recaptchaVersion = RecaptchaVersion.V3, recaptchaScore = 0.5)
            assertTrue(verifier.verify(v2, "token-1", "203.0.113.7"))
            assertTrue(received.last().contains("secret=the+secret") && received.last().contains("response=token-1") && received.last().contains("remoteip=203.0.113.7"), received.last())
            assertTrue(verifier.verify(v3, "token-2", "203.0.113.7"))
            answer = """{"success": true, "score": 0.3}"""
            assertFalse(verifier.verify(v3, "token-3", "203.0.113.7"), "v3 below the threshold")
            assertTrue(verifier.verify(v2, "token-4", "203.0.113.7"), "v2 has no score")
            answer = """{"success": false}"""
            assertFalse(verifier.verify(v2, "token-5", "203.0.113.7"))
            assertFalse(verifier.verify(v2, "", "203.0.113.7"), "An empty answer never reaches Google")
            answer = "garbage"
            assertFalse(verifier.verify(v2, "token-6", "203.0.113.7"))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun validationOfPhase3Fields() {
        val base = KovexyConfig()
        val captcha = base.copy(accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig(CaptchaProvider.GOOGLE))))
        assertTrue(validateConfig(captcha).any { it.contains("siteKey") || it.contains("site key") }, validateConfig(captcha).toString())
        val pow = base.copy(accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig(CaptchaProvider.POW, powDifficulty = 40))))
        assertTrue(validateConfig(pow).isNotEmpty())
        val site = { redirect: Boolean -> bayern.kickner.kovexy.config.SiteConfig(listOf("a.test"), httpsRedirect = redirect, access = "c") }
        val captchaOnHttp = captcha.copy(accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig(CaptchaProvider.POW))), sites = listOf(site(false)))
        assertTrue(validateConfig(captchaOnHttp).any { it.contains("only be reachable over HTTPS") }, validateConfig(captchaOnHttp).toString())
        assertTrue(validateConfig(captchaOnHttp.copy(sites = listOf(site(true)))).none { it.contains("HTTPS") }, "With the redirect the site is HTTPS only")
        val oidcWithoutApp = base.copy(accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("o", oidc = bayern.kickner.kovexy.config.AppOidcConfig())))
        assertTrue(validateConfig(oidcWithoutApp).any { it.contains("appAuth") }, validateConfig(oidcWithoutApp).toString())
        val before = rootCheck
        try {
            rootCheck = { false }
            assertTrue(validateConfig(base.copy(incus = bayern.kickner.kovexy.config.IncusConfig(enabled = true))).any { it.contains("root") })
            rootCheck = { true }
            assertTrue(validateConfig(base.copy(incus = bayern.kickner.kovexy.config.IncusConfig(enabled = true))).isEmpty())
        } finally {
            rootCheck = before
        }
        val upstream = base.copy(upstreams = listOf(bayern.kickner.kovexy.config.UpstreamConfig("incus:x", listOf(bayern.kickner.kovexy.config.UpstreamServerConfig("127.0.0.1:1")))))
        assertTrue(validateConfig(upstream).any { it.contains("incus:") })
    }

    @Test
    fun secretsOfPhase3StayOutOfTheAuditLog() {
        val old = KovexyConfig(
            appAuth = AppAuthConfig("http://localhost:1", "id", "old-app-secret"),
            accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig(CaptchaProvider.GOOGLE, "site", "old-google-secret"))),
        )
        val new = old.copy(
            appAuth = old.appAuth!!.copy(clientSecret = "new-app-secret"),
            accessProfiles = listOf(old.accessProfiles.first().copy(captcha = old.accessProfiles.first().captcha!!.copy(secretKey = "new-google-secret"))),
        )
        val diff = configDiff(old, new)
        listOf("old-app-secret", "new-app-secret", "old-google-secret", "new-google-secret").forEach { assertFalse(diff.contains(it), "No secret in the diff: $diff") }
        assertTrue(diff.contains("appAuth.clientSecret") && diff.contains("reCAPTCHA secret key in profile c"), diff)
    }
}

/** App sessions: memory first, SQLite for restarts. */
class AppSessionTest {
    @Test
    fun sessionsSurviveARestartAndUnknownTokensNeverHitTheDatabase(): Unit = runBlocking {
        val dir = Files.createTempDirectory("kovexy-app").toFile()
        val storage = Storage(File(dir, "kovexy.db"))
        var now = 1_000_000L
        val first = bayern.kickner.kovexy.access.AppAuthService(storage, { now })
        val token = first.createSession("a.test", bayern.kickner.kovexy.auth.IdTokenClaims("ada", "Ada", "ada@x.test", "ada"))
        assertEquals("ada", first.user(token, "a.test")?.forwardedUser)
        assertNull(first.user(token, "b.test"), "Per domain")
        assertNull(first.user("random", "a.test"))
        val second = bayern.kickner.kovexy.access.AppAuthService(storage, { now })
        assertEquals("ada@x.test", second.user(token, "a.test")?.email, "A restart keeps the session")
        now += bayern.kickner.kovexy.access.APP_SESSION_IDLE_MILLIS + 1
        assertNull(second.user(token, "a.test"), "Idle too long")
        val other = second.createSession("a.test", bayern.kickner.kovexy.auth.IdTokenClaims("bob", "Bob"))
        second.remove(other)
        assertNull(second.user(other, "a.test"), "Logged out at once")
        dir.deleteRecursively()
    }
}

/** Captcha and app login through the proxy. */
class AccessPhase3Test {
    private fun captchaConfig(backend: Int) = """
        { "admin": { "port": ADMIN_PORT },
          "accessProfiles": [
            { "name": "pow", "captcha": { "provider": "pow", "powDifficulty": 10, "exceptions": [ { "pathPrefix": "/public" } ] } },
            { "name": "ai", "exploitFilter": { "aiBots": true }, "captcha": { "provider": "pow", "powDifficulty": 8 } },
            { "name": "limited", "rateLimit": { "requestsPerSecond": 2 }, "captcha": { "provider": "pow", "powDifficulty": 8 } }
          ],
          "upstreams": [ { "name": "app", "servers": [ { "address": "127.0.0.1:$backend" } ] } ],
          "sites": [
            { "domains": ["a.test"], "access": "pow", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] },
            { "domains": ["b.test"], "access": "ai", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] },
            { "domains": ["c.test"], "listeners": ["https"], "access": "limited", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] }
          ] }
    """.trimIndent()

    /** The captcha only runs over HTTPS (decided on 18.11.2026). */
    private fun tlsRequest(h: Harness, host: String, path: String, method: String = "GET", headers: List<Pair<String, String>> = emptyList(), body: ByteArray? = null) =
        rawRequest(h.ports.https, host, path, tls = true, method = method, headers = headers, body = body)

    private fun attr(html: String, name: String) = Regex("""$name="([^"]*)"""").find(html)?.groupValues?.get(1)
    private fun hidden(html: String, name: String) = Regex("""name="$name" value="([^"]*)"""").find(html)?.groupValues?.get(1)
        ?: Regex("""value="([^"]*)" name="$name"""").find(html)?.groupValues?.get(1)

    @Test
    fun proofOfWorkCaptchaEndToEnd(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(captchaConfig(backend.port)).use { h ->
                val first = tlsRequest(h, "a.test", "/page?x=1")
                assertEquals(403, first.status)
                assertTrue(first.text.contains("/.kovexy/captcha.js"), first.text)
                val csp = first.header("Content-Security-Policy").orEmpty()
                assertTrue(csp.contains("script-src 'self';") && csp.contains("google").not(), csp)
                assertEquals(200, tlsRequest(h, "a.test", "/public/file").status, "Exceptions need no captcha")
                val script = tlsRequest(h, "a.test", "/.kovexy/captcha.js")
                assertEquals(200, script.status)
                assertTrue(script.text.contains("sha256Head"))

                val task = attr(first.text, "data-task")!!
                val token = hidden(first.text, "token")!!
                val wrong = tlsRequest(h, "a.test", "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader),
                    body = form("token" to token, "task" to task, "nonce" to "1"))
                assertEquals(403, wrong.status, "A wrong answer shows the page again")
                val solved = tlsRequest(h, "a.test", "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader),
                    body = form("token" to token, "task" to task, "nonce" to solvePow(task, 10)))
                assertEquals(302, solved.status, solved.text)
                assertEquals("/page?x=1", solved.header("Location"))
                val cookie = solved.headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-captcha=") }
                assertTrue(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Secure"), cookie)
                val pass = tlsRequest(h, "a.test", "/page?x=1", headers = listOf("Cookie" to cookie.substringBefore(';')))
                assertEquals(200, pass.status)
                assertTrue(pass.text.contains("uri=/page?x=1"))
                assertFalse(pass.text.contains("kovexy-captcha="), "The captcha cookie does not reach the upstream")
                assertEquals(403, tlsRequest(h, "b.test", "/", headers = listOf("Cookie" to cookie.substringBefore(';'), "User-Agent" to "GPTBot/1.1")).status,
                    "A session counts for its profile and domain only")
                val replay = tlsRequest(h, "a.test", "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader),
                    body = form("token" to token, "task" to task, "nonce" to solvePow(task, 10)))
                assertEquals(403, replay.status, "A solved task cannot be used twice")
                val huge = tlsRequest(h, "a.test", "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader),
                    body = form("token" to token, "task" to task, "nonce" to "1", "pad" to "x".repeat(40_000)))
                assertEquals(400, huge.status, "A form above the limit is not read into memory and counts as empty")
                val upstreamLog = tlsRequest(h, "a.test", "/.kovexy/anything")
                assertEquals(404, upstreamLog.status, "Reserved paths never reach the upstream")
                assertEquals(404, tlsRequest(h, "a.test", "/%2Ekovexy/anything", headers = listOf("Cookie" to cookie.substringBefore(';'))).status,
                    "Also not with an encoded dot")
            }
        }
    }

    @Test
    fun aCrawlerWithASolvedCaptchaIsStillRefused(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(captchaConfig(backend.port)).use { h ->
                val page = tlsRequest(h, "b.test", "/")
                assertEquals(403, page.status)
                val task = attr(page.text, "data-task")!!
                val solved = tlsRequest(h, "b.test", "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader),
                    body = form("token" to hidden(page.text, "token")!!, "task" to task, "nonce" to solvePow(task, 8)))
                val cookie = solved.headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-captcha=") }.substringBefore(';')
                assertEquals(200, tlsRequest(h, "b.test", "/", headers = listOf("Cookie" to cookie)).status)
                val bot = tlsRequest(h, "b.test", "/", headers = listOf("Cookie" to cookie, "User-Agent" to "GPTBot/1.1"))
                assertEquals(403, bot.status, "The exploit filter has no captcha answer, a solved captcha does not help a crawler")
                assertFalse(bot.text.contains("data-task"))
                assertEquals(308, rawRequest(h.ports.http, "a.test", "/.kovexy/captcha.js").status, "Plain HTTP is redirected before the reserved paths")
            }
        }
    }

    @Test
    fun theRateLimitAlsoCoversKovexyPaths(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(captchaConfig(backend.port)).use { h ->
                val statuses = (1..6).map { tlsRequest(h, "c.test", "/.kovexy/captcha.js").status }
                assertTrue(429 in statuses, statuses.toString())
            }
        }
    }

    @Test
    fun appLoginInFrontOfASite(): Unit = runBlocking {
        MockOidcProvider(autoLogin = MockUser("ada-sub", "Ada")).use { oidc ->
            TestBackend().use { backend ->
                val config = """
                    { "admin": { "port": ADMIN_PORT },
                      "appAuth": { "issuer": "${oidc.issuer}", "clientId": "apps", "clientSecret": "${oidc.clientSecret}" },
                      "accessProfiles": [ { "name": "login", "oidc": { "allowedSubjects": ["ada-sub"] } }, { "name": "nobody", "oidc": { "allowedSubjects": ["bob"] } } ],
                      "upstreams": [ { "name": "app", "servers": [ { "address": "127.0.0.1:${backend.port}" } ] } ],
                      "sites": [
                        { "domains": ["app.test"], "access": "login", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] },
                        { "domains": ["closed.test"], "access": "nobody", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] }
                      ] }
                """.trimIndent()
                Harness(config).use { h ->
                    val https = h.ports.https
                    val forged = listOf("X-Forwarded-User" to "mallory", "X-Forwarded-Email" to "m@evil.test")
                    val first = rawRequest(https, "app.test", "/inside?q=1", tls = true, headers = forged)
                    assertEquals(302, first.status, first.text)
                    assertEquals("/.kovexy/auth/start?rd=%2Finside%3Fq%3D1", first.header("Location"))
                    assertEquals(401, rawRequest(https, "app.test", "/api", tls = true, method = "POST", body = ByteArray(1)).status, "Only GET is redirected to the login")

                    val session = appLogin(https, "app.test", "/inside?q=1")
                    val inside = rawRequest(https, "app.test", "/inside?q=1", tls = true, headers = forged + ("Cookie" to session))
                    assertEquals(200, inside.status, inside.text)
                    assertTrue(inside.text.contains("x-forwarded-user=ada-sub"), inside.text)
                    assertFalse(inside.text.contains("mallory") || inside.text.contains("m@evil.test"), "Headers sent by the visitor are dropped")
                    assertFalse(inside.text.contains("__Host-kovexy-auth"), "The login cookie does not reach the upstream")

                    // Not an allowed user: the callback refuses and creates no session at all (audit run-2)
                    appLogin(https, "closed.test", "/", expectStatus = 403)
                    assertEquals(302, rawRequest(https, "closed.test", "/", tls = true, headers = listOf("Cookie" to session)).status, "A session counts for its domain only")

                    val logout = rawRequest(https, "app.test", "/.kovexy/auth/logout", tls = true, headers = listOf("Cookie" to session))
                    assertTrue(logout.status in listOf(200, 302), logout.text)
                    assertEquals(302, rawRequest(https, "app.test", "/inside", tls = true, headers = listOf("Cookie" to session)).status, "Logged out")

                    assertEquals(400, rawRequest(h.ports.http, "app.test", "/.kovexy/auth/start").status.let { if (it == 308 || it == 301) 400 else it },
                        "The login needs HTTPS")
                }
            }
        }
    }

    /** Runs the app login and returns the session cookie, empty when the callback did not log in. */
    private fun appLogin(port: Int, host: String, returnTo: String, expectStatus: Int = 302): String {
        val start = rawRequest(port, host, "/.kovexy/auth/start?rd=" + URLEncoder.encode(returnTo, Charsets.UTF_8), tls = true)
        assertEquals(302, start.status, start.text)
        val cookies = start.headerAll("Set-Cookie").map { it.substringBefore(';') }.joinToString("; ")
        val authorize = java.net.URI(start.header("Location")!!)
        val provider = rawRequest(authorize.port, "localhost:${authorize.port}", authorize.rawPath + "?" + authorize.rawQuery)
        assertEquals(302, provider.status)
        val callback = java.net.URI(provider.header("Location")!!)
        assertEquals(host, callback.host, "The callback goes to the protected domain")
        val back = rawRequest(port, host, callback.rawPath + "?" + callback.rawQuery, tls = true, headers = listOf("Cookie" to cookies))
        assertEquals(expectStatus, back.status, back.text)
        if (expectStatus != 302) return ""
        assertEquals(returnTo, back.header("Location"))
        return back.headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-auth=") && it.contains("Max-Age=0").not() }.substringBefore(';')
    }
}

/** Extended statistics. */
class StatisticsPhase3Test {
    @Test
    fun topListsKeepTheHeavyHittersAndPercentilesWork(): Unit = runBlocking {
        val dir = Files.createTempDirectory("kovexy-stats").toFile()
        val storage = Storage(File(dir, "kovexy.db"))
        val log = AccessLog(storage)
        val now = System.currentTimeMillis()
        fun record(ip: String, duration: Long, status: Int = 200, reason: String = "") = log.record(
            AccessRecord(time = now, clientIp = ip, method = "GET", domain = "a.test", path = "/p", status = status, bytesIn = 0, bytesOut = 0,
                durationMs = duration, site = "a.test", location = "/", upstream = "127.0.0.1:1", userAgent = "UA", reason = reason,
                referer = "https://ref.test/page", country = "DE")
        )
        repeat(TOP_LIST_SIZE + 50) { record("10.0.${it / 250}.${it % 250}", 5) }
        log.flush()
        repeat(500) { record("203.0.113.9", if (it < 450) 10 else 900, if (it % 100 == 0) 403 else 200, if (it % 100 == 0) "blocked list" else "") }
        log.flush()
        val tops = storage.topLists(log.dayStart(now), "a.test")
        assertEquals("203.0.113.9", tops.getValue(TopKind.IP).first().first, "A late heavy hitter still tops the full list")
        assertTrue(tops.getValue(TopKind.IP).first().second >= 500, "Space saving never counts too little")
        assertEquals("DE", tops.getValue(TopKind.COUNTRY).first().first)
        assertEquals("https://ref.test/page", tops.getValue(TopKind.REFERER).first().first)
        assertEquals(5L, tops.getValue(TopKind.BLOCK_REASON).first().second)
        val stored = storage.tx { exec("SELECT COUNT(*) FROM stats_top WHERE kind = 'IP'") { rs -> rs.next(); rs.getInt(1) } }
        assertEquals(TOP_LIST_SIZE, stored, "At most $TOP_LIST_SIZE entries per list and day")

        val histogram = storage.latencyHistograms(0, "a.test").values.single()
        assertEquals(10L, histogramQuantile(histogram, 0.5), "Median in the 10 ms bucket")
        assertEquals(1000L, histogramQuantile(histogram, 0.99), "99th percentile in the 1 s bucket")
        assertEquals(0, latencyBucket(0))
        val slow = LongArray(bayern.kickner.kovexy.stats.LATENCY_BOUNDS.size + 1).also { it[it.size - 1] = 3 }
        assertEquals("> 60 s", bayern.kickner.kovexy.stats.formatLatencyBound(histogramQuantile(slow, 0.5)))
        assertEquals("≤ 150 ms", bayern.kickner.kovexy.stats.formatLatencyBound(150))
        assertEquals("≤ 1.5 s", bayern.kickner.kovexy.stats.formatLatencyBound(1500))
        assertEquals("≤ 2 s", bayern.kickner.kovexy.stats.formatLatencyBound(2000))
        assertNull(histogramQuantile(LongArray(5), 0.5))

        log.applyRetention(kotlin.time.Duration.ZERO, kotlin.time.Duration.ZERO, now + 2 * 86_400_000L)
        assertTrue(storage.topLists(0, null)[TopKind.IP].isNullOrEmpty(), "Top IPs go with the access log")
        assertFalse(storage.topLists(0, null)[TopKind.PATH].isNullOrEmpty(), "Other lists stay")
        dir.deleteRecursively()
    }

    @Test
    fun ipv6VisitorsHaveNoBrackets(): Unit = runBlocking {
        assertEquals("::1", bayern.kickner.kovexy.config.plainAddress("[::1]"))
        assertEquals("127.0.0.1", bayern.kickner.kovexy.config.plainAddress("127.0.0.1"))
        TestBackend().use { backend ->
            val config = """{ "admin": { "port": ADMIN_PORT }, "upstreams": [ { "name": "app", "servers": [ { "address": "127.0.0.1:${backend.port}" } ] } ],
                "sites": [ { "domains": ["a.test"], "httpsRedirect": false, "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] } ] }"""
            Harness(config).use { h ->
                val socket = runCatching { java.net.Socket("::1", h.ports.http) }.getOrNull() ?: return@use
                socket.use { s ->
                    s.soTimeout = 10_000
                    s.getOutputStream().write("GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n".toByteArray())
                    val text = s.getInputStream().readBytes().decodeToString()
                    assertTrue(text.contains("x-forwarded-for=0:0:0:0:0:0:0:1") || text.contains("x-forwarded-for=::1"), text)
                }
            }
        }
    }

    @Test
    fun refererLosesItsQuery() {
        assertEquals("https://a.test/x", refererWithoutQuery("https://a.test/x?token=secret#frag"))
        assertEquals("", refererWithoutQuery(null))
    }
}

/** A fake Incus API on a unix socket (Ktor CIO), with instances and the events WebSocket. */
class FakeIncus(val socket: String) : AutoCloseable {
    @Volatile
    var instances: String = instancesJson()
    val sessions = CopyOnWriteArrayList<DefaultWebSocketServerSession>()
    val requests = CopyOnWriteArrayList<String>()

    private val server = embeddedServer(CIO, configure = { unixConnector(socket) }) {
        install(WebSockets)
        routing {
            get("/1.0/instances") {
                requests += call.request.local.uri
                // Like Incus: only the instances of the project asked for
                val project = call.request.queryParameters["project"] ?: "default"
                val all = Json.parseToJsonElement(instances).jsonObject
                val list = all["metadata"]!!.jsonArray.filter { (it.jsonObject["project"]?.jsonPrimitive?.content ?: "default") == project }
                call.respondText(JsonObject(all + ("metadata" to JsonArray(list))).toString(), ContentType.Application.Json)
            }
            webSocket("/1.0/events") {
                requests += call.request.local.uri
                sessions += this
                try {
                    // Keep the session open until the client goes away
                    while (incoming.receiveCatching().isSuccess) continue
                } finally {
                    sessions -= this
                }
            }
        }
    }.start(wait = false)

    /** Sends a lifecycle event about an instance to every listener. */
    suspend fun event(action: String = "instance-updated", instance: String = "web1") {
        sessions.forEach { it.send(Frame.Text("""{"type":"lifecycle","metadata":{"action":"$action","source":"/1.0/instances/$instance"}}""")) }
    }

    override fun close() {
        server.stop(100, 1000)
        File(socket).delete()
    }

    companion object {
        fun instance(name: String, project: String = "default", running: Boolean = true, keys: Map<String, String> = emptyMap(), address: String? = "127.0.0.1"): String {
            val config = keys.entries.joinToString(",") { (k, v) -> "\"user.kovexy.$k\":\"$v\"" }
            val addresses = address?.let { """{"family":"inet","address":"$it","netmask":"24","scope":"global"},{"family":"inet6","address":"fe80::1","netmask":"64","scope":"link"}""" }.orEmpty()
            return """{"name":"$name","project":"$project","status":"${if (running) "Running" else "Stopped"}","config":{$config,"image.os":"Debian"},
                "expanded_config":{"user.kovexy.domains":"from-profile.test"},
                "state":{"network":{"lo":{"addresses":[{"family":"inet","address":"127.0.0.1","scope":"local"}]},"eth0":{"addresses":[$addresses]}}}}"""
                .replace("{,", "{")
        }

        fun instancesJson(vararg instances: String) = """{"type":"sync","status":"Success","status_code":200,"metadata":[${instances.joinToString(",")}]}"""
    }
}

/** Incus discovery. */
class IncusTest {
    init {
        // The fake containers live on loopback, which real targets may not use
        bayern.kickner.kovexy.incus.incusAddressAllowed = { true }
    }

    @Test
    fun parsingAndClaims() {
        val body = FakeIncus.instancesJson(
            FakeIncus.instance("web1", keys = mapOf("domains" to "App.test, www.app.test", "port" to "8080")),
            FakeIncus.instance("db", keys = emptyMap()),
            FakeIncus.instance("other", project = "restricted", keys = mapOf("domains" to "evil.test", "port" to "80")),
            FakeIncus.instance("stopped", running = false, keys = mapOf("domains" to "s.test", "port" to "80")),
            FakeIncus.instance("bad", keys = mapOf("domains" to "manual.test,-x", "port" to "99999", "access" to "missing")),
            FakeIncus.instance("noip", keys = mapOf("domains" to "noip.test", "port" to "80"), address = null),
        )
        val instances = parseInstances(body, "eth0")
        assertEquals(6, instances.size)
        assertEquals("127.0.0.1", instances.first().address)
        assertTrue(instances.first { it.name == "db" }.keys.isEmpty(), "Keys of a profile (expanded_config) do not count")
        val config = KovexyConfig(sites = listOf(bayern.kickner.kovexy.config.SiteConfig(listOf("manual.test"))))
        var claims = buildClaims(instances, emptyList(), config)
        assertEquals(listOf("default/bad", "default/noip", "default/stopped", "default/web1"), claims.map { it.id }, "Other projects and instances without keys are left out")
        val web1 = claims.first { it.id == "default/web1" }
        assertEquals(listOf("app.test", "www.app.test"), web1.domains)
        assertEquals(IncusState.DETECTED, web1.state)
        assertFalse(web1.live, "Nothing goes live without approval")
        val bad = claims.first { it.id == "default/bad" }
        assertEquals(4, bad.problems.size, bad.problems.toString())

        val decisions = listOf(
            IncusDecision("default", "web1", listOf("www.app.test", "app.test"), true, 0, incusTarget("127.0.0.1", 8080, false, null)),
            IncusDecision("default", "stopped", listOf("s.test"), true, 0, incusTarget("127.0.0.1", 80, false, null)),
            IncusDecision("default", "noip", listOf("noip.test"), true, 0, incusTarget(null, 80, false, null)),
        )
        claims = buildClaims(instances, decisions, config)
        assertTrue(claims.first { it.id == "default/web1" }.live)
        assertFalse(claims.first { it.id == "default/stopped" }.live, "Stopped instances have no route")
        assertFalse(claims.first { it.id == "default/noip" }.live, "No address, no route")
        val effective = withIncusRoutes(config, claims)
        assertEquals(2, effective.sites.size)
        assertEquals("127.0.0.1:8080", effective.upstreams.single().servers.single().address)

        val changed = buildClaims(instances, listOf(IncusDecision("default", "web1", listOf("app.test"), true, 0)), config)
        assertEquals(IncusState.DETECTED, changed.first { it.id == "default/web1" }.state, "New domains need a new approval")
        val moved = buildClaims(instances, listOf(IncusDecision("default", "web1", listOf("app.test", "www.app.test"), true, 0, incusTarget("127.0.0.1", 9999, false, null))), config)
        assertEquals(IncusState.DETECTED, moved.first { it.id == "default/web1" }.state, "Another port, address, HTTPS or profile needs a new approval")
        val rejected = buildClaims(instances, listOf(IncusDecision("default", "web1", listOf("x.test"), false, 0)), config)
        assertEquals(IncusState.REJECTED, rejected.first { it.id == "default/web1" }.state, "A rejection counts whatever the domains are")

        assertTrue(isInstanceEvent("""{"type":"lifecycle","metadata":{"action":"instance-started","source":"/1.0/instances/web1"}}"""))
        assertFalse(isInstanceEvent("""{"type":"lifecycle","metadata":{"action":"network-updated","source":"/1.0/networks/incusbr0"}}"""))
    }

    @Test
    fun discoveryApprovalAndLiveRoutes(): Unit = runBlocking {
        val before = rootCheck
        rootCheck = { true }
        val socket = Files.createTempDirectory("kovexy-incus").resolve("incus.socket").toString()
        try {
            TestBackend().use { backend ->
                FakeIncus(socket).use { incus ->
                    incus.instances = FakeIncus.instancesJson(
                        FakeIncus.instance("web1", keys = mapOf("domains" to "c.test", "port" to backend.port.toString())),
                        FakeIncus.instance("plain"),
                    )
                    val config = """{ "admin": { "port": ADMIN_PORT }, "incus": { "enabled": true, "socket": "$socket" }, "defaultSite": { "type": "notFound" } }"""
                    Harness(config).use { h ->
                        waitFor("connected") { h.kovexy.incus.connected && h.kovexy.incus.claims.isNotEmpty() }
                        assertTrue(incus.requests.first().startsWith("/1.0/events?type=lifecycle&all-projects=true"), "Events are subscribed before the list is fetched: ${incus.requests}")
                        assertTrue(incus.requests.any { it.startsWith("/1.0/instances?recursion=2&project=default") }, incus.requests.toString())
                        assertEquals(404, status(h, "c.test", "/"), "Detected is not live")
                        assertEquals(listOf("plain"), h.kovexy.incus.withoutKeys().map { it.name })

                        assertTrue(h.kovexy.incus.approve("default/web1"))
                        waitFor("route") { status(h, "c.test", "/x") == 200 }
                        waitFor("certificate wanted") { "c.test" in h.kovexy.routing.tlsDomains() }

                        incus.instances = FakeIncus.instancesJson(FakeIncus.instance("web1", running = false, keys = mapOf("domains" to "c.test", "port" to backend.port.toString())))
                        incus.event("instance-stopped")
                        waitFor("route gone after stop") { status(h, "c.test", "/x") == 404 }

                        incus.instances = FakeIncus.instancesJson(FakeIncus.instance("web1", keys = mapOf("domains" to "c.test", "port" to backend.port.toString())))
                        incus.event("instance-started")
                        waitFor("route back after start") { status(h, "c.test", "/x") == 200 }

                        incus.instances = FakeIncus.instancesJson(FakeIncus.instance("web1", keys = mapOf("domains" to "c.test,d.test", "port" to backend.port.toString())))
                        incus.event()
                        waitFor("new domain needs approval") { status(h, "c.test", "/x") == 404 }
                        assertTrue(h.kovexy.incus.approve("default/web1"))
                        waitFor("approved again") { status(h, "d.test", "/x") == 200 }

                        h.kovexy.incus.remove("default/web1")
                        waitFor("removed") { status(h, "c.test", "/x") == 404 }

                        // A decision survives a restart of discovery, it lives in SQLite
                        h.kovexy.incus.approve("default/web1")
                        waitFor("approved") { status(h, "c.test", "/x") == 200 }
                        val fetchesBefore = incus.requests.count { it.startsWith("/1.0/instances") }
                        incus.sessions.forEach { it.close() }
                        waitFor("disconnect noticed") { h.kovexy.incus.connected.not() }
                        assertEquals(200, status(h, "c.test", "/x"), "Routes stay while Incus is away")
                        waitFor("reconnected", 30) { h.kovexy.incus.connected }
                        waitFor("full list fetched again after the reconnect") { incus.requests.count { it.startsWith("/1.0/instances") } > fetchesBefore }
                        assertEquals(200, status(h, "c.test", "/x"))
                    }
                }
            }
        } finally {
            rootCheck = before
        }
    }

    /** Status over HTTPS, approved containers get the HTTPS redirect like every new site. */
    private fun status(h: Harness, host: String, path: String) = rawRequest(h.ports.https, host, path, tls = true).status

    private suspend fun waitFor(what: String, seconds: Int = 10, check: () -> Boolean) {
        repeat(seconds * 20) {
            if (runCatching(check).getOrDefault(false)) return
            delay(50)
        }
        error("Timed out waiting for: $what")
    }
}
