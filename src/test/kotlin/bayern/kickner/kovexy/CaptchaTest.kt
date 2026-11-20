package bayern.kickner.kovexy

import bayern.kickner.kovexy.config.parseConfig
import bayern.kickner.kovexy.stats.Storage
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetSocketAddress
import java.net.URLEncoder
import java.nio.file.Files
import java.sql.DriverManager
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private fun form(vararg pairs: Pair<String, String>) = pairs.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, Charsets.UTF_8)}" }.toByteArray()

private val formHeader = "Content-Type" to "application/x-www-form-urlencoded"

/** A stand-in for Google's verification endpoint: the answer `good` passes, everything else fails. */
private class FakeGoogle : AutoCloseable {
    /** The form of every check, as Kovexy sent it. */
    val received = CopyOnWriteArrayList<String>()
    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)

    val url: String get() = "http://127.0.0.1:${server.address.port}/siteverify"

    init {
        server.createContext("/siteverify") { ex ->
            val body = ex.requestBody.readBytes().decodeToString()
            received += body
            val bytes = """{"success": ${"response=good" in body}, "score": 0.9}""".toByteArray()
            ex.sendResponseHeaders(200, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }
        server.start()
    }

    override fun close() = server.stop(0)
}

/** The captcha is Google's reCAPTCHA, Kovexy has no captcha of its own. */
class GoogleCaptchaTest {
    private fun config(backend: Int) = """
        { "admin": { "port": ADMIN_PORT },
          "accessProfiles": [
            { "name": "v2", "captcha": { "siteKey": "site-v2", "secretKey": "the secret", "exceptions": [ { "pathPrefix": "/public" } ] } },
            { "name": "v3", "captcha": { "siteKey": "site-v3", "secretKey": "the secret", "recaptchaVersion": "v3" } },
            { "name": "ai", "exploitFilter": { "aiBots": true }, "captcha": { "siteKey": "site-v2", "secretKey": "the secret" } },
            { "name": "limited", "rateLimit": { "requestsPerSecond": 2 }, "captcha": { "siteKey": "site-v2", "secretKey": "the secret" } }
          ],
          "upstreams": [ { "name": "app", "servers": [ { "address": "127.0.0.1:$backend" } ] } ],
          "sites": [
            { "domains": ["a.test"], "access": "v2", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] },
            { "domains": ["b.test"], "access": "ai", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] },
            { "domains": ["c.test"], "access": "limited", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] },
            { "domains": ["d.test"], "access": "v3", "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] }
          ] }
    """.trimIndent()

    /** The captcha only runs over HTTPS (decided on 18.11.2026). */
    private fun tlsRequest(h: Harness, host: String, path: String, method: String = "GET", headers: List<Pair<String, String>> = emptyList(), body: ByteArray? = null) =
        rawRequest(h.ports.https, host, path, tls = true, method = method, headers = headers, body = body)

    private fun hidden(html: String, name: String) = Regex("""name="$name" value="([^"]*)"""").find(html)?.groupValues?.get(1)
        ?: Regex("""value="([^"]*)" name="$name"""").find(html)?.groupValues?.get(1)

    private fun verify(h: Harness, host: String, token: String, answer: String) =
        tlsRequest(h, host, "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader), body = form("token" to token, "g-recaptcha-response" to answer))

    @Test
    fun theCheckboxCaptchaEndToEnd(): Unit = runBlocking {
        FakeGoogle().use { google ->
            TestBackend().use { backend ->
                Harness(config(backend.port), googleSiteverify = google.url).use { h ->
                    val first = tlsRequest(h, "a.test", "/page?x=1")
                    assertEquals(403, first.status)
                    assertTrue(first.text.contains("/.kovexy/captcha.js") && first.text.contains("g-recaptcha") && first.text.contains("data-sitekey=\"site-v2\""), first.text)
                    val csp = first.header("Content-Security-Policy").orEmpty()
                    assertTrue(csp.contains("script-src 'self' https://www.google.com/recaptcha/"), csp)
                    assertEquals(200, tlsRequest(h, "a.test", "/public/file").status, "Exceptions need no captcha")
                    val script = tlsRequest(h, "a.test", "/.kovexy/captcha.js")
                    assertEquals(200, script.status)
                    assertTrue(script.text.contains("grecaptcha"), "The script drives reCAPTCHA")
                    assertFalse(script.text.contains("sha256Head"), "No proof of work code is shipped")

                    val token = hidden(first.text, "token")!!
                    val wrong = verify(h, "a.test", token, "bad")
                    assertEquals(403, wrong.status, "A wrong answer shows the page again")
                    assertTrue(wrong.text.contains("g-recaptcha"), "With a new checkbox")
                    val solved = verify(h, "a.test", token, "good")
                    assertEquals(302, solved.status, solved.text)
                    assertEquals("/page?x=1", solved.header("Location"))
                    val sent = google.received.last()
                    assertTrue(sent.contains("secret=the+secret") && sent.contains("response=good") && sent.contains("remoteip="), sent)
                    val cookie = solved.headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-captcha=") }
                    assertTrue(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Secure"), cookie)

                    val pass = tlsRequest(h, "a.test", "/page?x=1", headers = listOf("Cookie" to cookie.substringBefore(';')))
                    assertEquals(200, pass.status)
                    assertTrue(pass.text.contains("uri=/page?x=1"))
                    assertFalse(pass.text.contains("kovexy-captcha="), "The captcha cookie does not reach the upstream")
                    assertEquals(403, tlsRequest(h, "b.test", "/", headers = listOf("Cookie" to cookie.substringBefore(';'), "User-Agent" to "GPTBot/1.1")).status,
                        "A session counts for its profile and domain only")
                    val huge = tlsRequest(h, "a.test", "/.kovexy/captcha/verify", method = "POST", headers = listOf(formHeader),
                        body = form("token" to token, "g-recaptcha-response" to "good", "pad" to "x".repeat(40_000)))
                    assertEquals(400, huge.status, "A form above the limit is not read into memory and counts as empty")
                    assertEquals(404, tlsRequest(h, "a.test", "/.kovexy/anything").status, "Reserved paths never reach the upstream")
                    assertEquals(404, tlsRequest(h, "a.test", "/%2Ekovexy/anything", headers = listOf("Cookie" to cookie.substringBefore(';'))).status, "Also not with an encoded dot")
                }
            }
        }
    }

    @Test
    fun theInvisibleCaptchaPageCarriesTheSiteKeyForTheScript(): Unit = runBlocking {
        FakeGoogle().use { google ->
            TestBackend().use { backend ->
                Harness(config(backend.port), googleSiteverify = google.url).use { h ->
                    val page = tlsRequest(h, "d.test", "/")
                    assertEquals(403, page.status)
                    assertTrue(page.text.contains("data-provider=\"recaptcha3\"") && page.text.contains("data-sitekey=\"site-v3\""), page.text)
                    assertTrue(page.text.contains("name=\"g-recaptcha-response\""), "The script fills the answer in")
                    assertEquals(302, verify(h, "d.test", hidden(page.text, "token")!!, "good").status)
                }
            }
        }
    }

    @Test
    fun aCrawlerWithASolvedCaptchaIsStillRefused(): Unit = runBlocking {
        FakeGoogle().use { google ->
            TestBackend().use { backend ->
                Harness(config(backend.port), googleSiteverify = google.url).use { h ->
                    val page = tlsRequest(h, "b.test", "/")
                    assertEquals(403, page.status)
                    val solved = verify(h, "b.test", hidden(page.text, "token")!!, "good")
                    val cookie = solved.headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-captcha=") }.substringBefore(';')
                    assertEquals(200, tlsRequest(h, "b.test", "/", headers = listOf("Cookie" to cookie)).status)
                    val bot = tlsRequest(h, "b.test", "/", headers = listOf("Cookie" to cookie, "User-Agent" to "GPTBot/1.1"))
                    assertEquals(403, bot.status, "The exploit filter has no captcha answer, a solved captcha does not help a crawler")
                    assertFalse(bot.text.contains("g-recaptcha"))
                    assertEquals(308, rawRequest(h.ports.http, "a.test", "/.kovexy/captcha.js").status, "Plain HTTP is redirected before the reserved paths")
                }
            }
        }
    }

    @Test
    fun theRateLimitAlsoCoversKovexyPaths(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(config(backend.port)).use { h ->
                val statuses = (1..6).map { tlsRequest(h, "c.test", "/.kovexy/captcha.js").status }
                assertTrue(429 in statuses, statuses.toString())
            }
        }
    }
}

/** Kovexy puts no login in front of apps (removed on 19.11.2026), they protect themselves. */
class NoAppLoginTest {
    private val config = """
        { "admin": { "port": ADMIN_PORT },
          "upstreams": [ { "name": "app", "servers": [ { "address": "127.0.0.1:BACKEND" } ] } ],
          "sites": [ { "domains": ["app.test"], "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] } ] }
    """.trimIndent()

    @Test
    fun theLoginPathsAreNotKovexys(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(config.replace("BACKEND", backend.port.toString())).use { h ->
                listOf("/.kovexy/auth/start", "/.kovexy/auth/callback", "/.kovexy/auth/logout").forEach { path ->
                    assertEquals(404, rawRequest(h.ports.https, "app.test", path, tls = true).status, path)
                }
            }
        }
    }

    @Test
    fun identityHeadersOfVisitorsNeverReachTheUpstream(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(config.replace("BACKEND", backend.port.toString())).use { h ->
                val forged = listOf("X-Forwarded-User" to "mallory", "X-Forwarded-Email" to "m@evil.test", "X.Forwarded.Preferred.Username" to "mallory")
                val answer = rawRequest(h.ports.https, "app.test", "/inside", tls = true, headers = forged)
                assertEquals(200, answer.status, answer.text)
                assertFalse(answer.text.contains("mallory") || answer.text.contains("m@evil.test"), answer.text)
            }
        }
    }

    @Test
    fun theSettingsOfTheLoginAreRefused() {
        fun refused(json: String) = assertTrue(parseConfig(json) is ResultOf2.Failure, json)
        refused("""{ "appAuth": { "issuer": "https://id.example", "clientId": "a", "clientSecret": "s" } }""")
        refused("""{ "accessProfiles": [ { "name": "p", "oidc": {} } ] }""")
    }

    @Test
    fun theSettingsOfTheProofOfWorkAreRefused() {
        fun captcha(fields: String) = """{ "accessProfiles": [ { "name": "p", "captcha": { "siteKey": "k", "secretKey": "s"$fields } } ] }"""
        assertTrue(parseConfig(captcha("")) is ResultOf2.Success, "Google needs only the keys")
        assertTrue(parseConfig(captcha(""", "provider": "pow"""")) is ResultOf2.Failure, "There is no provider to choose")
        assertTrue(parseConfig(captcha(""", "provider": "google"""")) is ResultOf2.Failure)
        assertTrue(parseConfig(captcha(""", "powDifficulty": 12""")) is ResultOf2.Failure)
    }

    @Test
    fun aDatabaseFromBeforeLosesTheStoredLoginSessions() {
        val dir = Files.createTempDirectory("kovexy-legacy").toFile()
        try {
            val file = File(dir, "kovexy.db")
            DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}").use { c ->
                c.createStatement().use { it.execute("CREATE TABLE app_sessions (token_hash VARCHAR(64) PRIMARY KEY, sub VARCHAR(256))") }
                c.createStatement().use { it.execute("INSERT INTO app_sessions VALUES ('abc', 'ada')") }
            }
            Storage(file)
            val tables = DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}").use { c ->
                c.createStatement().use { st -> st.executeQuery("SELECT name FROM sqlite_master WHERE name = 'app_sessions'").use { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }
            }
            assertEquals(emptyList<String>(), tables, "No session of the removed login stays behind")
        } finally {
            dir.deleteRecursively()
        }
    }
}
