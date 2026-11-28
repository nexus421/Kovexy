package bayern.kickner.kovexy

import bayern.kickner.kovexy.stats.statistics
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Proxying with real ports: routing, headers, redirects, TLS per domain, bodies. */
class ProxyIntegrationTest {
    private lateinit var backend: TestBackend
    private lateinit var harness: Harness

    private fun config(backendPort: Int) = """
        {
          "admin": { "port": ADMIN_PORT },
          "backends": [ { "name": "app", "servers": [ { "address": "127.0.0.1:$backendPort" } ] } ],
          "domains": [
            {
              "names": ["a.test", "www.a.test"],
              "routes": [
                { "path": "/", "target": { "type": "backend", "backend": "app" } },
                { "path": "/api", "stripPrefix": true, "target": { "type": "backend", "backend": "app" },
                  "requestHeaders": [ { "action": "set", "name": "X-Extra", "value": "1" } ],
                  "responseHeaders": [ { "action": "set", "name": "X-Frame-Options", "value": "DENY" } ] },
                { "path": "/admin", "target": { "type": "deny", "status": 403 } },
                { "path": "/old", "target": { "type": "redirect", "url": "https://new.test/base", "status": 301 } },
                { "path": "/exact", "match": "exact", "target": { "type": "deny", "status": 410 } }
              ]
            }
          ],
          "fallback": { "type": "notFound" }
        }
    """.trimIndent()

    @BeforeTest
    fun setUp() {
        backend = TestBackend()
        harness = Harness(config(backend.port))
        runBlocking { waitForCert("a.test") }
    }

    @AfterTest
    fun tearDown() {
        harness.close()
        backend.close()
    }

    private suspend fun waitForCert(domain: String) {
        repeat(100) {
            if (harness.kovexy.keyManager.certificateOf(domain) != null) return
            delay(50)
        }
        error("No certificate for $domain")
    }

    private fun https(host: String, path: String = "/", method: String = "GET", headers: List<Pair<String, String>> = emptyList(), body: ByteArray? = null, sni: String? = host) =
        rawRequest(harness.ports.https, host, path, tls = true, method = method, headers = headers, body = body, sni = sni)

    private fun http(host: String, path: String = "/", method: String = "GET", headers: List<Pair<String, String>> = emptyList()) =
        rawRequest(harness.ports.http, host, path, method = method, headers = headers)

    private fun echo(response: RawResponse): Map<String, List<String>> =
        response.text.lines().filter { '=' in it }.groupBy({ it.substringBefore('=') }, { it.substringAfter('=') })

    /** Jetty refuses broken request targets itself, the visitor must get Kovexy's neutral page and not Jetty's. */
    @Test
    fun brokenRequestTargetsGetTheNeutralPage(): Unit = run {
        listOf("/%", "/%zz", "/a%00b").forEach { path ->
            val answers = listOf(
                "http" to http("a.test", path),
                "https" to https("a.test", path),
                "admin" to rawRequest(harness.adminPort, "127.0.0.1", path),
            )
            answers.forEach { (port, response) ->
                assertEquals(400, response.status, "$port $path")
                assertTrue(response.text.startsWith("<!DOCTYPE html>") && "Error 400" in response.text, "Neutral page on $port for $path: ${response.text}")
                assertTrue("HTTP ERROR" !in response.text && "badMessage" !in response.text && "badRequest" !in response.text, "Jetty page on $port for $path")
                assertTrue(response.header("Content-Type")?.startsWith("text/html") == true, "$port $path")
            }
        }
    }

    @Test
    fun forwardsWithCaddyHeaders(): Unit = run {
        val response = https("a.test", "/x/y?q=1", headers = listOf(
            "X-Forwarded-For" to "6.6.6.6", "Connection" to "close, X-Hop", "X-Hop" to "secret", "Keep-Alive" to "timeout=5", "Te" to "trailers",
        ))
        assertEquals(200, response.status)
        val seen = echo(response)
        assertEquals(listOf("/x/y?q=1"), seen["uri"])
        assertEquals(listOf("a.test"), seen["host"], "Host must pass unchanged")
        assertEquals(listOf("127.0.0.1"), seen["x-forwarded-for"], "Untrusted X-Forwarded-For must be replaced")
        assertEquals(listOf("https"), seen["x-forwarded-proto"])
        assertEquals(listOf("a.test"), seen["x-forwarded-host"])
        assertNull(seen["x-hop"], "Headers named in Connection are hop-by-hop")
        assertNull(seen["keep-alive"])
        assertNull(seen["te"])
        assertEquals("backend", response.header("X-Backend"))
    }

    @Test
    fun stripsPrefixAndAppliesHeaderRules(): Unit = run {
        val response = https("a.test", "/api/users?id=3")
        val seen = echo(response)
        assertEquals(listOf("/users?id=3"), seen["uri"])
        assertEquals(listOf("1"), seen["x-extra"])
        assertEquals("DENY", response.header("X-Frame-Options"))
        // Path boundary: /apix is not below /api and goes to the root route unchanged
        assertEquals(listOf("/apix"), echo(https("a.test", "/apix"))["uri"])
    }

    @Test
    fun denyRedirectExactAndNormalizedPaths(): Unit = run {
        assertEquals(403, https("a.test", "/admin").status)
        assertEquals(403, https("a.test", "/admin/x").status)
        assertEquals(403, https("a.test", "/%61dmin").status, "Encoded paths hit the same rule")
        // Jetty refuses empty path segments as ambiguous (URI compliance), so they never reach a rule
        assertEquals(400, https("a.test", "//admin").status)
        assertEquals(403, https("a.test", "/x/../admin").status, "Dot segments hit the same rule")
        assertEquals(200, https("a.test", "/administrator").status, "A prefix only matches at path boundaries")
        assertEquals(410, https("a.test", "/exact").status)
        assertEquals(200, https("a.test", "/exact/more").status)
        val redirect = https("a.test", "/old/page?x=1")
        assertEquals(301, redirect.status)
        assertEquals("https://new.test/base/page?x=1", redirect.header("Location"))
    }

    @Test
    fun plainHttpOnlyRedirects(): Unit = run {
        val redirect = http("a.test", "/p?q=1")
        assertEquals(308, redirect.status)
        assertEquals("https://a.test:${harness.ports.https}/p?q=1", redirect.header("Location"))
        assertEquals(308, http("a.test", "/p", method = "POST").status, "308 keeps the method")
        val unknown = http("unknown.test", "/x")
        assertEquals(308, unknown.status, "Unknown hosts are redirected too, the fallback only answers on HTTPS")
        assertEquals("https://unknown.test:${harness.ports.https}/x", unknown.header("Location"))
        assertEquals(400, http("a.test@evil.test", "/").status, "A crafted Host never ends up in Route")
        assertEquals(400, http("a.test/evil", "/").status)
        assertEquals(200, https("a.test").status)
    }

    @Test
    fun certificatePerDomainAndFallback(): Unit = runBlocking {
        waitForCert("www.a.test")
        assertEquals("CN=a.test", https("a.test").certificate!!.subjectX500Principal.name)
        assertEquals("CN=www.a.test", https("www.a.test").certificate!!.subjectX500Principal.name)
        assertEquals("CN=kovexy-fallback", https("unknown.test").certificate!!.subjectX500Principal.name)
        assertEquals("CN=kovexy-fallback", https("a.test", sni = "").certificate!!.subjectX500Principal.name)
        // SNI host check is off: a Host that does not match the certificate still reaches the domain
        assertEquals(200, https("a.test", sni = "unknown.test").status)
        assertEquals(404, https("unknown.test").status)
    }

    @Test
    fun streamsLargeBodiesBothWays(): Unit = run {
        val size = 50 * 1024 * 1024
        val download = https("a.test", "/big/$size")
        assertEquals(200, download.status)
        assertEquals(sha256(testBytes(size)), sha256(download.body))
        val data = testBytes(20 * 1024 * 1024)
        val upload = https("a.test", "/upload", method = "POST", body = data, headers = listOf("Content-Type" to "application/octet-stream"))
        assertEquals(200, upload.status)
        assertEquals(sha256(data), upload.text)
    }

    @Test
    fun headAndStatusCodesPassThrough(): Unit = run {
        assertEquals(418, https("a.test", "/status/418").status)
        assertEquals(204, https("a.test", "/status/204").status)
        val head = https("a.test", "/big/1000", method = "HEAD")
        assertEquals(200, head.status)
    }

    @Test
    fun accessLogAndStatistics(): Unit = runBlocking {
        https("a.test", "/x?token=secret")
        https("a.test", "/admin")
        var entries = emptyList<bayern.kickner.kovexy.stats.AccessRecord>()
        repeat(50) {
            entries = harness.kovexy.accessLog.latest(domain = "a.test")
            if (entries.size >= 2) return@repeat
            delay(100)
        }
        assertTrue(entries.any { it.path == "/x" && it.status == 200 }, "Query must not be stored: $entries")
        assertTrue(entries.any { it.path == "/admin" && it.status == 403 && it.reason == "denied" })
        val stats = harness.kovexy.storage.statistics(hourly = true, from = 0, domains = listOf("a.test"))
        assertTrue(stats.sumOf { it.requests } >= 2)
    }

    private fun run(block: () -> Unit) = block()
}
