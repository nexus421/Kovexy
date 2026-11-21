package bayern.kickner.kovexy

import bayern.kickner.kovexy.access.Geo
import bayern.kickner.kovexy.access.RateLimiter
import bayern.kickner.kovexy.access.addressKey
import bayern.kickner.kovexy.access.isLocalAddress
import bayern.kickner.kovexy.stats.TopKind
import bayern.kickner.kovexy.stats.statistics
import bayern.kickner.kovexy.stats.topLists
import bayern.kickner.kovexy.access.matchAiBot
import bayern.kickner.kovexy.access.matchCommonExploit
import bayern.kickner.kovexy.audit.AuditAction
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.audit.configDiff
import bayern.kickner.kovexy.auth.hashBcrypt
import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.auth.isValidBcryptHash
import bayern.kickner.kovexy.auth.verifyBasicAuthHash
import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.BasicAuthConfig
import bayern.kickner.kovexy.config.BasicAuthUser
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.WebhookConfig
import bayern.kickner.kovexy.dev.MockOidcProvider
import bayern.kickner.kovexy.dev.MockUser
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.Socket
import java.net.URLEncoder
import java.nio.file.Files
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours

/** Unit tests of the phase 2 building blocks. */
class AccessUnitTest {
    @Test
    fun addressKeysAndLocalAddresses() {
        assertEquals("203.0.113.7", addressKey(InetAddress.getByName("203.0.113.7")))
        assertEquals("2001:db8:1:2::/64", addressKey(InetAddress.getByName("2001:db8:1:2:aaaa:bbbb:cccc:dddd")))
        assertEquals(addressKey(InetAddress.getByName("2001:db8::1")), addressKey(InetAddress.getByName("2001:db8::ffff")), "One /64 is one key")
        assertTrue(isLocalAddress(InetAddress.getByName("192.168.1.5")))
        assertTrue(isLocalAddress(InetAddress.getByName("fd00::1")))
        assertTrue(isLocalAddress(InetAddress.getByName("127.0.0.1")))
        assertFalse(isLocalAddress(InetAddress.getByName("8.8.8.8")))
    }

    @Test
    fun exploitPatternsAndAiBots() {
        assertEquals("sql injection", matchCommonExploit("id=1 union select(1)", ""))
        assertEquals("sql injection", matchCommonExploit("id=1%20union%20select(1)", ""), "Encoded attacks are caught too")
        assertEquals("common exploit", matchCommonExploit("q=<script>alert(1)</script>", ""))
        assertEquals("known tool", matchCommonExploit("", "libwww-perl/6.0"))
        assertNull(matchCommonExploit("page=2&sort=name", "Mozilla/5.0"))
        assertNotNull(matchAiBot("Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"))
        assertNull(matchAiBot("Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"))
        val changes = bayern.kickner.kovexy.config.AiCrawlersConfig(add = listOf("MyScraper"), ignore = listOf("GPTBot"))
        assertNull(matchAiBot("Mozilla/5.0 (compatible; GPTBot/1.1)", changes), "Ignored names no longer count")
        assertEquals("myscraper", matchAiBot("myscraper/2.0", changes), "Added names count, case insensitive")
        assertNotNull(matchAiBot("Mozilla/5.0 (compatible; GPTBot/1.1)"), "Without changes the shipped list applies")
    }

    @Test
    fun rateLimitWindows() {
        var now = 1_000_000L
        val limiter = RateLimiter { now }
        repeat(3) { assertFalse(limiter.exceeded("p", "1.1.1.1", 3)) }
        assertTrue(limiter.exceeded("p", "1.1.1.1", 3))
        assertFalse(limiter.exceeded("other", "1.1.1.1", 3), "Counted per profile")
        now += 1000
        assertFalse(limiter.exceeded("p", "1.1.1.1", 3), "A new second starts a new window")
    }

    @Test
    fun basicAuthHashes() {
        val bcrypt = hashBcrypt("secret password", cost = 4)
        assertTrue(isValidBcryptHash(bcrypt))
        assertTrue(verifyBasicAuthHash("secret password", bcrypt))
        assertFalse(verifyBasicAuthHash("wrong", bcrypt))
        assertTrue(verifyBasicAuthHash("argon password", hashPassword("argon password")), "Argon2id is accepted too")
        assertFalse(isValidBcryptHash(bcrypt.replace("\$04\$", "\$31\$")), "Costs that would hang the login are refused")
    }

    @Test
    fun auditDiffMasksSecrets() {
        val old = KovexyConfig(webhooks = listOf(WebhookConfig("k", "https://k.test/api/webhooks/1/old-token", mapOf("X-API-Key" to "old-key"))))
        val new = old.copy(
            updateCheck = false,
            webhooks = listOf(WebhookConfig("k", "https://k.test/api/webhooks/1/new-token", mapOf("X-API-Key" to "new-key"))),
            accessProfiles = listOf(AccessProfile("p", basicAuth = BasicAuthConfig(listOf(BasicAuthUser("u", hashBcrypt("x", 4)))))),
        )
        val diff = configDiff(old, new)
        assertTrue(diff.lines().any { it.startsWith("+") && it.contains("\"updateCheck\": false") }, diff)
        assertTrue(diff.contains("* changed: header X-API-Key of webhook k"), diff)
        assertFalse(diff.contains("new-key") || diff.contains("old-key") || diff.contains("\$2b\$"), "No secret in the diff: $diff")
        assertTrue(diff.contains("* changed: URL of webhook k"), diff)
        assertFalse(diff.contains("token"), "Webhook URLs carry tokens in the path: $diff")
    }

    @Test
    fun countryDataIsCheckedAndOnlyDownloadedWhenChanged() {
        val dir = Files.createTempDirectory("kovexy-geo").toFile()
        val v4 = "1.0.0.0,1.0.0.255,AU\n5.0.0.0,5.255.255.255,DE\n"
        val v6 = "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,NL\n"
        val files = mapOf("user-country-ipv4.csv" to v4, "user-country-ipv6.csv" to v6)
        val fetched = mutableListOf<String>()
        var tamper = false
        val geo = Geo(dir, fetch = { url, target ->
            fetched += url
            val name = url.substringAfterLast('/')
            when {
                name.endsWith(".sha256") -> target.writeText(sha256(files.getValue(name.removeSuffix(".sha256")).toByteArray()) + "  " + name.removeSuffix(".sha256"))
                else -> target.writeText(files.getValue(name) + if (tamper) "6.0.0.0,6.0.0.255,XX\n" else "")
            }
            200
        })
        tamper = true
        geo.round()
        assertFalse(geo.loaded, "A file that does not match the published checksum is refused")
        assertNotNull(geo.status().lastError)
        tamper = false
        val retry = Geo(dir, fetch = { url, target ->
            fetched += url
            val name = url.substringAfterLast('/')
            if (name.endsWith(".sha256")) target.writeText(sha256(files.getValue(name.removeSuffix(".sha256")).toByteArray())) else target.writeText(files.getValue(name))
            200
        })
        retry.round()
        assertTrue(retry.loaded)
        assertEquals("DE", retry.country(InetAddress.getByName("5.1.2.3")))
        assertEquals("NL", retry.country(InetAddress.getByName("2001:db8::7")))
        assertNull(retry.country(InetAddress.getByName("9.9.9.9")))
        dir.deleteRecursively()
    }
}

/** Access profiles, bans, OIDC and audit with real ports. */
class Phase2IntegrationTest {

    private fun config(backend: Int, profiles: String, domainAccess: String = "\"access\": \"p\",", extra: String = "") = """
        { "admin": { "port": ADMIN_PORT }, $extra
          "accessProfiles": [ $profiles ],
          "backends": [ { "name": "app", "servers": [ { "address": "127.0.0.1:$backend" } ] } ],
          "domains": [
            { "names": ["a.test"], $domainAccess "routes": [
              { "path": "/", "target": { "type": "backend", "backend": "app" } },
              { "path": "/open", "access": "open", "target": { "type": "backend", "backend": "app" } },
              { "path": "/.env", "match": "exact", "target": { "type": "backend", "backend": "app" } } ] },
            { "names": ["b.test"], "routes": [ { "path": "/", "target": { "type": "backend", "backend": "app" } } ] }
          ] }
    """.trimIndent()

    private fun get(h: Harness, host: String, path: String, headers: List<Pair<String, String>> = emptyList(), method: String = "GET") =
        h.https(host, path, method = method, headers = headers, body = if (method == "POST") ByteArray(1) else null)

    @Test
    fun ipListsAndRouteProfileReplacesDomainProfile(): Unit = runBlocking {
        TestBackend().use { backend ->
            val profiles = """{ "name": "p", "denyIps": ["127.0.0.1"] }, { "name": "open" }"""
            Harness(config(backend.port, profiles)).use { h ->
                assertEquals(403, get(h, "a.test", "/x").status)
                assertEquals(200, get(h, "a.test", "/open/x").status, "The route profile replaces the domain profile completely")
                assertEquals(200, get(h, "b.test", "/x").status)
                h.writeConfigByHand(config(backend.port, """{ "name": "p", "allowIps": ["10.0.0.0/8"] }, { "name": "open" }"""))
                assertEquals(403, get(h, "a.test", "/x").status)
                h.writeConfigByHand(config(backend.port, """{ "name": "p", "allowIps": ["10.0.0.0/8"], "allowLocal": true }, { "name": "open" }"""))
                assertEquals(200, get(h, "a.test", "/x").status)
                // The background writer collects events for up to a second before it writes them
                var tries = 0
                while (h.kovexy.security.latest(SecurityEventType.ACCESS_DENIED).isEmpty() && tries++ < 40) {
                    h.kovexy.security.flush()
                    delay(100)
                }
                assertTrue(h.kovexy.security.latest(SecurityEventType.ACCESS_DENIED).isNotEmpty())
            }
        }
    }

    @Test
    fun allowListedAddressIsNeverBanned(): Unit = runBlocking {
        TestBackend().use { backend ->
            // The profile of the trap names the address: the trap refuses it but bans nobody
            Harness(config(backend.port, """{ "name": "p", "allowIps": ["127.0.0.1"], "trapPaths": { "enabled": true } }, { "name": "open" }""")).use { h ->
                assertEquals(403, get(h, "a.test", "/wp-login.php").status, "The trap still refuses the request")
                assertEquals(0, h.kovexy.bans.list().size, "An address on the allow list is not banned")
                assertEquals(200, get(h, "a.test", "/x").status)
            }
            // A ban from another profile holds everywhere, except where the profile of the domain and route names the address
            Harness(config(backend.port, """{ "name": "p", "trapPaths": { "enabled": true } }, { "name": "open", "allowIps": ["127.0.0.1"] }""")).use { h ->
                assertEquals(403, get(h, "a.test", "/wp-login.php").status)
                assertEquals(1, h.kovexy.bans.list().size, "A profile without the address bans it")
                assertEquals(403, get(h, "a.test", "/x").status, "Still banned where the profile does not name it")
                assertEquals(403, get(h, "b.test", "/x").status, "Still banned on a domain without a profile")
                assertEquals(200, get(h, "a.test", "/open/x").status, "The profile of this route names the address")
            }
        }
    }

    @Test
    fun blockedRequestsAndRedirectsAreCounted(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(config(backend.port, """{ "name": "p", "denyIps": ["127.0.0.1"] }, { "name": "open" }""")).use { h ->
                assertEquals(403, get(h, "a.test", "/x").status)
                assertEquals(200, get(h, "b.test", "/x").status)
                assertEquals(308, rawRequest(h.ports.http, "a.test", "/x").status)
                // The background writer collects records for a moment before it writes them
                var rows = h.kovexy.storage.statistics(hourly = false, from = 0)
                var tries = 0
                while (rows.sumOf { it.requests } < 3 && tries++ < 50) {
                    h.kovexy.accessLog.flush()
                    delay(100)
                    rows = h.kovexy.storage.statistics(hourly = false, from = 0)
                }
                assertEquals(3, rows.sumOf { it.requests })
                assertEquals(1, rows.sumOf { it.blocked }, "Only the refused request counts as blocked, a redirect does not")
                assertEquals(1, rows.sumOf { it.redirected })
                assertEquals(listOf("IP_RULES" to 1L), h.kovexy.storage.topLists(0, null)[TopKind.BLOCK_KIND])
                val blocked = h.kovexy.accessLog.latest(blockedOnly = true)
                assertEquals("IP_RULES", blocked.single().block)
            }
        }
    }

    @Test
    fun trapBansForAllDomainsUntilLiftedOrExpired(): Unit = runBlocking {
        var now = System.currentTimeMillis()
        TestBackend().use { backend ->
            Harness(config(backend.port, """{ "name": "p", "trapPaths": { "enabled": true, "banDuration": "1h" } }, { "name": "open" }"""), clock = { now }).use { h ->
                assertEquals(200, get(h, "a.test", "/.env").status, "An exact route for the path disarms the trap")
                // A browser sent there by another site (an image or a link on a foreign page) is refused, not banned
                assertEquals(403, get(h, "a.test", "/wp-login.php", listOf("Sec-Fetch-Site" to "cross-site", "Sec-Fetch-Mode" to "no-cors")).status)
                assertEquals(403, get(h, "a.test", "/wp-admin/", listOf("Referer" to "https://evil.example/page")).status)
                assertEquals(403, get(h, "a.test", "/wp-admin/", listOf("Origin" to "null")).status)
                assertEquals(0, h.kovexy.bans.list().size, "Foreign initiated trap requests ban nobody")
                assertEquals(200, get(h, "b.test", "/x").status)
                assertEquals(403, get(h, "a.test", "/wp-login.php", listOf("Referer" to "http://a.test/home")).status)
                assertEquals(1, h.kovexy.bans.list().size, "A same-site Referer still bans")
                assertTrue(h.kovexy.bans.lift("127.0.0.1"))
                assertEquals(403, get(h, "a.test", "/wp-login.php").status)
                assertEquals(403, get(h, "b.test", "/x").status, "The ban counts for all domains")
                assertEquals(1, h.kovexy.bans.list().size)
                assertTrue(h.kovexy.bans.lift("127.0.0.1"))
                assertEquals(200, get(h, "b.test", "/x").status)
                assertEquals(403, get(h, "a.test", "/.git/config").status)
                now += 1.hours.inWholeMilliseconds + 1000
                assertEquals(200, get(h, "b.test", "/x").status, "The ban expired")
            }
        }
    }

    @Test
    fun plainHttpNeverReachesASiteOrTheFallback(): Unit = runBlocking {
        TestBackend().use { backend ->
            TestBackend(name = "default").use { fallback ->
                val config = """
                    { "admin": { "port": ADMIN_PORT },
                      "backends": [ { "name": "app", "servers": [ { "address": "127.0.0.1:${backend.port}" } ] },
                                     { "name": "fallback", "servers": [ { "address": "127.0.0.1:${fallback.port}" } ] } ],
                      "fallback": { "type": "backend", "backend": "fallback" },
                      "domains": [ { "names": ["tls.test"], "routes": [ { "path": "/", "target": { "type": "backend", "backend": "app" } } ] } ] }
                """.trimIndent()
                Harness(config).use { h ->
                    val domain = get(h, "tls.test", "/x")
                    assertEquals(200, domain.status)
                    assertNotEquals("default", domain.header("X-Backend"))
                    listOf("tls.test", "other.test").forEach { host ->
                        val plain = rawRequest(h.ports.http, host, "/x")
                        assertEquals(308, plain.status, "$host on port 80 is only redirected")
                        assertNull(plain.header("X-Backend"), "No backend, not even the default one, sees plain HTTP")
                    }
                    val other = get(h, "other.test", "/x")
                    assertEquals(200, other.status, "Unknown domains still go to the fallback")
                    assertEquals("default", other.header("X-Backend"))
                }
            }
        }
    }

    @Test
    fun exploitFilterRateLimitAndMethods(): Unit = runBlocking {
        val now = System.currentTimeMillis() / 1000 * 1000 + 100
        TestBackend().use { backend ->
            val profile = """{ "name": "p", "exploitFilter": { "commonExploits": true, "aiBots": true, "response": "notFound" },
                "rateLimit": { "requestsPerSecond": 5 }, "allowedMethods": ["GET", "HEAD"] }, { "name": "open" }"""
            Harness(config(backend.port, profile), clock = { now }).use { h ->
                assertEquals(404, get(h, "a.test", "/x?id=1+union+select(1)").status)
                assertEquals(404, get(h, "a.test", "/x", listOf("User-Agent" to "ClaudeBot/1.0")).status)
                val post = get(h, "a.test", "/x", method = "POST")
                assertEquals(405, post.status)
                assertEquals("GET, HEAD", post.header("Allow"))
                // The 405 was counted, the exploit answers came before the rate limit. Four more fill the frozen second
                repeat(4) { assertEquals(200, get(h, "a.test", "/x").status) }
                assertEquals(429, get(h, "a.test", "/x").status)
            }
            val aiOnly = """{ "name": "p", "exploitFilter": { "aiBots": true } }, { "name": "open" }"""
            Harness(config(backend.port, aiOnly)).use { h ->
                assertEquals(403, get(h, "a.test", "/x", listOf("User-Agent" to "ClaudeBot/1.0")).status)
                assertEquals(200, get(h, "a.test", "/x", listOf("User-Agent" to "MyScraper/1.0")).status)
                h.writeConfigByHand(config(backend.port, aiOnly, extra = "\"aiCrawlers\": { \"add\": [\"MyScraper\"], \"ignore\": [\"ClaudeBot\"] },"))
                assertEquals(200, get(h, "a.test", "/x", listOf("User-Agent" to "ClaudeBot/1.0")).status, "Ignored live")
                assertEquals(403, get(h, "a.test", "/x", listOf("User-Agent" to "MyScraper/1.0")).status, "Added live")
            }
            Harness(config(backend.port, """{ "name": "p", "exploitFilter": { "commonExploits": true, "response": "drop" } }, { "name": "open" }""")).use { h ->
                val dropped = get(h, "a.test", "/x?q=<script>x</script>")
                assertEquals(204, dropped.status)
                assertEquals("close", dropped.header("Connection"))
            }
        }
    }

    @Test
    fun basicAuth(): Unit = runBlocking {
        TestBackend().use { backend ->
            val hash = hashBcrypt("letmein please", cost = 4)
            val profile = """{ "name": "p", "basicAuth": { "users": [ { "name": "ada", "hash": "$hash" } ], "realm": "Home",
                "exceptions": [ { "pathPrefix": "/public" } ] } }, { "name": "open" }"""
            Harness(config(backend.port, profile)).use { h ->
                val challenge = get(h, "a.test", "/x")
                assertEquals(401, challenge.status)
                assertEquals("Basic realm=\"Home\", charset=\"UTF-8\"", challenge.header("WWW-Authenticate"))
                val wrong = "Basic " + Base64.getEncoder().encodeToString("ada:nope".toByteArray())
                assertEquals(401, get(h, "a.test", "/x", listOf("Authorization" to wrong)).status)
                val right = "Basic " + Base64.getEncoder().encodeToString("ada:letmein please".toByteArray())
                val ok = get(h, "a.test", "/x", listOf("Authorization" to right))
                assertEquals(200, ok.status)
                assertFalse(ok.text.contains("authorization="), "The password does not reach the backend: ${ok.text}")
                assertEquals(200, get(h, "a.test", "/public/file").status, "Exceptions need no login")
                assertEquals(401, get(h, "a.test", "/publicity").status, "Exception prefixes only match at path boundaries")
            }
        }
    }

    @Test
    fun connectionLimitPerAddress(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(config(backend.port, """{ "name": "p" }, { "name": "open" }""", extra = "\"limits\": { \"maxConnectionsPerAddress\": 2 },")).use { h ->
                h.kovexy.server.limitLoopbackForTests()
                fun refused(): Boolean = runCatching {
                    Socket("127.0.0.1", h.ports.http).use { s ->
                        s.soTimeout = 1500
                        s.getOutputStream().write("GET / HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n".toByteArray())
                        s.getInputStream().read() < 0
                    }
                }.getOrDefault(true)
                // Two idle connections of the same address fill its share (S1, decided on 19.11.2026)
                Socket("127.0.0.1", h.ports.http).use { first ->
                    Socket("127.0.0.1", h.ports.http).use { second ->
                        delay(200)
                        assertTrue(refused(), "A third connection of the address is closed at once")
                    }
                }
                delay(200)
                assertEquals(200, get(h, "b.test", "/x").status, "Below the limit again")
                h.writeConfigByHand(config(backend.port, """{ "name": "p" }, { "name": "open" }""", extra = "\"limits\": { \"maxConnectionsPerAddress\": 0 },"))
                delay(200)
                Socket("127.0.0.1", h.ports.http).use { Socket("127.0.0.1", h.ports.http).use { delay(200); assertFalse(refused(), "0 turns it off, live") } }
            }
        }
    }

    @Test
    fun connectionLimitAppliesWhileRunning(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness(config(backend.port, """{ "name": "p" }, { "name": "open" }""", extra = "\"limits\": { \"maxConnections\": 1 },")).use { h ->
                assertEquals(1, h.kovexy.server.activeConnectionLimit)
                // One idle TLS connection fills the limit. TLS counts like plain HTTP (Jetty's own ConnectionLimit did not count it)
                val ctx = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, arrayOf<javax.net.ssl.TrustManager>(TrustAllManager), null) }
                (ctx.socketFactory.createSocket("127.0.0.1", h.ports.https) as javax.net.ssl.SSLSocket).use { tls ->
                    tls.startHandshake()
                    delay(200)
                    assertFailsWith<java.io.IOException>("A connection above the limit gets no answer") {
                        Socket("127.0.0.1", h.ports.http).use { s ->
                            s.soTimeout = 1500
                            s.getOutputStream().write("GET / HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n".toByteArray())
                            if (s.getInputStream().read() < 0) throw java.io.EOFException("closed")
                        }
                    }
                }
                delay(200)
                assertEquals(200, get(h, "b.test", "/x").status, "Below the limit again")
                h.writeConfigByHand(config(backend.port, """{ "name": "p" }, { "name": "open" }""", extra = "\"limits\": { \"maxConnections\": 0 },"))
                // The new version is visible before every part has applied it
                repeat(100) { if (h.kovexy.server.activeConnectionLimit != null) delay(20) }
                assertNull(h.kovexy.server.activeConnectionLimit)
                assertEquals(200, get(h, "b.test", "/x").status)
            }
        }
    }

    @Test
    fun oidcLoginBothModesAndAudit(): Unit = runBlocking {
        MockOidcProvider(autoLogin = MockUser("ada-sub", "Ada")).use { oidc ->
            val adminPort = freePort()
            val oidcJson = """"oidc": { "issuer": "${oidc.issuer}", "clientId": "kovexy-test", "clientSecret": "${oidc.clientSecret}", "forceReauth": false, "allowedSubjects": ["ada-sub"] }"""
            val text = """{ "admin": { "port": ADMIN_PORT, "publicUrl": "http://localhost:$adminPort", "loginMode": "MODE", "passwordHash": "${hashPassword("admin password 1")}", $oidcJson } }"""
            Harness(text.replace("MODE", "oidc"), adminPort = adminPort).use { h ->
                val session = oidcLogin(h)
                assertTrue(session.startsWith("__Host-kovexy-session="))
                assertEquals(200, rawRequest(h.adminPort, "localhost:${h.adminPort}", "/", headers = listOf("Cookie" to session)).status)
                assertEquals(AuditAction.LOGIN, h.kovexy.audit.latest().first().action)
                assertEquals("Ada", h.kovexy.audit.latest().first().actor.name)
                assertEquals(302, rawRequest(h.adminPort, "localhost:${h.adminPort}", "/login", method = "POST", body = "password=admin+password+1".toByteArray(),
                    headers = listOf("Origin" to "http://localhost:${h.adminPort}", "Content-Type" to "application/x-www-form-urlencoded")).status.let { if (it == 302) 302 else it }, "Mode oidc ignores the password form")

                h.writeConfigByHand(text.replace("MODE", "both"))
                val pending = oidcLogin(h)
                assertTrue(pending.startsWith("__Host-kovexy-pending="), "Mode both asks for the password after OIDC")
                val form = "password=" + URLEncoder.encode("admin password 1", Charsets.UTF_8)
                val done = rawRequest(h.adminPort, "localhost:${h.adminPort}", "/login", method = "POST", body = form.toByteArray(),
                    headers = listOf("Origin" to "http://localhost:${h.adminPort}", "Content-Type" to "application/x-www-form-urlencoded", "Cookie" to pending))
                assertEquals(200, done.status)
                assertNotNull(done.headerAll("Set-Cookie").firstOrNull { it.startsWith("__Host-kovexy-session=") && it.contains("Max-Age=0").not() })
                val changes = h.kovexy.audit.latest(AuditAction.CONFIG_CHANGED)
                assertTrue(changes.isNotEmpty())
                assertFalse(changes.first().detail.contains(oidc.clientSecret), "No secret in the audit log")
            }
        }
    }

    /** Runs the OIDC flow against the mock provider and returns the first cookie Kovexy sets at the end. */
    private fun oidcLogin(h: Harness): String {
        val host = "localhost:${h.adminPort}"
        val start = rawRequest(h.adminPort, host, "/auth/start")
        assertEquals(302, start.status, start.text)
        val loginCookie = start.header("Set-Cookie")!!.substringBefore(';')
        val authorize = java.net.URI(start.header("Location")!!)
        val provider = rawRequest(authorize.port, "localhost:${authorize.port}", authorize.rawPath + "?" + authorize.rawQuery)
        assertEquals(302, provider.status)
        val callback = java.net.URI(provider.header("Location")!!)
        val back = rawRequest(h.adminPort, host, callback.rawPath + "?" + callback.rawQuery, headers = listOf("Cookie" to loginCookie))
        assertEquals(200, back.status, back.text)
        return back.headerAll("Set-Cookie").first { it.contains("Max-Age=0").not() && it.startsWith("__Host-kovexy-login").not() }.substringBefore(';')
    }
}
