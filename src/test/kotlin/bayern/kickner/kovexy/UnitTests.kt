package bayern.kickner.kovexy

import bayern.kickner.kovexy.auth.LoginThrottle
import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.auth.isValidPasswordHash
import bayern.kickner.kovexy.auth.verifyPassword
import bayern.kickner.kovexy.config.CONFIG_BACKUPS_KEPT
import bayern.kickner.kovexy.config.Cidr
import bayern.kickner.kovexy.config.ConfigStore
import bayern.kickner.kovexy.config.HostPort
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.LETS_ENCRYPT_PRODUCTION
import bayern.kickner.kovexy.config.LETS_ENCRYPT_STAGING
import bayern.kickner.kovexy.config.LocationConfig
import bayern.kickner.kovexy.config.MatchType
import bayern.kickner.kovexy.config.SaveError
import bayern.kickner.kovexy.config.SiteConfig
import bayern.kickner.kovexy.config.Target
import bayern.kickner.kovexy.config.WebhookConfig
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.config.encodeConfig
import bayern.kickner.kovexy.config.parseConfig
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.notify.Webhooks
import bayern.kickner.kovexy.notify.fillTemplate
import bayern.kickner.kovexy.proxy.CompiledSite
import bayern.kickner.kovexy.proxy.HeaderList
import bayern.kickner.kovexy.proxy.isValidPath
import bayern.kickner.kovexy.access.matchCommonExploit
import bayern.kickner.kovexy.proxy.normalizePath
import bayern.kickner.kovexy.config.plainAddress
import bayern.kickner.kovexy.proxy.stripPrefix
import bayern.kickner.kovexy.proxy.visitorIp
import bayern.kickner.kovexy.tls.CertStore
import bayern.kickner.kovexy.tls.CertificateManager
import bayern.kickner.kovexy.tls.DynamicKeyManager
import bayern.kickner.kovexy.tls.RETRY_INTERVALS
import bayern.kickner.kovexy.web.parseHeaderRules
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class ConfigTest {
    @Test
    fun emptyFileIsTheDefaultAndDefaultsAreNotWritten(): Unit = run {
        val parsed = parseConfig("{}")
        assertIs<ResultOf2.Success<KovexyConfig>>(parsed)
        assertEquals(KovexyConfig(), parsed.value)
        assertEquals("{}\n", encodeConfig(KovexyConfig()))
        val withSite = KovexyConfig(sites = listOf(SiteConfig(listOf("a.test"), locations = listOf(LocationConfig("/", target = Target.Deny())))))
        val text = encodeConfig(withSite)
        assertFalse(text.contains("httpsRedirect"), text)
        assertTrue(text.contains("\"type\": \"deny\""), text)
        assertEquals(withSite, (parseConfig(text) as ResultOf2.Success).value)
    }

    @Test
    fun unknownFieldsAndEveryProblemAtOnce(): Unit = run {
        val unknown = parseConfig("""{ "sitez": [] }""")
        assertIs<ResultOf2.Failure<List<String>>>(unknown)
        assertTrue(unknown.value.single().contains("sitez"))
        val broken = parseConfig(
            """
            { "admin": { "port": 443, "loginMode": "oidc", "session": { "idleTimeout": "30s" } },
              "listeners": [ { "name": "http", "port": 8080, "tls": false } ],
              "trustedProxies": ["nope"],
              "sites": [ { "domains": ["*.a.test", "a.test"], "access": "x", "locations": [
                { "path": "api/", "target": { "type": "upstream", "upstream": "missing" } },
                { "path": "/x/", "target": { "type": "redirect", "url": "ftp://x", "status": 302 } } ] },
                { "domains": ["a.test"] } ] }
            """
        )
        assertIs<ResultOf2.Failure<List<String>>>(broken)
        val all = broken.value.joinToString("\n")
        listOf(
            "admin.port must not be a proxy port", "needs admin.oidc", "needs admin.publicUrl", "idleTimeout", "listeners cannot be changed", "trustedProxies[0]",
            "without wildcard", "is no access profile", "must start with /", "does not exist", "must not end with a slash",
            "absolute https URL", "301 or 307", "belongs to more than one site",
        ).forEach { assertTrue(all.contains(it), "Missing \"$it\" in:\n$all") }
    }

    @Test
    fun durationsAsText(): Unit = run {
        val parsed = parseConfig("""{ "retention": { "accessLog": "30d", "hourlyStats": "1d 12h" }, "webSocketCloseDelay": "5s" }""")
        val config = (parsed as ResultOf2.Success).value
        assertEquals(30.days, config.retention.accessLog)
        assertEquals(5.seconds, config.webSocketCloseDelay)
        val bad = parseConfig("""{ "webSocketCloseDelay": "soon" }""")
        assertTrue((bad as ResultOf2.Failure).value.single().contains("Invalid duration"))
    }

    @Test
    fun storeWritesAtomicallyKeepsBackupsAndDetectsConflicts(): Unit = run {
        val dir = Files.createTempDirectory("kovexy-store").toFile()
        val store = ConfigStore(dir)
        assertIs<ResultOf2.Success<*>>(store.load())
        repeat(CONFIG_BACKUPS_KEPT + 3) { i -> store.update { it.copy(updateCheck = i % 2 == 0) } }
        assertEquals(CONFIG_BACKUPS_KEPT, store.backupDir.listFiles()!!.size)
        assertEquals("rw-------", Files.getPosixFilePermissions(store.file.toPath()).let { java.nio.file.attribute.PosixFilePermissions.toString(it) })
        val conflict = store.update("stale") { it }
        assertEquals(SaveError.Conflict, (conflict as ResultOf2.Failure).value)
        val invalid = store.update { it.copy(trustedProxies = listOf("x")) }
        assertIs<SaveError.Invalid>((invalid as ResultOf2.Failure).value)
        assertEquals(0, dir.listFiles()!!.count { it.name.endsWith(".tmp") })
        dir.deleteRecursively()
    }

    @Test
    fun exampleConfigIsValid(): Unit = run {
        val parsed = parseConfig(File("kovexy.example.json").readText())
        assertIs<ResultOf2.Success<KovexyConfig>>(parsed, parsed.toString())
    }

    private fun run(block: () -> Unit) = block()
}

class RoutingTest {
    private fun loc(path: String, match: MatchType = MatchType.PREFIX) = LocationConfig(path, match, target = Target.Deny())

    @Test
    fun normalizesPaths() {
        assertEquals("/admin", normalizePath("/a/../admin"))
        assertEquals("/admin", normalizePath("//admin"))
        assertEquals("/admin", normalizePath("/%61dmin"))
        assertEquals("/a/b/", normalizePath("/a/./b/"))
        assertEquals("/", normalizePath("/../.."))
        assertEquals("/a+b", normalizePath("/a+b"))
        assertEquals("/admin/secret", normalizePath("/admin;x/secret"), "Path parameters do not hide a rule")
        assertEquals("/.kovexy/x", normalizePath("/.kovexy;a/x"))
        assertFalse(isValidPath("/%zz"))
        assertFalse(isValidPath("/a%00b"))
        assertTrue(isValidPath("/a%20b"))
        assertEquals("fe80::1", plainAddress("fe80::1%eth0"))
        assertEquals("::1", plainAddress("[::1]"))
    }

    @Test
    fun mostSpecificLocationWinsAtPathBoundaries() {
        val site = CompiledSite(SiteConfig(listOf("a.test"), locations = listOf(loc("/"), loc("/api"), loc("/api", MatchType.EXACT), loc("/api/v2"))))
        assertEquals("/", site.locationFor("/apix")?.path)
        assertEquals(MatchType.EXACT, site.locationFor("/api")?.match)
        assertEquals(MatchType.PREFIX, site.locationFor("/api/users")?.match)
        assertEquals("/api/v2", site.locationFor("/api/v2/x")?.path)
        assertEquals("/api", site.locationFor("/api/v22")?.path)
        assertNull(CompiledSite(SiteConfig(listOf("a.test"), locations = listOf(loc("/x")))).locationFor("/y"))
    }

    @Test
    fun stripsPrefixes() {
        assertEquals("/users", stripPrefix(loc("/api"), "/api/users", "/api/users"))
        assertEquals("/", stripPrefix(loc("/api"), "/api", "/api"))
        assertEquals("/%2561dmin", stripPrefix(loc("/api"), "/%61pi/%2561dmin", normalizePath("/%61pi/%2561dmin")), "Never decoded twice")
        assertEquals("/a%3Fb", stripPrefix(loc("/api"), "/%61pi/a%3Fb", normalizePath("/%61pi/a%3Fb")), "An encoded ? stays encoded")
        assertEquals("/a%20b", stripPrefix(loc("/api"), "/api/a%20b", "/api/a b"))
        assertEquals("/x", stripPrefix(loc("/"), "/x", "/x"))
    }

    @Test
    fun headerRules() {
        val (rules, problems) = parseHeaderRules("h", "set X-A: 1\nadd X-B: 2\nremove Server\nbogus")
        assertEquals(3, rules.size)
        assertEquals(1, problems.size)
        val list = HeaderList(listOf("Server" to "nginx", "X-A" to "0", "Connection" to "close, X-Secret", "X-Secret" to "s", "Upgrade" to "h2c"))
        list.apply(rules)
        list.removeHopByHop()
        assertEquals(listOf("X-A" to "1", "X-B" to "2"), list.entries)
        val spoofed = HeaderList(listOf("X_Forwarded_User" to "admin", "x_real_ip" to "10.0.0.1", "X-Other" to "kept"))
        spoofed.remove("X-Forwarded-User")
        spoofed.remove("X-Real-IP")
        assertEquals(listOf("X-Other" to "kept"), spoofed.entries, "Underscore spellings are removed too, CGI servers read them as the same header")
    }

    @Test
    fun exploitPatternsAreLinear() {
        assertEquals("sql injection", matchCommonExploit("id=1 union all select password from users", ""))
        assertEquals("sql injection", matchCommonExploit("q=union%20select%20x(", ""))
        assertEquals("common exploit", matchCommonExploit("q=%3Cscript%3Ealert(1)%3C/script%3E", ""))
        assertEquals("common exploit", matchCommonExploit("x=base64_decode(abc)", ""))
        assertNull(matchCommonExploit("q=<scr\nipt>", ""), "Like the regex, the parts must be on one line")
        assertNull(matchCommonExploit("q=selection union", ""))
        val started = System.nanoTime()
        assertNull(matchCommonExploit("<script".repeat(2300), ""))
        assertNull(matchCommonExploit("unionselect".repeat(1500), ""))
        assertTrue(System.nanoTime() - started < 500_000_000, "16 KiB of crafted query takes milliseconds, not minutes")
    }
}

class NetTest {
    @Test
    fun cidrRanges() {
        val range = Cidr.parse("192.168.1.0/24")!!
        assertTrue(range.contains(InetAddress.getByName("192.168.1.77")))
        assertFalse(range.contains(InetAddress.getByName("192.168.2.1")))
        assertTrue(Cidr.parse("fd00::/8")!!.contains(InetAddress.getByName("fd12::1")))
        assertTrue(Cidr.parse("10.0.0.1")!!.contains(InetAddress.getByName("10.0.0.1")))
        assertNull(Cidr.parse("example.com"))
        assertNull(Cidr.parse("10.0.0.0/33"))
    }

    @Test
    fun hostPorts() {
        assertEquals(HostPort("127.0.0.1", 8080), HostPort.parse("127.0.0.1:8080"))
        assertEquals(HostPort("::1", 80), HostPort.parse("[::1]:80"))
        assertEquals("[::1]:80", HostPort("::1", 80).toString())
        assertEquals(HostPort("app.lan", 3000), HostPort.parse("app.lan:3000"))
        assertNull(HostPort.parse("app.lan"))
        assertNull(HostPort.parse("app.lan:0"))
        assertNull(HostPort.parse("::1:80"))
    }

    @Test
    fun visitorAddressOnlyFromTrustedProxies() {
        val trusted = listOf(Cidr.parse("10.0.0.0/8")!!)
        assertEquals("1.2.3.4", visitorIp("1.2.3.4", listOf("6.6.6.6"), trusted))
        assertEquals("6.6.6.6", visitorIp("10.0.0.2", listOf("6.6.6.6, 10.0.0.5"), trusted))
    }
}

class PasswordTest {
    @Test
    fun argon2Hashes(): Unit = run {
        val hash = hashPassword("correct horse")
        assertTrue(hash.startsWith("\$argon2id\$v=19\$m=65536,t=3,p=1\$"))
        assertTrue(isValidPasswordHash(hash))
        assertTrue(verifyPassword("correct horse", hash))
        assertFalse(verifyPassword("wrong", hash))
        assertFalse(isValidPasswordHash(hash.replace("m=65536", "m=99999999")), "Parameters that would exhaust the heap are refused")
        assertFalse(verifyPassword("x", "plain"))
    }

    @Test
    fun lockout() {
        var now = 0L
        val throttle = LoginThrottle { now }
        repeat(4) { assertNull(throttle.begin("1.1.1.1")) }
        assertNull(throttle.lockedUntil("1.1.1.1"))
        assertNull(throttle.begin("1.1.1.1"), "The fifth attempt still runs")
        assertNotNull(throttle.lockedUntil("1.1.1.1"))
        assertNotNull(throttle.begin("1.1.1.1"), "Then it is locked")
        assertNull(throttle.lockedUntil("2.2.2.2"))
        now += 16.minutes.inWholeMilliseconds
        assertNull(throttle.lockedUntil("1.1.1.1"))
        assertNull(throttle.begin("1.1.1.1"))
        throttle.success("1.1.1.1")
        repeat(5) { throttle.begin("2001:db8::1") }
        assertNotNull(throttle.lockedUntil("2001:db8::ffff"), "IPv6 counts per /64")
        assertNull(throttle.lockedUntil("2001:db8:0:1::1"))
    }

    private fun run(block: () -> Unit) = block()
}

class CertificateTest {
    @Test
    fun storeRoundTrip() {
        val dir = Files.createTempDirectory("kovexy-certs").toFile()
        val store = CertStore(dir)
        val fallback = store.loadOrCreateFallback()
        val again = CertStore(dir).loadOrCreateFallback()
        assertEquals(fallback.leaf, again.leaf, "The fallback is read back, not created twice")
        assertEquals(fallback.key.encoded.toList(), again.key.encoded.toList())
        val account = store.loadOrCreateAccountKey()
        assertEquals(account.public, CertStore(dir).loadOrCreateAccountKey().public)
        val issued = FakeIssuer().issue("a.test", "x")
        store.save("a.test", issued)
        assertEquals(issued.leaf, store.load("a.test")!!.leaf)
        assertEquals(listOf("a.test"), store.storedDomains())
        assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(File(dir, "a.test/privkey.pem").toPath())))
        dir.deleteRecursively()
    }

    @Test
    fun renewalBackoffAndStaging() {
        val dir = Files.createTempDirectory("kovexy-certs").toFile()
        val store = CertStore(dir)
        val fallback = store.loadOrCreateFallback()
        val keyManager = DynamicKeyManager(fallback.key, fallback.chain)
        var now = System.currentTimeMillis()
        val issuer = FakeIssuer(fail = true)
        val events = mutableListOf<Event>()
        val manager = CertificateManager(store, keyManager, issuer, { events += it }, { LETS_ENCRYPT_PRODUCTION }) { now }
        assertEquals(kotlin.time.Duration.parse("6h"), RETRY_INTERVALS.last(), "Exactly Caddy's retryIntervals, ending at 6 hours")
        manager.setWanted(setOf("a.test"))
        manager.maintain()
        assertEquals(listOf("a.test" to LETS_ENCRYPT_PRODUCTION), issuer.calls)
        assertEquals(WebhookEvent.CERT_FAILED, events.single().type)
        manager.maintain()
        assertEquals(1, issuer.calls.size, "No retry before the backoff has passed")
        now += RETRY_INTERVALS.first().inWholeMilliseconds
        issuer.fail = false
        manager.maintain()
        assertEquals(listOf(LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING, LETS_ENCRYPT_PRODUCTION), issuer.calls.map { it.second }, "Retries go to staging first")
        assertNotNull(keyManager.certificateOf("a.test"))
        assertEquals(WebhookEvent.CERT_ISSUED, events.last().type)

        // Renewal in the last third of the lifetime
        issuer.calls.clear()
        val lifetime = 90.days.inWholeMilliseconds
        now = keyManager.certificateOf("a.test")!!.notBefore.time + lifetime / 2
        manager.maintain()
        assertTrue(issuer.calls.isEmpty())
        now = keyManager.certificateOf("a.test")!!.notBefore.time + lifetime * 2 / 3 + 1000
        manager.maintain()
        assertEquals(1, issuer.calls.size)
        dir.deleteRecursively()
    }

    @Test
    fun expiredCertificatesOfUnusedDomainsAreRemoved() {
        val dir = Files.createTempDirectory("kovexy-certs").toFile()
        val store = CertStore(dir)
        val fallback = store.loadOrCreateFallback()
        store.loadOrCreateAccountKey()
        val keyManager = DynamicKeyManager(fallback.key, fallback.chain)
        var now = System.currentTimeMillis()
        val removed = mutableListOf<String>()
        val manager = CertificateManager(store, keyManager, FakeIssuer(), {}, { LETS_ENCRYPT_PRODUCTION }, onRemoved = { removed += it }) { now }
        manager.setWanted(setOf("a.test", "b.test"))
        manager.maintain()
        assertEquals(listOf("a.test", "b.test"), store.storedDomains())

        manager.setWanted(setOf("a.test"))
        manager.maintain()
        assertNotNull(keyManager.certificateOf("b.test"), "An unused certificate stays while it is valid")
        assertTrue("b.test" in store.storedDomains())

        now = keyManager.certificateOf("b.test")!!.notAfter.time + 1000
        manager.setWanted(setOf("a.test"))
        manager.maintain()
        assertNull(keyManager.certificateOf("b.test"))
        assertEquals(listOf("a.test"), store.storedDomains(), "Only the expired unused one is gone")
        assertEquals(listOf("b.test"), removed)
        assertTrue(File(dir, "fallback").isDirectory && store.accountKeyFile.isFile, "Fallback and ACME account stay")
        dir.deleteRecursively()
    }
}

class WebhookTest {
    @Test
    fun templateValuesAreJsonEscaped() {
        val event = Event(WebhookEvent.UPSTREAM_DOWN, "Quote \" and\nnewline", "body", "a.test", 0)
        val text = fillTemplate("""{"subject": "{{subject}}", "event": "{{event}}", "site": "{{site}}"}""", event)
        val json = Json.parseToJsonElement(text).toString()
        assertTrue(json.contains("upstreamDown"))
        assertTrue(text.contains("Quote \\\" and\\nnewline"))
    }

    @Test
    fun bundlesLoginFailures(): Unit = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val sent = java.util.Collections.synchronizedList(mutableListOf<String>())
        val hook = WebhookConfig("t", "http://127.0.0.1:9", events = listOf(WebhookEvent.ADMIN_LOGIN_FAILED, WebhookEvent.CERT_FAILED), bundleWindow = 1.seconds,
            template = "{{subject}}")
        val webhooks = Webhooks(scope, { listOf(hook) }) { _, body -> sent += body; 200 }
        repeat(5) { webhooks.emit(Event(WebhookEvent.ADMIN_LOGIN_FAILED, "Failed admin login from 1.1.1.$it", "", time = 0, item = "1.1.1.$it")) }
        webhooks.emit(Event(WebhookEvent.UPSTREAM_DOWN, "not selected", "", time = 0))
        webhooks.emit(Event(WebhookEvent.CERT_FAILED, "single", "", time = 0))
        delay(1500)
        assertEquals(setOf("Failed admin login from 1.1.1.0", "4 more failed admin logins", "single"), sent.toSet())
        scope.cancel()
    }
}
