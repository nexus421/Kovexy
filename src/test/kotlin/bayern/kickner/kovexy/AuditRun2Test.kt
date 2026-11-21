package bayern.kickner.kovexy

import bayern.kickner.kovexy.access.BasicAuthChecker
import bayern.kickner.kovexy.access.CaptchaSessions
import bayern.kickner.kovexy.access.Signer
import bayern.kickner.kovexy.access.isForeignInitiated
import bayern.kickner.kovexy.access.matchCommonExploit
import bayern.kickner.kovexy.auth.LoginThrottle
import bayern.kickner.kovexy.auth.hashBcrypt
import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.BasicAuthConfig
import bayern.kickner.kovexy.config.BasicAuthUser
import bayern.kickner.kovexy.config.checkAbsoluteUrl
import bayern.kickner.kovexy.config.parseConfig
import bayern.kickner.kovexy.incus.IncusDecision
import bayern.kickner.kovexy.incus.IncusState
import bayern.kickner.kovexy.incus.buildClaims
import bayern.kickner.kovexy.incus.incusTarget
import bayern.kickner.kovexy.incus.parseInstances
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.proxy.HeaderList
import bayern.kickner.kovexy.proxy.setForwarded
import bayern.kickner.kovexy.proxy.certificateMatchesHost
import bayern.kickner.kovexy.proxy.isKovexyBasicCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import bayern.kickner.kovexy.proxy.MAX_WEBSOCKETS
import bayern.kickner.kovexy.proxy.MAX_WEBSOCKETS_PER_ADDRESS
import bayern.kickner.kovexy.proxy.WebSocketRegistry
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Regression tests for the findings of the second security audit (run 2, 19.11.2026). */
class AuditRun2Test {

    @Test
    fun foreignInitiatedRequests() {
        assertFalse(isForeignInitiated("a.test", null, null, null), "A scanner sends none of the headers")
        assertFalse(isForeignInitiated("a.test", "none", null, null), "Typed into the address bar")
        assertFalse(isForeignInitiated("a.test", "same-origin", "https://a.test", "https://a.test/x"))
        assertTrue(isForeignInitiated("a.test", "cross-site", null, null))
        assertTrue(isForeignInitiated("a.test", "same-site", null, null), "Another subdomain may belong to somebody else")
        assertTrue(isForeignInitiated("a.test", null, null, "https://evil.example/page"))
        assertTrue(isForeignInitiated("a.test", null, "null", null), "Opaque origin, e.g. a sandboxed frame")
        assertTrue(isForeignInitiated("a.test", null, null, "::garbage::"))
        // Over plain HTTP browsers send no Sec-Fetch headers and a page can suppress the Referer
        assertTrue(isForeignInitiated("a.test", null, null, null, https = false, accept = "image/avif,image/webp,*/*"))
        assertTrue(isForeignInitiated("a.test", null, null, null, https = false, accept = "text/html,application/xhtml+xml"))
        assertFalse(isForeignInitiated("a.test", null, null, null, https = false, accept = "*/*"), "curl and scanners")
        assertFalse(isForeignInitiated("a.test", null, null, null, https = true, accept = "text/html"), "Over HTTPS the fetch headers decide")
    }

    @Test
    fun throttleScopesAreIndependent() {
        val throttle = LoginThrottle { 0L }
        repeat(5) { throttle.begin("1.1.1.1", "low") }
        assertNotNull(throttle.lockedUntil("1.1.1.1", "low"))
        assertNull(throttle.lockedUntil("1.1.1.1", "high"), "Another profile is not locked")
        assertNull(throttle.lockedUntil("1.1.1.1"), "Nor the admin login")
    }

    @Test
    fun basicAuthRememberedLoginSurvivesOthersFailures(): Unit = runBlocking {
        val checker = BasicAuthChecker { 0L }
        val config = BasicAuthConfig(users = listOf(BasicAuthUser("bob", hashBcrypt("bob-password"))))
        fun header(user: String, password: String) = "Basic " + Base64.getEncoder().encodeToString("$user:$password".toByteArray())
        val ok = checker.check(config, header("bob", "bob-password"), "2001:db8::1", "p")
        assertTrue(ok.toString().startsWith("Ok"), ok.toString())
        // A neighbour in the same /64 tries five wrong passwords
        repeat(5) { checker.check(config, header("bob", "wrong$it"), "2001:db8::2", "p") }
        assertEquals("Locked", checker.check(config, header("bob", "x"), "2001:db8::2", "p").toString())
        assertTrue(checker.check(config, header("bob", "bob-password"), "2001:db8::1", "p").toString().startsWith("Ok"), "The remembered login still passes")
        // A user whose login is not remembered: the lockout of profile p does not reach profile other
        val carol = BasicAuthConfig(users = listOf(BasicAuthUser("carol", hashBcrypt("carol-password"))))
        assertEquals("Locked", checker.check(carol, header("carol", "carol-password"), "2001:db8::2", "p").toString())
        assertTrue(checker.check(carol, header("carol", "carol-password"), "2001:db8::2", "other").toString().startsWith("Ok"), "Another profile is not locked")
    }

    @Test
    fun parallelBasicAuthRequestsShareOneCheck(): Unit = runBlocking {
        val checker = BasicAuthChecker { 0L }
        val config = BasicAuthConfig(users = listOf(BasicAuthUser("bob", hashBcrypt("bob-password"))))
        val header = "Basic " + Base64.getEncoder().encodeToString("bob:bob-password".toByteArray())
        // More than BASIC_AUTH_CONCURRENT_CHECKS at once, like a page with many requests after the cache ran out
        val results = (1..20).map { async(Dispatchers.Default) { checker.check(config, header, "10.0.0.1", "p") } }.awaitAll()
        assertTrue(results.all { it.toString().startsWith("Ok") }, results.toString())
    }

    @Test
    fun webSocketPlacesAreReservedAtomically() {
        val registry = WebSocketRegistry()
        repeat(MAX_WEBSOCKETS_PER_ADDRESS) { assertTrue(registry.reserve("a")) }
        assertFalse(registry.reserve("a"), "The address is full")
        assertTrue(registry.reserve("b"))
        registry.release("a")
        assertTrue(registry.reserve("a"), "A released place can be taken again")
        repeat(MAX_WEBSOCKETS - MAX_WEBSOCKETS_PER_ADDRESS - 1) { registry.reserve(null) }
        assertFalse(registry.reserve("c"), "All places are taken")
    }

    @Test
    fun kovexyBasicCredentialIsRecognized() {
        val profile = AccessProfile("p", basicAuth = BasicAuthConfig(users = listOf(BasicAuthUser("bob", "x"))))
        fun header(user: String) = "Basic " + Base64.getEncoder().encodeToString("$user:pw".toByteArray())
        assertTrue(isKovexyBasicCredential(header("bob"), listOf(null, profile)))
        assertFalse(isKovexyBasicCredential(header("alice"), listOf(profile)), "An app's own Basic Auth user passes")
        assertFalse(isKovexyBasicCredential("Bearer abc", listOf(profile)))
        assertFalse(isKovexyBasicCredential(header("bob"), listOf(null)))
    }

    @Test
    fun captchaSessionsAreBounded() {
        var now = 0L
        val sessions = CaptchaSessions(max = 3) { now }
        val ids = (1..5).map { sessions.create("p|a.test", 3_600_000) }
        assertEquals(3, sessions.size)
        assertFalse(sessions.isValid(ids[0], "p|a.test"), "The oldest went first")
        assertTrue(sessions.isValid(ids[4], "p|a.test"))
        now += 3_600_001
        sessions.create("p|a.test", 1000)
        assertEquals(1, sessions.size, "Expired ones are purged")
    }

    @Test
    fun fileInjectionPatternsDoNotOverflowTheStack() {
        assertEquals("file injection", matchCommonExploit("a=" + "/a".repeat(8000), ""))
        assertEquals("file injection", matchCommonExploit("a=" + "../".repeat(5000), ""))
        assertNull(matchCommonExploit("a=b&c=d", ""))
    }

    @Test
    fun identityHeadersAreRemovedInEverySpelling() {
        val headers = HeaderList(listOf("X.Forwarded.User" to "admin", "x_forwarded-user" to "admin", "X+Forwarded+User" to "admin", "X-Other" to "ok"))
        headers.remove("X-Forwarded-User")
        assertEquals(listOf("X-Other" to "ok"), headers.entries)
    }

    @Test
    fun rejectedUrlsAreNotEchoed() {
        val message = checkAbsoluteUrl("webhooks[0].url", "ftp://hooks.example/secret-token?key=abc", { true })!!
        assertFalse("secret-token" in message || "abc" in message, message)
        assertTrue("ftp://hooks.example" in message, message)
    }

    @Test
    fun captchaExceptionNeedsAPathAndSessionsAnEnd() {
        fun profile(captcha: String) = """{ "accessProfiles": [ { "name": "p", "captcha": { "siteKey": "k", "secretKey": "s", $captcha } } ] }"""
        val empty = parseConfig(profile(""""exceptions": [ { "pathPrefix": "" } ]"""))
        assertTrue(empty is ResultOf2.Failure && empty.value.any { "must start with /" in it }, empty.toString())
        val long = parseConfig(profile(""""sessionDuration": "60d""""))
        assertTrue(long is ResultOf2.Failure && long.value.any { "sessionDuration" in it }, long.toString())
        assertTrue(parseConfig(profile(""""exceptions": [ { "pathPrefix": "/api" } ]""")) is ResultOf2.Success)
    }

    @Test
    fun unapprovedIncusClaimDoesNotDisableAnApprovedRoute() {
        bayern.kickner.kovexy.incus.incusAddressAllowed = { true }
        val body = FakeIncus.instancesJson(
            FakeIncus.instance("web1", keys = mapOf("domains" to "app.test", "port" to "8080")),
            FakeIncus.instance("intruder", keys = mapOf("domains" to "app.test", "port" to "80")),
        )
        val instances = parseInstances(body, "eth0")
        val approved = IncusDecision("default", "web1", listOf("app.test"), true, 0, incusTarget("127.0.0.1", 8080, false, null))
        val claims = buildClaims(instances, listOf(approved), KovexyConfig())
        assertTrue(claims.first { it.id == "default/web1" }.live, claims.toString())
        val intruder = claims.first { it.id == "default/intruder" }
        assertEquals(IncusState.DETECTED, intruder.state)
        assertTrue(intruder.problems.any { "claimed by another container" in it }, "The unapproved claim gets the warning")
        val rejected = buildClaims(instances, listOf(approved, IncusDecision("default", "intruder", listOf("app.test"), false, 0)), KovexyConfig())
        assertTrue(rejected.first { it.id == "default/web1" }.live, "A rejected claim does not disable it either")
    }

    @Test
    fun backendCertificatesMustNameTheHost() {
        fun cert(vararg names: GeneralName): X509Certificate {
            val pair = bayern.kickner.kovexy.tls.newEcKeyPair()
            val name = X500Name("CN=evil.example")
            val builder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, Date(), Date(System.currentTimeMillis() + 3_600_000), name, pair.public)
            if (names.isNotEmpty()) builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(names))
            return JcaX509CertificateConverter().getCertificate(builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private)))
        }
        val dns = cert(GeneralName(GeneralName.dNSName, "app.example"), GeneralName(GeneralName.dNSName, "*.lan.example"))
        assertTrue(certificateMatchesHost(dns, "app.example"))
        assertTrue(certificateMatchesHost(dns, "APP.example"))
        assertTrue(certificateMatchesHost(dns, "nas.lan.example"))
        assertFalse(certificateMatchesHost(dns, "a.b.lan.example"), "A wildcard stands for one label")
        assertFalse(certificateMatchesHost(dns, "other.example"))
        assertFalse(certificateMatchesHost(dns, "192.168.1.10"), "An IP needs an IP entry")
        val ip = cert(GeneralName(GeneralName.iPAddress, "192.168.1.10"))
        assertTrue(certificateMatchesHost(ip, "192.168.1.10"))
        assertFalse(certificateMatchesHost(ip, "192.168.1.11"))
        assertFalse(certificateMatchesHost(ip, "app.example"), "A name needs a DNS entry")
        assertFalse(certificateMatchesHost(cert(), "evil.example"), "The common name does not count")
    }
}

/** The decisions of 19.11.2026 on the open points R1 to S7. */
class DecisionsTest {
    @Test
    fun otherForwardingHeadersPassLikeCaddy() {
        val headers = HeaderList(listOf("X-Real-IP" to "10.9.9.9", "Forwarded" to "for=10.9.9.9", "X-Forwarded-For" to "10.9.9.9", "X-Forwarded-Port" to "8443"))
        headers.setForwarded("203.0.113.5", "https", "a.test", trusted = false)
        assertEquals("203.0.113.5", headers["X-Forwarded-For"], "X-Forwarded-For is always Kovexy's")
        assertEquals("10.9.9.9", headers["X-Real-IP"], "R1: passes unchanged like in Caddy")
        assertEquals("for=10.9.9.9", headers["Forwarded"])
        assertEquals("8443", headers["X-Forwarded-Port"])
    }

    @Test
    fun startStopsWhenTheAdminAddressIsTaken() {
        java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress()).use { taken ->
            val failure = runCatching { Harness("""{ "admin": { "port": ADMIN_PORT } }""", adminPort = taken.localPort).close() }.exceptionOrNull()
            assertNotNull(failure, "R5: Kovexy does not start without its admin UI")
            assertTrue(generateSequence(failure) { it.cause }.any { it is java.net.BindException }, failure.toString())
        }
    }

    @Test
    fun forwardedUserIsSubAndEmailNeedsVerification() {
        fun token(vararg extra: Pair<String, Any>): String {
            val now = System.currentTimeMillis() / 1000
            val claims = mapOf("iss" to "https://idp.test", "aud" to "c", "exp" to now + 60, "iat" to now, "nonce" to "n", "sub" to "u-1", "email" to "a@x.test") + extra
            val json = claims.entries.joinToString(",", "{", "}") { (k, v) -> "\"$k\":" + if (v is String) "\"$v\"" else v.toString() }
            val b64 = Base64.getUrlEncoder().withoutPadding()
            return b64.encodeToString("{}".toByteArray()) + "." + b64.encodeToString(json.toByteArray()) + "."
        }
        fun claims(token: String) = (bayern.kickner.kovexy.auth.validateIdToken(token, "https://idp.test", "c", "n", System.currentTimeMillis() / 1000) as ResultOf2.Success).value
        assertNull(claims(token()).email, "S3: no email_verified, no email")
        assertNull(claims(token("email_verified" to false)).email)
        assertEquals("a@x.test", claims(token("email_verified" to true)).email)
        assertEquals("a@x.test", claims(token("email_verified" to "true")).email, "Some providers send a string")
    }

    @Test
    fun commandLineRefusesSymlinks() {
        val dir = java.nio.file.Files.createTempDirectory("kovexy-cli").toFile()
        try {
            val elsewhere = java.io.File(dir, "elsewhere.json").apply { writeText("{}") }
            java.nio.file.Files.createSymbolicLink(java.io.File(dir, "kovexy.json").toPath(), elsewhere.toPath())
            assertTrue(bayern.kickner.kovexy.config.ConfigStore(dir).read() is ResultOf2.Success, "The service follows links")
            assertTrue(bayern.kickner.kovexy.config.ConfigStore(dir, followLinks = false).read() is ResultOf2.Failure, "S4: the command line does not")
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun webSocketOriginHost() {
        assertEquals("a.test", bayern.kickner.kovexy.proxy.originHost("https://A.test"))
        assertEquals("a.test", bayern.kickner.kovexy.proxy.originHost("https://a.test:8443"))
        assertEquals("::1", bayern.kickner.kovexy.proxy.originHost("http://[::1]:80"))
        assertNull(bayern.kickner.kovexy.proxy.originHost("null"))
    }

    @Test
    fun webhookBundlesKeepAtMostHundredItems(): Unit = runBlocking {
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + Dispatchers.Default)
        val sent = java.util.Collections.synchronizedList(mutableListOf<String>())
        val hook = bayern.kickner.kovexy.config.WebhookConfig("t", "http://127.0.0.1:9", events = listOf(bayern.kickner.kovexy.config.WebhookEvent.ADMIN_LOGIN_FAILED),
            bundleWindow = kotlin.time.Duration.parse("1s"), template = "{{subject}}")
        val webhooks = bayern.kickner.kovexy.notify.Webhooks(scope, { listOf(hook) }) { _, body -> sent += body; 200 }
        repeat(1001) { webhooks.emit(bayern.kickner.kovexy.notify.Event(bayern.kickner.kovexy.config.WebhookEvent.ADMIN_LOGIN_FAILED, "x$it", "", time = 0, item = "x$it")) }
        kotlinx.coroutines.delay(1500)
        assertTrue("1000 more failed admin logins" in sent, sent.toString())
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
