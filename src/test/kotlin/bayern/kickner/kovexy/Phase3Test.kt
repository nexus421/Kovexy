package bayern.kickner.kovexy

import bayern.kickner.kovexy.access.CaptchaService
import bayern.kickner.kovexy.access.GoogleVerifier
import bayern.kickner.kovexy.access.Signer
import bayern.kickner.kovexy.access.safeReturnPath
import bayern.kickner.kovexy.audit.configDiff
import bayern.kickner.kovexy.config.CaptchaConfig
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.RecaptchaVersion
import bayern.kickner.kovexy.config.rootCheck
import bayern.kickner.kovexy.config.validateConfig
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
import java.nio.file.Files
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

/** Captcha building blocks without a server. */
class CaptchaUnitTest {
    @Test
    fun captchaPagesRender() {
        listOf("recaptcha2", "recaptcha3").forEach { provider ->
            val html = bayern.kickner.kovexy.site.captchaPage("tok", provider, "site-key")
            assertTrue(html.contains("kovexy-captcha") && html.contains("/.kovexy/captcha.js") && html.contains("site-key"), provider)
        }
        assertTrue(bayern.kickner.kovexy.proxy.CAPTCHA_POLICY.contains("https://www.gstatic.com/recaptcha/"))
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
            val v2 = CaptchaConfig("site", "the secret")
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
        val captcha = base.copy(accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig())))
        assertTrue(validateConfig(captcha).any { it.contains("siteKey") }, validateConfig(captcha).toString())
        val withSite = captcha.copy(accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig("k", "s"))), sites = listOf(bayern.kickner.kovexy.config.SiteConfig(listOf("a.test"), access = "c")))
        assertTrue(validateConfig(withSite).isEmpty(), "Every site is HTTPS only, so a captcha profile is fine on any site: ${validateConfig(withSite)}")
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
        val admin = bayern.kickner.kovexy.config.AdminConfig()
        val old = KovexyConfig(
            admin = admin.copy(oidc = bayern.kickner.kovexy.config.OidcConfig(issuer = "http://localhost:1", clientId = "id", clientSecret = "old-admin-secret")),
            accessProfiles = listOf(bayern.kickner.kovexy.config.AccessProfile("c", captcha = CaptchaConfig("site", "old-google-secret"))),
        )
        val new = old.copy(
            admin = old.admin.copy(oidc = old.admin.oidc!!.copy(clientSecret = "new-admin-secret")),
            accessProfiles = listOf(old.accessProfiles.first().copy(captcha = old.accessProfiles.first().captcha!!.copy(secretKey = "new-google-secret"))),
        )
        val diff = configDiff(old, new)
        listOf("old-admin-secret", "new-admin-secret", "old-google-secret", "new-google-secret").forEach { assertFalse(diff.contains(it), "No secret in the diff: $diff") }
        assertTrue(diff.contains("admin.oidc.clientSecret") && diff.contains("reCAPTCHA secret key in profile c"), diff)
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
                "sites": [ { "domains": ["a.test"], "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] } ] }"""
            Harness(config).use { h ->
                val socket = runCatching { trustAllContext.socketFactory.createSocket("::1", h.ports.https) }.getOrNull() ?: return@use
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
