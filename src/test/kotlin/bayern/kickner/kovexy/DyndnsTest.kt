package bayern.kickner.kovexy

import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.DomainConfig
import bayern.kickner.kovexy.config.DyndnsClient
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.RouteConfig
import bayern.kickner.kovexy.config.Target
import bayern.kickner.kovexy.config.validateConfig
import bayern.kickner.kovexy.dyndns.DyndnsStore
import bayern.kickner.kovexy.dyndns.addressesFromQuery
import bayern.kickner.kovexy.dyndns.parseReported
import bayern.kickner.kovexy.dyndns.withDyndnsAllowIps
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** DynDNS: address rules, merged allow lists and the `/nic/update` endpoint. */
class DyndnsTest {
    private fun ok(raw: String) = (parseReported(raw) as ResultOf2.Success).value

    private fun refused(raw: String) = assertTrue(parseReported(raw) is ResultOf2.Failure, "$raw should be refused")

    @Test
    fun reportedAddressRules(): Unit {
        assertEquals("1.2.3.4/32", ok("1.2.3.4").text)
        assertEquals("1.2.3.4", ok("1.2.3.4").display)
        assertEquals("2003:d5:df4a:a500::/56", ok("2003:d5:df4a:a5ff::1/56").text)
        assertEquals("2003:d5:df4a:a500::/56", ok("2003:d5:df4a:a500::/56").display)
        listOf("10.0.0.1", "203.0.113.5", "127.0.0.1", "1.2.3.0/24", "1.2.3", "", "fe80::1", "2001:db8::1", "2003:d5::/40", "example.com", "1.2.3.4%eth0").forEach(::refused)
    }

    @Test
    fun queryParameters(): Unit {
        val both = (addressesFromQuery(mapOf("myip" to "1.2.3.4,2003:d5:df4a:a500::/56")) as ResultOf2.Success).value!!
        assertEquals(listOf("1.2.3.4/32", "2003:d5:df4a:a500::/56"), both.map { it.text })
        assertEquals(listOf("1.2.3.4/32"), (addressesFromQuery(mapOf("ip" to "1.2.3.4")) as ResultOf2.Success).value!!.map { it.text })
        assertEquals(listOf("2003:d5:df4a:a500::/56"), (addressesFromQuery(mapOf("ipv6" to "2003:d5:df4a:a500::/56")) as ResultOf2.Success).value!!.map { it.text })
        assertNull((addressesFromQuery(mapOf("hostname" to "x")) as ResultOf2.Success).value)
        assertNull((addressesFromQuery(mapOf("myip" to "")) as ResultOf2.Success).value)
        assertTrue(addressesFromQuery(mapOf("myipv6" to "1.2.3.4")) is ResultOf2.Failure)
        assertTrue(addressesFromQuery(mapOf("myipv4" to "2003:d5:df4a:a500::/56")) is ResultOf2.Failure)
        assertTrue(addressesFromQuery(mapOf("myip" to "1.2.3.4,5.6.7.8")) is ResultOf2.Failure)
    }

    private val hash = sha256Hex("secret")

    private fun client(name: String, vararg profiles: String) = DyndnsClient(name, hash, profiles.toList())

    private fun problems(config: KovexyConfig) = validateConfig(config).joinToString("\n")

    @Test
    fun validation(): Unit {
        val base = KovexyConfig(admin = bayern.kickner.kovexy.config.AdminConfig(passwordHash = hashPassword("x".repeat(16))), accessProfiles = listOf(AccessProfile("p")))
        assertEquals("", problems(base.copy(dyndnsClients = listOf(client("home", "p")))))
        assertTrue("used more than once" in problems(base.copy(dyndnsClients = listOf(client("home", "p"), client("home", "p")))))
        assertTrue("dyndnsClients[0].name" in problems(base.copy(dyndnsClients = listOf(client("bad name", "p")))))
        assertTrue("at least one access profile" in problems(base.copy(dyndnsClients = listOf(client("home")))))
        assertTrue("\"gone\" is no access profile" in problems(base.copy(dyndnsClients = listOf(client("home", "gone")))))
        assertTrue("passwordHash" in problems(base.copy(dyndnsClients = listOf(DyndnsClient("home", "plain", listOf("p"))))))
        val routes = listOf(RouteConfig("/", target = Target.Deny()))
        assertTrue("answers only /nic/update" in problems(base.copy(domains = listOf(DomainConfig(listOf("dyn.test"), routes = routes, dyndns = true)))))
    }

    @Test
    fun mergedAllowList(): Unit {
        val dir = Files.createTempDirectory("dyndns-test").toFile()
        try {
            val file = File(dir, "state.json")
            val store = DyndnsStore(file)
            val config = KovexyConfig(accessProfiles = listOf(AccessProfile("p", allowIps = listOf("10.0.0.0/8")), AccessProfile("q")), dyndnsClients = listOf(client("a", "p"), client("b", "p")))
            fun report(name: String, vararg raw: String) = (store.report(name, raw.map { ok(it) }) as ResultOf2.Success).value
            assertTrue(report("a", "1.2.3.4"))
            assertTrue(report("b", "1.2.3.4", "2003:d5:df4a:a5ff::1/56"))
            report("ghost", "5.6.7.8")
            fun allow(c: KovexyConfig = config) = withDyndnsAllowIps(c, store).accessProfiles.associate { it.name to it.allowIps }
            assertEquals(listOf("10.0.0.0/8", "1.2.3.4/32", "2003:d5:df4a:a500::/56"), allow()["p"])
            assertEquals(emptyList(), allow()["q"])
            assertTrue(report("b", "2003:d5:df4a:a5ff::1/56"))
            assertEquals(listOf("10.0.0.0/8", "1.2.3.4/32", "2003:d5:df4a:a500::/56"), allow()["p"], "a still reports 1.2.3.4")
            assertTrue(report("b", "2003:d5:df4a:a5ff::1/56").not(), "same addresses are no change")
            assertEquals(listOf("10.0.0.0/8", "1.2.3.4/32"), allow(config.copy(dyndnsClients = listOf(client("a", "p"))))["p"], "a removed client drops out")
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath())))
            assertEquals("1.2.3.4/32", DyndnsStore(file).lastReport("a")?.ipv4)
            file.writeText("{ broken")
            assertNull(DyndnsStore(file).lastReport("a"))
        } finally {
            dir.deleteRecursively()
        }
    }

    private val endpointConfig = """
        { "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword("test password 123")}" },
          "accessProfiles": [ { "name": "p", "allowIps": ["192.0.2.1"] } ],
          "dyndnsClients": [ { "name": "home", "passwordHash": "$hash", "profiles": ["p"] } ],
          "domains": [ { "names": ["dyn.test"], "dyndns": true }, { "names": ["app.test"], "access": "p", "routes": [ { "path": "/", "target": { "type": "deny" } } ] } ] }
    """.trimIndent()

    private fun basic(password: String, user: String = "home") = "Authorization" to "Basic " + Base64.getEncoder().encodeToString("$user:$password".toByteArray())

    @Test
    fun updateEndpoint(): Unit {
        Harness(endpointConfig).use { h ->
            fun get(path: String, vararg headers: Pair<String, String>, method: String = "GET") = h.https("dyn.test", path, method = method, headers = headers.toList())
            val first = get("/nic/update?hostname=x&myip=1.2.3.4", basic("secret"))
            assertEquals(200, first.status)
            assertEquals("good 1.2.3.4", first.text)
            assertEquals("nochg 1.2.3.4", get("/nic/update?myip=1.2.3.4", basic("secret")).text)
            assertTrue("1.2.3.4/32" in h.kovexy.routing.profile("p")!!.allowIps, "the report is on the allow list")
            assertTrue("192.0.2.1" in h.kovexy.routing.profile("p")!!.allowIps)
            assertEquals(listOf("192.0.2.1"), h.kovexy.config.accessProfiles.single().allowIps, "the config itself is not changed")
            val wrong = get("/nic/update?myip=1.2.3.4", basic("nope"))
            assertEquals(401, wrong.status)
            assertEquals("badauth", wrong.text)
            assertTrue(wrong.header("www-authenticate")!!.startsWith("Basic"))
            assertEquals(401, get("/nic/update?myip=1.2.3.4").status)
            assertEquals(401, get("/nic/update?myip=1.2.3.4", basic("secret", user = "other")).status)
            assertTrue(get("/nic/update?myip=10.0.0.1", basic("secret")).text.startsWith("badrequest"))
            assertEquals(400, get("/nic/update?myip=%zz", basic("secret")).status)
            assertEquals(404, get("/other", basic("secret")).status)
            assertEquals(404, get("/", basic("secret")).status)
            val post = get("/nic/update?myip=1.2.3.4", basic("secret"), method = "POST")
            assertEquals(405, post.status)
            assertEquals("GET", post.header("allow"), "a 405 names the allowed method")
            // No address parameter: the source address counts, here loopback, which is refused
            assertTrue(get("/nic/update", basic("secret")).text.startsWith("badrequest"))
            assertEquals("1.2.3.4/32", h.kovexy.dyndns.lastReport("home")?.ipv4, "refused updates change nothing")
            // The domain with a profile still obeys it
            assertEquals(403, h.https("app.test", "/").status)
        }
    }

    @Test
    fun adminPage(): Unit {
        Harness(endpointConfig).use { h ->
            val origin = "http://127.0.0.1:${h.adminPort}"
            val host = "127.0.0.1:${h.adminPort}"
            fun form(vararg fields: Pair<String, String>) = fields.joinToString("&") { (k, v) -> java.net.URLEncoder.encode(k, Charsets.UTF_8) + "=" + java.net.URLEncoder.encode(v, Charsets.UTF_8) }.toByteArray()
            fun post(path: String, body: ByteArray, cookie: String? = null) = rawRequest(
                h.adminPort, host, path, method = "POST", body = body,
                headers = listOfNotNull("Content-Type" to "application/x-www-form-urlencoded", "Origin" to origin, cookie?.let { "Cookie" to it }),
            )
            val cookie = post("/login", form("password" to "test password 123")).headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-session=") }.substringBefore(';')
            fun get(path: String) = rawRequest(h.adminPort, host, path, headers = listOf("Cookie" to cookie))

            assertTrue("No clients yet" !in get("/dyndns").text)
            val created = post("/dyndns/new", form("version" to h.store.current.version, "name" to "router", "profile.p" to "on"), cookie)
            assertEquals(200, created.status, created.text)
            val password = Regex(">([0-9a-f]{48})<").find(created.text)?.groupValues?.get(1)
            assertTrue(password != null, "the password is shown once: ${created.text.take(400)}")
            val stored = h.kovexy.config.dyndnsClients.single { it.name == "router" }
            assertEquals(sha256Hex(password!!), stored.passwordHash)
            assertEquals(listOf("p"), stored.profiles)
            assertTrue(password !in get("/dyndns").text && password !in get("/dyndns/router").text, "the password is never shown again")
            assertTrue("router" in get("/dyndns").text)
            // The new client works on the endpoint
            assertEquals("good 8.8.8.8", h.https("dyn.test", "/nic/update?myip=8.8.8.8", headers = listOf(basic(password, "router"))).text)
            assertTrue("8.8.8.8" in get("/dyndns").text, "the list shows the reported address")
            // Name "new" and a duplicate are refused
            assertEquals(400, post("/dyndns/new", form("version" to h.store.current.version, "name" to "router", "profile.p" to "on"), cookie).status)
            assertEquals(400, post("/dyndns/new", form("version" to h.store.current.version, "name" to "new", "profile.p" to "on"), cookie).status)
            // A new password replaces the old one
            val renewed = post("/dyndns/router/password", form("version" to h.store.current.version), cookie)
            assertEquals(200, renewed.status)
            assertEquals(401, h.https("dyn.test", "/nic/update?myip=8.8.8.8", headers = listOf(basic(password, "router"))).status)
            // Delete removes the client and its addresses
            assertEquals(302, post("/dyndns/router/delete", form("version" to h.store.current.version), cookie).status)
            assertTrue(h.kovexy.config.dyndnsClients.none { it.name == "router" })
            assertTrue("8.8.8.8/32" !in h.kovexy.routing.profile("p")!!.allowIps)
            // The domain form saves the flag and refuses routes next to it
            val domain = post("/domains/new", form("version" to h.store.current.version, "names" to "dyn2.test", "enabled" to "on", "dyndns" to "on", "rootBackend" to ""), cookie)
            assertEquals(302, domain.status, domain.text)
            assertTrue(h.kovexy.config.domains.last().dyndns)
        }
    }

    /** Logs in to the admin UI of [h] and offers form posts and pages with the session. */
    private class Admin(val h: Harness) {
        private val origin = "http://127.0.0.1:${h.adminPort}"
        private val host = "127.0.0.1:${h.adminPort}"

        fun form(vararg fields: Pair<String, String>) = fields.joinToString("&") { (k, v) -> java.net.URLEncoder.encode(k, Charsets.UTF_8) + "=" + java.net.URLEncoder.encode(v, Charsets.UTF_8) }.toByteArray()

        private fun rawPost(path: String, body: ByteArray, cookie: String?) = rawRequest(
            h.adminPort, host, path, method = "POST", body = body,
            headers = listOfNotNull("Content-Type" to "application/x-www-form-urlencoded", "Origin" to origin, cookie?.let { "Cookie" to it }),
        )

        private val cookie = rawPost("/login", form("password" to "test password 123"), null).headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-session=") }.substringBefore(';')

        fun post(path: String, vararg fields: Pair<String, String>) = rawPost(path, form("version" to h.store.current.version, *fields), cookie)

        fun get(path: String) = rawRequest(h.adminPort, host, path, headers = listOf("Cookie" to cookie))
    }

    @Test
    fun renamingAProfileKeepsItsClients(): Unit {
        Harness(endpointConfig).use { h ->
            val renamed = Admin(h).post("/access/p", "name" to "q", "allowIps" to "192.0.2.1", "banDuration" to "1h", "method.GET" to "on")
            assertEquals(302, renamed.status, renamed.text)
            assertEquals(listOf("q"), h.kovexy.config.dyndnsClients.single().profiles)
        }
    }

    @Test
    fun profileListNamesItsClients(): Unit {
        Harness(endpointConfig).use { h ->
            assertTrue("DynDNS client home" in Admin(h).get("/access").text)
        }
    }

    @Test
    fun readdedClientStartsWithoutAddresses(): Unit {
        Harness(endpointConfig).use { h ->
            val admin = Admin(h)
            assertEquals("good 8.8.8.8", h.https("dyn.test", "/nic/update?myip=8.8.8.8", headers = listOf(basic("secret"))).text)
            assertEquals(302, admin.post("/dyndns/home/delete").status)
            assertEquals(200, admin.post("/dyndns/new", "name" to "home", "profile.p" to "on").status)
            assertNull(h.kovexy.dyndns.lastReport("home"), "the report of the deleted client is gone")
            assertTrue("8.8.8.8/32" !in h.kovexy.routing.profile("p")!!.allowIps)
        }
    }

    @Test
    fun profileWithClientsIsClosedUntilAReport(): Unit {
        val dir = Files.createTempDirectory("dyndns-test").toFile()
        try {
            val store = DyndnsStore(File(dir, "state.json"))
            val config = KovexyConfig(
                accessProfiles = listOf(AccessProfile("only"), AccessProfile("own", allowIps = listOf("10.0.0.0/8")), AccessProfile("land", allowCountries = listOf("DE")), AccessProfile("free")),
                dyndnsClients = listOf(client("a", "only", "own", "land")),
            )
            fun profiles() = withDyndnsAllowIps(config, store).accessProfiles.associateBy { it.name }
            assertEquals(listOf(bayern.kickner.kovexy.dyndns.NOBODY_ALLOW_ENTRY), profiles().getValue("only").allowIps, "no report yet: nobody gets in")
            assertEquals(listOf("10.0.0.0/8"), profiles().getValue("own").allowIps, "an own allow list already restricts the profile")
            assertEquals(listOf(bayern.kickner.kovexy.dyndns.NOBODY_ALLOW_ENTRY), profiles().getValue("land").allowIps)
            assertEquals(listOf("DE"), profiles().getValue("land").allowCountries, "the countries still let their visitors in")
            assertEquals(emptyList(), profiles().getValue("free").allowIps, "a profile without clients is not touched")
            store.report("a", listOf(ok("8.8.8.8")))
            assertEquals(listOf("8.8.8.8/32"), profiles().getValue("only").allowIps)
        } finally {
            dir.deleteRecursively()
        }
    }

    private val closedConfig = """
        { "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword("test password 123")}" },
          "accessProfiles": [ { "name": "only" } ],
          "dyndnsClients": [ { "name": "home", "passwordHash": "$hash", "profiles": ["only"] } ],
          "domains": [ { "names": ["app.test"], "access": "only", "routes": [ { "path": "/", "target": { "type": "redirect", "url": "https://x.test" } } ] } ] }
    """.trimIndent()

    @Test
    fun lostReportsBlockEverybody(): Unit {
        Harness(closedConfig, prepare = { File(it, "dyndns-state.json").writeText("{ broken") }).use { h ->
            assertEquals(403, h.https("app.test", "/").status)
        }
    }

    @Test
    fun lastRestrictingClientWarns(): Unit {
        Harness(closedConfig).use { h ->
            val page = Admin(h).get("/dyndns/home").text
            assertTrue("Without this client everybody gets into only" in page)
            assertTrue("class=\"notice warn\"" in page, "the warning uses the class app.css styles")
            assertTrue("notice warning" !in Admin(h).get("/dyndns").text + Admin(h).post("/dyndns/new", "name" to "second", "profile.only" to "on").text, "no unstyled warnings")
        }
        Harness(endpointConfig).use { h ->
            assertTrue("Without this client everybody gets into" !in Admin(h).get("/dyndns/home").text, "p has an allow list of its own")
        }
    }

    @Test
    fun reportsCountRightAfterAStart(): Unit {
        val state = """{ "clients": { "home": { "ipv4": "8.8.8.8/32", "updated": 1 } } }"""
        Harness(endpointConfig, prepare = { File(it, "dyndns-state.json").writeText(state) }).use { h ->
            assertEquals("8.8.8.8/32", h.kovexy.dyndns.lastReport("home")?.ipv4)
            assertTrue("8.8.8.8/32" in h.kovexy.routing.profile("p")!!.allowIps, "the stored report is on the allow list without a new update")
        }
    }

    @Test
    fun failedWriteAnswersServerError(): Unit {
        val dir = Files.createTempDirectory("dyndns-test").toFile()
        try {
            // A regular file as parent directory: the state file can never be written
            val blocker = File(dir, "blocker").apply { writeText("x") }
            val store = DyndnsStore(File(blocker, "state.json"))
            val config = KovexyConfig(accessProfiles = listOf(AccessProfile("p")), dyndnsClients = listOf(client("home", "p")))
            var changes = 0
            val endpoint = bayern.kickner.kovexy.dyndns.DyndnsEndpoint({ config }, store, { changes++ })
            val answer = endpoint.answer("GET", basic("secret").second, "myip=1.2.3.4", "9.9.9.9")
            assertEquals(500, answer.status)
            assertEquals("911", answer.body)
            assertNull(store.lastReport("home"), "memory keeps what is on disk")
            assertEquals(0, changes)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun wrongLoginIsASecurityEvent(): Unit = kotlinx.coroutines.runBlocking {
        Harness(endpointConfig).use { h ->
            assertEquals(401, h.https("dyn.test", "/nic/update?myip=1.2.3.4", headers = listOf(basic("nope"))).status)
            var tries = 0
            while (h.kovexy.security.latest(bayern.kickner.kovexy.audit.SecurityEventType.BASIC_AUTH_FAILED).isEmpty() && tries++ < 40) {
                h.kovexy.security.flush()
                kotlinx.coroutines.delay(100)
            }
            assertTrue(h.kovexy.security.latest(bayern.kickner.kovexy.audit.SecurityEventType.BASIC_AUTH_FAILED).isNotEmpty())
        }
    }

    @Test
    fun dyndnsDomainRefusesARootBackend(): Unit {
        Harness(endpointConfig).use { h ->
            val domain = Admin(h).post("/domains/new", "names" to "dyn2.test", "enabled" to "on", "dyndns" to "on", "rootBackend" to "web")
            assertEquals(400, domain.status, "the backend is not dropped without a word")
            assertTrue(h.kovexy.config.domains.none { "dyn2.test" in it.names })
        }
    }

    @Test
    fun routerMenuIsTranslated(): Unit {
        Harness(endpointConfig).use { h ->
            val created = Admin(h).post("/dyndns/new", "name" to "router", "profile.p" to "on")
            assertTrue("Freigaben" !in created.text, "the English page has no German menu names")
        }
    }
}
