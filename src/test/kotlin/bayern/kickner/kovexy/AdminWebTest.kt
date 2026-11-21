package bayern.kickner.kovexy

import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.backup.restoreBackup
import bayern.kickner.kovexy.backup.writeBackup
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import org.jetbrains.exposed.v1.jdbc.selectAll
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The admin UI: guards, login, saving through forms, backup. */
private const val SESSION_COOKIE_NAME = "__Host-kovexy-session="

class AdminWebTest {
    private val password = "test password 123"
    private lateinit var harness: Harness
    private val origin get() = "http://127.0.0.1:${harness.adminPort}"

    @BeforeTest
    fun setUp() {
        harness = Harness("""{ "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword(password)}" } }""")
    }

    @AfterTest
    fun tearDown() = harness.close()

    private fun form(vararg fields: Pair<String, String>) =
        fields.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}" }.toByteArray()

    private fun post(path: String, body: ByteArray, cookie: String? = null, origin: String? = this.origin) = rawRequest(
        harness.adminPort, "127.0.0.1:${harness.adminPort}", path, method = "POST", body = body,
        headers = listOfNotNull("Content-Type" to "application/x-www-form-urlencoded", origin?.let { "Origin" to it }, cookie?.let { "Cookie" to it }),
    )

    private fun get(path: String, cookie: String? = null) =
        rawRequest(harness.adminPort, "127.0.0.1:${harness.adminPort}", path, headers = listOfNotNull(cookie?.let { "Cookie" to it }))

    private fun login(): String {
        val response = post("/login", form("password" to password))
        // 200 with a same-site refresh, so the SameSite=Strict cookie also works after an OIDC redirect
        assertEquals(200, response.status)
        return response.headerAll("Set-Cookie").first { it.startsWith(SESSION_COOKIE_NAME) }.substringBefore(';')
    }

    @Test
    fun guardsAndHeaders(): Unit = run {
        assertEquals(302, get("/").status)
        assertEquals("/login", get("/domains").header("Location"))
        assertEquals(200, get("/healthz").status)
        assertEquals(200, get("/static/app.css").status)
        val login = get("/login")
        assertEquals(200, login.status)
        assertTrue(login.header("Content-Security-Policy")!!.contains("script-src 'self'"))
        assertEquals("nosniff", login.header("X-Content-Type-Options"))
        assertTrue(login.text.contains("protected by a password only"), "The warning shows on the login page")
        assertEquals(403, post("/login", form("password" to password), origin = null).status, "Posts need an allowed Origin")
        assertEquals(403, post("/login", form("password" to password), origin = "https://evil.test").status)
        assertEquals(401, post("/domains/new", form()).status, "Posts need a session")
    }

    @Test
    fun formsCarryHelpTexts(): Unit = run {
        val cookie = login()
        val settings = get("/settings", cookie).text
        assertTrue(settings.contains("class=\"help-btn\""), "The settings fields have a question mark")
        assertTrue(settings.contains("Largest size of all request headers") || settings.contains("largest size of all request headers"), "With the text behind it")
        // The same field name on two pages must not show the text of the other page
        assertTrue(get("/webhooks/new", cookie).text.contains("The address Kovexy sends the POST request to."))
        assertTrue(get("/domains/new", cookie).text.contains("The domain names this entry serves"))
    }

    @Test
    fun loginLockoutAndSession(): Unit = run {
        assertEquals(401, post("/login", form("password" to "wrong")).status)
        val cookie = login()
        assertTrue(cookie.startsWith("__Host-kovexy-session="))
        val status = get("/", cookie)
        assertEquals(200, status.status)
        assertTrue(status.text.contains("protected by a password only"), "The banner shows on every page")
        repeat(5) { post("/login", form("password" to "wrong")) }
        assertEquals(429, post("/login", form("password" to password)).status, "Locked out after five failures")
        assertEquals(200, get("/", cookie).status, "Existing sessions stay")
        assertEquals(302, post("/logout", ByteArray(0), cookie).status)
        assertEquals(302, get("/", cookie).status)
    }

    @Test
    fun savingThroughFormsAppliesAndDetectsConflicts(): Unit = run {
        val cookie = login()
        val version = harness.store.current.version
        val created = post("/backends/new", form(
            "version" to version, "name" to "app", "serverCount" to "1", "s0.address" to "127.0.0.1:9", "s0.weight" to "1", "s0.max" to "0",
            "healthPath" to "", "expectStatus" to "200", "interval" to "30s", "timeout" to "5s",
        ), cookie)
        assertEquals(302, created.status, created.text)
        assertEquals("app", harness.kovexy.config.backends.single().name)

        val stale = post("/domains/new", form("version" to version, "names" to "a.test", "enabled" to "on"), cookie)
        assertEquals(400, stale.status)
        assertTrue(stale.text.contains("changed since this page was loaded"))

        val invalid = post("/domains/new", form("version" to harness.store.current.version, "names" to "*.test"), cookie)
        assertEquals(400, invalid.status)
        assertTrue(invalid.text.contains("without wildcard"))

        val domain = post("/domains/new", form("version" to harness.store.current.version, "names" to "a.test\nb.test", "enabled" to "on", "rootBackend" to "app"), cookie)
        assertEquals(302, domain.status)
        assertEquals(listOf("a.test", "b.test"), harness.kovexy.config.domains.single().names)
        assertEquals(502, harness.https("a.test").status, "The new domain works at once (its backend is down)")
        assertTrue(harness.store.backupDir.listFiles()!!.isNotEmpty(), "Every save keeps a copy of the previous file")
    }

    @Test
    fun backupRoundTrip(): Unit = runBlocking {
        val cookie = login()
        post("/backends/new", form(
            "version" to harness.store.current.version, "name" to "keep", "serverCount" to "1", "s0.address" to "127.0.0.1:9", "s0.weight" to "1",
            "s0.max" to "0", "expectStatus" to "200", "interval" to "30s", "timeout" to "5s",
        ), cookie)
        harness.kovexy.bans.ban(java.net.InetAddress.getByName("203.0.113.9"), kotlin.time.Duration.parse("1h"), "test", "x")
        // Bans are written in the background
        repeat(50) { if (harness.kovexy.storage.tx { bayern.kickner.kovexy.stats.BanTable.selectAll().count() } == 0L) Thread.sleep(50) }
        val download = post("/settings/backup", form("database" to "on"), cookie)
        assertEquals(200, download.status)
        assertEquals("application/zip", download.header("Content-Type"))
        val zip = download.body

        harness.kovexy.configStore.update { it.copy(backends = emptyList()) }
        assertNull(harness.kovexy.backends.group("keep"))
        assertTrue(harness.kovexy.bans.lift("203.0.113.9"))
        assertNull(harness.kovexy.restoreBackup(zip.toTempFile()))
        assertNotNull(harness.kovexy.backends.group("keep"), "Restored and applied")
        assertNotNull(harness.kovexy.bans.banOf(java.net.InetAddress.getByName("203.0.113.9")), "Bans of the restored database are enforced at once")
        assertTrue(harness.store.backupDir.listFiles()!!.any { it.name.startsWith("restore-") })
        // The backup holds the session of this login, a restore must not bring sessions back (audit run-2)
        assertEquals(302, get("/", cookie).status, "A restored database ends every admin login")

        val evil = ByteArrayOutputStream().also { out ->
            java.util.zip.ZipOutputStream(out).use { z ->
                z.putNextEntry(java.util.zip.ZipEntry("../../etc/cron.d/x"))
                z.write(1)
                z.closeEntry()
            }
        }.toByteArray()
        assertTrue(harness.kovexy.restoreBackup(evil.toTempFile())!!.contains("Unexpected file"))
        val dotDot = ByteArrayOutputStream().also { out ->
            java.util.zip.ZipOutputStream(out).use { z ->
                z.putNextEntry(java.util.zip.ZipEntry("certs/../privkey.pem"))
                z.write(1)
                z.closeEntry()
            }
        }.toByteArray()
        assertTrue(harness.kovexy.restoreBackup(dotDot.toTempFile())!!.contains("Unexpected file"))
        val copy = ByteArrayOutputStream().also { harness.kovexy.writeBackup(it, includeDatabase = false) }
        assertTrue(copy.size() > 0)
    }

    @Test
    fun basicAuthPasswordsOfAnyLengthWithHint(): Unit = run {
        val cookie = login()
        fun save(password: String, version: String = harness.store.current.version, name: String = "p") = post("/access/new", form(
            "version" to version, "name" to name, "banDuration" to "1h", "exploitResponse" to "FORBIDDEN",
            "basicEnabled" to "on", "realm" to "Restricted", "userCount" to "1", "u0.name" to "ann", "u0.password" to password, "method.GET" to "on",
        ), cookie)
        val short = save("x")
        assertEquals(302, short.status, short.text)
        assertEquals("/access?done=profile-saved-short-password", short.header("Location"))
        assertTrue(get("/access?done=profile-saved-short-password", cookie).text.contains("shorter than 12 characters"))
        assertEquals("ann", harness.kovexy.config.accessProfiles.single().basicAuth!!.users.single().name, "A one character password is accepted")
        assertEquals("/access?done=profile-saved", save("a long enough password", name = "q").header("Location"))
    }

    @Test
    fun aiCrawlerListIsEditedOnTheAccessPage(): Unit = run {
        val cookie = login()
        val page = get("/access", cookie).text
        assertTrue(page.contains("Shipped list (") && page.contains("gptbot"), "The shipped names are listed")
        val saved = post("/access/ai-crawlers", form("version" to harness.store.current.version, "add" to "MyScraper\n\n  OtherBot ", "ignore" to "GPTBot"), cookie)
        assertEquals(302, saved.status, saved.text)
        assertEquals(listOf("MyScraper", "OtherBot"), harness.kovexy.config.aiCrawlers.add)
        assertEquals(listOf("GPTBot"), harness.kovexy.config.aiCrawlers.ignore)
        val tooLong = post("/access/ai-crawlers", form("version" to harness.store.current.version, "add" to "x".repeat(300)), cookie)
        assertEquals(400, tooLong.status)
        assertTrue(tooLong.text.contains("longer than 200"))
    }

    private fun run(block: () -> Unit) = block()
}

private fun ByteArray.toTempFile(): java.io.File = java.io.File.createTempFile("kovexy-backup", ".zip").also { it.deleteOnExit(); it.writeBytes(this) }
