package bayern.kickner.kovexy

import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.config.CONFIG_BACKUPS_KEPT
import bayern.kickner.kovexy.config.ConfigStore
import bayern.kickner.kovexy.config.rootCheck
import bayern.kickner.kovexy.incus.IncusState
import bayern.kickner.kovexy.incus.incusAddressAllowed
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.URLEncoder
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Regression tests for the findings of the third review (run 3, 25.11.2026). */
class AuditRun3Test {
    private val password = "test password 123"

    private fun form(vararg fields: Pair<String, String>) =
        fields.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}" }.toByteArray()

    private fun Harness.login(): String = rawRequest(
        adminPort, "127.0.0.1:$adminPort", "/login", method = "POST", body = form("password" to password),
        headers = listOf("Content-Type" to "application/x-www-form-urlencoded", "Origin" to "http://127.0.0.1:$adminPort"),
    ).headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-session=") }.substringBefore(';')

    /**
     * The command line runs as root and must not follow links that whoever controls the data directory plants (S4). An
     * attacker thread swaps every new backup copy and temporary config file for a link to a file outside the data
     * directory while updates run like `reset-password` does them. Neither file may change.
     */
    @Test
    fun commandLineNeverFollowsPlantedLinks() {
        val root = Files.createTempDirectory("kovexy-cli").toFile()
        try {
            val dataDir = File(root, "data").apply { mkdirs() }
            val victimMode = File(root, "victim-mode").apply { writeText("untouched\n") }
            val victimWrite = File(root, "victim-write").apply { writeText("untouched\n") }
            listOf(victimMode, victimWrite).forEach { Files.setPosixFilePermissions(it.toPath(), PosixFilePermissions.fromString("rw-r--r--")) }
            File(dataDir, "kovexy.json").writeText("{}\n")
            val store = ConfigStore(dataDir, followLinks = false)
            assertTrue(store.load() is ResultOf2.Success)
            val backups = File(dataDir, "backups")
            val stop = AtomicBoolean(false)
            val attacker = thread(isDaemon = true) {
                val seen = HashSet<String>()
                fun plant(dir: File, name: String, victim: File) {
                    if (seen.add(name).not()) return
                    val path = File(dir, name).toPath()
                    runCatching { Files.delete(path); Files.createSymbolicLink(path, victim.toPath()) }
                }
                while (stop.get().not()) {
                    backups.list()?.filter { it.startsWith("kovexy-") }?.forEach { plant(backups, it, victimMode) }
                    dataDir.list()?.filter { it.startsWith(".kovexy.json.") && it.endsWith(".tmp") }?.forEach { plant(dataDir, it, victimWrite) }
                }
            }
            fun untouched() = PosixFilePermissions.toString(Files.getPosixFilePermissions(victimMode.toPath())) == "rw-r--r--" &&
                victimWrite.readText() == "untouched\n"
            val until = System.currentTimeMillis() + 20_000
            var round = 0
            var saved = 0
            while (untouched() && round < 3000 && System.currentTimeMillis() < until) {
                // A planted link may make a save fail, it must never make it touch the victim
                if (store.update { it.copy(updateCheck = round % 2 == 0) } is ResultOf2.Success) saved++
                round++
            }
            stop.set(true)
            attacker.join()
            assertTrue(saved > round / 2, "Only $saved of $round saves worked, the race did not run")
            assertEquals("rw-r--r--", PosixFilePermissions.toString(Files.getPosixFilePermissions(victimMode.toPath())), "Mode of a file outside the data directory changed")
            assertEquals("untouched\n", victimWrite.readText(), "A file outside the data directory was written")
        } finally {
            root.deleteRecursively()
        }
    }

    /** The command line still saves: new file `0600`, the old one as backup, at most the newest copies kept. */
    @Test
    fun commandLineSavesAndKeepsBackups() {
        val dataDir = Files.createTempDirectory("kovexy-cli").toFile()
        try {
            File(dataDir, "kovexy.json").writeText("{}\n")
            val store = ConfigStore(dataDir, followLinks = false)
            repeat(CONFIG_BACKUPS_KEPT + 3) { i ->
                // Ends with false, the default true is not written to the file
                val saved = store.update { it.copy(updateCheck = i % 2 == 1) }
                assertTrue(saved is ResultOf2.Success, "Save $i failed: $saved")
            }
            assertTrue(File(dataDir, "kovexy.json").readText().contains("\"updateCheck\""), "The new config is on disk")
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(File(dataDir, "kovexy.json").toPath())))
            val backups = File(dataDir, "backups").listFiles().orEmpty()
            assertEquals(CONFIG_BACKUPS_KEPT, backups.size, backups.map { it.name }.toString())
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(File(dataDir, "backups").toPath())))
            assertTrue(backups.all { PosixFilePermissions.toString(Files.getPosixFilePermissions(it.toPath())) == "rw-------" })
            assertTrue(dataDir.list().orEmpty().none { it.endsWith(".tmp") }, "No temporary file is left")

            // A link as backup directory is refused, not followed
            File(dataDir, "backups").deleteRecursively()
            val elsewhere = Files.createTempDirectory("kovexy-elsewhere").toFile()
            Files.createSymbolicLink(File(dataDir, "backups").toPath(), elsewhere.toPath())
            assertTrue(store.update { it.copy(updateCheck = true) } is ResultOf2.Failure)
            assertTrue(elsewhere.list().orEmpty().isEmpty(), "Nothing was written through the link")
            elsewhere.deleteRecursively()
        } finally {
            dataDir.deleteRecursively()
        }
    }

    /** Incus users choose the keys of their container, over-long values must not break the admin's decisions. */
    @Test
    fun incusContainersWithOverlongKeysCanBeRejected(): Unit = runBlocking {
        val allowedBefore = incusAddressAllowed
        val rootBefore = rootCheck
        incusAddressAllowed = { true }
        rootCheck = { true }
        val socket = Files.createTempDirectory("kovexy-incus").resolve("incus.socket").toString()
        try {
            FakeIncus(socket).use { incus ->
                incus.instances = FakeIncus.instancesJson(
                    FakeIncus.instance("access", keys = mapOf("domains" to "access.test", "port" to "80", "access" to "x".repeat(700))),
                    FakeIncus.instance("many", keys = mapOf("domains" to (1..120).joinToString(",") { "d$it.example.test" }, "port" to "80")),
                )
                val config = """{ "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword(password)}" }, "incus": { "enabled": true, "socket": "$socket" }, "fallback": { "type": "notFound" } }"""
                Harness(config).use { h ->
                    repeat(200) { if (h.kovexy.incus.claims.size < 2) delay(50) }
                    assertEquals(2, h.kovexy.incus.claims.size)
                    assertFalse(h.kovexy.incus.approve("default/many"), "A claim whose domains do not fit cannot be approved")

                    val reject = rawRequest(
                        h.adminPort, "127.0.0.1:${h.adminPort}", "/incus/reject", method = "POST", body = form("id" to "default/access"),
                        headers = listOf("Content-Type" to "application/x-www-form-urlencoded", "Origin" to "http://127.0.0.1:${h.adminPort}", "Cookie" to h.login()),
                    )
                    assertEquals(302, reject.status, "Reject answered ${reject.status}")
                    assertTrue(h.kovexy.incus.reject("default/many"))
                    assertEquals(listOf(IncusState.REJECTED, IncusState.REJECTED), h.kovexy.incus.claims.map { it.state })
                }
            }
        } finally {
            incusAddressAllowed = allowedBefore
            rootCheck = rootBefore
        }
    }

    /** `OPTIONS *` is no path, it is refused before routing instead of ending as a broken backend URL (502). */
    @Test
    fun requestTargetThatIsNoPathIsRefused(): Unit = runBlocking {
        TestBackend().use { backend ->
            Harness("""{ "admin": { "port": ADMIN_PORT },
                "backends": [ { "name": "b", "servers": [ { "address": "127.0.0.1:${backend.port}" } ] } ],
                "domains": [ { "names": ["o.test"], "routes": [ { "path": "/", "target": { "type": "backend", "backend": "b" } } ] } ] }""").use { h ->
                assertEquals(400, rawRequest(h.ports.https, "o.test", "*", tls = true, method = "OPTIONS").status)
                assertEquals(400, rawRequest(h.ports.http, "o.test", "*", method = "OPTIONS").status, "Not redirected to https://o.test*")
            }
        }
    }

    /** A restore that brings another admin password ends every other session, like a password change in the settings. */
    @Test
    fun restoreWithAnotherPasswordEndsOtherSessions(): Unit = runBlocking {
        Harness("""{ "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword(password)}" } }""").use { h ->
            val own = h.login()
            val other = h.login()
            val zip = ByteArrayOutputStream().also { bytes ->
                ZipOutputStream(bytes).use { z ->
                    z.putNextEntry(ZipEntry("kovexy.json"))
                    z.write("""{ "admin": { "port": ${h.adminPort}, "passwordHash": "${hashPassword("another password 456")}" } }""".toByteArray())
                    z.closeEntry()
                }
            }.toByteArray()
            val body = ByteArrayOutputStream().apply {
                write("--b\r\nContent-Disposition: form-data; name=\"backup\"; filename=\"b.zip\"\r\nContent-Type: application/zip\r\n\r\n".toByteArray())
                write(zip)
                write("\r\n--b--\r\n".toByteArray())
            }.toByteArray()
            val restore = rawRequest(
                h.adminPort, "127.0.0.1:${h.adminPort}", "/settings/restore", method = "POST", body = body,
                headers = listOf("Content-Type" to "multipart/form-data; boundary=b", "Origin" to "http://127.0.0.1:${h.adminPort}", "Cookie" to own),
            )
            assertEquals("/settings?done=restored", restore.header("Location"))
            assertEquals(302, rawRequest(h.adminPort, "127.0.0.1:${h.adminPort}", "/settings", headers = listOf("Cookie" to other)).status, "The other session ended")
            assertEquals(200, rawRequest(h.adminPort, "127.0.0.1:${h.adminPort}", "/settings", headers = listOf("Cookie" to own)).status, "The own session stays")
        }
    }
}
