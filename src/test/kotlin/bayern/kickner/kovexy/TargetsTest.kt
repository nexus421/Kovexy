package bayern.kickner.kovexy

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Load balancing, health checks, static files and the fallback. */
class TargetsTest {

    private fun domain(target: String, domain: String = "a.test") =
        """{ "names": ["$domain"], "routes": [ { "path": "/", "target": $target } ] }"""

    @Test
    fun weightedBackupAndPassiveHealth(): Unit = runBlocking {
        val one = TestBackend(name = "one")
        val two = TestBackend(name = "two")
        val backupPort = freePort()
        val backup = TestBackend(backupPort, name = "backup")
        val config = """
            { "admin": { "port": ADMIN_PORT },
              "backends": [ { "name": "app", "servers": [
                { "address": "127.0.0.1:${one.port}", "weight": 3 },
                { "address": "127.0.0.1:${two.port}", "weight": 1 },
                { "address": "127.0.0.1:$backupPort", "weight": 0 } ] } ],
              "domains": [ ${domain("""{ "type": "backend", "backend": "app" }""")} ] }
        """.trimIndent()
        Harness(config).use { h ->
            val counts = (1..200).map { h.https("a.test", "/x").header("X-Backend") }.groupingBy { it }.eachCount()
            assertEquals(null, counts["backup"], "A backup server gets nothing while others are up")
            assertTrue((counts["one"] ?: 0) > (counts["two"] ?: 0) * 2, "Weight 3 to 1: $counts")

            // Both weighted servers fail: the first failed request marks them down, then the backup answers
            one.close()
            two.close()
            repeat(6) { runCatching { h.https("a.test", "/x") } }
            assertEquals("backup", h.https("a.test", "/x").header("X-Backend"))
            val states = h.kovexy.backends.group("app")!!.servers.associate { it.address.port to it.healthy }
            assertEquals(false, states[one.port])
            assertEquals(true, states[backupPort])
        }
        backup.close()
    }

    @Test
    fun singleServerIsUsedEvenWhenDownAndAnswers502(): Unit = runBlocking {
        val port = freePort()
        Harness("""{ "admin": { "port": ADMIN_PORT }, "backends": [ { "name": "app", "servers": [ { "address": "127.0.0.1:$port" } ] } ],
            "domains": [ ${domain("""{ "type": "backend", "backend": "app" }""")} ] }""").use { h ->
            assertEquals(502, h.https("a.test", "/").status)
            val backend = TestBackend(port)
            // Zoraxy: a group with one server always tries it, so the backend is back at once after a restart
            assertEquals(200, h.https("a.test", "/").status)
            backend.close()
        }
    }

    @Test
    fun activeHealthCheckAndStickySession(): Unit = runBlocking {
        val one = TestBackend(name = "one")
        val two = TestBackend(name = "two")
        fun config(check: String) = """
            { "admin": { "port": ADMIN_PORT },
              "backends": [ { "name": "app", "stickySession": true, $check
                "servers": [ { "address": "127.0.0.1:${one.port}" }, { "address": "127.0.0.1:${two.port}" } ] } ],
              "domains": [ ${domain("""{ "type": "backend", "backend": "app" }""")} ] }
        """.trimIndent()
        Harness(config("")).use { h ->
            val first = h.https("a.test", "/x")
            val cookie = first.header("Set-Cookie")
            assertNotNull(cookie)
            assertTrue(cookie.contains("HttpOnly") && cookie.contains("Path=/"))
            val value = cookie.substringBefore(';')
            val sameServer = (1..20).map { h.https("a.test", "/x", headers = listOf("Cookie" to value)).header("X-Backend") }.toSet()
            assertEquals(setOf(first.header("X-Backend")), sameServer)

            h.writeConfigByHand(config(""" "healthCheck": { "path": "/status/503", "interval": "1s", "expectStatus": 200 }, """))
            // /status/503 never answers 200: the active check marks both servers down within a few seconds
            repeat(50) {
                if (h.kovexy.backends.group("app")!!.servers.none { it.healthy }) return@repeat
                delay(100)
            }
            assertTrue(h.kovexy.backends.group("app")!!.servers.none { it.healthy })
            assertEquals(502, h.https("a.test", "/x").status)
        }
        one.close()
        two.close()
    }

    @Test
    fun staticFiles(): Unit = runBlocking {
        val root = Files.createTempDirectory("kovexy-static").toFile()
        val outside = Files.createTempDirectory("kovexy-outside").toFile()
        File(root, "index.html").writeText("<h1>home</h1>")
        File(root, "docs").mkdirs()
        File(root, "docs/a.txt").writeText("text")
        File(outside, "secret.txt").writeText("secret")
        Files.createSymbolicLink(File(root, "escape").toPath(), outside.toPath())
        File(root, "linked").mkdirs()
        Files.createSymbolicLink(File(root, "linked/index.html").toPath(), File(outside, "secret.txt").toPath())
        val config = """{ "admin": { "port": ADMIN_PORT }, "domains": [
            ${domain("""{ "type": "static", "root": "${root.absolutePath}" }""")},
            ${domain("""{ "type": "static", "root": "${root.absolutePath}", "directoryListing": true }""", "list.test")} ] }"""
        Harness(config).use { h ->
            assertEquals("<h1>home</h1>", h.https("a.test", "/").text)
            val file = h.https("a.test", "/docs/a.txt")
            assertEquals("text", file.text)
            assertNotNull(file.header("Last-Modified"))
            assertEquals(304, h.https("a.test", "/docs/a.txt", headers = listOf("If-Modified-Since" to file.header("Last-Modified")!!)).status)
            assertEquals(308, h.https("a.test", "/docs").status)
            assertEquals(404, h.https("a.test", "/docs/").status, "No listing by default")
            assertEquals(404, h.https("a.test", "/escape/secret.txt").status, "Symlinks out of the root are refused")
            assertEquals(404, h.https("a.test", "/linked/").status, "A symlinked index file is checked like any file")
            assertEquals(404, h.https("a.test", "/docs/%2e%2e/%2e%2e/etc/passwd").status.let { if (it == 400) 404 else it })
            assertEquals(405, h.https("a.test", "/", method = "POST", body = ByteArray(1)).status)
            assertTrue(h.https("list.test", "/docs/").text.contains("a.txt"))
        }
        root.deleteRecursively()
        outside.deleteRecursively()
    }

    @Test
    fun fallbackVariants(): Unit = runBlocking {
        Harness("""{ "admin": { "port": ADMIN_PORT } }""").use { h ->
            val page = h.https("unknown.test", "/")
            assertEquals(200, page.status)
            assertTrue(page.text.contains("It works"))

            h.writeConfigByHand("""{ "admin": { "port": ADMIN_PORT }, "fallback": { "type": "redirect", "url": "https://other.test" } }""")
            val redirect = h.https("unknown.test", "/p?q=1")
            assertEquals(307, redirect.status)
            assertEquals("https://other.test/p?q=1", redirect.header("Location"))
            // A client that sends the redirect target's name back to this server is misdirected, no server error
            val loop = h.https("other.test", "/loop")
            assertEquals(421, loop.status, "A redirect to itself is refused")
            assertTrue(loop.text.startsWith("<!DOCTYPE html>"), "Neutral page")
            val entry = run {
                repeat(50) {
                    h.kovexy.accessLog.flush()
                    h.kovexy.accessLog.latest().firstOrNull { it.host == "other.test" && it.path == "/loop" }?.let { return@run it }
                    delay(100)
                }
                error("No access log entry for the redirect loop")
            }
            assertEquals("redirect loop", entry.reason)
            assertEquals("MISDIRECTED", entry.block, "Counted as blocked, not as an error")

            h.writeConfigByHand("""{ "admin": { "port": ADMIN_PORT }, "fallback": { "type": "noResponse" } }""")
            val empty = h.https("unknown.test", "/")
            assertEquals(204, empty.status, "noResponse is an empty answer, without reflection on Ktor internals")
            assertEquals("close", empty.header("Connection"))

            h.writeConfigByHand("""{ "admin": { "port": ADMIN_PORT }, "fallback": { "type": "notFound" } }""")
            assertEquals(404, h.https("unknown.test", "/").status)
        }
    }

    @Test
    fun acmeChallengeIsAnsweredFirst(): Unit = runBlocking {
        Harness("""{ "admin": { "port": ADMIN_PORT }, "domains": [ ${domain("""{ "type": "deny", "status": 403 }""")} ] }""").use { h ->
            h.kovexy.challenges.put("token123", "token123.key")
            val answer = rawRequest(h.ports.http, "a.test", "/.well-known/acme-challenge/token123")
            assertEquals(200, answer.status)
            assertEquals("token123.key", answer.text)
            assertEquals(404, rawRequest(h.ports.http, "a.test", "/.well-known/acme-challenge/other").status)
            assertEquals(308, rawRequest(h.ports.http, "a.test", "/").status, "Everything but ACME is redirected on port 80")
            assertEquals(403, h.https("a.test", "/").status)
        }
    }
}
