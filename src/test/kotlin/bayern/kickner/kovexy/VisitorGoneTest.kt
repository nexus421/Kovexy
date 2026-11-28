package bayern.kickner.kovexy

import bayern.kickner.klogger.KLogger
import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.proxy.STATUS_CLIENT_GONE
import bayern.kickner.kovexy.stats.AccessRecord
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.Socket
import java.net.URLEncoder
import java.util.concurrent.CopyOnWriteArrayList
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A visitor who closes the connection while Kovexy still writes is no error of Kovexy. It must not end up in the
 * journal as ERROR with a stack trace (seen on 21.11.2026: "Broken pipe" from the status page and from downloads).
 */
class VisitorGoneTest {
    private val logs = CopyOnWriteArrayList<Triple<KLogger.Level, String, String>>()
    private val password = "test password 123"

    @BeforeTest
    fun captureLogs() {
        KLogger.configure {
            minLevel = KLogger.Level.DEBUG
            debug = true
            logToCustom(KLogger.Level.DEBUG) { level, tag, message -> logs += Triple(level, tag, message) }
        }
    }

    @AfterTest
    fun releaseLogs() {
        KLogger.configure { }
    }

    private fun errors(about: String) = logs.filter { it.first >= KLogger.Level.ERROR && about in it.third }

    private suspend fun entry(h: Harness, path: String): AccessRecord {
        repeat(100) {
            h.kovexy.accessLog.flush()
            h.kovexy.accessLog.latest().firstOrNull { it.path == path }?.let { return it }
            delay(100)
        }
        error("No access log entry for $path")
    }

    /** Opens [request] on a raw socket, reads a little, then resets the connection like a closed browser tab. */
    private fun leaveEarly(socket: Socket, request: String) {
        socket.use {
            it.soTimeout = 15_000
            it.getOutputStream().write(request.toByteArray())
            it.getOutputStream().flush()
            it.getInputStream().read(ByteArray(1000))
            it.setSoLinger(true, 0)
        }
    }

    @Test
    fun anAbortedDownloadOfKovexysOwnFileIsNoError(): Unit = runBlocking {
        Harness("""{ "admin": { "port": ADMIN_PORT } }""").use { h ->
            File(h.dataDir, "www/big.bin").writeBytes(ByteArray(30_000_000))
            val plain = Socket("127.0.0.1", h.ports.https)
            val socket = (trustAllContext.socketFactory.createSocket(plain, "unknown.test", h.ports.https, true) as SSLSocket).apply {
                sslParameters = sslParameters.apply { serverNames = listOf(SNIHostName("unknown.test")) }
            }
            leaveEarly(socket, "GET /big.bin HTTP/1.1\r\nHost: unknown.test\r\n\r\n")
            val record = entry(h, "/big.bin")
            assertEquals(STATUS_CLIENT_GONE, record.status)
            assertEquals("client gone", record.reason)
            assertEquals(emptyList(), errors("big.bin"), "A visitor who leaves is no error")
        }
    }

    @Test
    fun leavingTheStatusPageIsNoError(): Unit = runBlocking {
        Harness("""{ "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword(password)}" } }""").use { h ->
            val body = "password=" + URLEncoder.encode(password, Charsets.UTF_8)
            val cookie = rawRequest(
                h.adminPort, "127.0.0.1:${h.adminPort}", "/login", method = "POST", body = body.toByteArray(),
                headers = listOf("Content-Type" to "application/x-www-form-urlencoded", "Origin" to "http://127.0.0.1:${h.adminPort}"),
            ).headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-session=") }.substringBefore(';')
            leaveEarly(
                Socket("127.0.0.1", h.adminPort),
                "GET /status/events HTTP/1.1\r\nHost: 127.0.0.1:${h.adminPort}\r\nAccept: text/event-stream\r\nCookie: $cookie\r\n\r\n",
            )
            // The stream notices the closed connection at its next update (every 5 seconds)
            repeat(200) {
                if (logs.any { "/status/events" in it.third }) return@repeat
                delay(100)
            }
            delay(500)
            assertTrue(logs.any { "/status/events" in it.third }, "The ended stream is logged")
            assertEquals(emptyList(), errors("/status/events"), "A visitor who leaves the status page is no error")
        }
    }
}
