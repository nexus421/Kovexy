package bayern.kickner.kovexy

import bayern.kickner.kovexy.proxy.STATUS_CLIENT_GONE
import bayern.kickner.kovexy.stats.AccessRecord
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Response timeout, fail over on connection errors and visitors who go away. */
class BackendResilienceTest {
    private lateinit var backend: TestBackend
    private lateinit var harness: Harness

    /** A port nobody listens on. */
    private val deadPort = freePort()

    private fun config(backendPort: Int) = """
        {
          "admin": { "port": ADMIN_PORT },
          "limits": { "backendResponseTimeout": "1s" },
          "backends": [
            { "name": "app", "servers": [ { "address": "127.0.0.1:$backendPort" } ] },
            { "name": "pair", "servers": [
              { "address": "127.0.0.1:$deadPort", "weight": 1 },
              { "address": "127.0.0.1:$backendPort", "weight": 0 }
            ] }
          ],
          "domains": [
            { "names": ["a.test"], "routes": [ { "path": "/", "target": { "type": "backend", "backend": "app" } } ] },
            { "names": ["b.test"], "routes": [ { "path": "/", "target": { "type": "backend", "backend": "pair" } } ] }
          ]
        }
    """.trimIndent()

    @BeforeTest
    fun setUp() {
        backend = TestBackend()
        harness = Harness(config(backend.port))
        runBlocking {
            listOf("a.test", "b.test").forEach { domain ->
                repeat(100) {
                    if (harness.kovexy.keyManager.certificateOf(domain) != null) return@forEach
                    delay(50)
                }
                error("No certificate for $domain")
            }
        }
    }

    @AfterTest
    fun tearDown() {
        harness.close()
        backend.close()
    }

    private suspend fun entry(domain: String, path: String): AccessRecord {
        repeat(50) {
            harness.kovexy.accessLog.flush()
            harness.kovexy.accessLog.latest(domain = domain).firstOrNull { it.path == path }?.let { return it }
            delay(100)
        }
        error("No access log entry for $domain$path")
    }

    @Test
    fun aBackendWithoutAnswerGets504(): Unit = runBlocking {
        val start = System.currentTimeMillis()
        val response = harness.https("a.test", "/slow/5000")
        val took = System.currentTimeMillis() - start
        assertEquals(504, response.status)
        assertTrue(took < 4000, "The timeout must end the wait, took $took ms")
        assertEquals("backend timeout", entry("a.test", "/slow/5000").reason)
    }

    @Test
    fun aSlowButTimelyBackendPasses(): Unit = runBlocking {
        val response = harness.https("a.test", "/slow/300")
        assertEquals(200, response.status)
        assertEquals("late", response.text)
    }

    @Test
    fun aRunningBodyIsNeverCut(): Unit = runBlocking {
        // Headers come at once, the rest after twice the timeout
        val response = harness.https("a.test", "/drip/2000")
        assertEquals(200, response.status)
        assertEquals("first second", response.text)
    }

    @Test
    fun theTimeoutCanBeTurnedOff(): Unit = runBlocking {
        harness.writeConfigByHand(config(backend.port).replace("\"backendResponseTimeout\": \"1s\"", "\"backendResponseTimeout\": \"0s\""))
        assertEquals(200, harness.https("a.test", "/slow/1500").status)
    }

    @Test
    fun anUnreachableServerHandsTheRequestToAnother(): Unit = runBlocking {
        // The live server is a backup (weight 0), so the dead one is always picked first, without fail over that is 502
        val response = harness.https("b.test", "/first")
        assertEquals(200, response.status)
        val dead = harness.kovexy.backends.group("pair")!!.servers.first { it.address.port == deadPort }
        assertEquals(false, dead.healthy, "The dead server must be marked down")
        repeat(5) { assertEquals(200, harness.https("b.test", "/again").status) }
    }

    @Test
    fun aRequestWithBodyIsNotRepeated(): Unit = runBlocking {
        // The dead server is picked first, a request with body must not be repeated on the backup
        val response = harness.https("b.test", "/upload", method = "POST", body = "data".toByteArray())
        assertEquals(502, response.status)
    }

    @Test
    fun aVisitorWhoGoesAwayIsLoggedAs499(): Unit = runBlocking {
        val plain = Socket("127.0.0.1", harness.ports.https)
        val socket = trustAllContext.socketFactory.createSocket(plain, "a.test", harness.ports.https, true) as SSLSocket
        socket.sslParameters = socket.sslParameters.apply { serverNames = listOf(SNIHostName("a.test")) }
        socket.outputStream.write("GET /big/50000000 HTTP/1.1\r\nHost: a.test\r\n\r\n".toByteArray())
        socket.outputStream.flush()
        socket.inputStream.read(ByteArray(1000))
        socket.setSoLinger(true, 0)
        socket.close()
        val record = entry("a.test", "/big/50000000")
        assertEquals(STATUS_CLIENT_GONE, record.status)
        assertEquals("client gone", record.reason)
    }
}
