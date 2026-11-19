package bayern.kickner.kovexy

import bayern.kickner.kovexy.tls.newEcKeyPair
import bayern.kickner.kovexy.tls.selfSigned
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.header
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.net.ConnectException
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Everything that must change while running: certificates under load, ports, config files, WebSockets, HTTP/2. */
class LiveChangeTest {
    private lateinit var backend: TestBackend
    private lateinit var harness: Harness

    private fun config(extra: String = "") = """
        {
          "admin": { "port": ADMIN_PORT },
          $extra
          "upstreams": [ { "name": "app", "servers": [ { "address": "127.0.0.1:${backend.port}" } ] } ],
          "sites": [ { "domains": ["a.test", "b.test"], "httpsRedirect": false, "locations": [ { "path": "/", "target": { "type": "upstream", "upstream": "app" } } ] } ]
        }
    """.trimIndent()

    @BeforeTest
    fun setUp() {
        backend = TestBackend()
        harness = Harness(config("\"limits\": { \"clientIdleTimeout\": \"2s\" },"))
        runBlocking {
            repeat(100) {
                if (harness.kovexy.keyManager.certificateOf("b.test") != null) return@runBlocking
                delay(50)
            }
        }
    }

    @AfterTest
    fun tearDown() {
        harness.close()
        backend.close()
    }

    @Test
    fun certificateSwapUnderLoadHasNoErrors(): Unit = runBlocking {
        val failures = AtomicInteger()
        val swaps = async(Dispatchers.IO) {
            repeat(100) {
                val pair = newEcKeyPair()
                harness.kovexy.keyManager.install("a.test", pair.private, arrayOf(selfSigned(pair, "a.test")))
                delay(10)
            }
        }
        val requests = (1..30).map {
            async(Dispatchers.IO) {
                repeat(30) {
                    val ok = runCatching { rawRequest(harness.ports.https, "a.test", "/x", tls = true) }.getOrNull()
                    if (ok == null || ok.status != 200 || ok.certificate?.subjectX500Principal?.name != "CN=a.test") failures.incrementAndGet()
                }
            }
        }
        (requests + swaps).awaitAll()
        assertEquals(0, failures.get(), "Requests failed during 100 certificate swaps")
    }

    @Test
    fun adminPortMovesWhileRunning(): Unit = runBlocking {
        val oldPort = harness.adminPort
        assertEquals(200, rawRequest(oldPort, "localhost", "/healthz").status)
        val newPort = freePort()
        harness.writeConfigByHand(config().replace("\"port\": ADMIN_PORT", "\"port\": $newPort"))
        repeat(50) { if (harness.kovexy.server.adminPort == newPort) return@repeat; delay(50) }
        assertEquals(200, rawRequest(newPort, "localhost", "/healthz").status)
        assertFailsWith<ConnectException> { Socket("127.0.0.1", oldPort).close() }
        assertEquals(200, rawRequest(harness.ports.https, "a.test", "/x", tls = true).status, "The proxy ports stay untouched")
    }

    @Test
    fun invalidFileChangesNothing(): Unit = runBlocking {
        val before = harness.store.current.version
        harness.writeConfigByHand("""{ "sites": [ { "domains": ["UPPER.test"] } ], "typo": 1 }""", expectApplied = false)
        assertEquals(before, harness.store.current.version)
        assertEquals(200, rawRequest(harness.ports.https, "a.test", "/x", tls = true).status)
        // A valid change by hand is applied: b.test disappears
        harness.writeConfigByHand(config().replace("\"a.test\", \"b.test\"", "\"a.test\""))
        assertEquals(404, rawRequest(harness.ports.https, "b.test", "/x", tls = true).status)
    }

    @Test
    fun webSocketSurvivesIdleAndClosesOnConfigChange(): Unit = runBlocking {
        val client = HttpClient(CIO) { install(WebSockets) }
        try {
            val session = client.webSocketSession("ws://127.0.0.1:${harness.ports.http}/ws") { header("Host", "a.test") }
            session.send(Frame.Text("one"))
            assertEquals("echo:one", (withTimeout(5.seconds) { session.incoming.receive() } as Frame.Text).readText())
            // Longer than the client idle timeout of 2 seconds: an upgraded connection must stay open
            delay(4.seconds)
            session.send(Frame.Text("two"))
            assertEquals("echo:two", (withTimeout(5.seconds) { session.incoming.receive() } as Frame.Text).readText())
            assertEquals(1, harness.kovexy.webSockets.count)

            harness.writeConfigByHand(config("\"webSocketCloseDelay\": \"0s\","))
            // The client session handles the close frame itself and ends its incoming channel
            val reason = withTimeout(10.seconds) {
                session.incoming.consumeEach { }
                session.closeReason.await()
            }
            assertEquals(CloseReason.Codes.GOING_AWAY.code, reason?.code)
        } finally {
            client.close()
        }
    }

    @Test
    fun refusedWebSocketKeepsTheUpstreamStatus(): Unit = runBlocking {
        val response = rawRequest(harness.ports.http, "a.test", "/ws-denied", headers = listOf(
            "Upgrade" to "websocket", "Connection" to "Upgrade", "Sec-WebSocket-Version" to "13", "Sec-WebSocket-Key" to "dGhlIHNhbXBsZSBub25jZQ==",
        ))
        assertEquals(403, response.status, "The visitor sees why the upstream refused")
        assertTrue(harness.kovexy.upstreams.group("app")!!.servers.single().healthy, "A refusal is no connection error")
    }

    @Test
    fun http2WithCurl(): Unit = runBlocking {
        val curl = runCatching { ProcessBuilder("curl", "--version").start().waitFor() == 0 }.getOrDefault(false)
        if (curl.not()) return@runBlocking println("curl missing, HTTP/2 test skipped")
        val out = withContext(Dispatchers.IO) {
            val process = ProcessBuilder(
                "curl", "-sk", "--http2", "-m", "20", "-o", "/dev/null", "-w", "%{http_version} %{http_code} %{size_download}",
                "--resolve", "a.test:${harness.ports.https}:127.0.0.1", "https://a.test:${harness.ports.https}/big/10485760",
            ).start()
            process.inputStream.readAllBytes().decodeToString().also { process.waitFor() }
        }
        assertEquals("2 200 10485760", out)
    }

    @Test
    fun defaultCertificateRetriesAreScheduled(): Unit = runBlocking {
        val status = harness.kovexy.certificates.status()
        assertTrue(status.all { it.lastError == null }, "The fake issuer never fails: $status")
        assertTrue(harness.issuer.calls.any { it.first == "a.test" })
    }
}
