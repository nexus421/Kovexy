package bayern.kickner.kovexy

import bayern.kickner.kovexy.config.ConfigStore
import bayern.kickner.kovexy.proxy.Ports
import bayern.kickner.kovexy.tls.CertStore
import bayern.kickner.kovexy.tls.CertificateBundle
import bayern.kickner.kovexy.tls.CertificateIssuer
import bayern.kickner.kovexy.tls.ChallengeStore
import bayern.kickner.kovexy.tls.newEcKeyPair
import bayern.kickner.kovexy.tls.selfSigned
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpMethod
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.delay
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.HexFormat
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.time.Duration.Companion.seconds

/** A free TCP port on loopback. */
fun freePort(): Int = ServerSocket(0).use { it.localPort }

/** Accepts every certificate, the tests inspect the certificate themselves. */
object TrustAllManager : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/** An SSL context that trusts everything. */
val trustAllContext: SSLContext = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(TrustAllManager), null) }

/**
 * A raw HTTP/1.1 answer.
 *
 * @property status Status code.
 * @property headers Header lines, names in lower case.
 * @property body Body bytes, chunked encoding already removed.
 * @property certificate The server certificate for TLS requests.
 */
class RawResponse(val status: Int, val headers: List<Pair<String, String>>, val body: ByteArray, val certificate: X509Certificate?) {
    fun header(name: String): String? = headers.firstOrNull { it.first == name.lowercase() }?.second
    fun headerAll(name: String): List<String> = headers.filter { it.first == name.lowercase() }.map { it.second }
    val text: String get() = body.decodeToString()
}

/**
 * Sends one HTTP/1.1 request over a fresh connection with `Connection: close`. For TLS the SNI name is [host]
 * unless [sni] says otherwise (`""` sends no SNI at all).
 */
fun rawRequest(
    port: Int,
    host: String,
    path: String = "/",
    tls: Boolean = false,
    method: String = "GET",
    headers: List<Pair<String, String>> = emptyList(),
    body: ByteArray? = null,
    sni: String? = host,
): RawResponse {
    val plain = Socket("127.0.0.1", port)
    val socket: Socket = if (tls) {
        // A fresh context per request: a shared one would resume the TLS session of another name on the same port
        (SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(TrustAllManager), null) }.socketFactory.createSocket(plain, "127.0.0.1", port, true) as SSLSocket).apply {
            sslParameters = sslParameters.apply { serverNames = if (sni.isNullOrEmpty()) emptyList() else listOf(SNIHostName(sni)) }
            startHandshake()
        }
    } else plain
    socket.use {
        it.soTimeout = 30_000
        val request = buildString {
            append("$method $path HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("Connection: close\r\n")
            headers.forEach { (name, value) -> append("$name: $value\r\n") }
            if (body != null) append("Content-Length: ${body.size}\r\n")
            append("\r\n")
        }
        it.getOutputStream().write(request.toByteArray())
        if (body != null) it.getOutputStream().write(body)
        it.getOutputStream().flush()
        val cert = (it as? SSLSocket)?.session?.peerCertificates?.firstOrNull() as? X509Certificate
        return parseResponse(it.getInputStream(), method == "HEAD", cert)
    }
}

private fun readLine(input: InputStream): String {
    val out = ByteArrayOutputStream()
    while (true) {
        val b = input.read()
        if (b < 0 || b == '\n'.code) break
        if (b != '\r'.code) out.write(b)
    }
    return out.toString(Charsets.ISO_8859_1)
}

private fun parseResponse(input: InputStream, head: Boolean, cert: X509Certificate?): RawResponse {
    val statusLine = readLine(input)
    require(statusLine.startsWith("HTTP/1.1")) { "No HTTP answer: \"$statusLine\"" }
    val status = statusLine.split(' ')[1].toInt()
    val headers = mutableListOf<Pair<String, String>>()
    while (true) {
        val line = readLine(input)
        if (line.isEmpty()) break
        headers += line.substringBefore(':').trim().lowercase() to line.substringAfter(':').trim()
    }
    if (head || status == 204 || status == 304) return RawResponse(status, headers, ByteArray(0), cert)
    val chunked = headers.any { it.first == "transfer-encoding" && it.second.contains("chunked", true) }
    val body = if (chunked) {
        val out = ByteArrayOutputStream()
        while (true) {
            val size = readLine(input).substringBefore(';').trim().toInt(16)
            if (size == 0) break
            out.write(input.readNBytes(size))
            readLine(input)
        }
        out.toByteArray()
    } else {
        val length = headers.firstOrNull { it.first == "content-length" }?.second?.toInt()
        if (length != null) input.readNBytes(length) else input.readAllBytes()
    }
    return RawResponse(status, headers, body, cert)
}

/** SHA-256 hex of [bytes]. */
fun sha256(bytes: ByteArray): String = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))

/** Deterministic test data of [size] bytes. */
fun testBytes(size: Int): ByteArray = ByteArray(size) { (it * 31 + 7).toByte() }

/**
 * A small upstream server for tests (Ktor CIO):
 *
 * - `/echo...` answers with method, URI and every request header, one per line,
 * - `/big/{size}` streams [testBytes] of that size,
 * - `POST /upload` answers with the SHA-256 of the body,
 * - `/status/{code}` answers with that status,
 * - `/ws` echoes WebSocket text frames, `/ws-quiet` stays silent until the client writes.
 *
 * @property port Its port.
 * @property name Returned in the header `X-Backend`, to tell backends apart.
 */
class TestBackend(val port: Int = freePort(), val name: String = "backend") : AutoCloseable {
    private val server: EmbeddedServer<*, *> = embeddedServer(CIO, port = port, host = "127.0.0.1") {
        install(WebSockets)
        routing {
            get("/big/{size}") {
                val size = call.parameters["size"]!!.toInt()
                call.response.headers.append("X-Backend", name)
                call.respondBytesWriter(ContentType.Application.OctetStream) {
                    val data = testBytes(size)
                    var offset = 0
                    while (offset < size) {
                        val n = minOf(65536, size - offset)
                        writeFully(data, offset, offset + n)
                        offset += n
                    }
                }
            }
            post("/upload") {
                val channel = call.receiveChannel()
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(65536)
                while (true) {
                    val n = channel.readAvailable(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
                call.respondText(HexFormat.of().formatHex(digest.digest()))
            }
            get("/ws-denied") { call.respond(HttpStatusCode.Forbidden) }
            get("/status/{code}") { call.respond(HttpStatusCode.fromValue(call.parameters["code"]!!.toInt())) }
            webSocket("/ws") {
                for (frame in incoming) if (frame is Frame.Text) send(Frame.Text("echo:" + frame.readText()))
            }
            route("{...}") {
                handle {
                    call.response.headers.append("X-Backend", name)
                    val lines = buildString {
                        append("method=${call.request.httpMethod.value}\n")
                        append("uri=${call.request.uri}\n")
                        call.request.headers.entries().forEach { (n, values) -> values.forEach { append("${n.lowercase()}=$it\n") } }
                    }
                    call.respondText(lines)
                }
            }
        }
    }.start(wait = false)

    override fun close() {
        server.stop(100, 1000)
    }
}

/** A fake ACME issuer that signs a self-signed certificate valid for [lifetimeMillis]. */
class FakeIssuer(var lifetimeMillis: Long = 90L * 24 * 3600 * 1000, var fail: Boolean = false) : CertificateIssuer {
    val calls = mutableListOf<Pair<String, String>>()
    override fun issue(domain: String, directory: String): CertificateBundle {
        synchronized(calls) { calls += domain to directory }
        if (fail) error("fake failure")
        val pair = newEcKeyPair()
        return CertificateBundle(pair.private, arrayOf(selfSigned(pair, domain, lifetimeMillis = lifetimeMillis)))
    }
}

/**
 * A running Kovexy with its own data directory and free ports.
 *
 * @param config Text of `kovexy.json`. `ADMIN_PORT` is replaced by the admin port.
 */
class Harness(config: String, val issuer: FakeIssuer = FakeIssuer(), clock: () -> Long = System::currentTimeMillis, val adminPort: Int = freePort()) : AutoCloseable {
    val dataDir: File = Files.createTempDirectory("kovexy-test").toFile()
    val ports = Ports(freePort(), freePort())
    val store = ConfigStore(dataDir)
    val kovexy: Kovexy

    init {
        File(dataDir, "kovexy.json").writeText(config.replace("ADMIN_PORT", adminPort.toString()))
        val loaded = store.load()
        check(loaded is kotnexlib.ResultOf2.Success) { "Test config rejected: $loaded" }
        kovexy = createKovexy(store, ports, issuer = { _: CertStore, _: ChallengeStore, _: () -> String -> issuer }, clock = clock)
        kovexy.start()
    }

    /** Writes a new config file by hand and waits until Kovexy applied or rejected it. */
    suspend fun writeConfigByHand(text: String, expectApplied: Boolean = true) {
        val before = store.current.version
        File(dataDir, "kovexy.json").writeText(text.replace("ADMIN_PORT", adminPort.toString()))
        if (expectApplied) {
            repeat(100) {
                if (store.current.version != before) return
                delay(50)
            }
            error("Config was not applied")
        } else delay(1.seconds)
    }

    override fun close() {
        kovexy.stop()
        dataDir.deleteRecursively()
    }
}
