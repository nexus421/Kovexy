package bayern.kickner.kovexy

import bayern.kickner.kovexy.tls.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.net.Socket
import java.nio.file.Files
import javax.net.ssl.SSLContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Issues a real certificate through the HTTP-01 challenge against Pebble, Let's Encrypt's ACME test server. Never
 * against Let's Encrypt itself.
 *
 * Needs the `pebble` binary in `KOVEXY_PEBBLE` or on the `PATH`, otherwise the test is skipped. Pebble validates
 * against port 80 of the domain, the test points it to Kovexy's plain port. The domain must resolve to 127.0.0.1
 * for Pebble, by default `kovexy.localhost`, override it with `KOVEXY_PEBBLE_DOMAIN`.
 */
class PebbleAcmeTest {

    private fun pebbleBinary(): File? {
        System.getenv("KOVEXY_PEBBLE")?.let { return File(it).takeIf { f -> f.canExecute() } }
        return System.getenv("PATH").orEmpty().split(File.pathSeparator).map { File(it, "pebble") }.firstOrNull { it.canExecute() }
    }

    @Test
    fun issuesThroughHttp01(): Unit = runBlocking {
        val binary = pebbleBinary()
        assumeTrue(binary != null, "pebble not found, set KOVEXY_PEBBLE")
        val domain = System.getenv("KOVEXY_PEBBLE_DOMAIN") ?: "kovexy.localhost"
        val work = Files.createTempDirectory("kovexy-pebble").toFile()
        val backend = TestBackend()
        // Pebble's own TLS certificate, trusted by every client of this test JVM
        val pair = newEcKeyPair()
        File(work, "cert.pem").writeText(toPem(selfSigned(pair, "localhost")))
        File(work, "key.pem").writeText(privateKeyPem(pair.private))
        SSLContext.setDefault(trustAllContext)

        val harness = Harness(
            """{ "admin": { "port": ADMIN_PORT }, "backends": [ { "name": "app", "servers": [ { "address": "127.0.0.1:${backend.port}" } ] } ],
                "domains": [ { "names": ["$domain"], "routes": [ { "path": "/", "target": { "type": "backend", "backend": "app" } } ] } ] }"""
        )
        val acmePort = freePort()
        File(work, "pebble.json").writeText(
            """{ "pebble": { "listenAddress": "127.0.0.1:$acmePort", "managementListenAddress": "127.0.0.1:${freePort()}",
                "certificate": "${File(work, "cert.pem").absolutePath}", "privateKey": "${File(work, "key.pem").absolutePath}",
                "httpPort": ${harness.ports.http}, "tlsPort": ${freePort()}, "ocspResponderURL": "", "externalAccountBindingRequired": false } }"""
        )
        val pebble = ProcessBuilder(binary!!.absolutePath, "-config", File(work, "pebble.json").absolutePath)
            .redirectErrorStream(true).redirectOutput(File(work, "pebble.log"))
            .apply { environment()["PEBBLE_VA_NOSLEEP"] = "1"; environment()["PEBBLE_WFE_NONCEREJECT"] = "0" }
            .start()
        try {
            var listening = false
            for (attempt in 0 until 100) {
                if (runCatching { Socket("127.0.0.1", acmePort).close() }.isSuccess) {
                    listening = true
                    break
                }
                delay(100)
            }
            // A wrong binary fails here with its own output, not later with a bare network error. Canonical's Pebble
            // (a service manager, `/usr/bin/pebble` on some distributions) has the same name.
            check(listening) {
                "Pebble does not listen on port $acmePort. Is it the ACME test server from letsencrypt/pebble? Output: ${
                    File(
                        work,
                        "pebble.log"
                    ).readText().take(500)
                }"
            }
            val issuer = Acme4jIssuer(CertStore(File(work, "certs")), harness.kovexy.challenges) { "" }
            val bundle = issuer.issue(domain, "https://127.0.0.1:$acmePort/dir")
            assertTrue(bundle.leaf.subjectAlternativeNames.any { it[1] == domain })
            harness.kovexy.keyManager.install(domain, bundle.key, bundle.chain)
            assertEquals(bundle.leaf, rawRequest(harness.ports.https, domain, "/", tls = true).certificate)
        } finally {
            pebble.destroy()
            harness.close()
            backend.close()
            work.deleteRecursively()
        }
    }
}
