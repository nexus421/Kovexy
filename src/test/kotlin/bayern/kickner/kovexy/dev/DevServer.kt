package bayern.kickner.kovexy.dev

import bayern.kickner.klogger.KLogger
import bayern.kickner.kovexy.TestBackend
import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.config.ConfigStore
import bayern.kickner.kovexy.createKovexy
import bayern.kickner.kovexy.proxy.Ports
import java.io.File
import java.util.concurrent.CountDownLatch

/** Plain HTTP port of the dev proxy. */
const val DEV_HTTP_PORT = 18080

/** TLS port of the dev proxy. */
const val DEV_HTTPS_PORT = 18443

/** Port of the dev admin UI. */
const val DEV_ADMIN_PORT = 18000

/** Port of the mock OIDC provider of the dev instance. */
const val DEV_OIDC_PORT = 18001

/** Password of the throwaway dev instance. Never use it anywhere else. */
const val DEV_PASSWORD = "kovexy dev password only"

/**
 * Starts Kovexy for local development with two demo backends and the [MockOidcProvider]: run `./gradlew devRun`
 * and open `http://localhost:18000`, log in through the mock provider (login mode `oidc`, the password
 * [DEV_PASSWORD] is set as well for switching the mode). `http://app.localhost:18080` reaches the demo backends
 * through the proxy. Data lives in `build/dev`, delete it to start over. ACME cannot reach this machine, so the
 * certificate pages show failures, that is expected.
 */
fun main() {
    KLogger.configure { logToConsole() }
    val dir = File("build/dev").apply { mkdirs() }
    val first = TestBackend(name = "demo-1")
    val second = TestBackend(name = "demo-2")
    val oidc = MockOidcProvider(DEV_OIDC_PORT)
    val config = File(dir, "kovexy.json")
    if (config.exists().not()) {
        config.writeText(
            """
            {
              "admin": {
                "port": $DEV_ADMIN_PORT, "passwordHash": "${hashPassword(DEV_PASSWORD)}", "publicUrl": "http://localhost:$DEV_ADMIN_PORT",
                "loginMode": "oidc",
                "oidc": { "issuer": "${oidc.issuer}", "clientId": "kovexy-dev", "clientSecret": "${oidc.clientSecret}", "forceReauth": false }
              },
              "accessProfiles": [
                { "name": "demo-protection", "exploitFilter": { "commonExploits": true }, "trapPaths": { "enabled": true }, "rateLimit": { "requestsPerSecond": 50 } }
              ],
              "acme": { "staging": true },
              "backends": [
                { "name": "demo", "servers": [ { "address": "127.0.0.1:${first.port}" }, { "address": "127.0.0.1:${second.port}", "weight": 2 } ] }
              ],
              "domains": [
                { "names": ["app.localhost"], "access": "demo-protection", "routes": [
                  { "path": "/", "target": { "type": "backend", "backend": "demo" } },
                  { "path": "/.git", "target": { "type": "deny", "status": 404 } }
                ] }
              ]
            }
            """.trimIndent()
        )
    } else {
        // The demo backends get new ports on every start
        var n = 0
        config.writeText(config.readText().replace(Regex("""127\.0\.0\.1:\d+""")) { "127.0.0.1:${if (n++ == 0) first.port else second.port}" })
    }
    val store = ConfigStore(dir)
    check(store.load() is bayern.kickner.kovexy.ResultOf2.Success) { "build/dev/kovexy.json is invalid, delete build/dev to start over" }
    val kovexy = createKovexy(store, Ports(DEV_HTTP_PORT, DEV_HTTPS_PORT))
    kovexy.start()
    println("Admin UI on http://localhost:$DEV_ADMIN_PORT, login through the mock OIDC provider at ${oidc.issuer} (password for mode changes: $DEV_PASSWORD)")
    println("Proxy on http://app.localhost:$DEV_HTTP_PORT and https://app.localhost:$DEV_HTTPS_PORT")
    CountDownLatch(1).await()
}
