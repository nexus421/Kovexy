package bayern.kickner.kovexy

import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.i18n.I18n
import bayern.kickner.kovexy.i18n.LANGUAGES
import bayern.kickner.kovexy.web.flashMessages
import java.io.File
import java.net.URLEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Renders every admin page in German and collects the texts that have no translation. With the environment variable
 * `KOVEXY_COLLECT_TEXTS` set to a file name the texts are written there instead of failing, that is how a dictionary is
 * started for a new language.
 */
class TranslationsTest {
    private val password = "test password 123"

    private val config = """
        { "admin": { "port": ADMIN_PORT, "passwordHash": "${hashPassword(password)}" },
          "accessProfiles": [ { "name": "p", "denyIps": ["10.0.0.0/8"], "allowIps": ["127.0.0.1"], "exploitFilter": { "commonExploits": true, "aiBots": true },
                                "trapPaths": { "enabled": true }, "rateLimit": { "requestsPerSecond": 5 }, "allowedMethods": ["GET"] } ],
          "backends": [ { "name": "app", "servers": [ { "address": "127.0.0.1:9" } ], "healthCheck": { "path": "/health" } } ],
          "domains": [ { "names": ["a.test"], "access": "p", "routes": [
              { "path": "/", "target": { "type": "backend", "backend": "app" } },
              { "path": "/files", "target": { "type": "static", "root": "/tmp" } },
              { "path": "/go", "target": { "type": "redirect", "url": "https://x.test" } },
              { "path": "/no", "target": { "type": "deny" } } ] },
            { "names": ["quiet.test"], "accessLog": false } ],
          "webhooks": [ { "name": "w", "url": "https://hook.test/x" } ] }
    """.trimIndent()

    private fun form(vararg fields: Pair<String, String>) =
        fields.joinToString("&") { (k, v) -> "${URLEncoder.encode(k, Charsets.UTF_8)}=${URLEncoder.encode(v, Charsets.UTF_8)}" }.toByteArray()

    @Test
    fun everyPageIsTranslated(): Unit {
        val missing = sortedSetOf<String>()
        Harness(config).use { harness ->
            val origin = "http://127.0.0.1:${harness.adminPort}"
            val host = "127.0.0.1:${harness.adminPort}"
            fun post(path: String, body: ByteArray, cookie: String? = null) = rawRequest(
                harness.adminPort, host, path, method = "POST", body = body,
                headers = listOfNotNull("Content-Type" to "application/x-www-form-urlencoded", "Origin" to origin, cookie?.let { "Cookie" to it }),
            )
            val login = post("/login", form("password" to password))
            val cookie = login.headerAll("Set-Cookie").first { it.startsWith("__Host-kovexy-session=") }.substringBefore(';')
            fun get(path: String) = rawRequest(harness.adminPort, host, path, headers = listOf("Cookie" to cookie))

            val before = I18n.language
            I18n.language = "de"
            I18n.onMissing = { missing += it }
            try {
                val pages = listOf(
                    "/login", "/", "/statistics", "/statistics?range=7d", "/statistics?range=365d&domain=a.test", "/access-log", "/access-log?status=blocked", "/access-log?status=redirects",
                    "/domains", "/domains/new", "/domains/0", "/domains/0/routes/new", "/domains/0/routes/0", "/domains/0/routes/1", "/domains/0/routes/2", "/domains/0/routes/3",
                    "/backends", "/backends/new", "/backends/app", "/certificates", "/fallback", "/incus", "/access", "/access/new", "/access/p",
                    "/security", "/audit", "/webhooks", "/webhooks/new", "/webhooks/w", "/settings", "/domains/99", "/backends/none", "/access/none", "/webhooks/none",
                ) + flashMessages.keys.map { "/?done=$it" }
                pages.forEach { path -> get(path) }
                // The login page and an error page without a session
                rawRequest(harness.adminPort, host, "/login")
                rawRequest(harness.adminPort, host, "/nothing-here")
                // Refused forms show their problems and keep the fields
                post("/domains/new", form("names" to "*.test"), cookie)
                post("/access/new", form("name" to ""), cookie)
                post("/backends/new", form("name" to ""), cookie)
                post("/webhooks/new", form("name" to ""), cookie)
                post("/settings", form("adminPort" to "x"), cookie)
                post("/settings/password", form("current" to "wrong", "new" to "a", "repeat" to "b"), cookie)
            } finally {
                I18n.onMissing = null
                I18n.language = before
            }
        }
        // A helper translates again what a call site already translated from a template, that is no missing text
        val templates = I18n.dictionary("de").values.filter { "{" in it }.map { value ->
            Regex(value.split(Regex("\\{\\d+\\}")).joinToString(".+?") { Regex.escape(it) })
        }
        missing.removeAll { text -> templates.any { it.matches(text) } }
        val target = System.getenv("KOVEXY_COLLECT_TEXTS")
        if (target != null) {
            File(target).writeText(missing.joinToString("\n"))
            return
        }
        assertEquals(emptySet<String>(), missing.toSet(), "These texts have no German translation")
    }

    @Test
    fun theLanguageListMatchesTheDictionaries(): Unit {
        assertTrue("en" in LANGUAGES)
        LANGUAGES.keys.filter { it != "en" }.forEach { code ->
            assertTrue(I18n.dictionary(code).isNotEmpty(), "Language $code has no dictionary")
        }
    }

    @Test
    fun everyWrappedTextHasATranslation(): Unit {
        val dictionary = I18n.dictionary("de")
        val call = Regex("""(?<![A-Za-z0-9_.])t\("((?:[^"\\]|\\.)*)"""")
        val missing = sortedSetOf<String>()
        File("src/main/kotlin").walkTopDown().filter { it.extension == "kt" }.forEach { file ->
            call.findAll(file.readText()).forEach { match ->
                val text = match.groupValues[1].replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n")
                if (text !in dictionary) missing += text
            }
        }
        assertEquals(emptySet<String>(), missing.toSet(), "Texts in t(...) without a German translation")
    }

    @Test
    fun translationsKeepPlaceholdersAndWritingRules(): Unit {
        val placeholder = Regex("""\{\d+\}""")
        I18n.dictionary("de").forEach { (english, german) ->
            assertEquals(placeholder.findAll(english).map { it.value }.sorted().toList(), placeholder.findAll(german).map { it.value }.sorted().toList(), "Placeholders of: $english")
            assertTrue('\u2014' !in german && '\u2013' !in german && ';' !in german, "Writing rules: $german")
        }
    }
}
