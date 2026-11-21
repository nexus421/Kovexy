package bayern.kickner.kovexy.site

import kotlinx.html.ButtonType
import kotlinx.html.FormMethod
import kotlinx.html.HTML
import kotlinx.html.button
import kotlinx.html.form
import kotlinx.html.hiddenInput
import kotlinx.html.id
import kotlinx.html.noScript
import kotlinx.html.script
import kotlinx.html.a
import kotlinx.html.body
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.head
import kotlinx.html.html
import kotlinx.html.lang
import kotlinx.html.li
import kotlinx.html.meta
import kotlinx.html.p
import kotlinx.html.stream.createHTML
import kotlinx.html.style
import kotlinx.html.title
import kotlinx.html.ul

/**
 * Styles of the neutral pages Kovexy shows to visitors (error pages, default page, directory listings). They are
 * served on the proxied domains, where the admin UI's stylesheet is not reachable, so they travel inside the page.
 * kotlinx.html escapes the text, the CSS therefore avoids `<`, `>`, `&` and quotes, so the escaping changes nothing.
 */
private const val NEUTRAL_CSS = """
:root { color-scheme: light dark; --bg: #f4f5f7; --fg: #1d2330; --muted: #5b6475; --card: #ffffff; --line: #dde1e8; --accent: #3b6fd8; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f1115; --fg: #e6e9ef; --muted: #9aa3b2; --card: #171a21; --line: #262b35; --accent: #7aa2ff; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 32px 36px; max-width: 640px; width: 100%; }
h1 { margin: 0 0 8px; font-size: 1.6rem; }
.code { color: var(--muted); font-size: .9rem; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 4px; }
p { color: var(--muted); margin: 0; }
ul { list-style: none; padding: 0; margin: 16px 0 0; }
li { border-top: 1px solid var(--line); padding: 8px 0; overflow-wrap: anywhere; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
"""

private fun HTML.frame(title: String, content: kotlinx.html.DIV.() -> Unit) {
    lang = "en"
    head {
        meta(charset = "utf-8")
        meta(name = "viewport", content = "width=device-width, initial-scale=1")
        meta(name = "robots", content = "noindex")
        title(title)
        // Escaped text, not unsafe {}: the CSS has no character the escaping would change
        @Suppress("DEPRECATION")
        style { +NEUTRAL_CSS }
    }
    body { div("card") { content() } }
}

/** A neutral page with a status code, a title and one sentence. */
fun neutralPage(status: Int, title: String, text: String): String = "<!DOCTYPE html>\n" + createHTML().html {
    frame("$status $title") {
        div("code") { +"Error $status" }
        h1 { +title }
        p { +text }
    }
}

/** The page for a backend that cannot be reached. */
fun badGatewayPage(): String = neutralPage(502, "Bad Gateway", "The service behind this address is not reachable right now. Please try again later.")

/** The page for a path nobody serves. */
fun notFoundPage(): String = neutralPage(404, "Not Found", "There is nothing at this address.")

/** The default page for names no domain serves, written to `<dataDir>/www/index.html` on the first start. */
fun defaultIndexPage(): String = "<!DOCTYPE html>\n" + createHTML().html {
    frame("Kovexy") {
        h1 { +"It works" }
        p { +"This server runs Kovexy, but no domain is set up for this address yet." }
    }
}

/**
 * A directory listing.
 *
 * @param path The requested directory path, shown as heading.
 * @param entries Names of the entries, directories with a trailing slash.
 */
fun directoryListingPage(path: String, entries: List<String>): String = "<!DOCTYPE html>\n" + createHTML().html {
    frame("Index of $path") {
        h1 { +"Index of $path" }
        ul {
            if (path != "/") li { a(href = "../") { +"../" } }
            entries.forEach { name -> li { a(href = encodePathSegment(name.removeSuffix("/")) + if (name.endsWith("/")) "/" else "") { +name } } }
        }
    }
}

/** Percent-encodes one path segment for a link. */
fun encodePathSegment(segment: String): String = buildString {
    segment.toByteArray().forEach { byte ->
        val c = byte.toInt() and 0xFF
        val ch = c.toChar()
        if (ch.isLetterOrDigit() && c < 128 || ch in "-._~") append(ch) else append("%").append("%02X".format(c))
    }
}

/**
 * The captcha page (Zoraxy shows it with 403). It posts to `/.kovexy/captcha/verify` and goes back to the requested
 * address afterwards.
 *
 * @param token Signed page token with profile, domain and return address.
 * @param provider `recaptcha2` (the checkbox) or `recaptcha3` (invisible).
 * @param siteKey Google site key.
 * @param error Shown above the captcha after a failed attempt.
 */
fun captchaPage(token: String, provider: String, siteKey: String, error: String? = null): String =
    "<!DOCTYPE html>\n" + createHTML().html {
        lang = "en"
        head {
            meta(charset = "utf-8")
            meta(name = "viewport", content = "width=device-width, initial-scale=1")
            meta(name = "robots", content = "noindex")
            title("One moment")
            @Suppress("DEPRECATION")
            style { +NEUTRAL_CSS }
            when (provider) {
                "recaptcha2" -> script(src = "https://www.google.com/recaptcha/api.js") { attributes["async"] = ""; attributes["defer"] = "" }
                "recaptcha3" -> script(src = "https://www.google.com/recaptcha/api.js?render=${encodePathSegment(siteKey)}") {}
            }
        }
        body {
            div("card") {
                h1 { +"One moment" }
                if (error != null) p { +error }
                form(action = "/.kovexy/captcha/verify", method = FormMethod.post) {
                    // Attributes first, kotlinx.html writes the tag before its first child
                    id = "kovexy-captcha"
                    attributes["data-provider"] = provider
                    if (provider == "recaptcha3") attributes["data-sitekey"] = siteKey
                    hiddenInput(name = "token") { value = token }
                    if (provider == "recaptcha2") {
                        p { +"Please confirm that you are a human." }
                        div("g-recaptcha") { attributes["data-sitekey"] = siteKey }
                        button(type = ButtonType.submit) { +"Continue" }
                    } else {
                        hiddenInput(name = "g-recaptcha-response") { value = "" }
                        p { id = "kovexy-status"; +"Checking your browser." }
                    }
                    noScript { p { +"This page needs JavaScript." } }
                }
            }
            script(src = "/.kovexy/captcha.js") {}
        }
    }
