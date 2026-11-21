package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.I18n
import bayern.kickner.kovexy.i18n.t
import bayern.kickner.kovexy.PASSWORD_ONLY_WARNING
import bayern.kickner.kovexy.RELEASES_URL
import bayern.kickner.kovexy.appVersion
import bayern.kickner.kovexy.auth.Session
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.html.respondHtml
import kotlinx.html.ButtonType
import kotlinx.html.DIV
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.a
import kotlinx.html.summary
import kotlinx.html.details
import kotlinx.html.aside
import kotlinx.html.body
import kotlinx.html.button
import kotlinx.html.checkBoxInput
import kotlinx.html.dd
import kotlinx.html.div
import kotlinx.html.dl
import kotlinx.html.dt
import kotlinx.html.footer
import kotlinx.html.form
import kotlinx.html.h1
import kotlinx.html.h2
import kotlinx.html.head
import kotlinx.html.header
import kotlinx.html.hiddenInput
import kotlinx.html.id
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.li
import kotlinx.html.link
import kotlinx.html.main
import kotlinx.html.meta
import kotlinx.html.nav
import kotlinx.html.option
import kotlinx.html.p
import kotlinx.html.pre
import kotlinx.html.script
import kotlinx.html.select
import kotlinx.html.span
import kotlinx.html.textArea
import kotlinx.html.title
import kotlinx.html.ul

/** Groups of the navigation (decided on 18.11.2026). */
enum class NavGroup(val label: String) {
    OVERVIEW("Overview"),
    ROUTING("Routing"),
    PROTECTION("Protection"),
    SYSTEM("System"),
}

/** Navigation entries in the order they are shown, each in its [NavGroup]. */
enum class Nav(val label: String, val href: String, val group: NavGroup) {
    STATUS("Status", "/", NavGroup.OVERVIEW),
    STATISTICS("Statistics", "/statistics", NavGroup.OVERVIEW),
    ACCESS_LOG("Access log", "/access-log", NavGroup.OVERVIEW),
    DOMAINS("Domains", "/domains", NavGroup.ROUTING),
    BACKENDS("Backends", "/backends", NavGroup.ROUTING),
    CERTIFICATES("Certificates", "/certificates", NavGroup.ROUTING),
    FALLBACK("Fallback", "/fallback", NavGroup.ROUTING),
    INCUS("Incus", "/incus", NavGroup.ROUTING),
    ACCESS("Access", "/access", NavGroup.PROTECTION),
    SECURITY("Security", "/security", NavGroup.PROTECTION),
    WEBHOOKS("Webhooks", "/webhooks", NavGroup.SYSTEM),
    AUDIT("Audit", "/audit", NavGroup.SYSTEM),
    SETTINGS("Settings", "/settings", NavGroup.SYSTEM),
}

/** The grouped navigation with the logout button, the same list in the sidebar and in the phone menu. */
private fun FlowContent.navigation(active: Nav?) {
    nav("side-nav") {
        attributes["aria-label"] = t("Main")
        NavGroup.entries.forEach { group ->
            div("nav-group") {
                div("nav-heading") { +t(group.label) }
                Nav.entries.filter { it.group == group }.forEach { entry ->
                    a(href = entry.href, classes = if (entry == active) "active" else null) {
                        if (entry == active) attributes["aria-current"] = "page"
                        +t(entry.label)
                    }
                }
            }
        }
    }
    form(action = "/logout", method = FormMethod.post, classes = "logout") {
        button(type = ButtonType.submit, classes = "btn ghost sm") { +t("Log out") }
    }
}

private fun FlowContent.brand() = a(href = "/", classes = "brand") {
    span("logo") { +"K" }
    +t("Kovexy")
}

/** How a page is framed. */
enum class PageFrame {
    /** App bar with navigation and a centered content column. */
    APP,

    /** Only a centered card, for the login. */
    CENTER,
}

/**
 * Messages shown after a successful POST and redirect. The redirect only carries the key (`?done=domain-saved`), so
 * no text from the URL ever ends up on the page.
 */
internal val flashMessages = mapOf(
    "domain-saved" to "Domain saved and applied.",
    "domain-deleted" to "Domain deleted.",
    "route-saved" to "Route saved and applied.",
    "route-deleted" to "Route deleted.",
    "backend-saved" to "Backend saved and applied.",
    "backend-deleted" to "Backend deleted.",
    "default-saved" to "Fallback saved and applied.",
    "acme-saved" to "ACME settings saved.",
    "renew-started" to "Renewal started, the result shows here in a moment.",
    "webhook-saved" to "Webhook saved.",
    "webhook-deleted" to "Webhook deleted.",
    "webhook-tested" to "Test message delivered.",
    "settings-saved" to "Settings saved and applied.",
    "password-changed" to "Password changed. Every other session was ended.",
    "sessions-ended" to "Every other session was ended.",
    "restored" to "Backup restored and applied.",
    "restored-login" to "Backup restored and applied. The restore ended every login, please log in again.",
    "logged-out" to "Logged out.",
    "profile-saved" to "Access profile saved and applied.",
    "profile-saved-short-password" to "Access profile saved and applied. A new password is shorter than 12 characters, a longer one is harder to guess.",
    "profile-deleted" to "Access profile deleted.",
    "ai-crawlers-saved" to "AI crawler list saved and applied.",
    "ban-lifted" to "Ban lifted.",
    "incus-saved" to "Incus settings saved and applied.",
    "incus-approved" to "Container approved, its domain is live.",
    "incus-rejected" to "Container rejected.",
    "incus-removed" to "Decision removed.",
)

/** The HTMX config: no inline styles, no eval, so the strict CSP holds. */
private const val HTMX_CONFIG = """{"includeIndicatorStyles":false,"allowEval":false,"allowScriptTags":false,"selfRequestsOnly":true}"""

/**
 * Renders a full page in the common layout. All text goes through kotlinx.html, which escapes it.
 *
 * @param title Browser tab title.
 * @param session The logged-in admin, `null` on the login page.
 * @param nav The highlighted navigation entry.
 * @param frame Page framing.
 * @param htmx Loads htmx and its SSE extension, for pages with live updates.
 * @param refresh Content of a `<meta http-equiv="refresh">`, e.g. `0; url=/` to continue to another page.
 * @param status HTTP status of the response.
 * @param content The page body.
 */
suspend fun ApplicationCall.page(
    title: String,
    session: Session?,
    nav: Nav? = null,
    frame: PageFrame = PageFrame.APP,
    htmx: Boolean = false,
    refresh: String? = null,
    status: HttpStatusCode = HttpStatusCode.OK,
    content: FlowContent.() -> Unit,
) {
    val kovexy = application.attributes[KovexyKey]
    val flash = request.queryParameters["done"]?.let { key -> flashMessages[key]?.let { t(it) } }
    val updates = if (session != null) kovexy.updates else null
    updates?.checkIfDue(kovexy.scope)
    val newer = updates?.available()
    respondHtml(status) {
        attributes["lang"] = I18n.language
        head {
            meta(charset = "utf-8")
            meta(name = "viewport", content = "width=device-width, initial-scale=1, viewport-fit=cover")
            meta(name = "color-scheme", content = "light dark")
            meta(name = "theme-color", content = "#f4f5f7") { attributes["media"] = "(prefers-color-scheme: light)" }
            meta(name = "theme-color", content = "#0f1115") { attributes["media"] = "(prefers-color-scheme: dark)" }
            if (htmx) meta(name = "htmx-config", content = HTMX_CONFIG)
            if (refresh != null) meta { httpEquiv = "refresh"; this.content = refresh }
            title("${t(title)} | Kovexy")
            link(rel = "icon", href = "/static/favicon.svg") { attributes["type"] = "image/svg+xml" }
            link(rel = "stylesheet", href = "/static/app.css")
        }
        body {
            val withNav = frame == PageFrame.APP && session != null
            if (frame == PageFrame.CENTER) main("center-wrap") {
                div("center-card") {
                    brand()
                    if (flash != null) notice("success", flash)
                    content()
                }
            } else div(if (withNav) "shell" else "shell bare") {
                // Desktop: a fixed sidebar. Phones: a top bar whose menu opens the same list, without JavaScript
                if (withNav) {
                    aside("sidebar") {
                        brand()
                        navigation(nav)
                    }
                    header("topbar") {
                        brand()
                        details("menu") {
                            summary("btn sm") { +t("Menu") }
                            div("menu-panel") { navigation(nav) }
                        }
                    }
                } else header("topbar plain") { brand() }
                div("main-col") {
                    // Not dismissable on purpose: as long as only the password protects the UI, every page says so
                    if (kovexy.passwordOnly) div("banner") { +t(PASSWORD_ONLY_WARNING) }
                    main("container") {
                        if (flash != null) notice("success", flash)
                        content()
                    }
                    // The version is nobody's business before the login, so pages without a session have no footer
                    if (session != null) footer {
                        +t("Kovexy {0}", appVersion)
                        if (newer != null) {
                            +" · "
                            a(href = "$RELEASES_URL/tag/v$newer") {
                                attributes["rel"] = "noopener noreferrer"
                                +t("{0} available", newer)
                            }
                        }
                    }
                }
            }
            script(src = "/static/app.js") {}
            if (htmx) {
                script(src = "/static/vendor/htmx/htmx.min.js") {}
                script(src = "/static/vendor/htmx/sse.min.js") {}
            }
        }
    }
}

/** Page title with optional subtitle and action buttons on the right. */
fun FlowContent.pageHeader(title: String, subtitle: String? = null, actions: (DIV.() -> Unit)? = null) =
    div("page-header") {
        div {
            h1 { +t(title) }
            if (subtitle != null) p("subtitle") { +t(subtitle) }
        }
        if (actions != null) div("actions") { actions() }
    }

/** A card with an optional heading. */
fun FlowContent.card(title: String? = null, classes: String = "", content: DIV.() -> Unit) =
    div("card $classes".trim()) {
        if (title != null) h2 { +t(title) }
        content()
    }

/** A message box. [kind] is `success`, `info`, `warn` or `error`. */
fun FlowContent.notice(kind: String, text: String) = div("notice $kind") { +t(text) }

/** An error box listing every problem, e.g. of a rejected config. */
fun FlowContent.problems(title: String, items: List<String>) = div("notice error") {
    div {
        +t(title)
        ul("problems") { items.forEach { li { +it } } }
    }
}

/** A colored status pill. [kind] is `ok`, `warn`, `error` or empty for neutral. */
fun FlowContent.pill(kind: String, text: String) = span("pill $kind".trim()) { +t(text) }

/** A link styled as button. [kind] adds `primary`, `danger`, `ghost` or `sm`. */
fun FlowContent.linkButton(href: String, label: String, kind: String = "") =
    a(href = href, classes = "btn $kind".trim()) { +t(label) }

/**
 * A small POST form with a single button, for actions like delete. With [confirm] the browser asks before
 * submitting (through `app.js`).
 */
fun FlowContent.postButton(
    action: String,
    label: String,
    kind: String = "",
    confirm: String? = null,
    hidden: Map<String, String> = emptyMap(),
) = form(action = action, method = FormMethod.post, classes = "inline") {
    if (confirm != null) attributes["data-confirm"] = t(confirm)
    hidden.forEach { (name, value) -> hiddenInput(name = name) { this.value = value } }
    button(type = ButtonType.submit, classes = "btn $kind".trim()) { +t(label) }
}

private val elementCounter = java.util.concurrent.atomic.AtomicLong()

/**
 * Text in a code block with a copy button (Dirl's `copyBlock`). With [template] `app.js` rewrites the text from inputs
 * whose `data-fills` is [commandId], `{key}` in the template stands for the input with that `data-key`.
 */
fun FlowContent.copyBlock(text: String, commandId: String? = null, template: String? = null) = div("code") {
    val elementId = commandId ?: "copy-${elementCounter.incrementAndGet()}"
    pre {
        id = elementId
        if (template != null) attributes["data-template"] = template
        +text
    }
    button(type = ButtonType.button, classes = "btn sm") {
        attributes["data-copy"] = elementId
        attributes["data-copied"] = t("Copied")
        +t("Copy")
    }
}

/** A unique element ID for this page render. */
fun nextElementId(prefix: String): String = "$prefix-${elementCounter.incrementAndGet()}"

/** A definition list of label and value pairs. */
fun FlowContent.keyValues(vararg rows: Pair<String, String>) = dl("kv") {
    rows.forEach { (label, value) ->
        dt { +t(label) }
        dd { +value }
    }
}

/** A labeled text input with an optional hint below. */
fun FlowContent.textField(
    label: String,
    name: String,
    value: String = "",
    hint: String? = null,
    required: Boolean = true,
    placeholder: String? = null,
    type: InputType = InputType.text,
    help: String? = null,
) = label("field") {
    span { +t(label); helpButton(help ?: name, label) }
    input(type = type, name = name) {
        this.value = value
        this.required = required
        attributes["aria-label"] = t(label)
        if (placeholder != null) this.placeholder = t(placeholder)
        attributes["autocomplete"] = "off"
        attributes["spellcheck"] = "false"
    }
    if (hint != null) span("hint") { +t(hint) }
}

/** A labeled password input. */
fun FlowContent.passwordField(label: String, name: String, autocomplete: String, hint: String? = null) = label("field") {
    span { +t(label) }
    input(type = InputType.password, name = name) {
        required = true
        attributes["aria-label"] = t(label)
        attributes["autocomplete"] = autocomplete
    }
    if (hint != null) span("hint") { +t(hint) }
}

/** A labeled multi-line input. */
fun FlowContent.textAreaField(label: String, name: String, value: String = "", rows: Int = 4, hint: String? = null, required: Boolean = false, help: String? = null) =
    label("field") {
        span { +t(label); helpButton(help ?: name, label) }
        textArea(rows = rows.toString()) {
            this.name = name
            this.required = required
            attributes["aria-label"] = t(label)
            attributes["spellcheck"] = "false"
            attributes["autocomplete"] = "off"
            +value
        }
        if (hint != null) span("hint") { +t(hint) }
    }

/** A checkbox with its label text. */
fun FlowContent.checkField(label: String, name: String, checked: Boolean, hint: String? = null, help: String? = null) = label("check") {
    checkBoxInput(name = name) { this.checked = checked }
    span {
        +t(label)
        helpButton(help ?: name, label)
        if (hint != null) {
            +" "
            span("hint muted small") { +t(hint) }
        }
    }
}

/** A labeled select. [options] are value to label. */
fun FlowContent.selectField(label: String, name: String, selected: String, options: List<Pair<String, String>>, hint: String? = null, autosubmit: Boolean = false, help: String? = null) =
    label("field") {
        span { +t(label); helpButton(help ?: name, label) }
        select {
            this.name = name
            if (autosubmit) attributes["data-autosubmit"] = ""
            options.forEach { (value, text) ->
                option {
                    this.value = value
                    this.selected = value == selected
                    +t(text)
                }
            }
        }
        if (hint != null) span("hint") { +t(hint) }
    }

/** A plain primary submit button. */
fun FlowContent.submit(label: String, kind: String = "primary", name: String? = null, value: String? = null) =
    button(type = ButtonType.submit, classes = "btn $kind".trim()) {
        if (name != null) this.name = name
        if (value != null) this.value = value
        +t(label)
    }

/** The hidden field with the config version a form is based on, see [bayern.kickner.kovexy.config.LoadedConfig]. */
fun FlowContent.versionField(version: String) = hiddenInput(name = "version") { value = version }

/** A number tile of the status and statistics pages. With [href] the whole tile is a link to the page behind the number. */
fun FlowContent.stat(value: String, label: String, href: String? = null) {
    if (href == null) div("stat") {
        div("value") { +value }
        div("label") { +t(label) }
    } else a(href = href, classes = "stat") {
        div("value") { +value }
        div("label") { +t(label) }
    }
}

/**
 * A section that folds away, closed by default so a long page stays short. [state] is a short note beside the title that
 * stays visible when the section is closed, e.g. "on" or "3 entries". Open it with [open] for what is needed most and
 * after a refused save, so the fields with the problem are not hidden. The fields of a closed section are still sent.
 */
fun FlowContent.fold(title: String, state: String? = null, open: Boolean = false, content: DIV.() -> Unit) =
    details("fold") {
        if (open) attributes["open"] = "open"
        summary("fold-title") {
            span("fold-name") { +t(title) }
            if (state != null) span("fold-state") { +t(state) }
        }
        div("fold-body") { content() }
    }
