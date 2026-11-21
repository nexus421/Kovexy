package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.DEFAULT_WEBHOOK_TEMPLATE
import bayern.kickner.kovexy.config.KNOT_WEBHOOK_TEMPLATE
import bayern.kickner.kovexy.config.WebhookConfig
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.notify.BUNDLED_EVENTS
import bayern.kickner.kovexy.notify.key
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FormMethod
import kotlinx.html.a
import kotlinx.html.div
import kotlinx.html.fieldSet
import kotlinx.html.form
import kotlinx.html.legend
import kotlinx.html.p
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr

/** Webhook targets, with the KNot preset and a test message. */
fun Route.webhookRoutes(kovexy: Kovexy) {
    get("/webhooks") {
        call.page("Webhooks", call.session, Nav.WEBHOOKS) {
            pageHeader("Webhooks", "Kovexy sends a POST with your template when something happens. Delivery is tried three times.") {
                linkButton("/webhooks/new", "Add webhook", "primary")
            }
            val hooks = kovexy.config.webhooks
            card {
                if (hooks.isEmpty()) p("muted") { +"No webhooks yet. With KNot you get these events as mail." }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Name" }; th { +"URL" }; th { +"Events" }; th { } } }
                        tbody {
                            hooks.forEach { hook ->
                                tr {
                                    td { attributes["data-label"] = "Name"; a(href = "/webhooks/${urlPart(hook.name)}") { +hook.name } }
                                    td { attributes["data-label"] = "URL"; +hook.url }
                                    td { attributes["data-label"] = "Events"; +"${hook.events.size} of ${WebhookEvent.entries.size}" }
                                    td("actions") {
                                        postButton("/webhooks/${urlPart(hook.name)}/test", "Send test", "sm")
                                        linkButton("/webhooks/${urlPart(hook.name)}", "Edit", "sm")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    get("/webhooks/new") {
        val preset = call.request.queryParameters["preset"] == "knot"
        val hook = if (preset) WebhookConfig("KNot", "https://knot.example.com/hook", mapOf("X-API-Key" to "your-api-key"), KNOT_WEBHOOK_TEMPLATE)
        else WebhookConfig("", "", template = DEFAULT_WEBHOOK_TEMPLATE)
        call.webhookForm(kovexy, null, hook, emptyList(), null)
    }

    post("/webhooks/new") {
        val params = call.receiveForm()
        val (hook, parseProblems) = webhookFromForm(params)
        val problems = parseProblems.ifEmpty { call.saveConfig(params["version"]) { it.copy(webhooks = it.webhooks + hook) } }
        if (problems == null) return@post call.respondRedirect("/webhooks?done=webhook-saved")
        call.webhookForm(kovexy, null, hook, problems, params["version"])
    }

    get("/webhooks/{name}") {
        val hook = kovexy.config.webhooks.firstOrNull { it.name == call.parameters["name"] } ?: return@get call.notFoundWebhook()
        call.webhookForm(kovexy, hook.name, hook, emptyList(), null)
    }

    post("/webhooks/{name}") {
        val name = call.parameters["name"]!!
        if (kovexy.config.webhooks.none { it.name == name }) return@post call.notFoundWebhook()
        val params = call.receiveForm()
        val (hook, parseProblems) = webhookFromForm(params)
        val problems = parseProblems.ifEmpty { call.saveConfig(params["version"]) { c -> c.copy(webhooks = c.webhooks.map { if (it.name == name) hook else it }) } }
        if (problems == null) return@post call.respondRedirect("/webhooks?done=webhook-saved")
        call.webhookForm(kovexy, name, hook, problems, params["version"])
    }

    post("/webhooks/{name}/delete") {
        val name = call.parameters["name"]!!
        val params = call.receiveForm()
        if (kovexy.config.webhooks.none { it.name == name }) return@post call.notFoundWebhook()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(webhooks = c.webhooks.filter { it.name != name }) }
        if (problems == null) return@post call.respondRedirect("/webhooks?done=webhook-deleted")
        call.errorPage(HttpStatusCode.BadRequest, "Not deleted", problems.joinToString(" "))
    }

    post("/webhooks/{name}/test") {
        val hook = kovexy.config.webhooks.firstOrNull { it.name == call.parameters["name"] } ?: return@post call.notFoundWebhook()
        if (kovexy.webhooks.test(hook)) return@post call.respondRedirect("/webhooks?done=webhook-tested")
        call.errorPage(HttpStatusCode.BadGateway, "Test failed", "The webhook \"${hook.name}\" did not answer with a 2xx status within 10 seconds. The log has the details.")
    }
}

private suspend fun ApplicationCall.notFoundWebhook() = errorPage(HttpStatusCode.NotFound, "Webhook not found", "This webhook does not exist (any more).")

private fun webhookFromForm(params: Parameters): Pair<WebhookConfig, List<String>> {
    val problems = mutableListOf<String>()
    val headers = params["headers"].orEmpty().lines().map { it.trim() }.filter { it.isNotEmpty() }.mapNotNull { line ->
        if (':' !in line) {
            problems += "Header \"$line\" needs the form \"Name: value\""
            null
        } else line.substringBefore(':').trim() to line.substringAfter(':').trim()
    }.toMap()
    val events = WebhookEvent.entries.filter { params["event.${it.key}"] != null }
    val window = parseDuration("Bundle window", params["bundleWindow"], problems)
    val hook = WebhookConfig(
        name = params["name"].orEmpty().trim(),
        url = params["url"].orEmpty().trim(),
        headers = headers,
        template = params["template"].orEmpty(),
        events = events,
        bundleWindow = window ?: WebhookConfig("", "").bundleWindow,
    )
    return hook to problems
}

private suspend fun ApplicationCall.webhookForm(kovexy: Kovexy, name: String?, hook: WebhookConfig, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val title = if (name == null) "Add webhook" else "Webhook $name"
    val action = if (name == null) "/webhooks/new" else "/webhooks/${urlPart(name)}"
    page(title, session, Nav.WEBHOOKS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title) {
            if (name == null) linkButton("/webhooks/new?preset=knot", "Use KNot preset", "")
            linkButton("/webhooks", "All webhooks", "ghost")
        }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = action, method = FormMethod.post, classes = "form") {
                versionField(version)
                div("grid-2") {
                    textField("Name", "name", hook.name, help = "webhook.name")
                    textField("URL", "url", hook.url, placeholder = "https://knot.example.com/hook", help = "webhook.url")
                }
                textAreaField("Headers", "headers", hook.headers.entries.joinToString("\n") { "${it.key}: ${it.value}" }, rows = 2, help = "webhook.headers",
                    hint = "One per line, Name: value. Without Content-Type Kovexy sends application/json.")
                textAreaField("Template", "template", hook.template, rows = 4, required = true,
                    hint = "Placeholders: {{event}}, {{subject}}, {{body}}, {{time}}, {{domain}}. Values are escaped for JSON strings.")
                fieldSet {
                    legend { +"Events"; helpButton("webhook.events", "Events") }
                    WebhookEvent.entries.forEach { event ->
                        checkField(event.label, "event.${event.key}", event in hook.events, if (event in BUNDLED_EVENTS) "bundled" else null)
                    }
                }
                textField("Bundle window", "bundleWindow", hook.bundleWindow.toString(),
                    hint = "The first IP ban or failed login is sent at once, further ones within this time come as one message.")
                div("btn-row") { submit("Save webhook") }
            }
        }
        if (name != null) card("Delete webhook", "danger gap-top") {
            postButton("$action/delete", "Delete webhook", "danger", confirm = "Delete this webhook?", hidden = mapOf("version" to version))
        }
    }
}
