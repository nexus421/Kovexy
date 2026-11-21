package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.t
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.Fallback
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FormMethod
import kotlinx.html.div
import kotlinx.html.fieldSet
import kotlinx.html.form
import kotlinx.html.legend
import kotlinx.html.p

/** What happens for names no domain serves, like Zoraxy's "Default Site". */
fun Route.fallbackRoutes(kovexy: Kovexy) {
    get("/fallback") { call.fallbackForm(kovexy, kovexy.config.fallback, emptyList(), null) }

    post("/fallback") {
        val params = call.receiveForm()
        val fallback = when (params["targetType"]) {
            "backend" -> Fallback.Backend(params["backend"].orEmpty())
            "redirect" -> Fallback.Redirect(params["url"].orEmpty().trim(), params["redirectStatus"]?.toIntOrNull() ?: 307, params["keepPath"] != null)
            "notFound" -> Fallback.NotFound
            "noResponse" -> Fallback.NoResponse
            else -> Fallback.Static(params["root"].orEmpty().trim(), params["directoryListing"] != null)
        }
        val problems = call.saveConfig(params["version"]) { it.copy(fallback = fallback) }
        if (problems == null) return@post call.respondRedirect("/fallback?done=default-saved")
        call.fallbackForm(kovexy, fallback, problems, params["version"])
    }
}

private suspend fun ApplicationCall.fallbackForm(kovexy: Kovexy, fallback: Fallback, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val type = when (fallback) {
        is Fallback.Static -> "static"
        is Fallback.Backend -> "backend"
        is Fallback.Redirect -> "redirect"
        Fallback.NotFound -> "notFound"
        Fallback.NoResponse -> "noResponse"
    }
    page("Fallback", session, Nav.FALLBACK, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Fallback", "What visitors get for a name that no domain serves. Over HTTPS they also get the self-signed fallback certificate.")
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = "/fallback", method = FormMethod.post, classes = "form") {
                versionField(version)
                selectField("Answer", "targetType", type, help = "fallback.type", options = listOf(
                    "static" to "Static files",
                    "backend" to "Forward to a backend",
                    "redirect" to "Redirect to a fixed address",
                    "notFound" to "404 page",
                    "noResponse" to "Empty answer (204), then close the connection",
                ))
                fieldSet("target-fields target-static") {
                    legend { +t("Static files") }
                    textField("Directory", "root", (fallback as? Fallback.Static)?.root.orEmpty(), hint = t("Empty means www in the data directory, with a neutral page."), required = false)
                    checkField("List directories without index file", "directoryListing", (fallback as? Fallback.Static)?.directoryListing == true)
                }
                fieldSet("target-fields target-backend") {
                    legend { +t("Backend") }
                    selectField("Backend", "backend", (fallback as? Fallback.Backend)?.backend.orEmpty(),
                        kovexy.config.backends.map { it.name to it.name }.ifEmpty { listOf("" to "No backends yet") })
                }
                fieldSet("target-fields target-redirect") {
                    legend { +t("Redirect") }
                    textField("Target URL", "url", (fallback as? Fallback.Redirect)?.url.orEmpty(), help = "redirectUrl", placeholder = "https://example.com", required = false,
                        hint = t("A redirect to the requested domain itself is refused, it would loop."))
                    selectField("Status", "redirectStatus", ((fallback as? Fallback.Redirect)?.status ?: 307).toString(), listOf("307" to "307 temporary", "301" to "301 permanent"))
                    checkField("Keep the path and query", "keepPath", (fallback as? Fallback.Redirect)?.keepPath ?: true)
                }
                p("muted small") { +t("The 404 page and the empty answer need no settings.") }
                div("btn-row") { submit("Save fallback") }
            }
        }
    }
}
