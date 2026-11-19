package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.DefaultSite
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

/** What happens for domains no site serves, like Zoraxy's "Default Site". */
fun Route.defaultSiteRoutes(kovexy: Kovexy) {
    get("/default-site") { call.defaultSiteForm(kovexy, kovexy.config.defaultSite, emptyList(), null) }

    post("/default-site") {
        val params = call.receiveForm()
        val site = when (params["targetType"]) {
            "upstream" -> DefaultSite.Upstream(params["upstream"].orEmpty())
            "redirect" -> DefaultSite.Redirect(params["url"].orEmpty().trim(), params["redirectStatus"]?.toIntOrNull() ?: 307, params["keepPath"] != null)
            "notFound" -> DefaultSite.NotFound
            "noResponse" -> DefaultSite.NoResponse
            else -> DefaultSite.Static(params["root"].orEmpty().trim(), params["directoryListing"] != null)
        }
        val problems = call.saveConfig(params["version"]) { it.copy(defaultSite = site) }
        if (problems == null) return@post call.respondRedirect("/default-site?done=default-saved")
        call.defaultSiteForm(kovexy, site, problems, params["version"])
    }
}

private suspend fun ApplicationCall.defaultSiteForm(kovexy: Kovexy, site: DefaultSite, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val type = when (site) {
        is DefaultSite.Static -> "static"
        is DefaultSite.Upstream -> "upstream"
        is DefaultSite.Redirect -> "redirect"
        DefaultSite.NotFound -> "notFound"
        DefaultSite.NoResponse -> "noResponse"
    }
    page("Default site", session, Nav.DEFAULT_SITE, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Default site", "What visitors get for a domain no site serves. Over HTTPS they also get the self-signed fallback certificate.")
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = "/default-site", method = FormMethod.post, classes = "form") {
                versionField(version)
                selectField("Answer", "targetType", type, listOf(
                    "static" to "Static files",
                    "upstream" to "Forward to an upstream group",
                    "redirect" to "Redirect to a fixed address",
                    "notFound" to "404 page",
                    "noResponse" to "Empty answer (204), then close the connection",
                ))
                fieldSet("target-fields target-static") {
                    legend { +"Static files" }
                    textField("Directory", "root", (site as? DefaultSite.Static)?.root.orEmpty(), hint = "Empty means www in the data directory, with a neutral page.", required = false)
                    checkField("List directories without index file", "directoryListing", (site as? DefaultSite.Static)?.directoryListing == true)
                }
                fieldSet("target-fields target-upstream") {
                    legend { +"Upstream" }
                    selectField("Upstream group", "upstream", (site as? DefaultSite.Upstream)?.upstream.orEmpty(),
                        kovexy.config.upstreams.map { it.name to it.name }.ifEmpty { listOf("" to "No upstream groups yet") })
                }
                fieldSet("target-fields target-redirect") {
                    legend { +"Redirect" }
                    textField("Target URL", "url", (site as? DefaultSite.Redirect)?.url.orEmpty(), placeholder = "https://example.com", required = false,
                        hint = "A redirect to the requested domain itself is refused, it would loop.")
                    selectField("Status", "redirectStatus", ((site as? DefaultSite.Redirect)?.status ?: 307).toString(), listOf("307" to "307 temporary", "301" to "301 permanent"))
                    checkField("Keep the path and query", "keepPath", (site as? DefaultSite.Redirect)?.keepPath ?: true)
                }
                p("muted small") { +"The 404 page and the empty answer need no settings." }
                div("btn-row") { submit("Save default site") }
            }
        }
    }
}
