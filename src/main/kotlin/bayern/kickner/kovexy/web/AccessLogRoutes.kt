package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.t
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.formatTimestamp
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.html.FormMethod
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr

/** Most entries shown at once. */
private const val PAGE_SIZE = 200

/** The latest access log entries, filterable. Layout like Dirl's audit page. */
fun Route.accessLogRoutes(kovexy: Kovexy) {
    get("/access-log") {
        val params = call.request.queryParameters
        val domains = kovexy.config.domains.map { it.names.first() }
        val domain = params["domain"]?.takeIf { it != "*" }
        val blockedOnly = params["status"] == "blocked"
        val redirectsOnly = params["status"] == "redirects"
        val status = params["status"]?.toIntOrNull()?.takeIf { it in 1..5 }
        val search = params["q"]?.trim()?.take(200)
        val entries = kovexy.accessLog.latest(domain, status, search, PAGE_SIZE, blockedOnly, redirectsOnly)
        call.page("Access log", call.session, Nav.ACCESS_LOG) {
            pageHeader("Access log", t("One line per request, newest first. The query string is never stored, it often holds tokens. Kept {0}.", kovexy.config.retention.accessLog))
            card {
                form(action = "/access-log", method = FormMethod.get, classes = "filters") {
                    selectField("Domain", "domain", domain ?: "*", listOf("*" to "All domains", "" to "Fallback") + domains.map { it to it }, autosubmit = true, help = "accessLog.domain")
                    selectField("Status", "status", params["status"]?.takeIf { blockedOnly || redirectsOnly } ?: status?.toString() ?: "",
                        listOf("" to "All", "2" to "2xx", "3" to "3xx", "4" to "4xx", "5" to "5xx", "blocked" to "Blocked", "redirects" to "HTTPS redirects"), autosubmit = true, help = "accessLog.status")
                    textField("Search", "q", search.orEmpty(), required = false, placeholder = t("path, IP or domain"), help = "accessLog.q")
                    submit("Filter", "")
                }
            }
            card(classes = "gap-top") {
                if (entries.isEmpty()) p("muted") { +t("No entries.") }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Time") }; th { +t("Client") }; th { +t("Request") }; th(classes = "num") { +t("Status") }; th(classes = "num") { +t("Sent") }; th(classes = "num") { +t("Duration") }; th { +t("Backend") } } }
                        tbody {
                            entries.forEach { e ->
                                tr {
                                    td("nowrap") { attributes["data-label"] = t("Time"); +formatTimestamp(e.time) }
                                    td { attributes["data-label"] = t("Client"); +e.clientIp }
                                    td {
                                        attributes["data-label"] = t("Request")
                                        span("break") { +"${e.method} ${e.host}${e.path}" }
                                        if (e.block.isNotEmpty()) pill("warn", blockLabel(e.block))
                                        if (e.reason.isNotEmpty()) span("muted small") { +" (${e.reason})" }
                                        if (e.userAgent.isNotEmpty()) div("muted small break") { +e.userAgent }
                                    }
                                    td("num") {
                                        attributes["data-label"] = t("Status")
                                        val kind = when (e.status / 100) { 2, 3, 1 -> "ok"; 4 -> "warn"; else -> "error" }
                                        pill(kind, e.status.toString())
                                    }
                                    td("num") { attributes["data-label"] = t("Sent"); +bytes(e.bytesOut) }
                                    td("num") { attributes["data-label"] = t("Duration"); +t("{0} ms", e.durationMs) }
                                    td { attributes["data-label"] = t("Backend"); +e.backend }
                                }
                            }
                        }
                    }
                }
                if (entries.size == PAGE_SIZE) p("muted small gap-top") { +t("Showing the newest {0} entries. Narrow the filter to see older ones.", PAGE_SIZE) }
                // The statistics and the tiles of the status page count these domains too, the list cannot show them
                val unlogged = kovexy.config.domains.filter { it.accessLog.not() }.map { it.names.first() }
                if (unlogged.isNotEmpty()) p("muted small gap-top") {
                    +t("These domains have the access log turned off, their requests are counted in the statistics but not listed here: {0}", unlogged.joinToString(", "))
                }
            }
        }
    }
}
