package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.audit.AuditAction
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FormMethod
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.p
import kotlinx.html.pre
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr

/** Active bans and security events, and the audit log. */
fun Route.securityRoutes(kovexy: Kovexy) {
    get("/security") {
        val type = SecurityEventType.entries.firstOrNull { it.name == call.request.queryParameters["type"] }
        val bans = kovexy.bans.list()
        val events = kovexy.security.latest(type)
        call.page("Security", call.session, Nav.SECURITY) {
            pageHeader("Security", "Bans from trap paths and everything the access profiles refused. Kept ${kovexy.config.retention.securityEvents}.")
            card("Active bans") {
                if (bans.isEmpty()) p("muted") { +"Nobody is banned." }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Address" }; th { +"Reason" }; th { +"Domain" }; th { +"Until" }; th { } } }
                        tbody {
                            bans.forEach { ban ->
                                tr {
                                    td { attributes["data-label"] = "Address"; +ban.key }
                                    td { attributes["data-label"] = "Reason"; +ban.reason }
                                    td { attributes["data-label"] = "Domain"; +ban.domain }
                                    td("nowrap") { attributes["data-label"] = "Until"; +formatTimestamp(ban.expiresAt) }
                                    td("actions") { postButton("/security/lift", "Lift", "sm", confirm = "Lift the ban of ${ban.key}?", hidden = mapOf("key" to ban.key)) }
                                }
                            }
                        }
                    }
                }
            }
            card("Events", "gap-top") {
                form(action = "/security", method = FormMethod.get, classes = "filters") {
                    selectField("Kind", "type", type?.name.orEmpty(), listOf("" to "All") + SecurityEventType.entries.map { it.name to it.label }, autosubmit = true)
                    submit("Filter", "")
                }
                if (events.isEmpty()) p("muted gap-top") { +"No events." }
                else div("table-wrap gap-top") {
                    table("stack-mobile") {
                        thead { tr { th { +"Time" }; th { +"Kind" }; th { +"Address" }; th { +"Domain" }; th { +"Detail" } } }
                        tbody {
                            events.forEach { e ->
                                tr {
                                    td("nowrap") { attributes["data-label"] = "Time"; +formatTimestamp(e.time) }
                                    td { attributes["data-label"] = "Kind"; +e.type.label }
                                    td { attributes["data-label"] = "Address"; +e.ip }
                                    td { attributes["data-label"] = "Domain"; +e.domain }
                                    td { attributes["data-label"] = "Detail"; span("small break") { +e.detail } }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    post("/security/lift") {
        val key = call.receiveForm()["key"].orEmpty()
        // Already expired or lifted in another tab: nothing to report
        if (kovexy.bans.lift(key).not()) return@post call.respondRedirect("/security")
        kovexy.audit.record(call.actor, AuditAction.BAN_LIFTED, key)
        call.respondRedirect("/security?done=ban-lifted")
    }

    get("/audit") {
        val action = AuditAction.entries.firstOrNull { it.name == call.request.queryParameters["action"] }
        val entries = kovexy.audit.latest(action)
        call.page("Audit", call.session, Nav.AUDIT) {
            pageHeader("Audit", "Who changed what and when. Secrets show as ***. Kept ${kovexy.config.retention.audit}.")
            card {
                form(action = "/audit", method = FormMethod.get, classes = "filters") {
                    selectField("Action", "action", action?.name.orEmpty(), listOf("" to "All") + AuditAction.entries.map { it.name to it.label }, autosubmit = true)
                    submit("Filter", "")
                }
                if (entries.isEmpty()) p("muted gap-top") { +"No entries." }
                else div("table-wrap gap-top") {
                    table("stack-mobile") {
                        thead { tr { th { +"Time" }; th { +"Who" }; th { +"Action" }; th { +"Detail" } } }
                        tbody {
                            entries.forEach { e ->
                                tr {
                                    td("nowrap") { attributes["data-label"] = "Time"; +formatTimestamp(e.time) }
                                    td {
                                        attributes["data-label"] = "Who"
                                        +e.actor.name
                                        if (e.actor.ip.isNotEmpty()) span("muted small") { +" ${e.actor.ip}" }
                                    }
                                    td { attributes["data-label"] = "Action"; +e.action.label; if (e.target.isNotEmpty()) span("muted small") { +" ${e.target}" } }
                                    td {
                                        attributes["data-label"] = "Detail"
                                        if (e.detail.contains('\n')) pre("diff") { +e.detail } else span("small break") { +e.detail }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
