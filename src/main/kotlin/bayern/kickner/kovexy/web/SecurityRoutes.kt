package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.t
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
            pageHeader("Security", t("Bans from trap paths and everything the access profiles refused. Kept {0}.", kovexy.config.retention.securityEvents))
            card("Active bans") {
                if (bans.isEmpty()) p("muted") { +t("Nobody is banned.") }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Address") }; th { +t("Reason") }; th { +t("Domain") }; th { +t("Until") }; th { } } }
                        tbody {
                            bans.forEach { ban ->
                                tr {
                                    td { attributes["data-label"] = t("Address"); +ban.key }
                                    td { attributes["data-label"] = t("Reason"); +ban.reason }
                                    td { attributes["data-label"] = t("Domain"); +ban.domain }
                                    td("nowrap") { attributes["data-label"] = t("Until"); +formatTimestamp(ban.expiresAt) }
                                    td("actions") { postButton("/security/lift", "Lift", "sm", confirm = t("Lift the ban of {0}?", ban.key), hidden = mapOf("key" to ban.key)) }
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
                if (events.isEmpty()) p("muted gap-top") { +t("No events.") }
                else div("table-wrap gap-top") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Time") }; th { +t("Kind") }; th { +t("Address") }; th { +t("Domain") }; th { +t("Detail") } } }
                        tbody {
                            events.forEach { e ->
                                tr {
                                    td("nowrap") { attributes["data-label"] = t("Time"); +formatTimestamp(e.time) }
                                    td { attributes["data-label"] = t("Kind"); +t(e.type.label) }
                                    td { attributes["data-label"] = t("Address"); +e.ip }
                                    td { attributes["data-label"] = t("Domain"); +e.domain }
                                    td { attributes["data-label"] = t("Detail"); span("small break") { +e.detail } }
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
            pageHeader("Audit", t("Who changed what and when. Secrets show as ***. Kept {0}.", kovexy.config.retention.audit))
            card {
                form(action = "/audit", method = FormMethod.get, classes = "filters") {
                    selectField("Action", "action", action?.name.orEmpty(), listOf("" to "All") + AuditAction.entries.map { it.name to it.label }, autosubmit = true)
                    submit("Filter", "")
                }
                if (entries.isEmpty()) p("muted gap-top") { +t("No entries.") }
                else div("table-wrap gap-top") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Time") }; th { +t("Who") }; th { +t("Action") }; th { +t("Detail") } } }
                        tbody {
                            entries.forEach { e ->
                                tr {
                                    td("nowrap") { attributes["data-label"] = t("Time"); +formatTimestamp(e.time) }
                                    td {
                                        attributes["data-label"] = t("Who")
                                        +e.actor.name
                                        if (e.actor.ip.isNotEmpty()) span("muted small") { +" ${e.actor.ip}" }
                                    }
                                    td { attributes["data-label"] = t("Action"); +t(e.action.label); if (e.target.isNotEmpty()) span("muted small") { +" ${e.target}" } }
                                    td {
                                        attributes["data-label"] = t("Detail")
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
