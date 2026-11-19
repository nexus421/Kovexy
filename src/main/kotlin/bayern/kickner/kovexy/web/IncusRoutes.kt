package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.audit.AuditAction
import bayern.kickner.kovexy.config.IncusConfig
import bayern.kickner.kovexy.config.isRoot
import bayern.kickner.kovexy.incus.IncusClaim
import bayern.kickner.kovexy.incus.IncusDiscovery
import bayern.kickner.kovexy.incus.IncusState
import bayern.kickner.kovexy.incus.incusSetCommand
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.li
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import kotlinx.html.ul

/** Incus discovery: detected containers, approvals, copy-ready commands and the settings. */
fun Route.incusRoutes(kovexy: Kovexy) {
    get("/incus") { call.incusPage(kovexy, emptyList(), null) }

    post("/incus/settings") {
        val params = call.receiveForm()
        val projects = params["projects"].orEmpty().split('\n', ',', ' ').map { it.trim() }.filter { it.isNotEmpty() }
        val incus = IncusConfig(
            enabled = params["enabled"] != null,
            socket = params["socket"].orEmpty().trim().ifEmpty { IncusConfig().socket },
            projects = projects.ifEmpty { listOf("default") },
            `interface` = params["interface"].orEmpty().trim().ifEmpty { "eth0" },
        )
        val problems = call.saveConfig(params["version"]) { it.copy(incus = incus) }
        if (problems == null) return@post call.respondRedirect("/incus?done=incus-saved")
        call.incusPage(kovexy, problems, params["version"])
    }

    post("/incus/approve") {
        val params = call.receiveForm()
        val id = params["id"].orEmpty()
        // Approve exactly what the admin saw, the domains may have changed in between
        val domains = params["domains"].orEmpty().split(',').filter { it.isNotEmpty() }
        if (kovexy.incus.approve(id, domains, params["target"].orEmpty()).not()) {
            return@post call.incusPage(kovexy, listOf("The container, its domains or its target changed meanwhile, check the list again"), null)
        }
        kovexy.audit.record(call.actor, AuditAction.INCUS_APPROVED, id, domains.joinToString(", "))
        call.respondRedirect("/incus?done=incus-approved")
    }

    post("/incus/reject") {
        val id = call.receiveForm()["id"].orEmpty()
        val claim = kovexy.incus.claims.firstOrNull { it.id == id } ?: return@post call.incusPage(kovexy, listOf("This container is gone"), null)
        kovexy.incus.reject(id)
        kovexy.audit.record(call.actor, AuditAction.INCUS_REJECTED, id, claim.domains.joinToString(", "))
        call.respondRedirect("/incus?done=incus-rejected")
    }

    post("/incus/remove") {
        val id = call.receiveForm()["id"].orEmpty()
        if ('/' !in id) return@post call.incusPage(kovexy, listOf("Unknown container"), null)
        kovexy.incus.remove(id)
        kovexy.audit.record(call.actor, AuditAction.INCUS_REMOVED, id)
        call.respondRedirect("/incus?done=incus-removed")
    }
}

private suspend fun ApplicationCall.incusPage(kovexy: Kovexy, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val settings = kovexy.config.incus
    val incus = kovexy.incus
    page("Incus", session, Nav.INCUS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Incus", "Containers with user.kovexy.* keys show up here. Nothing goes live on its own, every container needs a click.")
        if (problems.isNotEmpty()) problems("Not done:", problems)
        when {
            settings.enabled.not() -> notice("info", "Discovery is off. Turn it on below.")
            incus.connected -> notice("success", "Connected to Incus at ${settings.socket}, changes show up at once.")
            else -> notice("warn", "Not connected to Incus at ${settings.socket}: ${incus.lastError ?: "connecting"}. Kovexy tries again every 10 seconds.")
        }
        // While discovery is off the lists would only be empty, the settings come right after the notice
        if (settings.enabled) incusLists(incus)
        card("Settings", "gap-top") {
            if (isRoot().not()) notice("warn", "Kovexy does not run as root. Discovery needs root, the Incus socket gives root access to the host.")
            form(action = "/incus/settings", method = FormMethod.post, classes = "form") {
                versionField(version)
                checkField("Discover Incus containers", "enabled", settings.enabled, "only reads, never changes an instance")
                textField("Socket", "socket", settings.socket, required = false)
                textField("Projects", "projects", settings.projects.joinToString(" "), required = false,
                    hint = "Only instances of these Incus projects count. In restricted projects non-admins may create instances and set keys.")
                textField("Interface", "interface", settings.`interface`, required = false, hint = "Its first global IPv4 address is the target.")
                div("btn-row") { submit("Save Incus settings") }
            }
            p("muted small gap-top") {
                +"Decisions are stored in the database. A backup holds them only when the database is included, otherwise every container needs a new click after a restore."
            }
        }
    }
}

/** Detected, approved and rejected containers and the ones without keys. */
private fun FlowContent.incusLists(incus: IncusDiscovery) {
    val claims = incus.claims
    val detected = claims.filter { it.state == IncusState.DETECTED && it.instance.running }
    card("Detected", "gap-top") {
        if (detected.isEmpty()) p("muted") { +"No running container waits for a decision." }
        else claimTable(detected) { claim ->
            postButton("/incus/approve", "Approve", "primary sm", hidden = mapOf("id" to claim.id, "domains" to claim.domains.joinToString(","), "target" to claim.target))
            postButton("/incus/reject", "Reject", "sm", hidden = mapOf("id" to claim.id))
        }
        if (claims.any { it.state == IncusState.DETECTED && it.approvedDomains.isNotEmpty() }) {
            p("muted small") { +"A container whose domains, address, port, HTTPS or profile changed after the approval shows up here again and needs a new click." }
        }
    }
    val approved = claims.filter { it.state == IncusState.APPROVED }
    card("Approved", "gap-top") {
        if (approved.isEmpty()) p("muted") { +"No container approved yet." }
        else claimTable(approved) { claim ->
            postButton("/incus/remove", "Remove", "danger sm", confirm = "Remove the route of ${claim.id}? It is gone at once.", hidden = mapOf("id" to claim.id))
        }
    }
    val rejected = claims.filter { it.state == IncusState.REJECTED }
    if (rejected.isNotEmpty()) card("Rejected", "gap-top") {
        claimTable(rejected) { claim -> postButton("/incus/remove", "Reset", "sm", hidden = mapOf("id" to claim.id)) }
    }
    val plain = incus.withoutKeys()
    card("Without keys", "gap-top") {
        p("muted small") { +"Running containers without user.kovexy.* keys. Set the keys on the host, then the container shows up under Detected." }
        if (plain.isEmpty()) p("muted") { +if (incus.connected) "None." else "Shown once Kovexy is connected to Incus." }
        plain.forEach { instance ->
            val commandId = nextElementId("cmd")
            div("incus-command gap-top") {
                p { +"${instance.project}/${instance.name}" }
                div("grid-2") {
                    commandInput("Domain", commandId, "domain", "app.example.com", "a-z0-9.,-")
                    commandInput("Port", commandId, "port", "8080", "0-9")
                }
                copyBlock(incusSetCommand(instance, "app.example.com", "8080"), commandId, template = incusSetCommand(instance, "{domain}", "{port}"))
            }
        }
        p("muted small gap-top") { +"Optional: user.kovexy.tls=true when the container speaks HTTPS (its certificate is not checked), user.kovexy.access=<profile> for an access profile." }
    }
}

private fun FlowContent.commandInput(label: String, commandId: String, key: String, example: String, allowed: String) = label("field") {
    span { +label }
    input(InputType.text) {
        placeholder = example
        attributes["data-fills"] = commandId
        attributes["data-key"] = key
        attributes["data-allowed"] = allowed
        attributes["autocomplete"] = "off"
        attributes["aria-label"] = label
    }
}

private fun FlowContent.claimTable(claims: List<IncusClaim>, actions: kotlinx.html.TD.(IncusClaim) -> Unit) = div("table-wrap") {
    table("stack-mobile") {
        thead { tr { th { +"Container" }; th { +"Domains" }; th { +"Target" }; th { +"Profile" }; th { +"State" }; th { } } }
        tbody {
            claims.forEach { claim ->
                tr {
                    td { attributes["data-label"] = "Container"; +claim.id }
                    td { attributes["data-label"] = "Domains"; span("break") { +claim.domains.joinToString(", ").ifEmpty { "-" } } }
                    td {
                        attributes["data-label"] = "Target"
                        +"${claim.instance.address ?: "no address"}:${if (claim.port == 0) "?" else claim.port}${if (claim.tls) " (HTTPS)" else ""}"
                    }
                    td { attributes["data-label"] = "Profile"; +(claim.access ?: "none") }
                    td {
                        attributes["data-label"] = "State"
                        when {
                            claim.live -> pill("ok", "live")
                            claim.instance.running.not() -> pill("", "stopped")
                            claim.problems.isNotEmpty() -> pill("warn", "problem")
                            else -> pill("", claim.state.name.lowercase())
                        }
                        if (claim.problems.isNotEmpty()) ul("small muted") { claim.problems.forEach { li { +it } } }
                    }
                    td("actions") { actions(claim) }
                }
            }
        }
    }
}
