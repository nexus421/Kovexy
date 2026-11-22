package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.DyndnsClient
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.i18n.t
import bayern.kickner.kovexy.secureRandom
import bayern.kickner.kovexy.sha256Hex
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.a
import kotlinx.html.checkBoxInput
import kotlinx.html.div
import kotlinx.html.fieldSet
import kotlinx.html.form
import kotlinx.html.label
import kotlinx.html.legend
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import java.util.HexFormat

/** A new password for a DynDNS client: 24 random bytes as hex, shown once and kept only as SHA-256. */
private fun newDyndnsPassword(): String = HexFormat.of().formatHex(ByteArray(24).also(secureRandom::nextBytes))

/** DynDNS clients: routers and other dyndns2 clients whose reported IP goes on the allow list of their access profiles. */
fun Route.dyndnsRoutes(kovexy: Kovexy) {
    get("/dyndns") {
        val config = kovexy.config
        val hosts = config.domains.filter { it.dyndns && it.enabled }.flatMap { it.names }
        call.page("DynDNS", call.session, Nav.DYNDNS) {
            pageHeader("DynDNS", "Routers report their current IP, Kovexy adds it to the allow list of the access profiles you pick.") {
                linkButton("/dyndns/new", "Add client", "primary")
            }
            if (hosts.isEmpty()) notice("warn", "No domain is used for DynDNS yet. Tick \"Use for DynDNS\" on a domain, clients report to it.")
            else p("muted") { +t("Clients report to {0}.", hosts.joinToString(", ")) }
            card {
                if (config.dyndnsClients.isEmpty()) p("muted") { +t("No clients yet.") }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Client") }; th { +t("Access profiles") }; th { +t("Reported addresses") }; th { +t("Last update") }; th { } } }
                        tbody {
                            config.dyndnsClients.forEach { client ->
                                val report = kovexy.dyndns.lastReport(client.name)
                                tr {
                                    td { attributes["data-label"] = t("Client"); a(href = "/dyndns/${urlPart(client.name)}") { +client.name } }
                                    td { attributes["data-label"] = t("Access profiles"); +client.profiles.joinToString(", ") }
                                    td {
                                        attributes["data-label"] = t("Reported addresses")
                                        val shown = listOfNotNull(report?.ipv4?.removeSuffix("/32"), report?.ipv6?.removeSuffix("/128"))
                                        if (shown.isEmpty()) +t("none yet") else +shown.joinToString(", ")
                                    }
                                    td { attributes["data-label"] = t("Last update"); +(report?.updated?.let(::formatTimestamp) ?: t("never")) }
                                    td("actions") { linkButton("/dyndns/${urlPart(client.name)}", "Edit", "sm") }
                                }
                            }
                        }
                    }
                }
            }
            card("Good to know", "gap-top") {
                p("muted") { +t("A profile with DynDNS clients lets nobody in by IP until one of them has reported, its countries and local addresses still count.") }
                p("muted") { +t("Use every login on one device only. A second device with the same login overwrites the addresses of the first.") }
                p("muted") { +t("Do not give the access profile of the DynDNS domain an allow list or a client. The routers could not report any more.") }
            }
        }
    }

    get("/dyndns/new") { call.clientForm(kovexy, null, DyndnsClient("", "", emptyList()), emptyList(), null) }

    post("/dyndns/new") {
        val params = call.receiveForm()
        val password = newDyndnsPassword()
        val client = DyndnsClient(params["name"].orEmpty().trim(), sha256Hex(password), profilesFrom(params, kovexy))
        val problems = call.saveConfig(params["version"]) { it.copy(dyndnsClients = it.dyndnsClients + client) }
        if (problems == null) return@post call.passwordPage(kovexy, client.name, password)
        call.clientForm(kovexy, null, client, problems, params["version"])
    }

    get("/dyndns/{name}") {
        val client = call.client(kovexy) ?: return@get
        call.clientForm(kovexy, client.name, client, emptyList(), null)
    }

    post("/dyndns/{name}") {
        val client = call.client(kovexy) ?: return@post
        val params = call.receiveForm()
        val changed = client.copy(profiles = profilesFrom(params, kovexy))
        val problems = call.saveConfig(params["version"]) { c -> c.copy(dyndnsClients = c.dyndnsClients.map { if (it.name == client.name) changed else it }) }
        if (problems == null) return@post call.respondRedirect("/dyndns?done=dyndns-saved")
        call.clientForm(kovexy, client.name, changed, problems, params["version"])
    }

    post("/dyndns/{name}/password") {
        val client = call.client(kovexy) ?: return@post
        val params = call.receiveForm()
        val password = newDyndnsPassword()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(dyndnsClients = c.dyndnsClients.map { if (it.name == client.name) it.copy(passwordHash = sha256Hex(password)) else it }) }
        if (problems == null) return@post call.passwordPage(kovexy, client.name, password)
        call.errorPage(HttpStatusCode.BadRequest, "Not changed", problems.joinToString(" "))
    }

    post("/dyndns/{name}/delete") {
        val client = call.client(kovexy) ?: return@post
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(dyndnsClients = c.dyndnsClients.filter { it.name != client.name }) }
        if (problems == null) return@post call.respondRedirect("/dyndns?done=dyndns-deleted")
        call.errorPage(HttpStatusCode.BadRequest, "Not deleted", problems.joinToString(" "))
    }
}

/** The client named in the path, or a 404 page and `null`. */
private suspend fun ApplicationCall.client(kovexy: Kovexy): DyndnsClient? =
    kovexy.config.dyndnsClients.firstOrNull { it.name == parameters["name"] }
        ?: run { errorPage(HttpStatusCode.NotFound, "Client not found", "This DynDNS client does not exist (any more)."); null }

/** The profiles ticked in the form, in the order of the config. */
private fun profilesFrom(params: Parameters, kovexy: Kovexy): List<String> =
    kovexy.config.accessProfiles.map { it.name }.filter { params["profile.$it"] != null }

private suspend fun ApplicationCall.clientForm(kovexy: Kovexy, name: String?, client: DyndnsClient, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val title = if (name == null) "Add DynDNS client" else t("DynDNS client {0}", name)
    val action = if (name == null) "/dyndns/new" else "/dyndns/${urlPart(name)}"
    page(title, session, Nav.DYNDNS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title) { linkButton("/dyndns", "All clients", "ghost") }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        if (name != null) {
            val opens = onlyRestrictedBy(kovexy, name)
            if (opens.isNotEmpty()) {
                // Not through notice(), it translates its text itself and this one carries a placeholder
                div("notice warn") { +t("Without this client everybody gets into {0}. No other client uses it and it has no allow list of its own, so deleting the client or unticking the profile opens it.", opens.joinToString(", ")) }
            }
        }
        card {
            form(action = action, method = FormMethod.post, classes = "form") {
                versionField(version)
                if (name == null) textField("Client name", "name", client.name, hint = t("The user name in the router. Letters, digits, dots, underscores and hyphens."), help = "dyndns.client")
                fieldSet {
                    legend { +t("Access profiles"); helpButton("dyndns.profiles", "Access profiles") }
                    val profiles = kovexy.config.accessProfiles
                    if (profiles.isEmpty()) p("muted") { +t("No access profiles yet. Add one under Access first.") }
                    profiles.forEach { profile ->
                        label("check") {
                            checkBoxInput(name = "profile.${profile.name}") { checked = profile.name in client.profiles }
                            span { +profile.name }
                        }
                    }
                }
                div("btn-row") { submit(if (name == null) "Add client" else "Save client") }
            }
        }
        if (name != null) {
            card("New password", "gap-top") {
                p("muted") { +t("Replaces the password. The router stops reporting until it has the new one.") }
                postButton("$action/password", "New password", "", confirm = t("Replace the password?"), hidden = mapOf("version" to version))
            }
            card("Delete client", "danger gap-top") {
                postButton("$action/delete", "Delete client", "danger", confirm = t("Delete this client?"), hidden = mapOf("version" to version))
            }
        }
    }
}

/**
 * The profiles that only the client [name] keeps closed: no other client uses them and they have neither `allowIps`
 * nor `allowCountries` of their own. Without the client they let everybody in.
 */
private fun onlyRestrictedBy(kovexy: Kovexy, name: String): List<String> {
    val config = kovexy.config
    val client = config.dyndnsClients.firstOrNull { it.name == name } ?: return emptyList()
    return config.accessProfiles.filter { profile ->
        profile.name in client.profiles && profile.allowIps.isEmpty() && profile.allowCountries.isEmpty() &&
            config.dyndnsClients.none { it.name != name && profile.name in it.profiles }
    }.map { it.name }
}

/** Shows the password once, together with the settings for the router. */
private suspend fun ApplicationCall.passwordPage(kovexy: Kovexy, name: String, password: String) {
    val host = kovexy.config.domains.firstOrNull { it.dyndns && it.enabled }?.names?.firstOrNull()
    page("DynDNS", session, Nav.DYNDNS) {
        pageHeader(t("DynDNS client {0}", name)) { linkButton("/dyndns", "All clients", "ghost") }
        notice("warn", "This is the only time the password is shown. Copy it into the router now.")
        notice("warn", "Use this login on one device only, add a client for every further device.")
        if (host == null) notice("warn", "No domain is used for DynDNS yet. Tick \"Use for DynDNS\" on a domain and use its name below.")
        card("Password") {
            copyBlock(password)
        }
        card("FRITZ!Box", "gap-top") {
            p("muted") { +t("Internet, Permit Access, DynDNS, User-defined") }
            copyBlock("https://<username>:<pass>@${host ?: "dyndns.example.com"}/nic/update?hostname=<domain>&myip=<ipaddr>,<ip6lanprefix>")
            keyValues("Domain name" to (host ?: "dyndns.example.com"), "User name" to name)
        }
        card("Other clients", "gap-top") {
            p("muted") { +t("ddclient, inadyn, OPNsense and others: protocol dyndns2, HTTPS, path /nic/update.") }
            keyValues("Server" to (host ?: "dyndns.example.com"), "User name" to name)
        }
    }
}
