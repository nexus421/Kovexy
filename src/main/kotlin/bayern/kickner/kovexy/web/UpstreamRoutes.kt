package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.DefaultSite
import bayern.kickner.kovexy.config.HealthCheckConfig
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.Target
import bayern.kickner.kovexy.config.UpstreamConfig
import bayern.kickner.kovexy.config.UpstreamServerConfig
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.a
import kotlinx.html.checkBoxInput
import kotlinx.html.div
import kotlinx.html.fieldSet
import kotlinx.html.form
import kotlinx.html.hiddenInput
import kotlinx.html.input
import kotlinx.html.legend
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import kotlin.time.Duration

/** Empty server rows below the existing ones in the form. */
private const val EMPTY_SERVER_ROWS = 2

/** Upstream groups with their servers. */
fun Route.upstreamRoutes(kovexy: Kovexy) {
    get("/upstreams") {
        call.page("Upstreams", call.session, Nav.UPSTREAMS) {
            pageHeader("Upstreams", "Groups of servers behind the proxy, with load balancing and health checks.") {
                linkButton("/upstreams/new", "Add upstream group", "primary")
            }
            val groups = kovexy.upstreams.all()
            card {
                if (groups.isEmpty()) p("muted") { +"No upstream groups yet." }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Group" }; th { +"Servers" }; th { +"Health check" }; th { } } }
                        tbody {
                            groups.forEach { group ->
                                tr {
                                    td { attributes["data-label"] = "Group"; a(href = "/upstreams/${urlPart(group.config.name)}") { +group.config.name } }
                                    td {
                                        attributes["data-label"] = "Servers"
                                        group.servers.forEach { server ->
                                            div {
                                                if (server.healthy) pill("ok", "up") else pill("error", "down")
                                                +" ${server.address}"
                                                span("muted small") {
                                                    +" weight ${server.config.weight}"
                                                    if (server.config.weight == 0) +" (backup)"
                                                    if (server.config.tls) +", https"
                                                }
                                            }
                                        }
                                    }
                                    td {
                                        attributes["data-label"] = "Health check"
                                        val check = group.config.healthCheck
                                        +(if (check.path.isEmpty()) "passive only" else "GET ${check.path} every ${check.interval}")
                                    }
                                    td("actions") { linkButton("/upstreams/${urlPart(group.config.name)}", "Edit", "sm") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    get("/upstreams/new") { call.upstreamForm(kovexy, null, UpstreamConfig("", emptyList()), emptyList(), null) }

    post("/upstreams/new") {
        val params = call.receiveForm()
        val (group, parseProblems) = upstreamFromForm(params)
        val problems = parseProblems.ifEmpty { call.saveConfig(params["version"]) { it.copy(upstreams = it.upstreams + group) } }
        if (problems == null) return@post call.respondRedirect("/upstreams?done=upstream-saved")
        call.upstreamForm(kovexy, null, group, problems, params["version"])
    }

    get("/upstreams/{name}") {
        val name = call.parameters["name"]!!
        val group = kovexy.config.upstreams.firstOrNull { it.name == name } ?: return@get call.notFoundUpstream()
        call.upstreamForm(kovexy, name, group, emptyList(), null)
    }

    post("/upstreams/{name}") {
        val name = call.parameters["name"]!!
        if (kovexy.config.upstreams.none { it.name == name }) return@post call.notFoundUpstream()
        val params = call.receiveForm()
        val (group, parseProblems) = upstreamFromForm(params)
        val problems = parseProblems.ifEmpty {
            call.saveConfig(params["version"]) { c ->
                c.copy(upstreams = c.upstreams.map { if (it.name == name) group else it }).renameUpstream(name, group.name)
            }
        }
        if (problems == null) return@post call.respondRedirect("/upstreams?done=upstream-saved")
        call.upstreamForm(kovexy, name, group, problems, params["version"])
    }

    post("/upstreams/{name}/delete") {
        val name = call.parameters["name"]!!
        val group = kovexy.config.upstreams.firstOrNull { it.name == name } ?: return@post call.notFoundUpstream()
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(upstreams = c.upstreams.filter { it.name != name }) }
        if (problems == null) return@post call.respondRedirect("/upstreams?done=upstream-deleted")
        call.upstreamForm(kovexy, name, group, problems, params["version"])
    }
}

private suspend fun ApplicationCall.notFoundUpstream() =
    errorPage(HttpStatusCode.NotFound, "Upstream group not found", "This upstream group does not exist (any more).")

/** Points every target that uses [old] to [new], so renaming a group keeps the sites working. */
private fun KovexyConfig.renameUpstream(old: String, new: String): KovexyConfig {
    if (old == new) return this
    return copy(
        sites = sites.map { site ->
            site.copy(locations = site.locations.map { location ->
                val target = location.target
                if (target is Target.Upstream && target.upstream == old) location.copy(target = Target.Upstream(new)) else location
            })
        },
        defaultSite = (defaultSite as? DefaultSite.Upstream)?.takeIf { it.upstream == old }?.let { DefaultSite.Upstream(new) } ?: defaultSite,
    )
}

private fun upstreamFromForm(params: Parameters): Pair<UpstreamConfig, List<String>> {
    val problems = mutableListOf<String>()
    val count = params["serverCount"]?.toIntOrNull()?.coerceIn(0, 200) ?: 0
    val servers = (0 until count).mapNotNull { k ->
        val address = params["s$k.address"].orEmpty().trim()
        if (address.isEmpty()) return@mapNotNull null
        UpstreamServerConfig(
            address = address,
            tls = params["s$k.tls"] != null,
            skipCertVerify = params["s$k.skip"] != null,
            weight = params["s$k.weight"]?.trim()?.toIntOrNull() ?: run { problems += "Weight of $address must be a number"; 1 },
            maxConnections = params["s$k.max"]?.trim()?.ifEmpty { "0" }?.toIntOrNull() ?: run { problems += "Max connections of $address must be a number"; 0 },
        )
    }
    val interval = parseDuration("Health check interval", params["interval"], problems)
    val timeout = parseDuration("Health check timeout", params["timeout"], problems)
    val group = UpstreamConfig(
        name = params["name"].orEmpty().trim(),
        servers = servers,
        stickySession = params["sticky"] != null,
        healthCheck = HealthCheckConfig(
            path = params["healthPath"].orEmpty().trim(),
            interval = interval ?: HealthCheckConfig().interval,
            timeout = timeout ?: HealthCheckConfig().timeout,
            expectStatus = params["expectStatus"]?.trim()?.toIntOrNull() ?: run { problems += "Expected status must be a number"; 200 },
        ),
    )
    return group to problems
}

/** Parses a duration typed in a form, e.g. `30s`, reporting a problem if it is not one. */
fun parseDuration(label: String, text: String?, problems: MutableList<String>): Duration? {
    val value = text?.trim().orEmpty()
    return runCatching { Duration.parse(value) }.getOrElse {
        problems += "$label \"$value\" is no duration, use for example 30s, 5m, 12h or 90d"
        null
    }
}

private suspend fun ApplicationCall.upstreamForm(kovexy: Kovexy, name: String?, group: UpstreamConfig, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val title = if (name == null) "Add upstream group" else "Upstream $name"
    val rows = group.servers + List(EMPTY_SERVER_ROWS) { UpstreamServerConfig("") }
    val action = if (name == null) "/upstreams/new" else "/upstreams/${urlPart(name)}"
    page(title, session, Nav.UPSTREAMS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title) { linkButton("/upstreams", "All upstreams", "ghost") }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = action, method = FormMethod.post, classes = "form") {
                versionField(version)
                textField("Name", "name", group.name, hint = "Sites refer to the group by this name. Renaming updates them.")
                fieldSet {
                    legend { +"Servers" }
                    p("muted small") {
                        +"Requests are spread by weight at random. Weight 0 makes a backup server that only gets requests when no other server is up. "
                        +"Empty rows are ignored, clear the address to remove a server."
                    }
                    hiddenInput(name = "serverCount") { value = rows.size.toString() }
                    div("table-wrap") {
                        table("stack-mobile server-table") {
                            thead { tr { th { +"Address" }; th { +"Weight" }; th { +"Max connections" }; th { +"HTTPS" }; th { +"Any certificate" } } }
                            tbody {
                                rows.forEachIndexed { k, server ->
                                    tr {
                                        td {
                                            attributes["data-label"] = "Address"
                                            input(InputType.text, name = "s$k.address") {
                                                value = server.address
                                                placeholder = "127.0.0.1:8080"
                                                attributes["aria-label"] = "Address"
                                            }
                                        }
                                        td { attributes["data-label"] = "Weight"; input(InputType.number, name = "s$k.weight") { value = server.weight.toString(); min = "0"; attributes["aria-label"] = "Weight" } }
                                        td { attributes["data-label"] = "Max connections"; input(InputType.number, name = "s$k.max") { value = server.maxConnections.toString(); min = "0"; attributes["aria-label"] = "Max connections, 0 is unlimited" } }
                                        td { attributes["data-label"] = "HTTPS"; checkBoxInput(name = "s$k.tls") { checked = server.tls; attributes["aria-label"] = "HTTPS" } }
                                        td { attributes["data-label"] = "Any certificate"; checkBoxInput(name = "s$k.skip") { checked = server.skipCertVerify; attributes["aria-label"] = "Accept any certificate" } }
                                    }
                                }
                            }
                        }
                    }
                }
                checkField("Sticky sessions", "sticky", group.stickySession, "a cookie sends a visitor to the same server again")
                fieldSet {
                    legend { +"Active health check" }
                    p("muted small") { +"Without a path servers are only checked passively: a connection error marks a server down, it is tried again every 30 seconds." }
                    div("grid-2") {
                        textField("Path", "healthPath", group.healthCheck.path, placeholder = "/health", required = false)
                        textField("Expected status", "expectStatus", group.healthCheck.expectStatus.toString(), type = InputType.number)
                        textField("Interval", "interval", group.healthCheck.interval.toString())
                        textField("Timeout", "timeout", group.healthCheck.timeout.toString())
                    }
                }
                div("btn-row") { submit("Save upstream group") }
            }
        }
        if (name != null) card("Delete upstream group", "danger gap-top") {
            p("muted") { +"Only possible while no site and not the default site use it." }
            postButton("$action/delete", "Delete upstream group", "danger", confirm = "Delete this upstream group?", hidden = mapOf("version" to version))
        }
    }
}
