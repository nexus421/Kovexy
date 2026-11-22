package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.t
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.HeaderAction
import bayern.kickner.kovexy.config.HeaderRule
import bayern.kickner.kovexy.config.RouteConfig
import bayern.kickner.kovexy.config.MatchType
import bayern.kickner.kovexy.config.DomainConfig
import bayern.kickner.kovexy.config.Target
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

/** The response headers of the "Security headers" template. */
val SECURITY_HEADER_TEMPLATE = listOf(
    HeaderRule(HeaderAction.SET, "Strict-Transport-Security", "max-age=31536000"),
    HeaderRule(HeaderAction.SET, "X-Content-Type-Options", "nosniff"),
    HeaderRule(HeaderAction.SET, "Referrer-Policy", "strict-origin-when-cross-origin"),
)

/** Header rules as text, one per line: `set Name: value`, `add Name: value` or `remove Name`. */
fun headerRulesToText(rules: List<HeaderRule>): String = rules.joinToString("\n") { rule ->
    when (rule.action) {
        HeaderAction.SET -> "set ${rule.name}: ${rule.value}"
        HeaderAction.ADD -> "add ${rule.name}: ${rule.value}"
        HeaderAction.REMOVE -> "remove ${rule.name}"
    }
}

/**
 * Parses header rules from text, see [headerRulesToText].
 *
 * @return the rules, or the problems of every line that cannot be read.
 */
fun parseHeaderRules(field: String, text: String): Pair<List<HeaderRule>, List<String>> {
    val rules = mutableListOf<HeaderRule>()
    val problems = mutableListOf<String>()
    text.lines().map { it.trim() }.filter { it.isNotEmpty() }.forEach { line ->
        val action = line.substringBefore(' ').lowercase()
        val rest = line.substringAfter(' ', "").trim()
        when (action) {
            "set", "add" -> {
                if (':' !in rest) problems += "$field: \"$line\" needs the form \"$action Name: value\""
                else rules += HeaderRule(if (action == "set") HeaderAction.SET else HeaderAction.ADD, rest.substringBefore(':').trim(), rest.substringAfter(':').trim())
            }

            "remove" -> rules += HeaderRule(HeaderAction.REMOVE, rest)
            else -> problems += "$field: \"$line\" must start with set, add or remove"
        }
    }
    return rules to problems
}

/** Domains with their routes. */
fun Route.domainRoutes(kovexy: Kovexy) {
    get("/domains") {
        val config = kovexy.config
        call.page("Domains", call.session, Nav.DOMAINS) {
            pageHeader("Domains", "Domains with their names and routes. Every change applies at once.") {
                linkButton("/domains/new", "Add domain", "primary")
            }
            card {
                if (config.domains.isEmpty()) p("muted") { +t("No domains yet. Add one to forward a name to a backend.") }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Domains") }; th { +t("Routes") }; th { +t("State") }; th { } } }
                        tbody {
                            config.domains.forEachIndexed { i, domain ->
                                tr {
                                    td { attributes["data-label"] = t("Domains"); a(href = "/domains/$i") { +domain.names.joinToString(", ") } }
                                    td { attributes["data-label"] = t("Routes"); +domain.routes.joinToString(", ") { it.path + " → " + targetLabel(it.target) } }
                                    td { attributes["data-label"] = t("State"); if (domain.enabled) pill("ok", "enabled") else pill("", "disabled") }
                                    td("actions") { linkButton("/domains/$i", "Edit", "sm") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    get("/domains/new") { call.domainForm(kovexy, null, DomainConfig(names = emptyList()), emptyList()) }

    post("/domains/new") {
        val params = call.receiveForm()
        val (domain, parseProblems) = domainFromForm(params, DomainConfig(names = emptyList()))
        val backend = params["rootBackend"].orEmpty()
        val withRoot = if (backend.isNotEmpty() && domain.dyndns.not()) domain.copy(routes = listOf(RouteConfig("/", target = Target.Backend(backend)))) else domain
        val problems = parseProblems.ifEmpty { call.saveConfig(params["version"]) { it.copy(domains = it.domains + withRoot) } }
        if (problems == null) return@post call.respondRedirect("/domains/${kovexy.config.domains.size - 1}?done=domain-saved")
        call.domainForm(kovexy, null, withRoot, problems, params["version"])
    }

    get("/domains/{i}") {
        val i = call.domainIndex(kovexy) ?: return@get
        call.domainForm(kovexy, i, kovexy.config.domains[i], emptyList())
    }

    post("/domains/{i}") {
        val i = call.domainIndex(kovexy) ?: return@post
        val params = call.receiveForm()
        val existing = kovexy.config.domains[i]
        val (domain, parseProblems) = domainFromForm(params, existing)
        val problems = parseProblems.ifEmpty {
            call.saveConfig(params["version"]) { c -> c.copy(domains = c.domains.toMutableList().also { it[i] = domain }) }
        }
        if (problems == null) return@post call.respondRedirect("/domains/$i?done=domain-saved")
        call.domainForm(kovexy, i, domain, problems, params["version"])
    }

    post("/domains/{i}/delete") {
        val i = call.domainIndex(kovexy) ?: return@post
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(domains = c.domains.filterIndexed { index, _ -> index != i }) }
        if (problems == null) return@post call.respondRedirect("/domains?done=domain-deleted")
        // Not the form of domain i: after a conflict that index may already belong to another site
        call.errorPage(HttpStatusCode.Conflict, "Not deleted", problems.joinToString(" "))
    }

    get("/domains/{i}/routes/new") {
        val i = call.domainIndex(kovexy) ?: return@get
        call.routeForm(kovexy, i, null, RouteForm.of(RouteConfig("/", target = Target.Backend(kovexy.config.backends.firstOrNull()?.name.orEmpty()))), emptyList())
    }

    get("/domains/{i}/routes/{j}") {
        val i = call.domainIndex(kovexy) ?: return@get
        val j = call.routeIndex(kovexy, i) ?: return@get
        call.routeForm(kovexy, i, j, RouteForm.of(kovexy.config.domains[i].routes[j]), emptyList())
    }

    post("/domains/{i}/routes/{j}") {
        val i = call.domainIndex(kovexy) ?: return@post
        val isNew = call.parameters["j"] == "new"
        val j = if (isNew) null else call.routeIndex(kovexy, i) ?: return@post
        val params = call.receiveForm()
        var form = RouteForm.of(params)
        if (params["action"] == "security-headers") {
            val existing = parseHeaderRules("", form.responseHeaders).first
            val added = SECURITY_HEADER_TEMPLATE.filter { rule -> existing.none { it.name.equals(rule.name, ignoreCase = true) } }
            form = form.copy(responseHeaders = headerRulesToText(existing + added))
            return@post call.routeForm(kovexy, i, j, form, emptyList(), params["version"])
        }
        val (route, parseProblems) = form.toRoute()
        val problems = parseProblems.ifEmpty {
            call.saveConfig(params["version"]) { c ->
                c.copy(domains = c.domains.toMutableList().also { domains ->
                    val domain = domains[i]
                    val routes = domain.routes.toMutableList()
                    if (j == null) routes += route!! else routes[j] = route!!
                    domains[i] = domain.copy(routes = routes)
                })
            }
        }
        if (problems == null) return@post call.respondRedirect("/domains/$i?done=route-saved")
        call.routeForm(kovexy, i, j, form, problems, params["version"])
    }

    post("/domains/{i}/routes/{j}/delete") {
        val i = call.domainIndex(kovexy) ?: return@post
        val j = call.routeIndex(kovexy, i) ?: return@post
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c ->
            c.copy(domains = c.domains.toMutableList().also { domains -> domains[i] = domains[i].copy(routes = domains[i].routes.filterIndexed { index, _ -> index != j }) })
        }
        if (problems == null) return@post call.respondRedirect("/domains/$i?done=route-deleted")
        call.routeForm(kovexy, i, j, RouteForm.of(kovexy.config.domains[i].routes[j]), problems)
    }
}

/** A short description of a target for lists. */
fun targetLabel(target: Target): String = when (target) {
    is Target.Backend -> t("backend {0}", target.backend)
    is Target.Static -> t("files {0}", target.root)
    is Target.Redirect -> "${target.status} ${target.url}"
    is Target.Deny -> t("blocked {0}", target.status)
}

private suspend fun ApplicationCall.domainIndex(kovexy: Kovexy): Int? {
    val i = parameters["i"]?.toIntOrNull()
    if (i == null || i !in kovexy.config.domains.indices) {
        errorPage(HttpStatusCode.NotFound, "Domain not found", "This domain does not exist (any more).")
        return null
    }
    return i
}

private suspend fun ApplicationCall.routeIndex(kovexy: Kovexy, domain: Int): Int? {
    val j = parameters["j"]?.toIntOrNull()
    if (j == null || j !in kovexy.config.domains[domain].routes.indices) {
        errorPage(HttpStatusCode.NotFound, "Route not found", "This route does not exist (any more).")
        return null
    }
    return j
}

private fun domainFromForm(params: Parameters, base: DomainConfig): Pair<DomainConfig, List<String>> {
    val domains = params["names"].orEmpty().split('\n', ',', ' ').map { it.trim().lowercase() }.filter { it.isNotEmpty() }
    val domain = base.copy(
        names = domains,
        enabled = params["enabled"] != null,
        accessLog = params["accessLog"] != null,
        dyndns = params["dyndns"] != null,
        access = params["access"]?.takeIf { it.isNotEmpty() },
    )
    return domain to emptyList()
}

private suspend fun ApplicationCall.domainForm(kovexy: Kovexy, index: Int?, domain: DomainConfig, problems: List<String>, posted: String? = null) {
    val version = posted ?: kovexy.configStore.current.version
    val title = if (index == null) "Add domain" else domain.names.firstOrNull() ?: "Domain"
    page(title, session, Nav.DOMAINS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title, "Every name gets its own certificate. Plain HTTP on port 80 is always redirected to HTTPS.") {
            linkButton("/domains", "All domains", "ghost")
        }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card("Domain") {
            form(action = if (index == null) "/domains/new" else "/domains/$index", method = FormMethod.post, classes = "form") {
                versionField(version)
                textAreaField("Domain names", "names", domain.names.joinToString("\n"), rows = 3, hint = t("One per line, exact names like example.com and www.example.com. No wildcards."), required = true)
                checkField("Enabled", "enabled", domain.enabled, help = "domain.enabled")
                checkField("Write requests to the access log", "accessLog", domain.accessLog)
                checkField("Use for DynDNS", "dyndns", domain.dyndns, hint = "answers only /nic/update, no routes", help = "domain.dyndns")
                profileSelect(kovexy, domain.access, "No profile, every visitor gets in", "A route with its own profile replaces it completely.")
                if (index == null) {
                    val backends = kovexy.config.backends.map { it.name to it.name }
                    selectField("Forward / to", "rootBackend", backends.firstOrNull()?.first.orEmpty(), listOf("" to "nothing yet, add routes later") + backends,
                        hint = t("Creates the route / with this backend."))
                }
                div("btn-row") { submit(if (index == null) "Add domain" else "Save domain") }
            }
        }
        if (index != null) {
            card("Routes", "gap-top") {
                p("muted") { +t("The most specific route wins: longer paths before shorter ones, exact before prefix. A prefix only matches at path boundaries, /api matches /api/users but not /apix.") }
                if (domain.routes.isEmpty()) p("muted") { +t("No routes yet, every request gets a 404.") }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +t("Path") }; th { +t("Match") }; th { +t("Target") }; th { +t("State") }; th { } } }
                        tbody {
                            domain.routes.forEachIndexed { j, route ->
                                tr {
                                    td { attributes["data-label"] = t("Path"); a(href = "/domains/$index/routes/$j") { +route.path } }
                                    td { attributes["data-label"] = t("Match"); +t(route.match.name.lowercase()) }
                                    td { attributes["data-label"] = t("Target"); +targetLabel(route.target) }
                                    td { attributes["data-label"] = t("State"); if (route.enabled) pill("ok", "enabled") else pill("", "disabled") }
                                    td("actions") { linkButton("/domains/$index/routes/$j", "Edit", "sm") }
                                }
                            }
                        }
                    }
                }
                div("btn-row gap-top") { linkButton("/domains/$index/routes/new", "Add route", "primary") }
            }
            card("Delete domain", "danger gap-top") {
                p("muted") { +t("The certificates stay on disk but are not renewed any more.") }
                postButton("/domains/$index/delete", "Delete domain", "danger", confirm = t("Delete this domain?"), hidden = mapOf("version" to version))
            }
        }
    }
}

/** The fields of the route form as text, so a rejected form shows exactly what was typed. */
private data class RouteForm(
    val path: String,
    val match: String,
    val stripPrefix: Boolean,
    val enabled: Boolean,
    val targetType: String,
    val backend: String,
    val root: String,
    val directoryListing: Boolean,
    val url: String,
    val redirectStatus: String,
    val keepPath: Boolean,
    val denyStatus: String,
    val html: String,
    val requestHeaders: String,
    val responseHeaders: String,
    val access: String,
) {
    fun toRoute(): Pair<RouteConfig?, List<String>> {
        val problems = mutableListOf<String>()
        val target = when (targetType) {
            "static" -> Target.Static(root.trim(), directoryListing)
            "redirect" -> Target.Redirect(url.trim(), redirectStatus.toIntOrNull() ?: 307, keepPath)
            "deny" -> Target.Deny(denyStatus.toIntOrNull() ?: run { problems += "Status must be a number"; 404 }, html)
            else -> Target.Backend(backend)
        }
        val (requestRules, requestProblems) = parseHeaderRules("Request headers", requestHeaders)
        val (responseRules, responseProblems) = parseHeaderRules("Response headers", responseHeaders)
        problems += requestProblems + responseProblems
        val route = RouteConfig(
            path = path.trim(),
            match = if (match == "exact") MatchType.EXACT else MatchType.PREFIX,
            stripPrefix = stripPrefix && target is Target.Backend,
            target = target,
            requestHeaders = requestRules,
            responseHeaders = responseRules,
            enabled = enabled,
            access = access.ifEmpty { null },
        )
        return route to problems
    }

    companion object {
        fun of(route: RouteConfig): RouteForm {
            val target = route.target
            return RouteForm(
                path = route.path,
                match = route.match.name.lowercase(),
                stripPrefix = route.stripPrefix,
                enabled = route.enabled,
                targetType = when (target) {
                    is Target.Backend -> "backend"
                    is Target.Static -> "static"
                    is Target.Redirect -> "redirect"
                    is Target.Deny -> "deny"
                },
                backend = (target as? Target.Backend)?.backend.orEmpty(),
                root = (target as? Target.Static)?.root.orEmpty(),
                directoryListing = (target as? Target.Static)?.directoryListing == true,
                url = (target as? Target.Redirect)?.url.orEmpty(),
                redirectStatus = ((target as? Target.Redirect)?.status ?: 307).toString(),
                keepPath = (target as? Target.Redirect)?.keepPath ?: true,
                denyStatus = ((target as? Target.Deny)?.status ?: 404).toString(),
                html = (target as? Target.Deny)?.html.orEmpty(),
                requestHeaders = headerRulesToText(route.requestHeaders),
                responseHeaders = headerRulesToText(route.responseHeaders),
                access = route.access.orEmpty(),
            )
        }

        fun of(params: Parameters) = RouteForm(
            path = params["path"].orEmpty(),
            match = params["match"].orEmpty(),
            stripPrefix = params["stripPrefix"] != null,
            enabled = params["enabled"] != null,
            targetType = params["targetType"].orEmpty(),
            backend = params["backend"].orEmpty(),
            root = params["root"].orEmpty(),
            directoryListing = params["directoryListing"] != null,
            url = params["url"].orEmpty(),
            redirectStatus = params["redirectStatus"].orEmpty(),
            keepPath = params["keepPath"] != null,
            denyStatus = params["denyStatus"].orEmpty(),
            html = params["html"].orEmpty(),
            requestHeaders = params["requestHeaders"].orEmpty(),
            responseHeaders = params["responseHeaders"].orEmpty(),
            access = params["access"].orEmpty(),
        )
    }
}

private suspend fun ApplicationCall.routeForm(kovexy: Kovexy, domain: Int, index: Int?, form: RouteForm, problems: List<String>, posted: String? = null) {
    val version = posted ?: kovexy.configStore.current.version
    val domainName = kovexy.config.domains[domain].names.firstOrNull().orEmpty()
    val title = if (index == null) "Add route" else t("Route {0}", form.path)
    page(title, session, Nav.DOMAINS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title, t("Domain {0}", domainName)) { linkButton("/domains/$domain", "Back to the domain", "ghost") }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = "/domains/$domain/routes/${index ?: "new"}", method = FormMethod.post, classes = "form") {
                versionField(version)
                div("grid-2") {
                    textField("Path", "path", form.path, hint = t("Starts with /, a prefix without trailing slash."), help = "route.path")
                    selectField("Match", "match", form.match, listOf("prefix" to "Prefix: the path and everything below it", "exact" to "Exact: only this path"))
                }
                checkField("Enabled", "enabled", form.enabled, help = "route.enabled")
                profileSelect(kovexy, form.access.ifEmpty { null }, "Profile of the domain", "An own profile replaces the one of the domain completely.")
                selectField("Target", "targetType", form.targetType, listOf("backend" to "Backend", "static" to "Static files", "redirect" to "Redirect", "deny" to "Block"))
                fieldSet("target-fields target-backend") {
                    legend { +t("Backend") }
                    selectField("Backend", "backend", form.backend, kovexy.config.backends.map { it.name to it.name }.ifEmpty { listOf("" to "No backends yet") })
                    checkField("Strip the path prefix", "stripPrefix", form.stripPrefix, "/api/users reaches the backend as /users")
                }
                fieldSet("target-fields target-static") {
                    legend { +t("Static files") }
                    textField("Directory", "root", form.root, hint = t("Absolute, or relative to the data directory."), required = false)
                    checkField("List directories without index file", "directoryListing", form.directoryListing, "off is safer")
                }
                fieldSet("target-fields target-redirect") {
                    legend { +t("Redirect") }
                    textField("Target URL", "url", form.url, placeholder = "https://example.com", required = false, help = "redirectUrl")
                    selectField("Status", "redirectStatus", form.redirectStatus, listOf("307" to "307 temporary", "301" to "301 permanent"))
                    checkField("Keep the path and query", "keepPath", form.keepPath, "/old/page?x=1 goes to <url>/page?x=1")
                }
                fieldSet("target-fields target-deny") {
                    legend { +t("Block") }
                    textField("Status code", "denyStatus", form.denyStatus, required = false, type = kotlinx.html.InputType.number)
                    textAreaField("Own HTML page", "html", form.html, rows = 4, hint = t("Optional, otherwise a neutral page."))
                }
                val headerCount = form.requestHeaders.lines().count { it.isNotBlank() } + form.responseHeaders.lines().count { it.isNotBlank() }
                fold("Headers", if (headerCount == 0) "none" else t("{0} rules", headerCount), open = headerCount > 0 || problems.isNotEmpty()) {
                    textAreaField("Request headers to the backend", "requestHeaders", form.requestHeaders, rows = 3, hint = t("One per line: set Name: value, add Name: value, remove Name"))
                    textAreaField("Response headers to the visitor", "responseHeaders", form.responseHeaders, rows = 4, hint = t("Same format. Remove only works for backend answers."))
                }
                div("btn-row sticky-save") {
                    submit("Save route", name = "action", value = "save")
                    submit("Add security headers", "", name = "action", value = "security-headers")
                }
            }
        }
        if (index != null) card("Delete route", "danger gap-top") {
            postButton("/domains/$domain/routes/$index/delete", "Delete route", "danger", confirm = t("Delete this route?"), hidden = mapOf("version" to version))
        }
    }
}

/** Select of the access profiles, with [none] as the empty choice. */
private fun kotlinx.html.FlowContent.profileSelect(kovexy: Kovexy, selected: String?, none: String, hint: String) =
    selectField("Access profile", "access", selected.orEmpty(), listOf("" to none) + kovexy.config.accessProfiles.map { it.name to it.name }, hint = hint)
