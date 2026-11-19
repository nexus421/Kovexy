package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.config.HeaderAction
import bayern.kickner.kovexy.config.HeaderRule
import bayern.kickner.kovexy.config.LISTENER_HTTP
import bayern.kickner.kovexy.config.LISTENER_HTTPS
import bayern.kickner.kovexy.config.LocationConfig
import bayern.kickner.kovexy.config.MatchType
import bayern.kickner.kovexy.config.SiteConfig
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

/** Sites with their locations. */
fun Route.siteRoutes(kovexy: Kovexy) {
    get("/sites") {
        val config = kovexy.config
        call.page("Sites", call.session, Nav.SITES) {
            pageHeader("Sites", "Domains and the rules for their paths. Every change applies at once.") {
                linkButton("/sites/new", "Add site", "primary")
            }
            card {
                if (config.sites.isEmpty()) p("muted") { +"No sites yet. Add one to forward a domain to an upstream." }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Domains" }; th { +"Listeners" }; th { +"Locations" }; th { +"State" }; th { } } }
                        tbody {
                            config.sites.forEachIndexed { i, site ->
                                tr {
                                    td { attributes["data-label"] = "Domains"; a(href = "/sites/$i") { +site.domains.joinToString(", ") } }
                                    td { attributes["data-label"] = "Listeners"; +site.listeners.joinToString(", ") }
                                    td { attributes["data-label"] = "Locations"; +site.locations.joinToString(", ") { it.path + " → " + targetLabel(it.target) } }
                                    td { attributes["data-label"] = "State"; if (site.enabled) pill("ok", "enabled") else pill("", "disabled") }
                                    td("actions") { linkButton("/sites/$i", "Edit", "sm") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    get("/sites/new") { call.siteForm(kovexy, null, SiteConfig(domains = emptyList()), emptyList()) }

    post("/sites/new") {
        val params = call.receiveForm()
        val (site, parseProblems) = siteFromForm(params, SiteConfig(domains = emptyList()))
        val upstream = params["rootUpstream"].orEmpty()
        val withRoot = if (upstream.isNotEmpty()) site.copy(locations = listOf(LocationConfig("/", target = Target.Upstream(upstream)))) else site
        val problems = parseProblems.ifEmpty { call.saveConfig(params["version"]) { it.copy(sites = it.sites + withRoot) } }
        if (problems == null) return@post call.respondRedirect("/sites/${kovexy.config.sites.size - 1}?done=site-saved")
        call.siteForm(kovexy, null, withRoot, problems, params["version"])
    }

    get("/sites/{i}") {
        val i = call.siteIndex(kovexy) ?: return@get
        call.siteForm(kovexy, i, kovexy.config.sites[i], emptyList())
    }

    post("/sites/{i}") {
        val i = call.siteIndex(kovexy) ?: return@post
        val params = call.receiveForm()
        val existing = kovexy.config.sites[i]
        val (site, parseProblems) = siteFromForm(params, existing)
        val problems = parseProblems.ifEmpty {
            call.saveConfig(params["version"]) { c -> c.copy(sites = c.sites.toMutableList().also { it[i] = site }) }
        }
        if (problems == null) return@post call.respondRedirect("/sites/$i?done=site-saved")
        call.siteForm(kovexy, i, site, problems, params["version"])
    }

    post("/sites/{i}/delete") {
        val i = call.siteIndex(kovexy) ?: return@post
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(sites = c.sites.filterIndexed { index, _ -> index != i }) }
        if (problems == null) return@post call.respondRedirect("/sites?done=site-deleted")
        // Not the form of site i: after a conflict that index may already belong to another site
        call.errorPage(HttpStatusCode.Conflict, "Not deleted", problems.joinToString(" "))
    }

    get("/sites/{i}/locations/new") {
        val i = call.siteIndex(kovexy) ?: return@get
        call.locationForm(kovexy, i, null, LocationForm.of(LocationConfig("/", target = Target.Upstream(kovexy.config.upstreams.firstOrNull()?.name.orEmpty()))), emptyList())
    }

    get("/sites/{i}/locations/{j}") {
        val i = call.siteIndex(kovexy) ?: return@get
        val j = call.locationIndex(kovexy, i) ?: return@get
        call.locationForm(kovexy, i, j, LocationForm.of(kovexy.config.sites[i].locations[j]), emptyList())
    }

    post("/sites/{i}/locations/{j}") {
        val i = call.siteIndex(kovexy) ?: return@post
        val isNew = call.parameters["j"] == "new"
        val j = if (isNew) null else call.locationIndex(kovexy, i) ?: return@post
        val params = call.receiveForm()
        var form = LocationForm.of(params)
        if (params["action"] == "security-headers") {
            val existing = parseHeaderRules("", form.responseHeaders).first
            val added = SECURITY_HEADER_TEMPLATE.filter { rule -> existing.none { it.name.equals(rule.name, ignoreCase = true) } }
            form = form.copy(responseHeaders = headerRulesToText(existing + added))
            return@post call.locationForm(kovexy, i, j, form, emptyList(), params["version"])
        }
        val (location, parseProblems) = form.toLocation()
        val problems = parseProblems.ifEmpty {
            call.saveConfig(params["version"]) { c ->
                c.copy(sites = c.sites.toMutableList().also { sites ->
                    val site = sites[i]
                    val locations = site.locations.toMutableList()
                    if (j == null) locations += location!! else locations[j] = location!!
                    sites[i] = site.copy(locations = locations)
                })
            }
        }
        if (problems == null) return@post call.respondRedirect("/sites/$i?done=location-saved")
        call.locationForm(kovexy, i, j, form, problems, params["version"])
    }

    post("/sites/{i}/locations/{j}/delete") {
        val i = call.siteIndex(kovexy) ?: return@post
        val j = call.locationIndex(kovexy, i) ?: return@post
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c ->
            c.copy(sites = c.sites.toMutableList().also { sites -> sites[i] = sites[i].copy(locations = sites[i].locations.filterIndexed { index, _ -> index != j }) })
        }
        if (problems == null) return@post call.respondRedirect("/sites/$i?done=location-deleted")
        call.locationForm(kovexy, i, j, LocationForm.of(kovexy.config.sites[i].locations[j]), problems)
    }
}

/** A short description of a target for lists. */
fun targetLabel(target: Target): String = when (target) {
    is Target.Upstream -> "upstream ${target.upstream}"
    is Target.Static -> "files ${target.root}"
    is Target.Redirect -> "${target.status} ${target.url}"
    is Target.Deny -> "blocked ${target.status}"
}

private suspend fun ApplicationCall.siteIndex(kovexy: Kovexy): Int? {
    val i = parameters["i"]?.toIntOrNull()
    if (i == null || i !in kovexy.config.sites.indices) {
        errorPage(HttpStatusCode.NotFound, "Site not found", "This site does not exist (any more).")
        return null
    }
    return i
}

private suspend fun ApplicationCall.locationIndex(kovexy: Kovexy, site: Int): Int? {
    val j = parameters["j"]?.toIntOrNull()
    if (j == null || j !in kovexy.config.sites[site].locations.indices) {
        errorPage(HttpStatusCode.NotFound, "Location not found", "This location does not exist (any more).")
        return null
    }
    return j
}

private fun siteFromForm(params: Parameters, base: SiteConfig): Pair<SiteConfig, List<String>> {
    val domains = params["domains"].orEmpty().split('\n', ',', ' ').map { it.trim().lowercase() }.filter { it.isNotEmpty() }
    val listeners = listOfNotNull(LISTENER_HTTP.takeIf { params["listenHttp"] != null }, LISTENER_HTTPS.takeIf { params["listenHttps"] != null })
    val site = base.copy(
        domains = domains,
        listeners = listeners,
        httpsRedirect = params["httpsRedirect"] != null,
        enabled = params["enabled"] != null,
        accessLog = params["accessLog"] != null,
        access = params["access"]?.takeIf { it.isNotEmpty() },
    )
    return site to emptyList()
}

private suspend fun ApplicationCall.siteForm(kovexy: Kovexy, index: Int?, site: SiteConfig, problems: List<String>, posted: String? = null) {
    val version = posted ?: kovexy.configStore.current.version
    val title = if (index == null) "Add site" else site.domains.firstOrNull() ?: "Site"
    page(title, session, Nav.SITES, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title, "Every domain gets its own certificate when the site is on the TLS listener.") {
            linkButton("/sites", "All sites", "ghost")
        }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card("Site") {
            form(action = if (index == null) "/sites/new" else "/sites/$index", method = FormMethod.post, classes = "form") {
                versionField(version)
                textAreaField("Domains", "domains", site.domains.joinToString("\n"), rows = 3, hint = "One per line, exact names like example.com and www.example.com. No wildcards.", required = true)
                fieldSet {
                    legend { +"Listeners" }
                    checkField("HTTP (port 80)", "listenHttp", LISTENER_HTTP in site.listeners)
                    checkField("HTTPS (port 443)", "listenHttps", LISTENER_HTTPS in site.listeners)
                    checkField("Redirect HTTP to HTTPS", "httpsRedirect", site.httpsRedirect, "only when HTTPS is on")
                }
                checkField("Enabled", "enabled", site.enabled)
                checkField("Write requests to the access log", "accessLog", site.accessLog)
                profileSelect(kovexy, site.access, "No profile, every visitor gets in", "A location with its own profile replaces it completely.")
                if (index == null) {
                    val upstreams = kovexy.config.upstreams.map { it.name to it.name }
                    selectField("Forward / to", "rootUpstream", upstreams.firstOrNull()?.first.orEmpty(), listOf("" to "nothing yet, add locations later") + upstreams,
                        hint = "Creates the location / with this upstream group.")
                }
                div("btn-row") { submit(if (index == null) "Add site" else "Save site") }
            }
        }
        if (index != null) {
            card("Locations", "gap-top") {
                p("muted") { +"The most specific location wins: longer paths before shorter ones, exact before prefix. A prefix only matches at path boundaries, /api matches /api/users but not /apix." }
                if (site.locations.isEmpty()) p("muted") { +"No locations yet, every request gets a 404." }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Path" }; th { +"Match" }; th { +"Target" }; th { +"State" }; th { } } }
                        tbody {
                            site.locations.forEachIndexed { j, location ->
                                tr {
                                    td { attributes["data-label"] = "Path"; a(href = "/sites/$index/locations/$j") { +location.path } }
                                    td { attributes["data-label"] = "Match"; +location.match.name.lowercase() }
                                    td { attributes["data-label"] = "Target"; +targetLabel(location.target) }
                                    td { attributes["data-label"] = "State"; if (location.enabled) pill("ok", "enabled") else pill("", "disabled") }
                                    td("actions") { linkButton("/sites/$index/locations/$j", "Edit", "sm") }
                                }
                            }
                        }
                    }
                }
                div("btn-row gap-top") { linkButton("/sites/$index/locations/new", "Add location", "primary") }
            }
            card("Delete site", "danger gap-top") {
                p("muted") { +"The certificates stay on disk but are not renewed any more." }
                postButton("/sites/$index/delete", "Delete site", "danger", confirm = "Delete this site?", hidden = mapOf("version" to version))
            }
        }
    }
}

/** The fields of the location form as text, so a rejected form shows exactly what was typed. */
private data class LocationForm(
    val path: String,
    val match: String,
    val stripPrefix: Boolean,
    val enabled: Boolean,
    val targetType: String,
    val upstream: String,
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
    fun toLocation(): Pair<LocationConfig?, List<String>> {
        val problems = mutableListOf<String>()
        val target = when (targetType) {
            "static" -> Target.Static(root.trim(), directoryListing)
            "redirect" -> Target.Redirect(url.trim(), redirectStatus.toIntOrNull() ?: 307, keepPath)
            "deny" -> Target.Deny(denyStatus.toIntOrNull() ?: run { problems += "Status must be a number"; 404 }, html)
            else -> Target.Upstream(upstream)
        }
        val (requestRules, requestProblems) = parseHeaderRules("Request headers", requestHeaders)
        val (responseRules, responseProblems) = parseHeaderRules("Response headers", responseHeaders)
        problems += requestProblems + responseProblems
        val location = LocationConfig(
            path = path.trim(),
            match = if (match == "exact") MatchType.EXACT else MatchType.PREFIX,
            stripPrefix = stripPrefix && target is Target.Upstream,
            target = target,
            requestHeaders = requestRules,
            responseHeaders = responseRules,
            enabled = enabled,
            access = access.ifEmpty { null },
        )
        return location to problems
    }

    companion object {
        fun of(location: LocationConfig): LocationForm {
            val target = location.target
            return LocationForm(
                path = location.path,
                match = location.match.name.lowercase(),
                stripPrefix = location.stripPrefix,
                enabled = location.enabled,
                targetType = when (target) {
                    is Target.Upstream -> "upstream"
                    is Target.Static -> "static"
                    is Target.Redirect -> "redirect"
                    is Target.Deny -> "deny"
                },
                upstream = (target as? Target.Upstream)?.upstream.orEmpty(),
                root = (target as? Target.Static)?.root.orEmpty(),
                directoryListing = (target as? Target.Static)?.directoryListing == true,
                url = (target as? Target.Redirect)?.url.orEmpty(),
                redirectStatus = ((target as? Target.Redirect)?.status ?: 307).toString(),
                keepPath = (target as? Target.Redirect)?.keepPath ?: true,
                denyStatus = ((target as? Target.Deny)?.status ?: 404).toString(),
                html = (target as? Target.Deny)?.html.orEmpty(),
                requestHeaders = headerRulesToText(location.requestHeaders),
                responseHeaders = headerRulesToText(location.responseHeaders),
                access = location.access.orEmpty(),
            )
        }

        fun of(params: Parameters) = LocationForm(
            path = params["path"].orEmpty(),
            match = params["match"].orEmpty(),
            stripPrefix = params["stripPrefix"] != null,
            enabled = params["enabled"] != null,
            targetType = params["targetType"].orEmpty(),
            upstream = params["upstream"].orEmpty(),
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

private suspend fun ApplicationCall.locationForm(kovexy: Kovexy, site: Int, index: Int?, form: LocationForm, problems: List<String>, posted: String? = null) {
    val version = posted ?: kovexy.configStore.current.version
    val siteName = kovexy.config.sites[site].domains.firstOrNull().orEmpty()
    val title = if (index == null) "Add location" else "Location ${form.path}"
    page(title, session, Nav.SITES, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title, "Site $siteName") { linkButton("/sites/$site", "Back to the site", "ghost") }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = "/sites/$site/locations/${index ?: "new"}", method = FormMethod.post, classes = "form") {
                versionField(version)
                div("grid-2") {
                    textField("Path", "path", form.path, hint = "Starts with /, a prefix without trailing slash.")
                    selectField("Match", "match", form.match, listOf("prefix" to "Prefix: the path and everything below it", "exact" to "Exact: only this path"))
                }
                checkField("Enabled", "enabled", form.enabled)
                profileSelect(kovexy, form.access.ifEmpty { null }, "Profile of the site", "An own profile replaces the one of the site completely.")
                selectField("Target", "targetType", form.targetType, listOf("upstream" to "Upstream group", "static" to "Static files", "redirect" to "Redirect", "deny" to "Block"))
                fieldSet("target-fields target-upstream") {
                    legend { +"Upstream" }
                    selectField("Upstream group", "upstream", form.upstream, kovexy.config.upstreams.map { it.name to it.name }.ifEmpty { listOf("" to "No upstream groups yet") })
                    checkField("Strip the path prefix", "stripPrefix", form.stripPrefix, "/api/users reaches the upstream as /users")
                }
                fieldSet("target-fields target-static") {
                    legend { +"Static files" }
                    textField("Directory", "root", form.root, hint = "Absolute, or relative to the data directory.", required = false)
                    checkField("List directories without index file", "directoryListing", form.directoryListing, "off is safer")
                }
                fieldSet("target-fields target-redirect") {
                    legend { +"Redirect" }
                    textField("Target URL", "url", form.url, placeholder = "https://example.com", required = false)
                    selectField("Status", "redirectStatus", form.redirectStatus, listOf("307" to "307 temporary", "301" to "301 permanent"))
                    checkField("Keep the path and query", "keepPath", form.keepPath, "/old/page?x=1 goes to <url>/page?x=1")
                }
                fieldSet("target-fields target-deny") {
                    legend { +"Block" }
                    textField("Status code", "denyStatus", form.denyStatus, required = false, type = kotlinx.html.InputType.number)
                    textAreaField("Own HTML page", "html", form.html, rows = 4, hint = "Optional, otherwise a neutral page.")
                }
                textAreaField("Request headers to the upstream", "requestHeaders", form.requestHeaders, rows = 3, hint = "One per line: set Name: value, add Name: value, remove Name")
                textAreaField("Response headers to the visitor", "responseHeaders", form.responseHeaders, rows = 4, hint = "Same format. Remove only works for upstream answers.")
                div("btn-row") {
                    submit("Save location", name = "action", value = "save")
                    submit("Add security headers", "", name = "action", value = "security-headers")
                }
            }
        }
        if (index != null) card("Delete location", "danger gap-top") {
            postButton("/sites/$site/locations/$index/delete", "Delete location", "danger", confirm = "Delete this location?", hidden = mapOf("version" to version))
        }
    }
}

/** Select of the access profiles, with [none] as the empty choice. */
private fun kotlinx.html.FlowContent.profileSelect(kovexy: Kovexy, selected: String?, none: String, hint: String) =
    selectField("Access profile", "access", selected.orEmpty(), listOf("" to none) + kovexy.config.accessProfiles.map { it.name to it.name }, hint = hint)
