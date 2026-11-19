package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.auth.RECOMMENDED_PASSWORD_LENGTH
import bayern.kickner.kovexy.auth.hashBcrypt
import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.access.shippedAiBotNames
import bayern.kickner.kovexy.config.AiCrawlersConfig
import bayern.kickner.kovexy.config.BasicAuthConfig
import bayern.kickner.kovexy.config.BasicAuthException
import bayern.kickner.kovexy.config.AppOidcConfig
import bayern.kickner.kovexy.config.CaptchaConfig
import bayern.kickner.kovexy.config.CaptchaProvider
import bayern.kickner.kovexy.config.DEFAULT_POW_DIFFICULTY
import bayern.kickner.kovexy.config.POW_DIFFICULTY_HINT
import bayern.kickner.kovexy.config.RecaptchaVersion
import bayern.kickner.kovexy.config.BasicAuthUser
import bayern.kickner.kovexy.config.DEFAULT_TRAP_PATHS
import bayern.kickner.kovexy.config.ExploitFilterConfig
import bayern.kickner.kovexy.config.ExploitResponse
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.RateLimitConfig
import bayern.kickner.kovexy.config.TrapPathsConfig
import bayern.kickner.kovexy.formatTimestamp
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.ApplicationCall
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.FlowContent
import kotlinx.html.FormMethod
import kotlinx.html.InputType
import kotlinx.html.a
import kotlinx.html.checkBoxInput
import kotlinx.html.div
import kotlinx.html.summary
import kotlinx.html.details
import kotlinx.html.fieldSet
import kotlinx.html.form
import kotlinx.html.hiddenInput
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.legend
import kotlinx.html.option
import kotlinx.html.p
import kotlinx.html.select
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import java.util.Locale

/** Empty Basic Auth rows below the existing users. */
private const val EMPTY_USER_ROWS = 2

/** HTTP methods offered as checkboxes. */
private val METHODS = listOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

/** Every ISO country with its English name, sorted by name, for the country selects. */
private val COUNTRIES: List<Pair<String, String>> = Locale.getISOCountries()
    .map { it to Locale.of("", it).getDisplayCountry(Locale.ENGLISH) }
    .sortedBy { it.second }

/** Access profiles, like Zoraxy's "Access Control". */
fun Route.accessRoutes(kovexy: Kovexy) {
    get("/access") { call.accessPage(kovexy, emptyList(), null) }

    post("/access/ai-crawlers") {
        val params = call.receiveForm()
        val changes = AiCrawlersConfig(entries(params["add"]), entries(params["ignore"]))
        val problems = call.saveConfig(params["version"]) { it.copy(aiCrawlers = changes) }
        if (problems == null) return@post call.respondRedirect("/access?done=ai-crawlers-saved")
        call.accessPage(kovexy, problems, params["version"])
    }

    get("/access/new") { call.profileForm(kovexy, null, AccessProfile(""), emptyList(), null) }
    post("/access/new") {
        val params = call.receiveForm()
        val (profile, parseProblems) = profileFromForm(params, null)
        val problems = parseProblems.ifEmpty { call.saveConfig(params["version"]) { it.copy(accessProfiles = it.accessProfiles + profile) } }
        if (problems == null) return@post call.respondRedirect("/access?done=${savedKey(params)}")
        call.profileForm(kovexy, null, profile, problems, params["version"])
    }

    get("/access/{name}") {
        val profile = kovexy.config.accessProfiles.firstOrNull { it.name == call.parameters["name"] } ?: return@get call.notFoundProfile()
        call.profileForm(kovexy, profile.name, profile, emptyList(), null)
    }

    post("/access/{name}") {
        val name = call.parameters["name"]!!
        val existing = kovexy.config.accessProfiles.firstOrNull { it.name == name } ?: return@post call.notFoundProfile()
        val params = call.receiveForm()
        val (profile, parseProblems) = profileFromForm(params, existing)
        val problems = parseProblems.ifEmpty {
            call.saveConfig(params["version"]) { c -> c.copy(accessProfiles = c.accessProfiles.map { if (it.name == name) profile else it }).renameProfile(name, profile.name) }
        }
        if (problems == null) return@post call.respondRedirect("/access?done=${savedKey(params)}")
        call.profileForm(kovexy, name, profile, problems, params["version"])
    }

    post("/access/{name}/delete") {
        val name = call.parameters["name"]!!
        val existing = kovexy.config.accessProfiles.firstOrNull { it.name == name } ?: return@post call.notFoundProfile()
        val params = call.receiveForm()
        val problems = call.saveConfig(params["version"]) { c -> c.copy(accessProfiles = c.accessProfiles.filter { it.name != name }) }
        if (problems == null) return@post call.respondRedirect("/access?done=profile-deleted")
        call.profileForm(kovexy, name, existing, problems, params["version"])
    }
}

private suspend fun ApplicationCall.notFoundProfile() = errorPage(HttpStatusCode.NotFound, "Access profile not found", "This access profile does not exist (any more).")

/** The success message after saving, with a hint when a new Basic Auth password is short. */
private fun savedKey(params: Parameters): String {
    val count = params["userCount"]?.toIntOrNull()?.coerceIn(0, 100) ?: 0
    val short = params["basicEnabled"] != null && (0 until count).any { k -> params["u$k.password"].orEmpty().length in 1 until RECOMMENDED_PASSWORD_LENGTH }
    return if (short) "profile-saved-short-password" else "profile-saved"
}

private suspend fun ApplicationCall.accessPage(kovexy: Kovexy, problems: List<String>, posted: String?) {
    val config = kovexy.config
    val geo = kovexy.geo.status()
    val version = posted ?: kovexy.configStore.current.version
    page("Access", session, Nav.ACCESS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Access profiles", "IP and country rules, exploit filter, trap paths, rate limit, methods, captcha, OIDC login and Basic Auth. A site or location uses a profile by name.") {
            linkButton("/access/new", "Add profile", "primary")
        }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            if (config.accessProfiles.isEmpty()) p("muted") { +"No access profiles yet." }
            else div("table-wrap") {
                table("stack-mobile") {
                    thead { tr { th { +"Profile" }; th { +"Rules" }; th { +"Used by" }; th { } } }
                    tbody {
                        config.accessProfiles.forEach { profile ->
                            tr {
                                td { attributes["data-label"] = "Profile"; a(href = "/access/${urlPart(profile.name)}") { +profile.name } }
                                td { attributes["data-label"] = "Rules"; +profileSummary(profile) }
                                td { attributes["data-label"] = "Used by"; +usedBy(config, profile.name).ifEmpty { listOf("nothing") }.joinToString(", ") }
                                td("actions") { linkButton("/access/${urlPart(profile.name)}", "Edit", "sm") }
                            }
                        }
                    }
                }
            }
        }
        card("Country data", "gap-top") {
            when {
                geo.loaded -> p { +"${geo.rows} IP ranges loaded, data from ${geo.updatedAt?.let(::formatTimestamp) ?: "-"}. Checked daily against sapics/ip-location-db (user-country, PDDL)." }
                else -> notice("warn", "Country rules have no effect yet: no country data is loaded. ${geo.lastError ?: "The download is running."}")
            }
            geo.lastError?.takeIf { geo.loaded }?.let { p("muted small") { +"Last check failed: $it. The old data stays in use." } }
        }
        card("AI crawlers", "gap-top") {
            val shipped = shippedAiBotNames
            p("muted small") {
                +"Profiles with \"Block AI crawlers\" use the list of ai.robots.txt (${shipped.size} names, updated with every Kovexy release) and these changes. A name counts when it appears anywhere in the user agent, upper or lower case does not matter."
            }
            form(action = "/access/ai-crawlers", method = FormMethod.post, classes = "form") {
                versionField(version)
                div("grid-2") {
                    textAreaField("Also block", "add", config.aiCrawlers.add.joinToString("\n"), rows = 4, hint = "One user agent part per line, e.g. MyScraper")
                    textAreaField("Do not block", "ignore", config.aiCrawlers.ignore.joinToString("\n"), rows = 4, hint = "Names from the list below, one per line")
                }
                div("btn-row") { submit("Save AI crawler list") }
            }
            details("gap-top") {
                summary { +"Shipped list (${shipped.size})" }
                val ignored = config.aiCrawlers.ignore.map { it.trim().lowercase() }.toSet()
                p("small break") {
                    shipped.forEachIndexed { i, name ->
                        if (i > 0) +", "
                        if (name in ignored) span("muted strike") { +name } else +name
                    }
                }
            }
        }
    }
}

/** One entry per line, empty lines dropped. */
private fun entries(text: String?): List<String> = text.orEmpty().lines().map { it.trim() }.filter { it.isNotEmpty() }

/** Short list of what a profile does. */
private fun profileSummary(p: AccessProfile): String = buildList {
    if (p.denyIps.isNotEmpty() || p.denyCountries.isNotEmpty()) add("block list")
    if (p.allowIps.isNotEmpty() || p.allowCountries.isNotEmpty()) add("allow list")
    if (p.exploitFilter.commonExploits) add("exploit filter")
    if (p.exploitFilter.aiBots) add("AI crawlers")
    if (p.trapPaths.enabled) add("trap paths")
    p.rateLimit?.let { add("${it.requestsPerSecond} req/s") }
    if (p.allowedMethods.isNotEmpty()) add(p.allowedMethods.joinToString("/"))
    p.captcha?.let { add(if (it.provider == CaptchaProvider.POW) "proof of work" else "reCAPTCHA") }
    if (p.oidc != null) add("OIDC login")
    if (p.basicAuth != null) add("Basic Auth")
}.ifEmpty { listOf("no rules") }.joinToString(", ")

/** Sites and locations that use the profile [name]. */
private fun usedBy(config: KovexyConfig, name: String): List<String> = config.sites.flatMap { site ->
    val label = site.domains.firstOrNull().orEmpty()
    listOfNotNull(label.takeIf { site.access == name }) + site.locations.filter { it.access == name }.map { "$label${it.path}" }
}

/** Points every site and location that uses [old] to [new], so renaming a profile keeps them protected. */
private fun KovexyConfig.renameProfile(old: String, new: String): KovexyConfig {
    if (old == new) return this
    return copy(sites = sites.map { site ->
        site.copy(
            access = if (site.access == old) new else site.access,
            locations = site.locations.map { if (it.access == old) it.copy(access = new) else it },
        )
    })
}

/** Splits a text area into its non-empty lines, also accepting commas and spaces as separators. */
private fun lines(text: String?): List<String> = text.orEmpty().split('\n', ',', ' ').map { it.trim() }.filter { it.isNotEmpty() }

/**
 * Reads the profile form. New Basic Auth passwords are hashed with bcrypt (cost 14) here, but only when the form has no
 * problems, an empty password field keeps the stored hash of an existing user. A user without a stored hash keeps an
 * empty hash while the form is shown again, so the form asks for a new password.
 */
private suspend fun profileFromForm(params: Parameters, existing: AccessProfile?): Pair<AccessProfile, List<String>> {
    val problems = mutableListOf<String>()
    var pendingPasswords = emptyMap<String, String>()
    val rateLimit = if (params["rateEnabled"] != null) {
        RateLimitConfig(
            requestsPerSecond = params["rps"]?.trim()?.toIntOrNull() ?: run { problems += "Requests per second must be a number"; 1 },
            ipv6Prefix = params["ipv6Prefix"]?.trim()?.toIntOrNull() ?: run { problems += "The IPv6 prefix must be a number"; 64 },
        )
    } else null
    val banDuration = parseDuration("Ban duration", params["banDuration"], problems) ?: TrapPathsConfig().banDuration

    val basicAuth = if (params["basicEnabled"] != null) {
        val count = params["userCount"]?.toIntOrNull()?.coerceIn(0, 100) ?: 0
        val oldHashes = existing?.basicAuth?.users.orEmpty().associate { it.name to it.hash }
        val users = (0 until count).mapNotNull { k ->
            val name = params["u$k.name"].orEmpty().trim()
            if (name.isEmpty() || params["u$k.delete"] != null) return@mapNotNull null
            val password = params["u$k.password"].orEmpty()
            val previous = params["u$k.previous"].orEmpty()
            when {
                password.isNotEmpty() -> name to password
                oldHashes[previous] != null -> name to null
                else -> {
                    problems += "User $name needs a password"
                    name to null
                }
            }.let { (user, plain) -> Triple(user, plain, oldHashes[previous].orEmpty()) }
        }
        val exceptions = exceptionsFromText(params["exceptions"], problems)
        BasicAuthConfig(users.map { BasicAuthUser(it.first, if (it.second != null) "" else it.third) }, params["realm"].orEmpty().trim().ifEmpty { "Restricted" }, exceptions)
            .also { pendingPasswords = users.filter { it.second != null }.associate { it.first to it.second!! } }
    } else null

    val captcha = if (params["captchaEnabled"] != null) {
        val provider = CaptchaProvider.entries.firstOrNull { it.name == params["captchaProvider"] } ?: CaptchaProvider.POW
        CaptchaConfig(
            provider = provider,
            siteKey = params["siteKey"].orEmpty().trim(),
            // An empty field keeps the stored secret, like passwords
            secretKey = params["secretKey"].orEmpty().trim().ifEmpty { existing?.captcha?.secretKey.orEmpty() },
            recaptchaVersion = RecaptchaVersion.entries.firstOrNull { it.name == params["recaptchaVersion"] } ?: RecaptchaVersion.V2,
            recaptchaScore = params["recaptchaScore"]?.trim()?.replace(',', '.')?.toDoubleOrNull() ?: run { problems += "The score must be a number like 0.5"; 0.5 },
            sessionDuration = parseDuration("Captcha valid for", params["captchaDuration"], problems) ?: CaptchaConfig(provider).sessionDuration,
            protectedPaths = params["captchaPaths"].orEmpty().lines().map { it.trim() }.filter { it.isNotEmpty() },
            exceptions = exceptionsFromText(params["captchaExceptions"], problems),
            powDifficulty = params["powDifficulty"]?.trim()?.toIntOrNull() ?: run { problems += "The difficulty must be a number"; DEFAULT_POW_DIFFICULTY },
        )
    } else null
    val oidc = if (params["oidcEnabled"] != null) AppOidcConfig(lines(params["oidcSubjects"])) else null

    val profile = AccessProfile(
        name = params["name"].orEmpty().trim(),
        denyIps = lines(params["denyIps"]),
        denyCountries = params.getAll("denyCountries").orEmpty(),
        allowIps = lines(params["allowIps"]),
        allowCountries = params.getAll("allowCountries").orEmpty(),
        allowLocal = params["allowLocal"] != null,
        exploitFilter = ExploitFilterConfig(
            commonExploits = params["commonExploits"] != null,
            aiBots = params["aiBots"] != null,
            response = ExploitResponse.entries.firstOrNull { it.name == params["exploitResponse"] } ?: ExploitResponse.FORBIDDEN,
        ),
        trapPaths = TrapPathsConfig(params["trapsEnabled"] != null, params["trapPaths"].orEmpty().lines().map { it.trim() }.filter { it.isNotEmpty() }, banDuration),
        rateLimit = rateLimit,
        allowedMethods = METHODS.filter { params["method.$it"] != null }.let {
            if (it.isEmpty()) problems += "Tick at least one method"
            if (it.size == METHODS.size) emptyList() else it
        },
        basicAuth = basicAuth,
        captcha = captcha,
        oidc = oidc,
    )
    // bcrypt costs about a second per user, so only for a form that can be saved
    if (problems.isNotEmpty() || pendingPasswords.isEmpty()) return profile to problems
    val hashed = withContext(Dispatchers.Default) { pendingPasswords.mapValues { hashBcrypt(it.value) } }
    val basic = profile.basicAuth ?: return profile to problems
    return profile.copy(basicAuth = basic.copy(users = basic.users.map { u -> hashed[u.name]?.let { u.copy(hash = it) } ?: u })) to problems
}

/** Exceptions as text, one per line: `path /public` or `cidr 192.168.1.0/24`. */
private fun exceptionsFromText(text: String?, problems: MutableList<String>): List<BasicAuthException> =
    text.orEmpty().lines().map { it.trim() }.filter { it.isNotEmpty() }.mapNotNull { line ->
        val value = line.substringAfter(' ', "").trim()
        when (line.substringBefore(' ').lowercase()) {
            "path" -> BasicAuthException(pathPrefix = value)
            "cidr" -> BasicAuthException(cidr = value)
            else -> {
                problems += "Exception \"$line\" must start with path or cidr"
                null
            }
        }
    }

private fun exceptionsText(list: List<BasicAuthException>) = list.joinToString("\n") { e -> e.pathPrefix?.let { "path $it" } ?: "cidr ${e.cidr}" }

private suspend fun ApplicationCall.profileForm(kovexy: Kovexy, name: String?, profile: AccessProfile, problems: List<String>, posted: String?) {
    val version = posted ?: kovexy.configStore.current.version
    val title = if (name == null) "Add access profile" else "Access profile $name"
    val action = if (name == null) "/access/new" else "/access/${urlPart(name)}"
    val users = profile.basicAuth?.users.orEmpty()
    // Users whose password is not stored yet, after a refused save the password has to be typed again
    val newUsers = users.filter { it.hash.isEmpty() }.map { it.name }.toSet()
    page(title, session, Nav.ACCESS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader(title, "Checked in this order: block lists, allow lists, exploit filter and traps, rate limit, methods, captcha, OIDC login, Basic Auth.") {
            linkButton("/access", "All profiles", "ghost")
        }
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        card {
            form(action = action, method = FormMethod.post, classes = "form") {
                versionField(version)
                textField("Name", "name", profile.name, hint = "Sites and locations refer to the profile by this name. Renaming updates them.")
                fieldSet {
                    legend { +"Block list" }
                    p("muted small") { +"Matching visitors get 403. Countries only count when the country of the IP is known." }
                    textAreaField("IPs and ranges", "denyIps", profile.denyIps.joinToString("\n"), rows = 2, hint = "One per line, e.g. 203.0.113.7 or 198.51.100.0/24")
                    countrySelect("Countries", "denyCountries", profile.denyCountries)
                }
                fieldSet {
                    legend { +"Allow list" }
                    p("muted small") { +"If one of the lists is filled, only matching visitors get in. An IP whose country is unknown gets in when only countries are listed." }
                    textAreaField("IPs and ranges", "allowIps", profile.allowIps.joinToString("\n"), rows = 2)
                    countrySelect("Countries", "allowCountries", profile.allowCountries)
                    checkField("Always allow private and loopback addresses", "allowLocal", profile.allowLocal)
                }
                fieldSet {
                    legend { +"Exploit filter" }
                    checkField("Block common exploits", "commonExploits", profile.exploitFilter.commonExploits, "SQL and file injection, script tags, spam, known tools (patterns of Nginx Proxy Manager)")
                    checkField("Block AI crawlers", "aiBots", profile.exploitFilter.aiBots, "by user agent, list of ai.robots.txt")
                    selectField("Answer", "exploitResponse", profile.exploitFilter.response.name, listOf(
                        "FORBIDDEN" to "403 Forbidden", "NOT_FOUND" to "404 Not Found", "BAD_REQUEST" to "400 Bad Request", "DROP" to "Empty answer (204), then close"
                    ))
                }
                fieldSet {
                    legend { +"Trap paths" }
                    checkField("Ban whoever calls a trap path", "trapsEnabled", profile.trapPaths.enabled, "the ban counts for all sites")
                    textAreaField("Paths", "trapPaths", profile.trapPaths.paths.joinToString("\n"), rows = 5,
                        hint = "Path prefixes, one per line. A location with match exact for exactly that path still works. Default: ${DEFAULT_TRAP_PATHS.size} typical scanner targets.")
                    textField("Ban duration", "banDuration", profile.trapPaths.banDuration.toString())
                }
                fieldSet {
                    legend { +"Rate limit" }
                    checkField("Limit requests per IP", "rateEnabled", profile.rateLimit != null, "more get 429")
                    div("grid-2") {
                        textField("Requests per second", "rps", (profile.rateLimit?.requestsPerSecond ?: 20).toString(), type = InputType.number, required = false)
                        textField("IPv6 prefix", "ipv6Prefix", (profile.rateLimit?.ipv6Prefix ?: 64).toString(), type = InputType.number, required = false,
                            hint = "IPv6 addresses count per prefix, a household usually has a whole /64.")
                    }
                }
                fieldSet {
                    legend { +"Allowed methods" }
                    p("muted small") { +"All ticked means all methods are allowed. Others get 405." }
                    div("btn-row") {
                        METHODS.forEach { method -> checkField(method, "method.$method", profile.allowedMethods.isEmpty() || method in profile.allowedMethods) }
                    }
                }
                fieldSet {
                    legend { +"Basic Auth" }
                    checkField("Require a login", "basicEnabled", profile.basicAuth != null, "passwords are stored as bcrypt hash")
                    textField("Realm", "realm", profile.basicAuth?.realm ?: "Restricted", required = false)
                    hiddenInput(name = "userCount") { value = (users.size + EMPTY_USER_ROWS).toString() }
                    div("table-wrap") {
                        table("stack-mobile") {
                            thead { tr { th { +"User" }; th { +"Password" }; th { +"Remove" } } }
                            tbody {
                                (users.map { it.name } + List(EMPTY_USER_ROWS) { "" }).forEachIndexed { k, user ->
                                    tr {
                                        td {
                                            attributes["data-label"] = "User"
                                            hiddenInput(name = "u$k.previous") { value = user }
                                            input(InputType.text, name = "u$k.name") { value = user; attributes["aria-label"] = "User name"; attributes["autocomplete"] = "off" }
                                        }
                                        td {
                                            attributes["data-label"] = "Password"
                                            input(InputType.password, name = "u$k.password") {
                                                attributes["aria-label"] = "Password"
                                                attributes["autocomplete"] = "new-password"
                                                placeholder = if (user.isEmpty() || user in newUsers) "new password" else "unchanged"
                                            }
                                        }
                                        td { attributes["data-label"] = "Remove"; if (user.isNotEmpty()) checkBoxInput(name = "u$k.delete") { attributes["aria-label"] = "Remove user" } }
                                    }
                                }
                            }
                        }
                    }
                    p("muted small") { +"Any length works, $RECOMMENDED_PASSWORD_LENGTH characters or more are harder to guess." }
                    textAreaField("Exceptions", "exceptions", exceptionsText(profile.basicAuth?.exceptions.orEmpty()),
                        rows = 2, hint = "No login needed for: path /public or cidr 192.168.1.0/24, one per line.")
                }
                fieldSet {
                    legend { +"Captcha" }
                    val captcha = profile.captcha
                    checkField("Ask for a captcha", "captchaEnabled", captcha != null, "visitors see a check page with 403 until they pass it, only on sites that are reachable over HTTPS alone")
                    selectField("Kind", "captchaProvider", (captcha?.provider ?: CaptchaProvider.POW).name, listOf(
                        "POW" to "Own proof of work (no third party, the browser calculates a few seconds)",
                        "GOOGLE" to "Google reCAPTCHA (sends visitor data to Google)",
                    ))
                    textField("Valid for", "captchaDuration", (captcha?.sessionDuration ?: CaptchaConfig(CaptchaProvider.POW).sessionDuration).toString(), required = false,
                        hint = "Then the visitor is asked again. Solved captchas live in memory, a restart asks once more.")
                    textAreaField("Only these paths", "captchaPaths", captcha?.protectedPaths.orEmpty().joinToString("\n"), rows = 2,
                        hint = "Path prefixes, one per line. Empty protects the whole site.")
                    textAreaField("Exceptions", "captchaExceptions", exceptionsText(captcha?.exceptions.orEmpty()), rows = 2,
                        hint = "No captcha for: path /api or cidr 192.168.1.0/24, one per line.")
                    textField("Proof of work difficulty", "powDifficulty", (captcha?.powDifficulty ?: DEFAULT_POW_DIFFICULTY).toString(), type = InputType.number, required = false,
                        hint = "Leading zero bits, 8 to 30. Every step up doubles the work. $POW_DIFFICULTY_HINT")
                    div("grid-2") {
                        textField("reCAPTCHA site key", "siteKey", captcha?.siteKey.orEmpty(), required = false)
                        label("field") {
                            span { +"reCAPTCHA secret key" }
                            input(InputType.password, name = "secretKey") {
                                attributes["autocomplete"] = "off"
                                placeholder = if (captcha?.secretKey.isNullOrEmpty()) "secret key" else "unchanged"
                            }
                        }
                        selectField("reCAPTCHA version", "recaptchaVersion", (captcha?.recaptchaVersion ?: RecaptchaVersion.V2).name, listOf("V2" to "v2 (checkbox)", "V3" to "v3 (invisible, score)"))
                        textField("Minimum score (v3)", "recaptchaScore", (captcha?.recaptchaScore ?: 0.5).toString(), required = false, hint = "0 to 1, Google suggests 0.5.")
                    }
                }
                fieldSet {
                    legend { +"OIDC login" }
                    checkField("Require a login at the OIDC provider", "oidcEnabled", profile.oidc != null,
                        "needs the app login under Settings and HTTPS on the site, Kovexy passes the user to the app as X-Forwarded-User")
                    if (kovexy.config.appAuth == null) notice("warn", "The app login is not set up yet. Set it up under Settings first, otherwise this profile cannot be saved with OIDC login.")
                    textAreaField("Allowed users", "oidcSubjects", profile.oidc?.allowedSubjects.orEmpty().joinToString("\n"), rows = 2,
                        hint = "sub values of the provider, one per line. Empty lets in everybody the provider lets through.")
                    val domains = name?.let { n -> kovexy.config.sites.filter { s -> s.access == n || s.locations.any { it.access == n } }.flatMap { it.domains } }.orEmpty()
                    if (domains.isNotEmpty()) p("muted small") {
                        +"Register these callback URLs at the provider: ${domains.joinToString(", ") { kovexy.appAuth.callbackUrl(it) }}"
                    }
                }
                div("btn-row") { submit("Save profile") }
            }
        }
        if (name != null) card("Delete profile", "danger gap-top") {
            p("muted") { +"Only possible while no site and no location use it." }
            postButton("$action/delete", "Delete profile", "danger", confirm = "Delete this access profile?", hidden = mapOf("version" to version))
        }
    }
}

/** A multi select of every country. */
private fun FlowContent.countrySelect(label: String, name: String, selected: List<String>) = label("field") {
    span { +label }
    select(classes = "countries") {
        this.name = name
        multiple = true
        attributes["size"] = "6"
        attributes["aria-label"] = label
        COUNTRIES.forEach { (code, country) ->
            option {
                value = code
                this.selected = code in selected
                +"$country ($code)"
            }
        }
    }
    span("hint") { +"Hold Ctrl or Cmd to pick several." }
}
