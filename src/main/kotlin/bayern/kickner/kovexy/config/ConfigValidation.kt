package bayern.kickner.kovexy.config

import bayern.kickner.kovexy.auth.isValidBcryptHash
import bayern.kickner.kovexy.auth.isValidPasswordHash
import java.net.URI
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private val headerName = """[!#$%&'*+.^_`|~0-9A-Za-z-]+""".toRegex()
private val emailAddress = """[^@\s]+@[^@\s]+\.[^@\s]+""".toRegex()

/** ISO 3166 alpha-2 codes the JDK knows. */
private val countryCodes: Set<String> = java.util.Locale.getISOCountries().toSet()

private val methodName = """[A-Z]{1,20}""".toRegex()

/**
 * Checks everything that parses fine but cannot work. All problems are reported at once, so a broken file needs
 * only one round of fixing.
 *
 * @return all problems found, empty if the config is usable. No message contains a secret.
 */
fun validateConfig(config: KovexyConfig): List<String> = buildList {
    validateAdmin(config.admin)
    validateAcme(config.acme)

    if (config.listeners != DEFAULT_LISTENERS) {
        add("listeners cannot be changed in this version, they are fixed to http on port 80 and https on port 443. Remove the field")
    }
    config.trustedProxies.forEachIndexed { i, range ->
        if (Cidr.parse(range) == null) add("trustedProxies[$i] \"$range\" is no IP address or CIDR range like 192.168.1.0/24")
    }

    val upstreamNames = config.upstreams.map { it.name }.toSet()
    config.upstreams.forEachIndexed { i, upstream -> validateUpstream("upstreams[$i]", upstream) }
    config.upstreams.groupBy { it.name }.filter { it.value.size > 1 }.keys.forEach { add("upstream name \"$it\" is used more than once") }

    validateDefaultSite(config.defaultSite, upstreamNames)

    val profileNames = config.accessProfiles.map { it.name }.toSet()
    config.accessProfiles.forEachIndexed { i, profile -> validateProfile("accessProfiles[$i]", profile) }
    config.accessProfiles.groupBy { it.name }.filter { it.value.size > 1 }.keys.forEach { add("access profile name \"$it\" is used more than once") }

    config.sites.forEachIndexed { i, site -> validateSite("sites[$i]", site, upstreamNames, profileNames) }
    (config.aiCrawlers.add.map { "aiCrawlers.add" to it } + config.aiCrawlers.ignore.map { "aiCrawlers.ignore" to it }).forEach { (field, entry) ->
        if (entry.isBlank()) add("$field must not contain empty entries")
        if (entry.length > MAX_AI_CRAWLER_ENTRY) add("$field entry \"${entry.take(40)}...\" is longer than $MAX_AI_CRAWLER_ENTRY characters")
    }
    if (config.aiCrawlers.add.size + config.aiCrawlers.ignore.size > 1000) add("aiCrawlers has more than 1000 entries")
    if (config.incus.enabled) {
        if (rootCheck().not()) add("incus.enabled needs Kovexy to run as root, the Incus socket gives root access to the host")
        if (config.incus.projects.isEmpty()) add("incus.projects must name at least one project")
        if (config.incus.socket.isBlank()) add("incus.socket must not be blank")
        if (config.incus.`interface`.isBlank()) add("incus.interface must not be blank")
    }
    val domainOwners = config.sites.flatMapIndexed { i, site -> site.domains.map { it to i } }
    domainOwners.groupBy({ it.first }, { it.second }).filter { it.value.size > 1 }.forEach { (domain, owners) ->
        add("domain \"$domain\" belongs to more than one site (sites ${owners.joinToString(", ")})")
    }

    config.webhooks.forEachIndexed { i, hook -> validateWebhook("webhooks[$i]", hook) }
    config.webhooks.groupBy { it.name }.filter { it.value.size > 1 }.keys.forEach { add("webhook name \"$it\" is used more than once") }

    validateLimits(config.limits)
    if (config.retention.accessLog < 1.days) add("retention.accessLog must be at least 1d")
    if (config.retention.hourlyStats < 1.days) add("retention.hourlyStats must be at least 1d")
    if (config.retention.audit < 1.days) add("retention.audit must be at least 1d")
    if (config.retention.securityEvents < 1.days) add("retention.securityEvents must be at least 1d")
    if (config.webSocketCloseDelay.isNegative()) add("webSocketCloseDelay must not be negative")
}

private fun MutableList<String>.validateAdmin(admin: AdminConfig) {
    if (admin.host.isBlank()) add("admin.host must not be blank")
    if (admin.port !in 1..65535) add("admin.port must be between 1 and 65535, is ${admin.port}")
    if (admin.port in DEFAULT_LISTENERS.map { it.port }) add("admin.port must not be a proxy port (80 or 443)")
    if (admin.publicUrl.isNotEmpty()) {
        checkAbsoluteUrl("admin.publicUrl", admin.publicUrl)?.let(::add)
        originProblems(admin.publicUrl).forEach(::add)
    }
    if (admin.loginMode != LoginMode.PASSWORD) {
        if (admin.oidc == null) add("admin.loginMode \"${admin.loginMode.name.lowercase()}\" needs admin.oidc")
        if (admin.publicUrl.isEmpty()) add("admin.loginMode \"${admin.loginMode.name.lowercase()}\" needs admin.publicUrl, the provider redirects back to <publicUrl>/auth/callback")
    }
    if (admin.loginMode == LoginMode.BOTH && admin.passwordHash.isEmpty()) add("admin.loginMode \"both\" needs a password, run reset-password")
    admin.oidc?.let { oidc ->
        checkAbsoluteUrl("admin.oidc.issuer", oidc.issuer)?.let(::add)
        if (oidc.clientId.isBlank()) add("admin.oidc.clientId must not be blank")
        if (oidc.clientSecret.isBlank()) add("admin.oidc.clientSecret must not be blank, register Kovexy as a confidential client")
        if ("openid" !in oidc.scopes) add("admin.oidc.scopes must contain \"openid\"")
    }
    if (admin.passwordHash.isNotEmpty() && isValidPasswordHash(admin.passwordHash).not()) {
        add("admin.passwordHash is no Argon2id hash, leave it empty to get a new password or run reset-password")
    }
    if (admin.session.idleTimeout < 1.minutes) add("admin.session.idleTimeout must be at least 1m")
    if (admin.session.maxAge < admin.session.idleTimeout) add("admin.session.maxAge must not be shorter than admin.session.idleTimeout")
}

/**
 * The origin check compares the browser's `Origin` header exactly with the origin of `publicUrl`. Browsers send the
 * host in lower case and leave out the default port, so any other spelling would reject every form.
 */
private fun originProblems(publicUrl: String): List<String> {
    val uri = runCatching { URI(publicUrl) }.getOrNull() ?: return emptyList()
    val host = uri.host ?: return emptyList()
    val defaultPort = when (uri.scheme) {
        "https" -> 443
        "http" -> 80
        else -> return emptyList()
    }
    return listOfNotNull(
        "admin.publicUrl must not contain the default port $defaultPort, browsers leave it out of the Origin header".takeIf { uri.port == defaultPort },
        "admin.publicUrl must use a lower case host name".takeIf { host != host.lowercase() },
        "admin.publicUrl must not contain user info".takeIf { uri.rawUserInfo != null },
        "admin.publicUrl must not contain a path, query or fragment".takeIf {
            uri.rawPath.orEmpty() !in setOf("", "/") || uri.rawQuery != null || uri.rawFragment != null
        },
        "admin.publicUrl must not end with a slash".takeIf { publicUrl.endsWith("/") },
    )
}

private fun MutableList<String>.validateAcme(acme: AcmeConfig) {
    checkAbsoluteUrl("acme.directory", acme.directory)?.let(::add)
    if (acme.email.isNotEmpty() && emailAddress.matches(acme.email).not()) add("acme.email is no valid mail address")
}

private fun MutableList<String>.validateUpstream(owner: String, upstream: UpstreamConfig) {
    if (upstream.name.isBlank()) add("$owner.name must not be blank")
    if (upstream.name.startsWith("incus:")) add("$owner.name must not start with incus:, Kovexy uses that for approved Incus containers")
    if (upstream.servers.isEmpty()) add("$owner (\"${upstream.name}\") needs at least one server")
    upstream.servers.forEachIndexed { j, server ->
        val where = "$owner.servers[$j]"
        if (HostPort.parse(server.address) == null) add("$where.address \"${server.address}\" must be host:port, IPv6 as [address]:port")
        if (server.weight < 0) add("$where.weight must not be negative")
        if (server.maxConnections < 0) add("$where.maxConnections must not be negative")
        if (server.skipCertVerify && server.tls.not()) add("$where.skipCertVerify only makes sense with tls")
    }
    upstream.servers.groupBy { it.address }.filter { it.value.size > 1 }.keys.forEach { add("$owner lists server $it more than once") }
    val check = upstream.healthCheck
    if (check.path.isNotEmpty() && check.path.startsWith("/").not()) add("$owner.healthCheck.path must start with /")
    if (check.interval < 1.seconds) add("$owner.healthCheck.interval must be at least 1s")
    if (check.timeout <= Duration.ZERO) add("$owner.healthCheck.timeout must be positive")
    if (check.expectStatus !in 100..599) add("$owner.healthCheck.expectStatus must be a HTTP status code")
}

private fun MutableList<String>.validateDefaultSite(site: DefaultSite, upstreams: Set<String>) {
    when (site) {
        is DefaultSite.Upstream -> if (site.upstream !in upstreams) add("defaultSite.upstream \"${site.upstream}\" does not exist")
        is DefaultSite.Redirect -> {
            checkAbsoluteUrl("defaultSite.url", site.url) { true }?.let(::add)
            if (site.status !in REDIRECT_STATUSES) add("defaultSite.status must be 301 or 307")
        }

        is DefaultSite.Static, DefaultSite.NotFound, DefaultSite.NoResponse -> Unit
    }
}

/** The redirect codes Kovexy offers, like Zoraxy. */
val REDIRECT_STATUSES = setOf(301, 307)

private fun MutableList<String>.validateSite(owner: String, site: SiteConfig, upstreams: Set<String>, profiles: Set<String>) {
    if (site.domains.isEmpty()) add("$owner needs at least one domain")
    site.domains.forEach { domain ->
        if (isValidHostName(domain).not()) add("$owner domain \"$domain\" must be a lower case domain name without wildcard, port or trailing dot")
    }
    site.domains.groupBy { it }.filter { it.value.size > 1 }.keys.forEach { add("$owner lists domain $it more than once") }
    site.access?.let { if (it !in profiles) add("$owner.access \"$it\" is no access profile") }

    site.locations.forEachIndexed { j, location -> validateLocation("$owner.locations[$j]", location, upstreams, profiles) }
    site.locations.groupBy { it.path to it.match }.filter { it.value.size > 1 }.keys.forEach { (path, match) ->
        add("$owner has more than one ${match.name.lowercase()} location for $path")
    }
}

private fun MutableList<String>.validateLocation(owner: String, location: LocationConfig, upstreams: Set<String>, profiles: Set<String>) {
    val path = location.path
    if (path.startsWith("/").not()) add("$owner.path must start with /")
    if (location.match == MatchType.PREFIX && path.length > 1 && path.endsWith("/")) {
        add("$owner.path of a prefix location must not end with a slash, \"${path.trimEnd('/')}\" already matches everything below it")
    }
    if (path.any { it.isWhitespace() || it == '?' || it == '#' }) add("$owner.path must not contain spaces, ? or #")
    location.access?.let { if (it !in profiles) add("$owner.access \"$it\" is no access profile") }
    if (location.stripPrefix && location.target !is Target.Upstream) add("$owner.stripPrefix only applies to upstream targets")

    when (val target = location.target) {
        is Target.Upstream -> if (target.upstream !in upstreams) add("$owner.target.upstream \"${target.upstream}\" does not exist")
        is Target.Static -> if (target.root.isBlank()) add("$owner.target.root must not be blank")
        is Target.Redirect -> {
            checkAbsoluteUrl("$owner.target.url", target.url) { true }?.let(::add)
            if (target.status !in REDIRECT_STATUSES) add("$owner.target.status must be 301 or 307")
        }

        is Target.Deny -> if (target.status !in 200..599) add("$owner.target.status must be between 200 and 599")
    }
    location.requestHeaders.forEachIndexed { k, rule -> validateHeaderRule("$owner.requestHeaders[$k]", rule) }
    location.responseHeaders.forEachIndexed { k, rule -> validateHeaderRule("$owner.responseHeaders[$k]", rule) }
}

private fun MutableList<String>.validateHeaderRule(owner: String, rule: HeaderRule) {
    if (headerName.matches(rule.name).not()) add("$owner.name \"${rule.name}\" is no valid header name")
    if (rule.action == HeaderAction.REMOVE && rule.value.isNotEmpty()) add("$owner.value must be empty for remove")
    if (rule.value.any { it == '\r' || it == '\n' || it == '\u0000' }) add("$owner.value must not contain line breaks")
}

private fun MutableList<String>.validateWebhook(owner: String, hook: WebhookConfig) {
    if (hook.name.isBlank()) add("$owner.name must not be blank")
    checkAbsoluteUrl("$owner.url", hook.url) { true }?.let(::add)
    if (hook.template.isBlank()) add("$owner.template must not be blank")
    if (hook.events.isEmpty()) add("$owner needs at least one event")
    hook.headers.forEach { (name, value) ->
        if (headerName.matches(name).not()) add("$owner header \"$name\" is no valid header name")
        if (value.any { it == '\r' || it == '\n' || it == '\u0000' }) add("$owner header $name must not contain line breaks")
    }
    if (hook.bundleWindow < 1.seconds) add("$owner.bundleWindow must be at least 1s")
}

private fun MutableList<String>.validateLimits(limits: LimitsConfig) {
    if (limits.upstreamConnectTimeout <= Duration.ZERO) add("limits.upstreamConnectTimeout must be positive")
    if (limits.upstreamKeepAlive <= Duration.ZERO) add("limits.upstreamKeepAlive must be positive")
    if (limits.clientIdleTimeout < 1.seconds) add("limits.clientIdleTimeout must be at least 1s")
    if (limits.maxRequestHeaderBytes !in 1024..1024 * 1024) add("limits.maxRequestHeaderBytes must be between 1024 and 1048576")
    if (limits.maxConnections < 0) add("limits.maxConnections must not be negative, 0 is unlimited")
    if (limits.maxAcceptsPerSecond < 0) add("limits.maxAcceptsPerSecond must not be negative, 0 is off")
    if (limits.maxConnectionsPerAddress < 0) add("limits.maxConnectionsPerAddress must not be negative, 0 is unlimited")
}

private fun MutableList<String>.validateProfile(owner: String, profile: AccessProfile) {
    if (profile.name.isBlank()) add("$owner.name must not be blank")
    val where = "$owner (\"${profile.name}\")"
    (profile.denyIps.map { "denyIps" to it } + profile.allowIps.map { "allowIps" to it }).forEach { (field, range) ->
        if (Cidr.parse(range) == null) add("$where.$field \"$range\" is no IP address or CIDR range")
    }
    (profile.denyCountries.map { "denyCountries" to it } + profile.allowCountries.map { "allowCountries" to it }).forEach { (field, code) ->
        if (code !in countryCodes) add("$where.$field \"$code\" is no ISO 3166 country code like DE")
    }
    profile.allowedMethods.forEach { if (methodName.matches(it).not()) add("$where.allowedMethods \"$it\" must be an upper case HTTP method like GET") }
    profile.rateLimit?.let {
        if (it.requestsPerSecond < 1) add("$where.rateLimit.requestsPerSecond must be at least 1")
        if (it.ipv6Prefix !in 16..128) add("$where.rateLimit.ipv6Prefix must be between 16 and 128")
    }
    val traps = profile.trapPaths
    traps.paths.forEach { if (it.startsWith("/").not()) add("$where.trapPaths.paths \"$it\" must start with /") }
    if (traps.banDuration < 1.minutes) add("$where.trapPaths.banDuration must be at least 1m")
    profile.captcha?.let { c ->
        if (c.siteKey.isBlank() || c.secretKey.isBlank()) add("$where.captcha needs siteKey and secretKey")
        if (c.recaptchaScore !in 0.0..1.0) add("$where.captcha.recaptchaScore must be between 0 and 1")
        if (c.sessionDuration < 1.minutes || c.sessionDuration > 30.days) add("$where.captcha.sessionDuration must be between 1m and 30d")
        c.protectedPaths.forEach { if (it.startsWith("/").not()) add("$where.captcha.protectedPaths \"$it\" must start with /") }
        c.exceptions.forEach { e ->
            if ((e.pathPrefix == null) == (e.cidr == null)) add("$where.captcha exception needs exactly one of pathPrefix and cidr")
            e.cidr?.let { if (Cidr.parse(it) == null) add("$where.captcha exception cidr \"$it\" is no IP address or CIDR range") }
            // An empty prefix would match every path and switch the captcha off (audit run-2)
            e.pathPrefix?.let { if (it.startsWith("/").not()) add("$where.captcha exception pathPrefix \"$it\" must start with /") }
        }
    }
    profile.basicAuth?.let { auth ->
        if (auth.users.isEmpty()) add("$where.basicAuth needs at least one user")
        auth.users.forEach { user ->
            if (user.name.isBlank() || ':' in user.name) add("$where.basicAuth user name \"${user.name}\" must not be blank or contain a colon")
            if (isValidBcryptHash(user.hash).not() && isValidPasswordHash(user.hash).not()) add("$where.basicAuth user \"${user.name}\" needs a bcrypt or Argon2id hash")
        }
        auth.users.groupBy { it.name }.filter { it.value.size > 1 }.keys.forEach { add("$where.basicAuth user \"$it\" is listed more than once") }
        if (auth.realm.isBlank() || auth.realm.any { it == '"' || it.isISOControl() }) add("$where.basicAuth.realm must not be blank or contain quotes")
        auth.exceptions.forEach { e ->
            if ((e.pathPrefix == null) == (e.cidr == null)) add("$where.basicAuth exception needs exactly one of pathPrefix and cidr")
            e.pathPrefix?.let { if (it.startsWith("/").not()) add("$where.basicAuth exception pathPrefix \"$it\" must start with /") }
            e.cidr?.let { if (Cidr.parse(it) == null) add("$where.basicAuth exception cidr \"$it\" is no IP address or CIDR range") }
        }
    }
}

/** The root check of the validation, only tests replace it. */
@Volatile
internal var rootCheck: () -> Boolean = { isRoot() }

/** Whether the process runs as uid 0. */
fun isRoot(): Boolean = runCatching { java.nio.file.Files.getAttribute(java.nio.file.Path.of("/proc/self"), "unix:uid") == 0 }.getOrDefault(false)
