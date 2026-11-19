package bayern.kickner.kovexy.web

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.OWNER_ONLY_FILE
import bayern.kickner.kovexy.setPermissions
import bayern.kickner.kovexy.auth.MIN_PASSWORD_LENGTH
import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.auth.verifyPassword
import bayern.kickner.kovexy.backup.MAX_BACKUP_BYTES
import bayern.kickner.kovexy.backup.backupFileName
import bayern.kickner.kovexy.backup.restoreBackup
import bayern.kickner.kovexy.backup.writeBackup
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.audit.AuditAction
import bayern.kickner.kovexy.config.LimitsConfig
import bayern.kickner.kovexy.config.LoginMode
import bayern.kickner.kovexy.config.OidcConfig
import bayern.kickner.kovexy.formatTimestamp
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveMultipart
import bayern.kickner.kovexy.receiveForm
import io.ktor.server.response.header
import io.ktor.server.response.respondOutputStream
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.utils.io.jvm.javaio.copyTo
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.html.FormMethod
import kotlinx.html.FormEncType
import kotlinx.html.InputType
import kotlinx.html.div
import kotlinx.html.fieldSet
import kotlinx.html.form
import kotlinx.html.input
import kotlinx.html.label
import kotlinx.html.legend
import kotlinx.html.p
import kotlinx.html.radioInput
import kotlinx.html.span
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr

private const val TAG = "Settings"

/** Settings, password, backup and restore, like Dirl's "Settings" and Zoraxy's "Utilities". */
fun Route.settingsRoutes(kovexy: Kovexy) {
    get("/settings") { call.settingsPage(kovexy, emptyList(), null) }

    post("/settings") {
        val params = call.receiveForm()
        val problems = mutableListOf<String>()
        val current = kovexy.config
        val idle = parseDuration("Session idle timeout", params["idleTimeout"], problems)
        val maxAge = parseDuration("Session maximum age", params["maxAge"], problems)
        val accessLog = parseDuration("Access log retention", params["retentionAccessLog"], problems)
        val hourly = parseDuration("Hourly statistics retention", params["retentionHourly"], problems)
        val wsDelay = parseDuration("WebSocket close delay", params["webSocketCloseDelay"], problems)
        val connect = parseDuration("Upstream connect timeout", params["upstreamConnectTimeout"], problems)
        val keepAlive = parseDuration("Upstream keep-alive", params["upstreamKeepAlive"], problems)
        val clientIdle = parseDuration("Client idle timeout", params["clientIdleTimeout"], problems)
        val headerBytes = params["maxRequestHeaderBytes"]?.trim()?.toIntOrNull() ?: run { problems += "Request header size must be a number"; 0 }
        val maxConnections = params["maxConnections"]?.trim()?.toIntOrNull() ?: run { problems += "Maximum connections must be a number"; 0 }
        val maxAccepts = params["maxAcceptsPerSecond"]?.trim()?.toIntOrNull() ?: run { problems += "New connections per second must be a number"; 0 }
        val maxPerAddress = params["maxConnectionsPerAddress"]?.trim()?.toIntOrNull() ?: run { problems += "Connections per address must be a number"; 0 }
        val audit = parseDuration("Audit log retention", params["retentionAudit"], problems)
        val securityEvents = parseDuration("Security event retention", params["retentionSecurity"], problems)
        val port = params["adminPort"]?.trim()?.toIntOrNull() ?: run { problems += "Admin port must be a number"; 0 }
        val next = if (problems.isNotEmpty()) null else { c: KovexyConfig ->
            c.copy(
                admin = c.admin.copy(
                    host = params["adminHost"].orEmpty().trim(),
                    port = port,
                    publicUrl = params["publicUrl"].orEmpty().trim(),
                    session = c.admin.session.copy(idleTimeout = idle!!, maxAge = maxAge!!),
                ),
                trustedProxies = params["trustedProxies"].orEmpty().split('\n', ',', ' ').map { it.trim() }.filter { it.isNotEmpty() },
                retention = c.retention.copy(accessLog = accessLog!!, hourlyStats = hourly!!, audit = audit!!, securityEvents = securityEvents!!),
                updateCheck = params["updateCheck"] != null,
                webSocketCloseDelay = wsDelay!!,
                limits = LimitsConfig(connect!!, keepAlive!!, clientIdle!!, headerBytes, maxConnections, maxAccepts, maxPerAddress),
            )
        }
        val saved = if (next == null) problems else call.saveConfig(params["version"], next)
        if (saved == null) {
            val moved = current.admin.host != kovexy.config.admin.host || current.admin.port != kovexy.config.admin.port
            if (moved) staticLog(KLogger.Level.INFO, TAG) { "Admin UI moved to ${kovexy.config.admin.host}:${kovexy.server.adminPort}" }
            return@post call.respondRedirect("/settings?done=settings-saved")
        }
        call.settingsPage(kovexy, saved, params["version"], params)
    }

    post("/settings/login") {
        val params = call.receiveForm()
        val mode = LoginMode.entries.firstOrNull { it.name == params["loginMode"] } ?: LoginMode.PASSWORD
        val issuer = params["issuer"].orEmpty().trim()
        val existing = kovexy.config.admin.oidc
        val oidc = if (issuer.isEmpty()) null else OidcConfig(
            issuer = issuer,
            clientId = params["clientId"].orEmpty().trim(),
            // An empty field keeps the stored secret, it is never shown
            clientSecret = params["clientSecret"].orEmpty().ifEmpty { existing?.clientSecret.orEmpty() },
            allowedSubjects = params["allowedSubjects"].orEmpty().split('\n', ',', ' ').map { it.trim() }.filter { it.isNotEmpty() },
            forceReauth = params["forceReauth"] != null,
            scopes = params["scopes"].orEmpty().split(' ', ',').map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { listOf("openid", "profile") },
        )
        val modeChanged = mode != kovexy.config.admin.loginMode
        val problems = call.saveConfig(params["version"]) { it.copy(admin = it.admin.copy(loginMode = mode, oidc = oidc)) }
        if (problems == null) {
            // Sessions from the old way of logging in end, the admin's own stays
            if (modeChanged) kovexy.sessions.removeAllExcept(call.attributes[SessionTokenKey])
            return@post call.respondRedirect("/settings?done=settings-saved")
        }
        call.settingsPage(kovexy, problems, params["version"], params)
    }

    post("/settings/password") {
        val params = call.receiveForm()
        val currentPassword = params["current"].orEmpty()
        val newPassword = params["new"].orEmpty()
        val problems = mutableListOf<String>()
        val hash = kovexy.config.admin.passwordHash
        val currentOk = withContext(Dispatchers.Default) { verifyPassword(currentPassword, hash) }
        if (currentOk.not()) problems += "The current password is wrong"
        if (newPassword.length < MIN_PASSWORD_LENGTH) problems += "The new password must have at least $MIN_PASSWORD_LENGTH characters"
        if (newPassword != params["repeat"]) problems += "The two new passwords differ"
        if (problems.isEmpty()) {
            val newHash = withContext(Dispatchers.Default) { hashPassword(newPassword) }
            call.saveConfig(null) { it.copy(admin = it.admin.copy(passwordHash = newHash)) }?.let { problems += it }
        }
        if (problems.isNotEmpty()) return@post call.settingsPage(kovexy, problems, null)
        kovexy.sessions.removeAllExcept(call.attributes[SessionTokenKey])
        kovexy.audit.record(call.actor, AuditAction.PASSWORD_CHANGED)
        staticLog(KLogger.Level.INFO, TAG) { "Admin password changed from ${call.adminClientIp}" }
        call.respondRedirect("/settings?done=password-changed")
    }

    post("/settings/backup") {
        val includeDatabase = call.receiveForm()["database"] != null
        kovexy.audit.record(call.actor, AuditAction.BACKUP_DOWNLOADED, detail = if (includeDatabase) "with database" else "without database")
        call.response.header(HttpHeaders.ContentDisposition, ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, backupFileName(kovexy.clock())).toString())
        call.respondOutputStream(ContentType.Application.Zip) {
            withContext(Dispatchers.IO) { kovexy.writeBackup(this@respondOutputStream, includeDatabase) }
        }
    }

    post("/settings/restore") {
        // Streamed to a private file, a backup with database can be larger than the heap
        val upload = File(kovexy.dataDir, ".upload-${System.nanoTime()}.zip")
        try {
            var tooLarge = false
            call.receiveMultipart(formFieldLimit = MAX_BACKUP_BYTES + 1).forEachPart { part ->
                if (part is PartData.FileItem && part.name == "backup") withContext(Dispatchers.IO) {
                    upload.outputStream().use { out -> part.provider().copyTo(out, MAX_BACKUP_BYTES + 1) }
                    setPermissions(upload.toPath(), OWNER_ONLY_FILE)
                    tooLarge = upload.length() > MAX_BACKUP_BYTES
                }
                part.release()
            }
            if (tooLarge) return@post call.settingsPage(kovexy, listOf("Not restored: the file is larger than ${MAX_BACKUP_BYTES / 1024 / 1024} MB"), null)
            if (upload.isFile.not() || upload.length() == 0L) return@post call.settingsPage(kovexy, listOf("Choose a backup file first"), null)
            val error = withContext(Dispatchers.IO) { kovexy.restoreBackup(upload) }
            if (error != null) return@post call.settingsPage(kovexy, listOf("Not restored: $error"), null)
        } finally {
            upload.delete()
        }
        kovexy.audit.record(call.actor, AuditAction.BACKUP_RESTORED)
        // A restored database ends every login, the own one too
        if (kovexy.sessions.get(call.attributes[SessionTokenKey], touch = false) == null) {
            call.response.cookies.append(sessionCookie("", 0))
            return@post call.respondRedirect("/login?done=restored-login")
        }
        call.respondRedirect("/settings?done=restored")
    }

    post("/settings/sessions/end-others") {
        kovexy.sessions.removeAllExcept(call.attributes[SessionTokenKey])
        kovexy.audit.record(call.actor, AuditAction.SESSIONS_ENDED)
        call.respondRedirect("/settings?done=sessions-ended")
    }
}

/**
 * The settings page. After a refused save [form] holds what was posted, so the admin keeps the input. The field names of
 * the forms are unique, a checkbox only takes the posted state when its own form was posted (its `marker` field is there).
 */
private suspend fun ApplicationCall.settingsPage(kovexy: Kovexy, problems: List<String>, posted: String?, form: Parameters? = null) {
    val version = posted ?: kovexy.configStore.current.version
    val config = kovexy.config
    fun v(name: String, stored: String) = form?.get(name) ?: stored
    fun c(name: String, marker: String, stored: Boolean) = if (form?.contains(marker) == true) form[name] != null else stored
    page("Settings", session, Nav.SETTINGS, status = if (problems.isEmpty()) HttpStatusCode.OK else HttpStatusCode.BadRequest) {
        pageHeader("Settings")
        if (problems.isNotEmpty()) problems("Not saved:", problems)
        div("columns") {
            card("Login") {
                val oidc = config.admin.oidc
                form(action = "/settings/login", method = FormMethod.post, classes = "form") {
                    versionField(version)
                    fieldSet {
                        legend { +"Login mode" }
                        listOf(
                            LoginMode.PASSWORD to "Password only",
                            LoginMode.OIDC to "OIDC only",
                            LoginMode.BOTH to "OIDC, then password (second barrier if the provider has a hole)",
                        ).forEach { (mode, text) ->
                            label("check") {
                                radioInput(name = "loginMode") {
                                    value = mode.name
                                    checked = mode.name == v("loginMode", config.admin.loginMode.name)
                                }
                                span { +text }
                            }
                        }
                        p("muted small") { +"OIDC needs the public URL below. In an emergency the command line switches back: java -jar kovexy.jar login-mode=password" }
                    }
                    fieldSet {
                        legend { +"OIDC provider" }
                        textField("Issuer", "issuer", v("issuer", oidc?.issuer.orEmpty()), required = false, placeholder = "https://id.example.com",
                            hint = "Exactly as the provider reports it. Callback URL to register: ${config.admin.publicUrl.ifEmpty { "<public URL>" }}/auth/callback")
                        div("grid-2") {
                            textField("Client ID", "clientId", v("clientId", oidc?.clientId.orEmpty()), required = false)
                            label("field") {
                                span { +"Client secret" }
                                input(InputType.password, name = "clientSecret") {
                                    attributes["autocomplete"] = "new-password"
                                    attributes["aria-label"] = "Client secret"
                                    placeholder = if (oidc?.clientSecret.isNullOrEmpty()) "" else "unchanged"
                                }
                            }
                        }
                        textAreaField("Allowed subjects", "allowedSubjects", v("allowedSubjects", oidc?.allowedSubjects.orEmpty().joinToString("\n")), rows = 2,
                            hint = "sub claims that may log in, one per line. Empty: everybody the provider lets through, then restrict the client to a group at the provider.")
                        textField("Scopes", "scopes", v("scopes", (oidc?.scopes ?: listOf("openid", "profile")).joinToString(" ")), required = false)
                        checkField("Ask for a fresh sign in every time", "forceReauth", c("forceReauth", "issuer", oidc?.forceReauth ?: true))
                    }
                    div("btn-row") { submit("Save login settings") }
                }
                form(action = "/settings/password", method = FormMethod.post, classes = "form gap-top") {
                    passwordField("Current password", "current", "current-password")
                    passwordField("New password", "new", "new-password", hint = "At least $MIN_PASSWORD_LENGTH characters.")
                    passwordField("Repeat new password", "repeat", "new-password")
                    div("btn-row") { submit("Change password") }
                }
            }
            card("Sessions") {
                val sessions = kovexy.sessions.list()
                div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Since" }; th { +"From" }; th { +"Browser" } } }
                        tbody {
                            sessions.forEach { s ->
                                tr {
                                    td("nowrap") { attributes["data-label"] = "Since"; +formatTimestamp(s.createdAt) }
                                    td { attributes["data-label"] = "From"; +s.ip; if (s.id == session.id) span("muted small") { +" (this one)" } }
                                    td { attributes["data-label"] = "Browser"; span("small break") { +s.userAgent } }
                                }
                            }
                        }
                    }
                }
                div("btn-row gap-top") { postButton("/settings/sessions/end-others", "End all other sessions", "danger", confirm = "End every other session?") }
            }
        }
        card("Admin UI, proxy and data", "gap-top") {
            form(action = "/settings", method = FormMethod.post, classes = "form") {
                versionField(version)
                fieldSet {
                    legend { +"Admin UI" }
                    div("grid-2") {
                        textField("Address", "adminHost", v("adminHost", config.admin.host), hint = "127.0.0.1 keeps it local. Changing it moves the UI at once. Browsers keep the login only on localhost or over HTTPS through the public URL.")
                        textField("Port", "adminPort", v("adminPort", config.admin.port.toString()), type = InputType.number)
                    }
                    textField("Public URL", "publicUrl", v("publicUrl", config.admin.publicUrl), required = false, placeholder = "https://proxy.example.com",
                        hint = "When the UI is reached through a site whose target is 127.0.0.1:${config.admin.port}. Empty for local use only.")
                    div("grid-2") {
                        textField("Session idle timeout", "idleTimeout", v("idleTimeout", config.admin.session.idleTimeout.toString()))
                        textField("Session maximum age", "maxAge", v("maxAge", config.admin.session.maxAge.toString()))
                    }
                }
                fieldSet {
                    legend { +"Proxy" }
                    textAreaField("Trusted proxies", "trustedProxies", v("trustedProxies", config.trustedProxies.joinToString("\n")), rows = 2,
                        hint = "IPs or ranges like 192.168.1.0/24 whose X-Forwarded-For is believed. Usually empty.")
                    div("grid-2") {
                        textField("Upstream connect timeout", "upstreamConnectTimeout", v("upstreamConnectTimeout", config.limits.upstreamConnectTimeout.toString()))
                        textField("Upstream keep-alive", "upstreamKeepAlive", v("upstreamKeepAlive", config.limits.upstreamKeepAlive.toString()))
                        textField("Client idle timeout", "clientIdleTimeout", v("clientIdleTimeout", config.limits.clientIdleTimeout.toString()))
                        textField("Request header size (bytes)", "maxRequestHeaderBytes", v("maxRequestHeaderBytes", config.limits.maxRequestHeaderBytes.toString()), type = InputType.number)
                        textField("Maximum connections", "maxConnections", v("maxConnections", config.limits.maxConnections.toString()), type = InputType.number,
                            hint = "All proxy connections together, 0 is unlimited. Keeps a flood from filling the memory.")
                        textField("Connections per address", "maxConnectionsPerAddress", v("maxConnectionsPerAddress", config.limits.maxConnectionsPerAddress.toString()), type = InputType.number,
                            hint = "Open proxy connections of one address, IPv6 per /64, 0 is unlimited. Loopback and trusted proxies are not limited.")
                        textField("New connections per second", "maxAcceptsPerSecond", v("maxAcceptsPerSecond", config.limits.maxAcceptsPerSecond.toString()), type = InputType.number,
                            hint = "0 is off. Shared by everybody, during an attack it locks normal visitors out too.")
                        textField("WebSocket close delay", "webSocketCloseDelay", v("webSocketCloseDelay", config.webSocketCloseDelay.toString()),
                            hint = "Open WebSockets are closed after a config change, after this delay.")
                    }
                }
                fieldSet {
                    legend { +"Data" }
                    div("grid-2") {
                        textField("Keep the access log", "retentionAccessLog", v("retentionAccessLog", config.retention.accessLog.toString()))
                        textField("Keep hourly statistics", "retentionHourly", v("retentionHourly", config.retention.hourlyStats.toString()))
                        textField("Keep the audit log", "retentionAudit", v("retentionAudit", config.retention.audit.toString()))
                        textField("Keep security events", "retentionSecurity", v("retentionSecurity", config.retention.securityEvents.toString()))
                    }
                    checkField("Check for updates", "updateCheck", c("updateCheck", "adminHost", config.updateCheck), "asks GitHub at most once an hour while the UI is used")
                }
                div("btn-row") { submit("Save settings") }
            }
        }
        div("columns gap-top") {
            card("Backup") {
                p("muted") { +"A ZIP with kovexy.json and the certificates. It holds the private keys, keep it safe. It is not encrypted." }
                form(action = "/settings/backup", method = FormMethod.post, classes = "form") {
                    checkField("Include the database (access log, statistics, sessions)", "database", false)
                    div("btn-row") { submit("Download backup", "") }
                }
            }
            card("Restore") {
                p("muted") { +"Replaces the configuration and certificates and applies them at once. The current state is saved in the backups directory first." }
                form(action = "/settings/restore", method = FormMethod.post, encType = FormEncType.multipartFormData, classes = "form") {
                    attributes["data-confirm"] = "Restore this backup? The current configuration is replaced."
                    label("field") {
                        span { +"Backup file" }
                        input(InputType.file, name = "backup") { accept = ".zip,application/zip"; required = true }
                    }
                    div("btn-row") { submit("Restore", "danger") }
                }
            }
        }
    }
}
