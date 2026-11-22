package bayern.kickner.kovexy

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.auth.LoginThrottle
import bayern.kickner.kovexy.i18n.I18n
import bayern.kickner.kovexy.auth.SessionStore
import bayern.kickner.kovexy.config.AdminConfig
import bayern.kickner.kovexy.config.ChangeSource
import bayern.kickner.kovexy.config.ConfigStore
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.LETS_ENCRYPT_STAGING
import bayern.kickner.kovexy.config.LISTENER_HTTP
import bayern.kickner.kovexy.config.LISTENER_HTTPS
import bayern.kickner.kovexy.config.LoginMode
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.notify.Webhooks
import bayern.kickner.kovexy.proxy.HealthChecker
import bayern.kickner.kovexy.proxy.Ports
import bayern.kickner.kovexy.proxy.ProxyHandler
import bayern.kickner.kovexy.proxy.ProxyServer
import bayern.kickner.kovexy.proxy.RoutingTable
import bayern.kickner.kovexy.proxy.BackendClientHolder
import bayern.kickner.kovexy.proxy.BackendPool
import bayern.kickner.kovexy.proxy.WebSocketRegistry
import bayern.kickner.kovexy.site.defaultIndexPage
import bayern.kickner.kovexy.stats.AccessLog
import bayern.kickner.kovexy.stats.DATABASE_FILE_NAME
import bayern.kickner.kovexy.stats.Storage
import bayern.kickner.kovexy.tls.Acme4jIssuer
import bayern.kickner.kovexy.tls.CertStore
import bayern.kickner.kovexy.tls.CertificateBundle
import bayern.kickner.kovexy.tls.CertificateIssuer
import bayern.kickner.kovexy.tls.CertificateManager
import bayern.kickner.kovexy.tls.ChallengeStore
import bayern.kickner.kovexy.tls.DynamicKeyManager
import bayern.kickner.kovexy.web.kovexyModule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.launch
import bayern.kickner.kovexy.access.AccessChecker
import bayern.kickner.kovexy.access.CaptchaService
import bayern.kickner.kovexy.access.GOOGLE_SITEVERIFY
import bayern.kickner.kovexy.access.GoogleVerifier
import bayern.kickner.kovexy.proxy.ReservedPaths
import bayern.kickner.kovexy.dyndns.DYNDNS_STATE_FILE
import bayern.kickner.kovexy.dyndns.DYNDNS_UPDATE_PATH
import bayern.kickner.kovexy.dyndns.DyndnsEndpoint
import bayern.kickner.kovexy.dyndns.DyndnsStore
import bayern.kickner.kovexy.dyndns.dyndnsClientNames
import bayern.kickner.kovexy.dyndns.withDyndnsAllowIps
import bayern.kickner.kovexy.incus.IncusDecisions
import bayern.kickner.kovexy.incus.IncusDiscovery
import bayern.kickner.kovexy.incus.withIncusRoutes
import bayern.kickner.kovexy.access.BanStore
import bayern.kickner.kovexy.access.BasicAuthChecker
import bayern.kickner.kovexy.access.Geo
import bayern.kickner.kovexy.access.RateLimiter
import bayern.kickner.kovexy.audit.Actor
import bayern.kickner.kovexy.audit.AuditAction
import bayern.kickner.kovexy.audit.AuditLog
import bayern.kickner.kovexy.audit.SecurityEventType
import bayern.kickner.kovexy.audit.SecurityEvents
import bayern.kickner.kovexy.audit.configDiff
import bayern.kickner.kovexy.auth.OidcClient
import bayern.kickner.kovexy.notify.EventSink
import java.io.File
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private const val TAG = "Kovexy"

/** Shown on every admin page and in the log while only the password protects the admin UI. */
const val PASSWORD_ONLY_WARNING = "The admin UI is protected by a password only. Set up OIDC under Settings."

/**
 * Everything Kovexy consists of, created once in [createKovexy] and handed to every part, like `web.Dirl` in Dirl.
 *
 * @property dataDir The data directory.
 * @property configStore `kovexy.json`.
 * @property storage SQLite database.
 * @property accessLog Access log and statistics writer.
 * @property sessions Admin sessions.
 * @property loginThrottle Lockout after failed logins.
 * @property certStore Certificates on disk.
 * @property keyManager Certificates in use.
 * @property certificates Issuing and renewing.
 * @property challenges Open ACME challenges.
 * @property backends Backends with their state.
 * @property clients HTTP clients for backends.
 * @property health Health checks.
 * @property webSockets Open proxied WebSockets.
 * @property webhooks Notifications.
 * @property updates Update check.
 * @property geo Country data.
 * @property bans Bans from trap paths.
 * @property security Security events.
 * @property audit Audit log.
 * @property access Runs access profiles.
 * @property captcha Solved captchas and the Google check.
 * @property incusDecisions Approvals and rejections of Incus containers.
 * @property dyndns Last addresses reported by the DynDNS clients.
 * @property scope Background work, cancelled on [stop].
 * @property clock Unix milliseconds.
 */
class Kovexy internal constructor(
    val dataDir: File,
    val configStore: ConfigStore,
    val storage: Storage,
    val accessLog: AccessLog,
    val sessions: SessionStore,
    val loginThrottle: LoginThrottle,
    val certStore: CertStore,
    val keyManager: DynamicKeyManager,
    val certificates: CertificateManager,
    val challenges: ChallengeStore,
    val backends: BackendPool,
    val clients: BackendClientHolder,
    val health: HealthChecker,
    val webSockets: WebSocketRegistry,
    val webhooks: Webhooks,
    val updates: UpdateCheck,
    val geo: Geo,
    val bans: BanStore,
    val security: SecurityEvents,
    val audit: AuditLog,
    val access: AccessChecker,
    val captcha: CaptchaService,
    val incusDecisions: IncusDecisions,
    val dyndns: DyndnsStore,
    val scope: CoroutineScope,
    val clock: () -> Long,
    ports: Ports,
    fallback: CertificateBundle,
) {
    /** Discovery of Incus containers, off unless `incus.enabled`. */
    val incus = IncusDiscovery({ configStore.current.config }, incusDecisions, webhooks, clock) {
        scope.launch {
            rebuildRouting()
            // A removed or changed route also ends the WebSockets it admitted
            val table = routing
            val servers = backends.all().flatMap { group -> group.servers.map { it.address.toString() } }.toSet()
            webSockets.closeWhere(scope, "after an Incus domain was removed") { tag ->
                // The fallback's traffic has no domain route of its own, only its backend can go away
                tag.backend !in servers || (tag.viaDomain && table.servesDomain(tag.domain).not())
            }
        }
    }

    /**
     * The routing table of the active config plus approved Incus containers and the addresses reported by DynDNS
     * clients, swapped in one step on every change.
     */
    @Volatile
    var routing: RoutingTable = RoutingTable(withDyndnsAllowIps(configStore.current.config, dyndns))
        private set

    /**
     * Builds the routing table from the active config and the live Incus claims. Backends and wanted
     * certificates follow, so a newly approved container gets its certificate at once.
     */
    @Synchronized
    fun rebuildRouting() {
        // A deleted client takes its addresses with it, also when it is added again under the same name
        dyndns.retain(config.dyndnsClientNames())
        val effective = withDyndnsAllowIps(withIncusRoutes(config, incus.claims), dyndns)
        backends.reconcile(effective.backends)
        // Clients of hosts that no backend uses any more (an edited address, an Incus container with a new IP) go away
        clients.current.retainHosts(backends.all().flatMap { group -> group.servers.map { it.address.host } }.toSet())
        routing = RoutingTable(effective)
        certificates.setWanted(routing.tlsDomains())
    }

    /** The active config. */
    val config: KovexyConfig get() = configStore.current.config

    /** Handles proxy requests. */
    val proxy = ProxyHandler(
        routing = { routing },
        pool = backends,
        clients = { clients.current },
        challenges = challenges,
        accessLog = accessLog,
        webSockets = webSockets,
        events = webhooks,
        dataDir = dataDir,
        httpsPort = { server.httpsPort },
        bans = bans,
        access = access,
        reserved = ReservedPaths(captcha, security),
        dyndns = DyndnsEndpoint({ config }, dyndns, ::rebuildRouting) { ip, domain ->
            security.record(SecurityEventType.BASIC_AUTH_FAILED, ip, domain, DYNDNS_UPDATE_PATH)
        },
        geo = geo,
        adminPort = { server.adminPort },
        clock = clock,
    )

    /** The OIDC client of the current config, `null` without `admin.oidc` or `admin.publicUrl`. */
    @Volatile
    var oidc: OidcClient? = createOidc(configStore.current.config)
        private set

    private fun createOidc(config: KovexyConfig): OidcClient? {
        val settings = config.admin.oidc ?: return null
        if (config.admin.publicUrl.isEmpty()) return null
        return OidcClient(settings, "${config.admin.publicUrl}/auth/callback", clock = clock)
    }

    /** The Jetty server. */
    val server: ProxyServer = ProxyServer(ports, keyManager, fallback, config.limits) { kovexyModule(this@Kovexy) }

    /** Unix milliseconds of the start. */
    val startedAt: Long = clock()

    init {
        backends.reconcile(config.backends)
        // Reports of clients that left the config while Kovexy was stopped
        dyndns.retain(config.dyndnsClientNames())
        configStore.onChange { old, new, source, actor -> apply(old, new, source, actor) }
        configStore.onInvalid { problems ->
            webhooks.emit(Event(WebhookEvent.CONFIG_INVALID, "Configuration file rejected", problems.joinToString("\n"), time = clock()))
        }
    }

    /**
     * Starts background work and opens the ports. Throws if a port cannot be bound.
     */
    fun start() {
        certificates.loadStored()
        certificates.setWanted(routing.tlsDomains())
        certificates.start(scope)
        health.start(scope)
        accessLog.start(scope)
        security.start(scope)
        geo.start(scope)
        incus.reconcile(scope)
        scope.launch {
            while (true) {
                runCatching {
                    val retention = config.retention
                    accessLog.applyRetention(retention.accessLog, retention.hourlyStats, clock())
                    audit.applyRetention(retention.audit, clock())
                    security.applyRetention(retention.securityEvents, clock())
                }.onFailure { staticLog(KLogger.Level.ERROR, TAG) { "Applying the retention failed: ${it.message}" } }
                delay(1.hours)
            }
        }
        scope.launch {
            while (true) {
                delay(1.minutes)
                runCatching { bans.purgeExpired() }
            }
        }
        server.start(config.admin, config.limits)
        server.updateTrustedProxies(routing.trustedProxies)
        configStore.startWatching()
        if (config.admin.loginMode == LoginMode.PASSWORD) staticLog(KLogger.Level.WARN, TAG) { PASSWORD_ONLY_WARNING }
    }

    /** Stops the server and background work. */
    fun stop() {
        configStore.stopWatching()
        incus.stop()
        runCatching { server.stop() }
        // The last second of access log and security events is still queued
        runBlocking { runCatching { accessLog.flush() }; runCatching { security.flush() } }
        scope.cancel()
        clients.close()
    }

    /**
     * Applies a new config while running: new routing table in one step, backends, admin connector, limits,
     * wanted certificates. Open WebSockets are closed after `webSocketCloseDelay`, like Caddy. Requests that already
     * run finish with the version they started with.
     */
    private fun apply(old: KovexyConfig?, new: KovexyConfig, source: ChangeSource, actor: Actor) {
        if (old != null) endSessionsAfterAuthChange(old.admin, new.admin, source)
        // Away from staging: its certificates are not trusted by browsers, replace them at once
        if (old != null && old.acme.effectiveDirectory == LETS_ENCRYPT_STAGING && new.acme.effectiveDirectory != LETS_ENCRYPT_STAGING) {
            routing.tlsDomains().forEach(certificates::renewNow)
        }
        I18n.language = new.language
        rebuildRouting()
        incus.reconcile(scope)
        clients.update(new.limits)
        server.updateLimits(new.limits)
        server.updateTrustedProxies(routing.trustedProxies)
        server.updateAdmin(new.admin)
        webSockets.closeAll(scope, new.webSocketCloseDelay)
        // A new client also means a new cookie key, login attempts in flight from the old settings end
        if (old?.admin?.oidc != new.admin.oidc || old?.admin?.publicUrl != new.admin.publicUrl || old?.admin?.loginMode != new.admin.loginMode) oidc = createOidc(new)
        val how = if (source == ChangeSource.FILE) "The file was changed on disk." else "Saved by ${actor.name}."
        staticLog(KLogger.Level.INFO, TAG) { "Configuration applied. $how" }
        if (old != null) {
            audit.record(actor, AuditAction.CONFIG_CHANGED, if (source == ChangeSource.FILE) "kovexy.json on disk" else "admin UI", configDiff(old, new))
            webhooks.emit(Event(WebhookEvent.CONFIG_CHANGED, "Configuration changed", how, time = clock()))
        }
    }

    /**
     * Ends admin sessions that the new login settings would not allow any more. A change in the admin UI ends the
     * other sessions in its route and keeps the admin's own, a change of the file (also `reset-password`) ends all.
     * Sessions of subjects that are no longer allowed end in any case.
     */
    private fun endSessionsAfterAuthChange(old: AdminConfig, new: AdminConfig, source: ChangeSource) {
        if (source == ChangeSource.FILE && (old.passwordHash != new.passwordHash || old.loginMode != new.loginMode)) {
            sessions.removeAll()
            return
        }
        val allowed = new.oidc?.allowedSubjects.orEmpty()
        if (new.loginMode != LoginMode.PASSWORD && allowed.isNotEmpty() && allowed != old.oidc?.allowedSubjects) sessions.removeSubjectsNotIn(allowed.toSet())
    }

    /** Whether the admin UI is protected by the password only. */
    val passwordOnly: Boolean get() = config.admin.loginMode == LoginMode.PASSWORD
}

/**
 * Creates every part. The config must be loaded already ([ConfigStore.load]). Nothing listens yet.
 *
 * @param ports Proxy ports, only tests and `devRun` change them.
 * @param issuer Orders certificates, the default uses ACME, tests pass a fake.
 * @param latestRelease Asks GitHub for the newest release, the default never asks, so tests do not reach GitHub.
 * @param googleSiteverify Google's reCAPTCHA verification endpoint, tests pass a fake.
 * @param clock Unix milliseconds for every part.
 */
fun createKovexy(
    configStore: ConfigStore,
    ports: Ports = Ports(),
    issuer: ((CertStore, ChallengeStore, () -> String) -> CertificateIssuer)? = null,
    latestRelease: () -> String? = { null },
    googleSiteverify: String = GOOGLE_SITEVERIFY,
    clock: () -> Long = System::currentTimeMillis,
): Kovexy {
    val dataDir = configStore.dataDir
    prepareDataDir(dataDir)
    I18n.language = configStore.current.config.language
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val config = { configStore.current.config }
    val storage = Storage(File(dataDir, DATABASE_FILE_NAME))
    val webhooks = Webhooks(scope, { config().webhooks }, clock)
    val audit = AuditLog(storage, clock)
    val security = SecurityEvents(storage, clock)
    // Issued certificates also go to the audit log
    val events = EventSink { event ->
        webhooks.emit(event)
        if (event.type == WebhookEvent.CERT_ISSUED) audit.record(Actor.SYSTEM, AuditAction.CERT_ISSUED, event.domain)
    }
    // Always loaded, the statistics show countries too (decided on 18.11.2026)
    val geo = Geo(File(dataDir, "geo"), clock = clock)
    val captcha = CaptchaService(GoogleVerifier(googleSiteverify), clock)
    val webSockets = WebSocketRegistry()
    // A banned address also loses the WebSockets it already has
    val bans = BanStore(storage, webhooks, security, clock) { key -> webSockets.closeWhere(scope, "after a ban") { it.clientKey == key } }
    val certStore = CertStore(File(dataDir, "certs"))
    val fallback = certStore.loadOrCreateFallback()
    val keyManager = DynamicKeyManager(fallback.key, fallback.chain)
    val challenges = ChallengeStore()
    val email = { config().acme.email }
    val certIssuer = issuer?.invoke(certStore, challenges, email) ?: Acme4jIssuer(certStore, challenges, email)
    val backends = BackendPool()
    val clients = BackendClientHolder(config().limits, scope)
    return Kovexy(
        dataDir = dataDir,
        configStore = configStore,
        storage = storage,
        accessLog = AccessLog(storage),
        sessions = SessionStore(storage, { config().admin.session.let { it.idleTimeout to it.maxAge } }, clock),
        loginThrottle = LoginThrottle(clock),
        certStore = certStore,
        keyManager = keyManager,
        certificates = CertificateManager(
            certStore, keyManager, certIssuer, events, { config().acme.effectiveDirectory },
            onRemoved = { domain -> audit.record(Actor.SYSTEM, AuditAction.CERT_REMOVED, domain) }, clock = clock,
        ),
        challenges = challenges,
        backends = backends,
        clients = clients,
        health = HealthChecker(backends, { clients.current }, webhooks, clock),
        webSockets = webSockets,
        webhooks = webhooks,
        updates = UpdateCheck({ config().updateCheck }, clock, fetchLatest = latestRelease),
        geo = geo,
        bans = bans,
        security = security,
        audit = audit,
        access = AccessChecker(geo, bans, security, RateLimiter(clock), BasicAuthChecker(clock), captcha) { config().aiCrawlers },
        captcha = captcha,
        incusDecisions = IncusDecisions(storage, clock),
        dyndns = DyndnsStore(File(dataDir, DYNDNS_STATE_FILE), clock),
        scope = scope,
        clock = clock,
        ports = ports,
        fallback = fallback,
    )
}

/** Creates the data directory layout: `www` with the neutral default page, `logs`, `backups`. */
private fun prepareDataDir(dataDir: File) {
    dataDir.mkdirs()
    val www = File(dataDir, "www")
    if (www.exists().not()) {
        www.mkdirs()
        setPermissions(www.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"))
        File(www, "index.html").writeText(defaultIndexPage())
        setPermissions(File(www, "index.html").toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"))
    }
}
