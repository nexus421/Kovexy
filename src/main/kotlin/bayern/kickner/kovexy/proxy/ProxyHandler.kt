package bayern.kickner.kovexy.proxy

import bayern.kickner.kovexy.config.plainAddress
import bayern.kickner.kovexy.access.CAPTCHA_COOKIE
import bayern.kickner.kovexy.access.addressKey
import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.access.AccessChecker
import bayern.kickner.kovexy.access.Geo
import bayern.kickner.kovexy.access.AccessRequest
import bayern.kickner.kovexy.access.AccessResult
import bayern.kickner.kovexy.access.BanStore
import bayern.kickner.kovexy.access.BlockKind
import bayern.kickner.kovexy.access.REASON_HTTPS_REDIRECT
import bayern.kickner.kovexy.access.allowsIp
import bayern.kickner.kovexy.access.isDrop
import bayern.kickner.kovexy.access.isForeignInitiated
import bayern.kickner.kovexy.cleanText
import bayern.kickner.kovexy.config.MatchType
import bayern.kickner.kovexy.dyndns.DYNDNS_UPDATE_PATH
import bayern.kickner.kovexy.dyndns.DyndnsEndpoint
import bayern.kickner.kovexy.config.AccessProfile
import bayern.kickner.kovexy.config.parseIpLiteral
import bayern.kickner.kovexy.config.Fallback
import bayern.kickner.kovexy.config.HeaderAction
import bayern.kickner.kovexy.config.LISTENER_HTTP
import bayern.kickner.kovexy.config.RouteConfig
import bayern.kickner.kovexy.config.Target
import bayern.kickner.kovexy.config.domainOfHostHeader
import bayern.kickner.kovexy.config.isValidHostName
import bayern.kickner.kovexy.randomToken
import bayern.kickner.kovexy.notify.EventSink
import bayern.kickner.kovexy.site.badGatewayPage
import bayern.kickner.kovexy.site.neutralPage
import bayern.kickner.kovexy.site.notFoundPage
import bayern.kickner.kovexy.site.serveStatic
import bayern.kickner.kovexy.stats.AccessLog
import bayern.kickner.kovexy.stats.AccessRecord
import bayern.kickner.kovexy.stats.FALLBACK_KEY
import bayern.kickner.kovexy.tls.ACME_CHALLENGE_PREFIX
import bayern.kickner.kovexy.tls.ChallengeStore
import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.request.header
import io.ktor.client.request.prepareRequest
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.net.ConnectException
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.UnknownHostException
import java.nio.channels.UnresolvedAddressException
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "Proxy"

/** Buffer size for relaying bodies. */
private const val COPY_BUFFER = 64 * 1024

/** Status code logged when the visitor went away before an answer was sent, like nginx. */
const val STATUS_CLIENT_GONE = 499

/** Status codes whose responses never have a body. */
private val NO_BODY_STATUSES = setOf(204, 304)

/**
 * Everything collected while a request runs, written to the access log at the end.
 */
private class Trace(val start: Long, val clientIp: String, val method: String, val host: String, val path: String, val userAgent: String) {
    var status = 0
    val bytesIn = AtomicLong()
    val bytesOut = AtomicLong()
    var domain = FALLBACK_KEY
    var route = ""
    var backend = ""
    var reason = ""

    /** Why the request was blocked, `null` if it was not. */
    var block: BlockKind? = null
    var logged = true
}

/**
 * Handles every request on the proxy ports, in the order of the concept (section 3.3):
 *
 * 1. ACME challenges on port 80, answered at once.
 * 2. Banned addresses (trap paths), for all domains.
 * 3. Plain HTTP to HTTPS, for every host (HTTPS or nothing). Port 80 never reaches a domain.
 * 4. The domain by domain, otherwise the fallback.
 * 4b. Kovexy's reserved paths `/.kovexy/` (captcha), never forwarded.
 * 5. The most specific route.
 * 6. The access profile of the route or else of the domain. It also runs when no route matches, so a trap
 *    path fires on a domain that does not serve that path.
 * 7. Request headers, 8. the target, 9. response headers.
 * 10. Access log and statistics, asynchronous.
 *
 * @param routing The routing table of the current config version.
 * @param pool Backends.
 * @param clients HTTP clients for backends.
 * @param challenges Open ACME challenges.
 * @param accessLog Receives a record per request.
 * @param webSockets Open proxied WebSockets and streamed responses, for revocations.
 * @param events Receives backend down events.
 * @param dataDir Base of relative static roots.
 * @param httpsPort Port of the TLS listener, for redirects.
 * @param bans Active bans.
 * @param access Runs access profiles.
 * @param reserved Answers `/.kovexy/` and shows captcha pages.
 * @param dyndns Answers `/nic/update` on domains with `dyndns`.
 * @param geo Country of the visitor for the statistics.
 * @param clock Unix milliseconds.
 */
class ProxyHandler(
    private val routing: () -> RoutingTable,
    private val pool: BackendPool,
    private val clients: () -> BackendClients,
    private val challenges: ChallengeStore,
    private val accessLog: AccessLog,
    private val webSockets: WebSocketRegistry,
    private val events: EventSink,
    private val dataDir: File,
    private val httpsPort: () -> Int,
    private val bans: BanStore,
    private val access: AccessChecker,
    private val reserved: ReservedPaths,
    private val dyndns: DyndnsEndpoint,
    private val geo: Geo,
    private val adminPort: () -> Int = { -1 },
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /**
     * Handles [call], which arrived on [listener]. Never throws, a failure is logged and answered with 502 if
     * nothing was sent yet.
     */
    suspend fun handle(call: ApplicationCall, listener: String) {
        val table = routing()
        val rawUri = call.request.local.uri
        val rawPath = rawUri.substringBefore('?').ifEmpty { "/" }
        val peer = plainAddress(call.request.local.remoteAddress)
        val clientIp = visitorIp(peer, call.request.headers.getAll(X_FORWARDED_FOR).orEmpty(), table.trustedProxies)
        val domain = domainOfHostHeader(call.request.local.serverHost) ?: ""
        val trace = Trace(
            clock(), clientIp, call.request.httpMethod.value, domain, rawPath,
            cleanText(call.request.headers[HttpHeaders.UserAgent].orEmpty(), 512).orEmpty(),
        )
        try {
            dispatch(call, table, listener, rawUri, rawPath, peer, trace)
        } catch (e: CancellationException) {
            if (trace.status == 0) trace.status = STATUS_CLIENT_GONE
            trace.reason = trace.reason.ifEmpty { "client gone" }
        } catch (e: Throwable) {
            staticLog(KLogger.Level.ERROR, TAG) { "Request to $domain$rawPath failed: ${e.stackTraceToString()}" }
            // Only when nothing was sent yet, a status set before the failure does not mean an answer went out
            if (call.response.isCommitted.not()) {
                trace.status = 502
                trace.reason = "internal error"
                runCatching { call.respondText(badGatewayPage(), ContentType.Text.Html.withCharset(Charsets.UTF_8), HttpStatusCode.BadGateway) }
            }
        } finally {
            accessLog.record(
                AccessRecord(
                    time = trace.start, clientIp = trace.clientIp, method = trace.method, host = trace.host, path = trace.path,
                    status = trace.status, bytesIn = trace.bytesIn.get(), bytesOut = trace.bytesOut.get(),
                    durationMs = clock() - trace.start, domain = trace.domain, route = trace.route, backend = trace.backend,
                    userAgent = trace.userAgent, reason = trace.reason, block = trace.block?.name.orEmpty(), logged = trace.logged,
                    referer = refererWithoutQuery(call.request.headers[HttpHeaders.Referrer]),
                    country = parseIpLiteral(trace.clientIp)?.let { runCatching { geo.country(InetAddress.getByAddress(it)) }.getOrNull() }.orEmpty(),
                )
            )
        }
    }

    private suspend fun dispatch(
        call: ApplicationCall,
        table: RoutingTable,
        listener: String,
        rawUri: String,
        rawPath: String,
        peer: String,
        trace: Trace,
    ) {
        // 0. A path that cannot be decoded cannot be checked against any rule
        if (isValidPath(rawPath).not()) {
            trace.reason = "bad path"
            trace.block = BlockKind.MALFORMED
            respondText(call, trace, "Bad Request", ContentType.Text.Plain, HttpStatusCode.BadRequest)
            return
        }

        // 0b. The domain is picked by the request's authority, the backend gets the Host header. HTTP/2 without
        // :authority would let them differ, so a Host naming another domain than the routed one is refused
        val hostHeader = call.request.headers[HttpHeaders.Host]
        if (hostHeader != null && domainOfHostHeader(hostHeader) != trace.host.ifEmpty { null }) {
            trace.reason = "host mismatch"
            trace.block = BlockKind.MALFORMED
            respondText(call, trace, "Bad Request", ContentType.Text.Plain, HttpStatusCode.BadRequest)
            return
        }

        // 1. ACME challenges, before any other rule
        if (listener == LISTENER_HTTP && rawPath.startsWith(ACME_CHALLENGE_PREFIX)) {
            trace.reason = "acme"
            val answer = challenges.answer(rawPath.removePrefix(ACME_CHALLENGE_PREFIX))
            if (answer != null) respondText(call, trace, answer, ContentType.Text.Plain, HttpStatusCode.OK)
            else respondText(call, trace, "Not found", ContentType.Text.Plain, HttpStatusCode.NotFound)
            return
        }

        // 2. Banned addresses
        val address = parseIpLiteral(trace.clientIp)?.let { InetAddress.getByAddress(it) }
        // A ban is global, but an address that the profile of this very domain and route names in its allow list passes
        // (decided on 20.11.2026). Without a profile (unknown domain, fallback) every ban holds
        if (address != null) bans.banOf(address)?.takeIf { table.profileFor(trace.host, normalizePath(rawPath))?.allowsIp(address) != true }?.let {
            trace.reason = "banned"
            trace.block = BlockKind.BANNED
            respondText(call, trace, neutralPage(403, "Forbidden", "Access to this address is not allowed."), ContentType.Text.Html, HttpStatusCode.Forbidden)
            return
        }

        // 3. HTTPS or nothing: everything on the plain port but ACME gets a redirect, with 308 like Caddy so the method
        // and body stay. A domain or the fallback is only served over TLS (decided on 20.11.2026)
        if (listener == LISTENER_HTTP) {
            redirectToHttps(call, table, rawUri, trace)
            return
        }

        // 4. Domain
        val domain = table.domain(trace.host)
        if (domain == null) {
            fallback(call, table, rawUri, rawPath, peer, trace)
            return
        }
        trace.domain = domain.name
        trace.logged = domain.config.accessLog

        // 4b. Reserved paths, on the cleaned path so `/%2Ekovexy/` cannot slip past to a backend
        val https = call.request.local.scheme == "https"
        val path = normalizePath(rawPath)
        if (path.startsWith(RESERVED_PREFIX)) {
            // The rate limit of the profile that applies to this path counts here too (decided on 18.11.2026)
            val reservedProfile = (domain.routeFor(path)?.access ?: domain.config.access)?.let { table.profile(it) }
            if (reservedProfile != null && address != null &&
                access.rateLimitExceeded(reservedProfile, address, domain.name, "${call.request.httpMethod.value} $path")
            ) {
                trace.reason = "rate limit"
                trace.block = BlockKind.RATE_LIMIT
                respondText(call, trace, neutralPage(429, "Too Many Requests", "Too many requests, please try again in a moment."), ContentType.Text.Html, HttpStatusCode.TooManyRequests)
                return
            }
            val result = reserved.handle(call, table, trace.host, path, trace.clientIp, https)
            trace.status = result.status
            trace.reason = result.reason
            return
        }

        // 5. Route
        val route = domain.routeFor(path)

        // 6. Access profile, the one of the route replaces the one of the domain
        val profile = (route?.access ?: domain.config.access)?.let { table.profile(it) }
        var basicAuthUser: String? = null
        // Fail closed: a profile that cannot check the address does not let the request through unchecked
        if (profile != null && address == null) {
            trace.reason = "unknown address"
            trace.block = BlockKind.IP_RULES
            respondText(call, trace, neutralPage(403, "Forbidden", "Access to this address is not allowed."), ContentType.Text.Html, HttpStatusCode.Forbidden)
            return
        }
        if (profile != null && address != null) {
            val request = AccessRequest(
                address = address,
                domain = domain.name,
                path = path,
                rawQuery = rawUri.substringAfter('?', ""),
                method = call.request.httpMethod.value,
                userAgent = call.request.headers[HttpHeaders.UserAgent].orEmpty(),
                authorization = call.request.headers[HttpHeaders.Authorization],
                exactRoute = route?.match == MatchType.EXACT && route.path == path,
                host = trace.host,
                captchaCookie = call.request.cookies[CAPTCHA_COOKIE],
                isWebSocket = call.request.headers[HttpHeaders.Upgrade].equals("websocket", ignoreCase = true),
                foreignInitiated = isForeignInitiated(
                    trace.host, call.request.headers["Sec-Fetch-Site"], call.request.headers[HttpHeaders.Origin], call.request.headers[HttpHeaders.Referrer],
                    https = call.request.local.scheme == "https", accept = call.request.headers[HttpHeaders.Accept],
                ),
            )
            when (val result = access.check(profile, request)) {
                is AccessResult.Allow -> {
                    basicAuthUser = result.basicAuthUser
                    // A foreign page must not open a WebSocket that Kovexy's own captcha cookie lets in (cross-site
                    // WebSocket hijacking). Browsers always send Origin with a WebSocket, other clients carry no visitor's
                    // cookies (decided on 19.11.2026)
                    val origin = call.request.headers[HttpHeaders.Origin]
                    if (request.isWebSocket && profile.captcha != null && origin != null && originHost(origin) != trace.host) {
                        route?.let { trace.route = it.path }
                        trace.reason = "websocket from another origin"
                        trace.block = BlockKind.ORIGIN
                        respondText(call, trace, neutralPage(403, "Forbidden", "Access to this address is not allowed."), ContentType.Text.Html, HttpStatusCode.Forbidden)
                        return
                    }
                }

                is AccessResult.CaptchaRequired -> {
                    route?.let { trace.route = it.path }
                    trace.reason = "captcha"
                    trace.block = BlockKind.CAPTCHA
                    trace.status = 403
                    reserved.challenge(call, result.profile, result.config, trace.host, rawUri)
                    return
                }

                is AccessResult.Deny -> {
                    route?.let { trace.route = it.path }
                    trace.reason = result.reason
                    trace.block = result.kind
                    if (result.isDrop) {
                        call.response.headers.append(HttpHeaders.Connection, "close", safeOnly = false)
                        trace.status = 204
                        call.respond(HttpStatusCode.NoContent)
                    } else {
                        result.allow?.let { call.response.headers.append(HttpHeaders.Allow, it) }
                        val status = HttpStatusCode.fromValue(result.status)
                        respondText(call, trace, neutralPage(status.value, status.description, "Access to this address is not allowed."), ContentType.Text.Html, status)
                    }
                    return
                }

                is AccessResult.Challenge -> {
                    route?.let { trace.route = it.path }
                    trace.reason = result.reason
                    if (result.failed) trace.block = BlockKind.BASIC_AUTH
                    call.response.headers.append(HttpHeaders.WWWAuthenticate, "Basic realm=\"${result.realm}\", charset=\"UTF-8\"")
                    respondText(call, trace, neutralPage(401, "Unauthorized", "This address needs a login."), ContentType.Text.Html, HttpStatusCode.Unauthorized)
                    return
                }
            }
        }

        // A DynDNS domain answers the update path itself and nothing else (it has no routes)
        if (domain.config.dyndns) {
            if (path != DYNDNS_UPDATE_PATH) {
                trace.reason = "dyndns domain"
                respondText(call, trace, notFoundPage(), ContentType.Text.Html, HttpStatusCode.NotFound)
                return
            }
            val answer = dyndns.answer(call.request.httpMethod.value, call.request.headers[HttpHeaders.Authorization], rawUri.substringAfter('?', ""), trace.clientIp)
            trace.reason = answer.reason
            if (answer.authFailed) {
                trace.block = BlockKind.BASIC_AUTH
                call.response.headers.append(HttpHeaders.WWWAuthenticate, "Basic realm=\"dyndns\", charset=\"UTF-8\"")
            }
            respondText(call, trace, answer.body, ContentType.Text.Plain, HttpStatusCode.fromValue(answer.status))
            return
        }

        if (route == null) {
            trace.reason = "no route"
            respondText(call, trace, notFoundPage(), ContentType.Text.Html, HttpStatusCode.NotFound)
            return
        }
        trace.route = route.path

        // 7. to 9. Target with its headers
        when (val target = route.target) {
            is Target.Backend -> {
                val group = pool.group(target.backend)
                if (group == null) {
                    trace.reason = "unknown backend"
                    respondText(call, trace, badGatewayPage(), ContentType.Text.Html, HttpStatusCode.BadGateway)
                } else {
                    // The browser sends Kovexy's Basic Auth login also to excepted paths and to other routes of the
                    // domain, the backend must not see it there either
                    val ownCredential = isKovexyBasicCredential(
                        call.request.headers[HttpHeaders.Authorization], (listOf(domain.config.access) + domain.config.routes.map { it.access }).map { it?.let(table::profile) },
                    )
                    forward(call, table, group, route, rawUri, rawPath, path, peer, trace, basicAuthUser != null || ownCredential)
                }
            }

            is Target.Static -> {
                val result = call.serveStatic(resolveRoot(target.root), rawPath, pathBelow(route, path), target.directoryListing) { applyResponseRules(it, route) }
                trace.status = result.status
                trace.bytesOut.set(result.bytes)
            }

            is Target.Redirect -> {
                val rest = if (target.keepPath) encodePath(pathBelow(route, path)).let { if (it == "/") "" else it } else ""
                val query = rawUri.substringAfter('?', "").let { if (it.isEmpty() || target.keepPath.not()) "" else "?$it" }
                applyResponseRules(call, route)
                // The target URL stays as written unless a rest path is appended
                val base = if (rest.isEmpty()) target.url else target.url.trimEnd('/') + rest
                call.response.headers.append(HttpHeaders.Location, base + query)
                trace.status = target.status
                call.respond(HttpStatusCode.fromValue(target.status))
            }

            is Target.Deny -> {
                trace.reason = "denied"
                applyResponseRules(call, route)
                val html = target.html.ifEmpty { neutralPage(target.status, HttpStatusCode.fromValue(target.status).description, "Access to this address is not allowed.") }
                respondText(call, trace, html, ContentType.Text.Html, HttpStatusCode.fromValue(target.status))
            }
        }
    }

    /**
     * Answers a plain HTTP request with `308` to the same URL on HTTPS. Only a host that is a valid domain name or an
     * IP address is put into `Location`, anything else gets 400, so a crafted `Host` cannot make Kovexy redirect to
     * another site.
     */
    private suspend fun redirectToHttps(call: ApplicationCall, table: RoutingTable, rawUri: String, trace: Trace) {
        val domain = trace.host
        val usable = isValidHostName(domain) || parseIpLiteral(domain.removeSurrounding("[", "]")) != null
        if (usable.not()) {
            trace.reason = "bad host"
            trace.block = BlockKind.MALFORMED
            respondText(call, trace, "Bad Request", ContentType.Text.Plain, HttpStatusCode.BadRequest)
            return
        }
        table.domain(domain)?.let {
            trace.domain = it.name
            trace.logged = it.config.accessLog
        }
        val port = httpsPort().let { if (it == 443) "" else ":$it" }
        call.response.headers.append(HttpHeaders.Location, "https://$domain$port$rawUri")
        trace.status = 308
        trace.reason = REASON_HTTPS_REDIRECT
        call.respond(HttpStatusCode.PermanentRedirect)
    }

    /** The fallback for names no domain serves (Zoraxy). */
    private suspend fun fallback(
        call: ApplicationCall,
        table: RoutingTable,
        rawUri: String,
        rawPath: String,
        peer: String,
        trace: Trace,
    ) {
        val path = normalizePath(rawPath)
        trace.reason = "fallback"
        when (val fallback = table.config.fallback) {
            is Fallback.Static -> {
                val root = if (fallback.root.isBlank()) File(dataDir, "www") else resolveRoot(fallback.root)
                val result = call.serveStatic(root, rawPath, path, fallback.directoryListing) { }
                trace.status = result.status
                trace.bytesOut.set(result.bytes)
            }

            is Fallback.Backend -> {
                val group = pool.group(fallback.backend)
                val root = RouteConfig("/", target = Target.Backend(fallback.backend))
                if (group == null) respondText(call, trace, badGatewayPage(), ContentType.Text.Html, HttpStatusCode.BadGateway)
                else forward(call, table, group, root, rawUri, rawPath, path, peer, trace)
            }

            is Fallback.Redirect -> {
                val targetHost = runCatching { java.net.URI(fallback.url).host?.lowercase() }.getOrNull()
                if (targetHost == trace.host) {
                    // Zoraxy refuses a redirect to the requested domain itself, it would loop forever
                    trace.reason = "redirect loop"
                    respondText(call, trace, neutralPage(500, "Redirect loop", "The fallback redirects to this address itself."), ContentType.Text.Html, HttpStatusCode.InternalServerError)
                    return
                }
                val rest = if (fallback.keepPath && path != "/") encodePath(path) else ""
                val query = rawUri.substringAfter('?', "").let { if (it.isEmpty() || fallback.keepPath.not()) "" else "?$it" }
                call.response.headers.append(HttpHeaders.Location, (if (rest.isEmpty()) fallback.url else fallback.url.trimEnd('/') + rest) + query)
                trace.status = fallback.status
                call.respond(HttpStatusCode.fromValue(fallback.status))
            }

            Fallback.NotFound -> respondText(call, trace, notFoundPage(), ContentType.Text.Html, HttpStatusCode.NotFound)

            Fallback.NoResponse -> {
                // An empty answer and the connection closed after it, like Zoraxy when it cannot close at once
                trace.reason = "fallback, empty answer"
                call.response.headers.append(HttpHeaders.Connection, "close", safeOnly = false)
                trace.status = 204
                call.respond(HttpStatusCode.NoContent)
            }
        }
    }

    /**
     * Forwards to a server of [group], HTTP or WebSocket.
     *
     * @param dropAuthorization Removes the `Authorization` header, after Kovexy's own Basic Auth let the request in, so
     *   the password does not reach the backend.
     */
    private suspend fun forward(
        call: ApplicationCall,
        table: RoutingTable,
        group: BackendGroup,
        route: RouteConfig,
        rawUri: String,
        rawPath: String,
        normalizedPath: String,
        peer: String,
        trace: Trace,
        dropAuthorization: Boolean = false,
    ) {
        val stickyIn = if (group.config.stickySession) call.request.cookies[group.stickyCookie] else null
        val server = group.pick(stickyIn)
        if (server == null) {
            trace.reason = "no backend up"
            respondText(call, trace, badGatewayPage(), ContentType.Text.Html, HttpStatusCode.BadGateway)
            return
        }
        trace.backend = server.address.toString()
        val stickyOut = if (group.config.stickySession && stickyIn != server.stickyId) {
            val secure = if (call.request.local.scheme == "https") "; Secure" else ""
            "${group.stickyCookie}=${server.stickyId}; Path=/; Max-Age=$STICKY_COOKIE_MAX_AGE_SECONDS; HttpOnly; SameSite=Lax$secure"
        } else null

        val semaphore = server.semaphore()
        semaphore?.acquire()
        server.active.incrementAndGet()
        try {
            val isWebSocket = call.request.httpMethod == HttpMethod.Get &&
                call.request.headers[HttpHeaders.Upgrade].equals("websocket", ignoreCase = true)
            val headers = backendHeaders(call, table, server, route, peer, trace.clientIp)
            if (dropAuthorization) headers.remove(HttpHeaders.Authorization)
            val path = if (route.stripPrefix) stripPrefix(route, rawPath, normalizedPath) else rawPath
            val query = rawUri.substringAfter('?', "").let { if (it.isEmpty()) "" else "?$it" }
            val client = clients().forServer(server.config.skipCertVerify, server.address.host)
            val clientKey = parseIpLiteral(trace.clientIp)?.let { addressKey(InetAddress.getByAddress(it)) }
            val tag = WebSocketTag(trace.host, server.address.toString(), clientKey, viaDomain = trace.domain != FALLBACK_KEY)
            if (isWebSocket) {
                // Each WebSocket can make Kovexy hold one visitor frame, the number of them bounds the memory
                val webSocketKey = parseIpLiteral(trace.clientIp)?.let { addressKey(InetAddress.getByAddress(it), WEBSOCKET_IPV6_PREFIX) }
                if (webSockets.reserve(webSocketKey).not()) {
                    trace.reason = "too many websockets"
                    trace.block = BlockKind.RATE_LIMIT
                    respondText(call, trace, neutralPage(503, "Service Unavailable", "Too many open connections, please try again later."), ContentType.Text.Html, HttpStatusCode.ServiceUnavailable)
                    return
                }
                val scheme = if (server.config.tls) "wss" else "ws"
                val traffic = WebSocketTraffic()
                try {
                    call.proxyWebSocket(client, "$scheme://${server.address}$path$query", headers, headers["Host"] ?: server.address.toString(), webSockets, traffic, tag)
                    trace.status = 101
                } catch (e: CancellationException) {
                    throw e
                } catch (e: WebSocketRefusedException) {
                    trace.reason = "websocket refused by backend"
                    respondText(call, trace, neutralPage(e.status.value, e.status.description, "The service refused the connection."), ContentType.Text.Html, e.status)
                } catch (e: Throwable) {
                    if (trace.status == 0) backendFailed(call, server, e, trace)
                } finally {
                    webSockets.release(webSocketKey)
                    trace.bytesIn.set(traffic.toBackend.get())
                    trace.bytesOut.set(traffic.toVisitor.get())
                }
                return
            }
            forwardHttp(call, client, server, "${if (server.config.tls) "https" else "http"}://${server.address}$path$query", headers, route, stickyOut, trace, tag)
        } finally {
            server.active.decrementAndGet()
            semaphore?.release()
        }
    }

    /** The request headers for the backend: hop-by-hop removed, `X-Forwarded-*` set, route rules applied. */
    private fun backendHeaders(call: ApplicationCall, table: RoutingTable, server: BackendServer, route: RouteConfig, peer: String, clientIp: String): HeaderList {
        val headers = HeaderList(call.request.headers.entries().flatMap { (name, values) -> values.map { name to it } })
        headers.removeHopByHop()
        headers.remove(ADMIN_RELAY_HEADER)
        // The admin UI published through a domain learns the real visitor from Kovexy itself, never from a header a
        // visitor or a local process could set
        if (server.address.port == adminPort() && isLoopbackHost(server.address.host)) headers.set(ADMIN_RELAY_HEADER, "$ADMIN_RELAY_SECRET $clientIp")
        IDENTITY_HEADERS.forEach(headers::remove)
        // The captcha cookie is Kovexy's, a backend must never see a session it could replay
        headers.removeCookies(KOVEXY_COOKIES)
        val host = headers["Host"] ?: call.request.local.serverHost.let { h ->
            val port = call.request.local.serverPort
            val default = if (call.request.local.scheme == "https") 443 else 80
            if (port == default || port <= 0) h else "$h:$port"
        }
        headers.set("Host", host)
        headers.setForwarded(peer, call.request.local.scheme, host, isTrusted(peer, table.trustedProxies))
        // Like Caddy since 2.11: an HTTPS backend gets its own address as Host, it usually checks the name against
        // its certificate. X-Forwarded-Host still carries the original name.
        if (server.config.tls) headers.set("Host", server.address.toString())
        headers.apply(route.requestHeaders)
        return headers
    }

    private suspend fun forwardHttp(
        call: ApplicationCall,
        client: io.ktor.client.HttpClient,
        server: BackendServer,
        url: String,
        headers: HeaderList,
        route: RouteConfig,
        stickyOut: String?,
        trace: Trace,
        tag: WebSocketTag,
    ) {
        val method = call.request.httpMethod
        val length = headers["Content-Length"]?.toLongOrNull()
        // HTTP/2 has no Transfer-Encoding, a streamed body there comes without Content-Length
        val streamedHttp2 = length == null && call.request.local.version.startsWith("HTTP/2") && method != HttpMethod.Get && method != HttpMethod.Head
        val hasBody = (length != null && length > 0) || call.request.headers[HttpHeaders.TransferEncoding] != null || streamedHttp2
        val contentType = headers["Content-Type"]
        val bodyHeaders = contentType?.let { headersOf(HttpHeaders.ContentType, it) } ?: Headers.Empty
        val body: OutgoingContent = if (hasBody.not()) {
            object : OutgoingContent.NoContent() {
                override val contentLength: Long? = length
                override val headers: Headers = bodyHeaders
            }
        } else {
            val requestBody = counting(call, call.receiveChannel(), trace.bytesIn)
            object : OutgoingContent.ReadChannelContent() {
                override val contentLength: Long? = length
                override val headers: Headers = bodyHeaders
                override fun readFrom(): ByteReadChannel = requestBody
            }
        }

        val statement = client.prepareRequest {
            this.method = method
            url(url)
            headers.entries.forEach { (name, value) ->
                if (name.lowercase() !in BODY_HEADERS) header(name, value)
            }
            setBody(body)
        }
        val responded = runCatching {
            statement.execute { response ->
                val status = response.status.value
                val out = HeaderList(response.headers.entries().flatMap { (name, values) -> values.map { name to it } })
                out.removeHopByHop()
                out.apply(route.responseHeaders)
                stickyOut?.let { out.add(HttpHeaders.SetCookie, it) }
                val responseLength = out["Content-Length"]?.toLongOrNull()
                out.remove("Content-Length")
                val outHeaders = Headers.build { out.entries.forEach { (name, value) -> append(name, value) } }
                trace.status = status
                val noBody = method == HttpMethod.Head || status in NO_BODY_STATUSES || status in 100..199
                val content: OutgoingContent = if (noBody) {
                    object : OutgoingContent.NoContent() {
                        override val status: HttpStatusCode = response.status
                        override val headers: Headers = outHeaders
                        override val contentLength: Long? = if (method == HttpMethod.Head) responseLength else null
                    }
                } else {
                    val source = response.bodyAsChannel()
                    object : OutgoingContent.WriteChannelContent() {
                        override val status: HttpStatusCode = response.status
                        override val headers: Headers = outHeaders
                        override val contentLength: Long? = responseLength
                        // Registered, so a ban or a removed Incus domain also ends a long download or stream
                        override suspend fun writeTo(channel: ByteWriteChannel) = webSockets.stream(tag) { copy(source, channel, trace.bytesOut) }
                    }
                }
                call.respond(content)
            }
        }
        val error = responded.exceptionOrNull() ?: return
        if (error is CancellationException) throw error
        if (trace.status != 0) {
            // The response had started, the visitor sees a cut off body
            trace.reason = "backend aborted"
            staticLog(KLogger.Level.DEBUG, TAG) { "Backend ${server.address} aborted: ${error.reason()}" }
            return
        }
        backendFailed(call, server, error, trace)
    }

    /** Last warning about a refused certificate per server address. */
    private val certificateWarnings = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /** Answers 502 and marks the server down on a connection error (passive health check, Zoraxy). */
    private suspend fun backendFailed(call: ApplicationCall, server: BackendServer, error: Throwable, trace: Trace) {
        val connectError = error.isConnectError()
        if (connectError) server.markHealth(false, "connection failed: ${error.reason()}", clock(), events)
        val certificateError = generateSequence(error) { it.cause }.any { it is java.security.cert.CertificateException || it::class.simpleName == "TLSException" }
        trace.reason = when {
            connectError -> "backend unreachable"
            certificateError -> "backend certificate refused"
            else -> "backend error"
        }
        // A refused certificate is a setup problem the admin has to see, the log says why, at most every 10 minutes
        val now = clock()
        if (certificateError && now - (certificateWarnings[server.address.toString()] ?: 0) > 600_000) {
            certificateWarnings[server.address.toString()] = now
            staticLog(KLogger.Level.WARN, TAG) {
                "Certificate of backend ${server.address} refused: ${error.reason()}. An IP address must be in the certificate as IP entry, " +
                    "a name as DNS entry. Use the name the certificate has as address or set skipCertVerify."
            }
        } else {
            staticLog(KLogger.Level.DEBUG, TAG) { "Backend ${server.address} failed: ${error.reason()}" }
        }
        runCatching { respondText(call, trace, badGatewayPage(), ContentType.Text.Html, HttpStatusCode.BadGateway) }
    }

    /**
     * Response header rules for answers Kovexy creates itself (files, redirects, blocks). Set and add both add the
     * header, these answers carry no header of the same name yet. Remove has nothing to remove here.
     */
    private fun applyResponseRules(call: ApplicationCall, route: RouteConfig) {
        route.responseHeaders.filter { it.action != HeaderAction.REMOVE }.forEach { rule ->
            call.response.headers.append(rule.name, rule.value, safeOnly = false)
        }
    }

    private suspend fun respondText(call: ApplicationCall, trace: Trace, text: String, type: ContentType, status: HttpStatusCode) {
        trace.status = status.value
        val bytes = text.toByteArray()
        trace.bytesOut.set(if (call.request.httpMethod == HttpMethod.Head) 0 else bytes.size.toLong())
        call.respondText(text, type.withCharset(Charsets.UTF_8), status)
    }

    private fun resolveRoot(root: String): File = File(root).let { if (it.isAbsolute) it else File(dataDir, root) }
}

/** The host of an `Origin` header, lower case without brackets, `null` for `null` or garbage. */
internal fun originHost(origin: String): String? =
    runCatching { java.net.URI(origin).host?.lowercase()?.removePrefix("[")?.removeSuffix("]") }.getOrNull()

/**
 * Whether [header] carries Basic Auth credentials of a user of one of [profiles], Kovexy's own login that never goes
 * to a backend. Other `Authorization` headers (an app's own Basic Auth or tokens) pass.
 */
internal fun isKovexyBasicCredential(header: String?, profiles: List<AccessProfile?>): Boolean {
    if (header == null || header.startsWith("Basic ", ignoreCase = true).not()) return false
    val name = runCatching { java.util.Base64.getDecoder().decode(header.substring(6).trim()).decodeToString() }.getOrNull()
        ?.takeIf { ':' in it }?.substringBefore(':') ?: return false
    return profiles.any { profile -> profile?.basicAuth?.users?.any { it.name == name } == true }
}

/** Headers the HTTP client derives from the body, they travel with the body content. */
private val BODY_HEADERS = setOf("content-length", "content-type", "transfer-encoding")

/** Whether [this] means the backend could not be connected at all. */
private fun Throwable.isConnectError(): Boolean = generateSequence(this) { it.cause }.any {
    it is ConnectException || it is ConnectTimeoutException || it is UnresolvedAddressException ||
        it is UnknownHostException || it is NoRouteToHostException || it is java.net.SocketTimeoutException && it.message?.contains("connect", true) == true
}

/** Copies [source] into [target] and counts the bytes. */
private suspend fun copy(source: ByteReadChannel, target: ByteWriteChannel, counter: AtomicLong) {
    val buffer = ByteArray(COPY_BUFFER)
    while (true) {
        val read = source.readAvailable(buffer)
        if (read < 0) break
        if (read == 0) continue
        target.writeFully(buffer, 0, read)
        target.flush()
        counter.addAndGet(read.toLong())
    }
}

/** A channel that relays [source] and counts its bytes, running in [scope]. */
private fun counting(scope: CoroutineScope, source: ByteReadChannel, counter: AtomicLong): ByteReadChannel =
    scope.writer(Dispatchers.Unconfined) { copy(source, channel, counter) }.channel

/** The `Referer` without query and fragment, at most 512 characters, empty if none. Queries never reach the statistics. */
internal fun refererWithoutQuery(value: String?): String =
    cleanText(value.orEmpty().substringBefore('?').substringBefore('#'), 512).orEmpty()

/** Cookies Kovexy sets on proxied domains, removed before a request goes to a backend. */
private val KOVEXY_COOKIES = setOf(CAPTCHA_COOKIE)

/**
 * The error message without the request URL Ktor puts into some messages (`[url=...]`), it may carry a query string
 * that must not reach the log, a webhook or the UI.
 */
internal fun Throwable.reason(): String =
    (message ?: "").substringBefore("[url=").substringBefore('?').trim().ifEmpty { this::class.simpleName ?: "error" }

/** Header that carries the visitor's address from the proxy to the admin UI behind it, with [ADMIN_RELAY_SECRET]. */
const val ADMIN_RELAY_HEADER = "X-Kovexy-Client"

/** Random per process, so only Kovexy's own proxy can tell the admin UI a visitor address. */
val ADMIN_RELAY_SECRET: String = randomToken()

/** Whether [host] is a loopback address or `localhost`. */
internal fun isLoopbackHost(host: String): Boolean =
    host == "localhost" || parseIpLiteral(host)?.let { InetAddress.getByAddress(it).isLoopbackAddress } == true
