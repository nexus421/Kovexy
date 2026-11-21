package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.access.BlockKind
import bayern.kickner.kovexy.stats.AccessLogTable
import bayern.kickner.kovexy.stats.TopKind
import bayern.kickner.kovexy.stats.topLists
import bayern.kickner.kovexy.stats.FALLBACK_KEY
import bayern.kickner.kovexy.stats.statistics
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.sse.sse
import io.ktor.sse.ServerSentEvent
import kotlinx.coroutines.delay
import kotlinx.html.FlowContent
import kotlinx.html.a
import kotlinx.html.div
import kotlinx.html.p
import kotlinx.html.span
import kotlinx.html.stream.createHTML
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.jdbc.selectAll
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

/** Interval of the live updates of the status page. */
private val LIVE_INTERVAL = 5.seconds

/** Certificates that expire within this time are shown as warning. */
private val EXPIRY_WARNING = 14.days

/** The status page with live updates over SSE. */
fun Route.statusRoutes(kovexy: Kovexy) {
    get("/") {
        call.page("Status", call.session, Nav.STATUS, htmx = true) {
            pageHeader("Status", "Overview of domains, backends and certificates. Updates every ${LIVE_INTERVAL.inWholeSeconds} seconds.")
            div {
                attributes["hx-ext"] = "sse"
                attributes["sse-connect"] = "/status/events"
                attributes["sse-swap"] = "status"
                attributes["hx-swap"] = "innerHTML"
                statusContent(kovexy)
            }
        }
    }

    sse("/status/events") {
        val token = call.attributes[SessionTokenKey]
        // Logout, expiry or "end all other sessions" also end an open stream
        while (true) {
            delay(LIVE_INTERVAL)
            if (kovexy.sessions.get(token, touch = false) == null) break
            val html = createHTML(prettyPrint = false).div { statusContent(kovexy) }
            send(ServerSentEvent(data = html, event = "status"))
        }
    }
}

/** Everything the status page shows, rendered for the page and for every live update. */
private fun FlowContent.statusContent(kovexy: Kovexy) {
    val config = kovexy.config
    val now = kovexy.clock()
    val today = kovexy.accessLog.dayStart(now)
    val todayRows = kovexy.storage.statistics(hourly = false, from = today)
    val requestsToday = todayRows.sumOf { it.requests }
    val errorsToday = todayRows.sumOf { it.status5xx }
    val blockedToday = todayRows.sumOf { it.blocked }
    val redirectsToday = todayRows.sumOf { it.redirected }
    val servers = kovexy.backends.all().flatMap { it.servers }
    val certs = kovexy.certificates.status().filter { it.wanted }
    val certProblems = certs.count { it.lastError != null || it.notAfter == null || it.notAfter - now < EXPIRY_WARNING.inWholeMilliseconds }

    div("stats-grid") {
        stat("${config.domains.count { it.enabled }} / ${config.domains.size}", "Domains enabled", "/domains")
        stat("${servers.count { it.healthy }} / ${servers.size}", "Backend servers up", "/backends")
        stat("${certs.size - certProblems} / ${certs.size}", "Certificates fine", "/certificates")
        stat(requestsToday.toString(), "Requests today", "/statistics")
        stat(blockedToday.toString(), "Blocked today", "/access-log?status=blocked")
        stat(redirectsToday.toString(), "HTTPS redirects today", "/access-log?status=3")
        stat(errorsToday.toString(), "5xx answers today", "/access-log?status=5")
        stat(kovexy.webSockets.count.toString(), "Open WebSockets")
    }

    div("columns gap-top") {
        card("Backends") {
            val groups = kovexy.backends.all()
            if (groups.isEmpty()) p("muted") { +"No backends yet." }
            else div("table-wrap") {
                table("stack-mobile") {
                    thead { tr { th { +"Server" }; th { +"Backend" }; th { +"State" }; th(classes = "num") { +"Active" } } }
                    tbody {
                        groups.forEach { group ->
                            group.servers.forEach { server ->
                                tr {
                                    td { attributes["data-label"] = "Server"; +server.address.toString() }
                                    td { attributes["data-label"] = "Backend"; a(href = "/backends/${urlPart(group.config.name)}") { +group.config.name } }
                                    td {
                                        attributes["data-label"] = "State"
                                        if (server.healthy) pill("ok", "up") else pill("error", "down")
                                        server.lastError?.let { span("muted small") { +" $it" } }
                                    }
                                    td("num") { attributes["data-label"] = "Active"; +server.active.get().toString() }
                                }
                            }
                        }
                    }
                }
            }
        }
        card("Certificates") {
            if (certs.isEmpty()) p("muted") { +"No domain yet." }
            else div("table-wrap") {
                table("stack-mobile") {
                    thead { tr { th { +"Domain" }; th { +"State" }; th { +"Valid until" } } }
                    tbody {
                        certs.forEach { cert ->
                            tr {
                                td { attributes["data-label"] = "Domain"; +cert.domain }
                                td {
                                    attributes["data-label"] = "State"
                                    certificatePill(cert, now)
                                }
                                td("nowrap") { attributes["data-label"] = "Valid until"; +(cert.notAfter?.let(::formatTimestamp) ?: "-") }
                            }
                        }
                    }
                }
            }
        }
    }

    card("Blocked today", "gap-top") {
        val reasons = kovexy.storage.topLists(today, null, 20)[TopKind.BLOCK_KIND].orEmpty()
        if (reasons.isEmpty()) p("muted") { +"Nothing was blocked today." }
        else table("top-list") {
            tbody {
                reasons.forEach { (key, count) ->
                    tr {
                        td("top-key") { +blockLabel(key) }
                        td("num") { +count.toString() }
                    }
                }
            }
        }
    }

    card("Latest errors", "gap-top") {
        val latest = kovexy.storage.tx {
            AccessLogTable.selectAll().where { AccessLogTable.status greaterEq 500 }
                .orderBy(AccessLogTable.id, SortOrder.DESC).limit(8)
                .map { Triple(it[AccessLogTable.time], "${it[AccessLogTable.status]} ${it[AccessLogTable.method]} ${it[AccessLogTable.host]}${it[AccessLogTable.path]}", it[AccessLogTable.reason]) }
        }
        if (latest.isEmpty()) p("muted") { +"No 5xx answers in the access log." }
        else div("table-wrap") {
            table("stack-mobile") {
                thead { tr { th { +"Time" }; th { +"Request" }; th { +"Reason" } } }
                tbody {
                    latest.forEach { (time, request, reason) ->
                        tr {
                            td("nowrap") { attributes["data-label"] = "Time"; +formatTimestamp(time) }
                            td { attributes["data-label"] = "Request"; span("break") { +request } }
                            td { attributes["data-label"] = "Reason"; +reason }
                        }
                    }
                }
            }
        }
    }
    p("muted small") {
        +"Running since ${formatTimestamp(kovexy.startedAt)}."
        val dropped = kovexy.accessLog.dropped.get()
        if (dropped > 0) +" $dropped access log records were dropped because the database could not keep up."
    }
}

/** The state of a certificate as pill. */
fun FlowContent.certificatePill(cert: bayern.kickner.kovexy.tls.CertificateStatus, now: Long) {
    when {
        cert.gaveUp -> pill("error", "gave up")
        cert.lastError != null && cert.notAfter == null -> pill("error", "failing")
        cert.lastError != null -> pill("warn", "renewal failing")
        cert.notAfter == null -> pill("warn", "pending")
        cert.notAfter < now -> pill("error", "expired")
        cert.notAfter - now < EXPIRY_WARNING.inWholeMilliseconds -> pill("warn", "expires soon")
        else -> pill("ok", "valid")
    }
}

/** Display name of a stored [BlockKind] name, the name itself for one that does not exist any more. */
fun blockLabel(key: String): String = BlockKind.entries.firstOrNull { it.name == key }?.label ?: key

/** Display name of a statistics site key. */
fun domainLabel(key: String): String = if (key == FALLBACK_KEY) "Fallback" else key

/** Encodes a name for a URL path segment. */
fun urlPart(name: String): String = java.net.URLEncoder.encode(name, Charsets.UTF_8).replace("+", "%20")
