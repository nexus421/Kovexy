package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.stats.sumHistograms
import bayern.kickner.kovexy.stats.StatsRow
import bayern.kickner.kovexy.stats.TOP_LIST_SIZE
import bayern.kickner.kovexy.stats.TopKind
import bayern.kickner.kovexy.stats.histogramQuantile
import bayern.kickner.kovexy.stats.formatLatencyBound
import bayern.kickner.kovexy.stats.LATENCY_BOUNDS
import bayern.kickner.kovexy.stats.latencyHistograms
import bayern.kickner.kovexy.stats.statistics
import bayern.kickner.kovexy.stats.topLists
import io.ktor.http.ContentType
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.html.FormMethod
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.img
import kotlinx.html.p
import kotlinx.html.table
import kotlinx.html.tbody
import kotlinx.html.td
import kotlinx.html.th
import kotlinx.html.thead
import kotlinx.html.tr
import java.time.Instant
import java.time.ZoneId
import java.util.Locale

/** Time ranges of the statistics page. */
private enum class Range(val key: String, val label: String, val hourly: Boolean, val buckets: Int) {
    DAY("24h", "Last 24 hours", true, 24),
    WEEK("7d", "Last 7 days", true, 24 * 7),
    MONTH("30d", "Last 30 days", false, 30),
    YEAR("365d", "Last 365 days", false, 365),
}

/** Every site key with statistics plus the configured sites. */
private fun Kovexy.statsSites(): List<String> = (config.sites.map { it.domains.first() } +
    storage.tx { exec("SELECT DISTINCT site FROM stats_daily") { rs -> buildList { while (rs.next()) add(rs.getString(1)) } } }.orEmpty())
    .distinct().sortedWith(compareBy({ it.isEmpty() }, { it }))

/** Statistics per site and time range, charts as server-side SVG. */
fun Route.statisticsRoutes(kovexy: Kovexy) {
    get("/statistics") {
        val range = Range.entries.firstOrNull { it.key == call.request.queryParameters["range"] } ?: Range.DAY
        val sites = kovexy.statsSites()
        val site = call.request.queryParameters["site"]?.takeIf { it in sites }
        val (buckets, rows) = kovexy.loadRange(range, site)
        val query = "range=${range.key}" + (site?.let { "&site=${urlPart(it)}" } ?: "")
        call.page("Statistics", call.session, Nav.STATISTICS) {
            pageHeader("Statistics", "Requests, status codes, traffic and response times. Hourly values are kept ${kovexy.config.retention.hourlyStats}, daily values forever.")
            card {
                form(action = "/statistics", method = FormMethod.get, classes = "filters") {
                    selectField("Site", "site", site ?: "*", listOf("*" to "All sites") + sites.map { it to siteLabel(it) }, autosubmit = true)
                    selectField("Range", "range", range.key, Range.entries.map { it.key to it.label }, autosubmit = true)
                    submit("Show", "")
                }
            }
            val totals = rows.values.flatten()
            div("stats-grid gap-top") {
                stat(totals.sumOf { it.requests }.toString(), "Requests")
                stat(totals.sumOf { it.status4xx }.toString(), "4xx answers")
                stat(totals.sumOf { it.status5xx }.toString(), "5xx answers")
                stat(bytes(totals.sumOf { it.bytesOut }), "Sent")
                stat(bytes(totals.sumOf { it.bytesIn }), "Received")
                val requests = totals.sumOf { it.requests }
                stat(if (requests == 0L) "-" else "${totals.sumOf { it.durationSum } / requests} ms", "Mean response time")
                val histogram = sumHistograms(kovexy.storage.latencyHistograms(buckets.first(), site).values)
                stat(formatLatencyBound(histogramQuantile(histogram, 0.5)), "Median")
                stat(formatLatencyBound(histogramQuantile(histogram, 0.95)), "95th percentile")
                stat(formatLatencyBound(histogramQuantile(histogram, 0.99)), "99th percentile")
            }
            card("Requests by status", "gap-top") { chart("/statistics/chart.svg?metric=requests&$query", "Requests per ${if (range.hourly) "hour" else "day"} by status class") }
            card("Response time", "gap-top") { chart("/statistics/chart.svg?metric=duration&$query", "Mean and highest response time") }
            card("Response time percentiles", "gap-top") {
                chart("/statistics/chart.svg?metric=percentiles&$query", "Median, 95th and 99th percentile of the response time")
                p("muted small") { +"Values are the upper bound of a bucket: ≤ 150 ms means between 100 and 150 ms. Times above 60 s show as 60 s in the chart. Kept as long as the hourly values." }
            }
            card("Traffic", "gap-top") { chart("/statistics/chart.svg?metric=traffic&$query", "Bytes received and sent") }
            card("Per site", "gap-top") {
                val perSite = totals.groupBy { it.site }
                if (perSite.isEmpty()) p("muted") { +"No requests in this range." }
                else div("table-wrap") {
                    table("stack-mobile") {
                        thead { tr { th { +"Site" }; th(classes = "num") { +"Requests" }; th(classes = "num") { +"2xx" }; th(classes = "num") { +"3xx" }; th(classes = "num") { +"4xx" }; th(classes = "num") { +"5xx" }; th(classes = "num") { +"Sent" }; th(classes = "num") { +"Mean" }; th(classes = "num") { +"Max" } } }
                        tbody {
                            perSite.entries.sortedByDescending { e -> e.value.sumOf { it.requests } }.forEach { (key, list) ->
                                val requests = list.sumOf { it.requests }
                                tr {
                                    td { attributes["data-label"] = "Site"; +siteLabel(key) }
                                    td("num") { attributes["data-label"] = "Requests"; +requests.toString() }
                                    td("num") { attributes["data-label"] = "2xx"; +list.sumOf { it.status2xx }.toString() }
                                    td("num") { attributes["data-label"] = "3xx"; +list.sumOf { it.status3xx }.toString() }
                                    td("num") { attributes["data-label"] = "4xx"; +list.sumOf { it.status4xx }.toString() }
                                    td("num") { attributes["data-label"] = "5xx"; +list.sumOf { it.status5xx }.toString() }
                                    td("num") { attributes["data-label"] = "Sent"; +bytes(list.sumOf { it.bytesOut }) }
                                    td("num") { attributes["data-label"] = "Mean"; +"${if (requests == 0L) 0 else list.sumOf { it.durationSum } / requests} ms" }
                                    td("num") { attributes["data-label"] = "Max"; +"${list.maxOfOrNull { it.durationMax } ?: 0} ms" }
                                }
                            }
                        }
                    }
                }
            }
            val tops = kovexy.storage.topLists(kovexy.accessLog.dayStart(buckets.first()), site)
            card("Top lists", "gap-top") {
                p("muted small") {
                    +"Counted per day, whole days from ${formatTimestamp(kovexy.accessLog.dayStart(buckets.first()))} on. Each list keeps the $TOP_LIST_SIZE most frequent entries per site and day, rare entries may be missing."
                }
            }
            div("top-grid gap-top") {
                TopKind.entries.forEach { kind ->
                    card(kind.label) {
                        val entries = tops[kind].orEmpty()
                        if (entries.isEmpty()) p("muted") { +"None." }
                        else table("top-list") {
                            tbody {
                                entries.forEach { (key, count) ->
                                    tr {
                                        td("top-key") { +key }
                                        td("num") { +count.toString() }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            p("muted small gap-top") { +"As of ${formatTimestamp(kovexy.clock())}. New requests show up within a few seconds." }
        }
    }

    get("/statistics/chart.svg") {
        val params = call.request.queryParameters
        val range = Range.entries.firstOrNull { it.key == params["range"] } ?: Range.DAY
        val site = params["site"]?.takeIf { it in kovexy.statsSites() }
        val (buckets, rows) = kovexy.loadRange(range, site)
        fun sum(selector: (StatsRow) -> Long) = buckets.map { b -> rows[b].orEmpty().sumOf(selector).toDouble() }
        val svg = when (params["metric"]) {
            "duration" -> chartSvg(buckets, listOf(
                Series("mean", "avg", buckets.map { b -> rows[b].orEmpty().let { l -> val r = l.sumOf { it.requests }; if (r == 0L) 0.0 else l.sumOf { it.durationSum }.toDouble() / r } }),
                Series("highest", "max", buckets.map { b -> rows[b].orEmpty().maxOfOrNull { it.durationMax }?.toDouble() ?: 0.0 }),
            ), stacked = false, hourly = range.hourly, unit = "ms")
            "percentiles" -> {
                val histograms = kovexy.storage.latencyHistograms(buckets.first(), site)
                val perBucket = buckets.mapIndexed { i, start ->
                    val end = buckets.getOrNull(i + 1) ?: Long.MAX_VALUE
                    sumHistograms(histograms.filterKeys { it in start until end }.values)
                }
                // Above the last bound the chart shows the last bound, the line stays readable
                fun q(value: Double) = perBucket.map { (histogramQuantile(it, value) ?: 0L).coerceAtMost(LATENCY_BOUNDS.last()).toDouble() }
                chartSvg(buckets, listOf(Series("median", "p50", q(0.5)), Series("95th", "p95", q(0.95)), Series("99th", "p99", q(0.99))), stacked = false, hourly = range.hourly, unit = "ms")
            }
            "traffic" -> chartSvg(buckets, listOf(Series("received", "in", sum { it.bytesIn }), Series("sent", "out", sum { it.bytesOut })), stacked = true, hourly = range.hourly, unit = "B")
            else -> chartSvg(buckets, listOf(
                Series("2xx", "s2", sum { it.status2xx }), Series("3xx", "s3", sum { it.status3xx }),
                Series("4xx", "s4", sum { it.status4xx }), Series("5xx", "s5", sum { it.status5xx }),
            ), stacked = true, hourly = range.hourly)
        }
        call.respondText(svg, ContentType.Image.SVG)
    }
}

/** Buckets of [range] ending now and the rows per bucket. */
private fun Kovexy.loadRange(range: Range, site: String?): Pair<List<Long>, Map<Long, List<StatsRow>>> {
    val now = clock()
    val buckets = if (range.hourly) {
        val current = accessLog.hourStart(now)
        (range.buckets - 1 downTo 0).map { current - it * 3_600_000L }
    } else {
        val zone = ZoneId.systemDefault()
        val today = Instant.ofEpochMilli(now).atZone(zone).toLocalDate()
        (range.buckets - 1 downTo 0).map { today.minusDays(it.toLong()).atStartOfDay(zone).toInstant().toEpochMilli() }
    }
    val rows = storage.statistics(range.hourly, buckets.first(), site?.let { listOf(it) }).groupBy { it.bucket }
    return buckets to rows
}

private fun kotlinx.html.FlowContent.chart(src: String, alt: String) = img(alt = alt, src = src, classes = "chart")

/** Bytes as text with binary units. */
fun bytes(value: Long): String = when {
    value >= 1L shl 30 -> String.format(Locale.ROOT, "%.1f GiB", value / (1L shl 30).toDouble())
    value >= 1L shl 20 -> String.format(Locale.ROOT, "%.1f MiB", value / (1L shl 20).toDouble())
    value >= 1L shl 10 -> String.format(Locale.ROOT, "%.1f KiB", value / (1L shl 10).toDouble())
    else -> "$value B"
}
