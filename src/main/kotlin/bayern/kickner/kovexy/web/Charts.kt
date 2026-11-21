package bayern.kickner.kovexy.web

import bayern.kickner.kovexy.i18n.t
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** Width and height of every chart in SVG units, it scales with the page. */
private const val WIDTH = 760
private const val HEIGHT = 220
private const val LEFT = 56
private const val RIGHT = 12
private const val TOP = 14
private const val BOTTOM = 28

/**
 * Colors inside the SVG. Charts are served as image files, so they carry their own light and dark style. Green,
 * yellow and red stand for the status classes, blue and violet for everything else.
 */
private const val CHART_STYLE = """
.bg{fill:#f8f9fb}.grid{stroke:#e2e5ea;stroke-width:1}.axis{fill:#5f6672;font:11px system-ui,sans-serif}
.s2{fill:#138a52}.s3{fill:#2f6fed}.s4{fill:#b35c00}.s5{fill:#c8322a}.blk{fill:#c2338a}.in{fill:#22a6c4}.out{fill:#7c6cf6}
.avg{stroke:#2f6fed;stroke-width:2;fill:none}.max{stroke:#7c6cf6;stroke-width:1.5;fill:none;stroke-dasharray:4 3}
.p50{stroke:#2f6fed;stroke-width:2;fill:none}.p95{stroke:#22a6c4;stroke-width:1.5;fill:none;stroke-dasharray:6 3}.p99{stroke:#7c6cf6;stroke-width:1.5;fill:none;stroke-dasharray:2 3}
.legend{font:12px system-ui,sans-serif;fill:#16181d}
@media (prefers-color-scheme: dark){.bg{fill:#1c2027}.grid{stroke:#272c35}.axis{fill:#9aa2b1}.legend{fill:#e7e9ee}
.s2{fill:#3ccf8e}.s3{fill:#5b8dff}.s4{fill:#f2a54a}.s5{fill:#ff6b61}.blk{fill:#ff7ab8}.avg{stroke:#5b8dff}.max{stroke:#a78bfa}.p50{stroke:#5b8dff}.p95{stroke:#4cc9e6}.p99{stroke:#a78bfa}}
"""

/**
 * One series of a chart.
 *
 * @property label Legend text.
 * @property cssClass Color class from the chart style.
 * @property values One value per bucket.
 */
class Series(val label: String, val cssClass: String, val values: List<Double>)

/** Escapes text for SVG. Chart labels are built from fixed words and numbers, this is defense in depth. */
private fun esc(text: String) = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

/** A number with k, M, G for the axis. */
fun compact(value: Double): String = when {
    value >= 1e9 -> String.format(Locale.ROOT, "%.1fG", value / 1e9)
    value >= 1e6 -> String.format(Locale.ROOT, "%.1fM", value / 1e6)
    value >= 1e3 -> String.format(Locale.ROOT, "%.1fk", value / 1e3)
    value == Math.floor(value) -> value.toLong().toString()
    else -> String.format(Locale.ROOT, "%.1f", value)
}

/**
 * Renders a chart as SVG document.
 *
 * @param buckets Start of every bucket, Unix milliseconds.
 * @param series Values per bucket.
 * @param stacked Bars stacked per bucket, otherwise lines.
 * @param hourly Labels with time of day instead of dates.
 * @param unit Suffix of the axis values, e.g. `ms`.
 */
fun chartSvg(buckets: List<Long>, series: List<Series>, stacked: Boolean, hourly: Boolean, unit: String = "", zone: ZoneId = ZoneId.systemDefault()): String {
    val plotW = WIDTH - LEFT - RIGHT
    val plotH = HEIGHT - TOP - BOTTOM
    val totals = buckets.indices.map { i -> if (stacked) series.sumOf { it.values[i] } else series.maxOfOrNull { it.values[i] } ?: 0.0 }
    val max = (totals.maxOrNull() ?: 0.0).let { if (it <= 0) 1.0 else it * 1.1 }
    val step = if (buckets.isEmpty()) 0.0 else plotW.toDouble() / buckets.size
    fun y(value: Double) = TOP + plotH - value / max * plotH

    val out = StringBuilder()
    out.append("""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $WIDTH ${HEIGHT + 22}" role="img">""")
    out.append("<style>").append(CHART_STYLE).append("</style>")
    out.append("""<rect class="bg" width="$WIDTH" height="${HEIGHT + 22}"/>""")
    for (k in 0..4) {
        val value = max / 4 * k
        val yy = y(value)
        out.append("""<line class="grid" x1="$LEFT" x2="${WIDTH - RIGHT}" y1="$yy" y2="$yy"/>""")
        out.append("""<text class="axis" x="${LEFT - 6}" y="${yy + 4}" text-anchor="end">${esc(compact(value) + unit)}</text>""")
    }
    if (stacked) {
        buckets.indices.forEach { i ->
            var base = 0.0
            series.forEach { s ->
                val v = s.values[i]
                if (v > 0) {
                    val top = y(base + v)
                    val height = y(base) - top
                    out.append("""<rect class="${s.cssClass}" x="${LEFT + i * step + step * 0.12}" y="$top" width="${step * 0.76}" height="$height"/>""")
                }
                base += v
            }
        }
    } else {
        series.forEach { s ->
            val points = buckets.indices.joinToString(" ") { i -> "${LEFT + i * step + step / 2},${y(s.values[i])}" }
            out.append("""<polyline class="${s.cssClass}" points="$points"/>""")
        }
    }
    val format = DateTimeFormatter.ofPattern(if (hourly.not()) "dd.MM" else if (buckets.size > 24) "dd.MM HH:mm" else "HH:mm", Locale.ENGLISH).withZone(zone)
    val labelEvery = maxOf(1, buckets.size / 8)
    buckets.forEachIndexed { i, bucket ->
        if (i % labelEvery == 0) {
            out.append("""<text class="axis" x="${LEFT + i * step + step / 2}" y="${HEIGHT - 8}" text-anchor="middle">${esc(format.format(Instant.ofEpochMilli(bucket)))}</text>""")
        }
    }
    var x = LEFT
    series.forEach { s ->
        val swatch = if (stacked) """<rect class="${s.cssClass}" x="$x" y="${HEIGHT + 6}" width="12" height="10"/>"""
        else """<line class="${s.cssClass}" x1="$x" x2="${x + 14}" y1="${HEIGHT + 11}" y2="${HEIGHT + 11}"/>"""
        out.append(swatch)
        out.append("""<text class="legend" x="${x + 18}" y="${HEIGHT + 16}">${esc(t(s.label))}</text>""")
        x += 30 + s.label.length * 7
    }
    out.append("</svg>")
    return out.toString()
}
