package bayern.kickner.kovexy.stats

import bayern.kickner.klogger.KLogger
import bayern.kickner.kovexy.access.REASON_HTTPS_REDIRECT
import bayern.kickner.klogger.staticLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import org.jetbrains.exposed.v1.core.LikePattern
import org.jetbrains.exposed.v1.core.SortOrder
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.between
import org.jetbrains.exposed.v1.core.or
import org.jetbrains.exposed.v1.jdbc.andWhere
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.neq
import org.jetbrains.exposed.v1.core.greaterEq
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.less
import org.jetbrains.exposed.v1.core.like
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.batchUpsert
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.upsert
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration

private const val TAG = "AccessLog"

/** Requests that may wait for the writer. More are dropped and counted, the proxy never waits for SQLite. */
private const val QUEUE_CAPACITY = 20_000

/** Most records written in one transaction. */
private const val BATCH_SIZE = 1000

/** Longest wait before a partial batch is written. */
private const val FLUSH_MILLIS = 1000L

/** Domain name in log and statistics for requests no domain served. */
const val FALLBACK_KEY = ""

/**
 * One handled request.
 *
 * @property time Unix milliseconds of the start.
 * @property clientIp Address of the visitor.
 * @property method HTTP method.
 * @property domain Requested domain.
 * @property path Path without query, the query often holds tokens and is never stored.
 * @property status Status code sent, `444` when the connection was closed without an answer (like Zoraxy).
 * @property bytesIn Bytes of the request body.
 * @property bytesOut Bytes of the response body.
 * @property durationMs Time until the response was complete.
 * @property domain First domain of the domain, [FALLBACK_KEY] for the fallback.
 * @property route Path of the route, empty if none.
 * @property backend Address of the backend server, empty if none.
 * @property userAgent The visitor's `User-Agent`.
 * @property reason Why the request was refused or failed, empty otherwise.
 * @property block [bayern.kickner.kovexy.access.BlockKind] name if Kovexy blocked the request, empty otherwise.
 * @property logged Whether the domain writes an access log. Statistics count every request.
 * @property referer The `Referer` without query, empty if none.
 * @property country ISO code of the visitor's country, empty if unknown.
 */
data class AccessRecord(
    val time: Long,
    val clientIp: String,
    val method: String,
    val host: String,
    val path: String,
    val status: Int,
    val bytesIn: Long,
    val bytesOut: Long,
    val durationMs: Long,
    val domain: String,
    val route: String,
    val backend: String,
    val userAgent: String,
    val reason: String,
    val block: String = "",
    val logged: Boolean = true,
    val referer: String = "",
    val country: String = "",
)

/** Kinds of the daily top lists. */
enum class TopKind(val label: String) {
    IP("IPs"), COUNTRY("Countries"), PATH("Paths"), USER_AGENT("User agents"), REFERER("Referers"), METHOD("Methods"),
    BACKEND("Backend servers"), BLOCK_KIND("Blocked by"), BLOCK_REASON("Refusals by reason"),
}

/** Entries kept per top list, domain and day (Zoraxy limits its lists too). */
const val TOP_LIST_SIZE = 100

/** Upper bounds of the response time buckets in milliseconds, the last bucket takes everything above. */
val LATENCY_BOUNDS: LongArray = longArrayOf(1, 2, 3, 5, 7, 10, 15, 20, 30, 50, 70, 100, 150, 200, 300, 500, 700, 1000, 1500, 2000, 3000, 5000, 7000, 10000, 20000, 30000, 60000)

/** Index of the bucket of [millis]. */
fun latencyBucket(millis: Long): Int = LATENCY_BOUNDS.indexOfFirst { millis <= it }.let { if (it < 0) LATENCY_BOUNDS.size else it }

/** Reported by [histogramQuantile] when the quantile lies above the last bound. */
const val LATENCY_ABOVE_LAST = Long.MAX_VALUE

/**
 * The [quantile] (0 to 1) of a histogram, as the upper bound of the bucket it falls in, [LATENCY_ABOVE_LAST] above
 * the last bound, `null` without any value.
 */
fun histogramQuantile(counts: LongArray, quantile: Double): Long? {
    val total = counts.sum()
    if (total == 0L) return null
    val target = kotlin.math.ceil(total * quantile).toLong().coerceAtLeast(1)
    var seen = 0L
    counts.forEachIndexed { i, c ->
        seen += c
        if (seen >= target) return LATENCY_BOUNDS.getOrElse(i) { LATENCY_ABOVE_LAST }
    }
    return LATENCY_ABOVE_LAST
}

/** A bucket bound for people: `≤ 150 ms`, from one second on in seconds (`≤ 1.5 s`), `> 60 s` above the last bound. */
fun formatLatencyBound(bound: Long?): String = when {
    bound == null -> "-"
    bound == LATENCY_ABOVE_LAST -> "> ${LATENCY_BOUNDS.last() / 1000} s"
    bound < 1000 -> "≤ $bound ms"
    else -> "≤ " + (bound / 1000.0).toString().removeSuffix(".0") + " s"
}

/** The keys a record adds to the top lists. Refusal reasons only count for answers of 400 and above. */
private fun topKeys(r: AccessRecord): List<Pair<TopKind, String>> = listOfNotNull(
    TopKind.IP to r.clientIp,
    TopKind.COUNTRY to r.country.ifEmpty { "unknown" },
    TopKind.PATH to r.path,
    TopKind.USER_AGENT to r.userAgent.ifEmpty { "none" },
    r.referer.takeIf { it.isNotEmpty() }?.let { TopKind.REFERER to it },
    TopKind.METHOD to r.method,
    r.backend.takeIf { it.isNotEmpty() }?.let { TopKind.BACKEND to it },
    r.block.takeIf { it.isNotEmpty() }?.let { TopKind.BLOCK_KIND to it },
    r.reason.takeIf { it.isNotEmpty() && r.status >= 400 }?.let { TopKind.BLOCK_REASON to it },
).map { it.first to it.second.take(512) }

/** Values of one statistics row. */
private class Counter(
    var requests: Long = 0, var s2: Long = 0, var s3: Long = 0, var s4: Long = 0, var s5: Long = 0,
    var bytesIn: Long = 0, var bytesOut: Long = 0, var durationSum: Long = 0, var durationMax: Long = 0,
    var blocked: Long = 0, var redirected: Long = 0,
) {
    fun add(record: AccessRecord) {
        requests++
        if (record.block.isNotEmpty()) blocked++
        if (record.reason == REASON_HTTPS_REDIRECT) redirected++
        when (record.status / 100) {
            2 -> s2++
            3 -> s3++
            4 -> s4++
            5 -> s5++
        }
        bytesIn += record.bytesIn
        bytesOut += record.bytesOut
        durationSum += record.durationMs
        durationMax = maxOf(durationMax, record.durationMs)
    }
}

/**
 * Writes the access log and the statistics in batches on a background coroutine. [record] never blocks: when the
 * queue is full, records are dropped and counted in [dropped].
 *
 * @param storage The database.
 * @param zone Time zone of the daily statistics.
 */
class AccessLog(private val storage: Storage, private val zone: ZoneId = ZoneId.systemDefault()) {
    private val queue = Channel<AccessRecord>(QUEUE_CAPACITY, BufferOverflow.DROP_LATEST) { dropped.incrementAndGet() }

    /** Records dropped because the queue was full. */
    val dropped = AtomicLong()

    /** Hands a record to the writer, returns at once. */
    fun record(record: AccessRecord) {
        if (queue.trySend(record).isFailure) dropped.incrementAndGet()
    }

    /** Starts the writer in [scope]. */
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (isActive) {
            val first = queue.receive()
            val batch = mutableListOf(first)
            withTimeoutOrNull(FLUSH_MILLIS) {
                while (batch.size < BATCH_SIZE) batch += queue.receive()
            }
            runCatching { write(batch) }.onFailure {
                staticLog(KLogger.Level.ERROR, TAG) { "Writing ${batch.size} access records failed: ${it.message}" }
            }
        }
    }

    /** Writes everything still queued, for tests and the shutdown. */
    suspend fun flush() {
        val batch = mutableListOf<AccessRecord>()
        while (true) batch += queue.tryReceive().getOrNull() ?: break
        if (batch.isNotEmpty()) write(batch)
    }

    private suspend fun write(batch: List<AccessRecord>) = storage.writeLock.withLock {
        val hourly = HashMap<Pair<String, Long>, Counter>()
        val daily = HashMap<Pair<String, Long>, Counter>()
        val tops = HashMap<Triple<String, Long, TopKind>, HashMap<String, Long>>()
        val latency = HashMap<Pair<String, Long>, LongArray>()
        batch.forEach { record ->
            hourly.getOrPut(record.domain to hourStart(record.time)) { Counter() }.add(record)
            val day = dayStart(record.time)
            daily.getOrPut(record.domain to day) { Counter() }.add(record)
            topKeys(record).forEach { (kind, key) -> tops.getOrPut(Triple(record.domain, day, kind)) { HashMap() }.merge(key, 1L, Long::plus) }
            latency.getOrPut(record.domain to hourStart(record.time)) { LongArray(LATENCY_BOUNDS.size + 1) }[latencyBucket(record.durationMs)]++
        }
        storage.tx {
            AccessLogTable.batchInsert(batch.filter { it.logged }, shouldReturnGeneratedValues = false) { r ->
                this[AccessLogTable.time] = r.time
                this[AccessLogTable.clientIp] = r.clientIp.take(64)
                this[AccessLogTable.method] = r.method.take(16)
                this[AccessLogTable.host] = r.host.take(253)
                this[AccessLogTable.path] = r.path.take(2048)
                this[AccessLogTable.status] = r.status
                this[AccessLogTable.bytesIn] = r.bytesIn
                this[AccessLogTable.bytesOut] = r.bytesOut
                this[AccessLogTable.durationMs] = r.durationMs
                this[AccessLogTable.domain] = r.domain.take(253)
                this[AccessLogTable.route] = r.route.take(512)
                this[AccessLogTable.backend] = r.backend.take(300)
                this[AccessLogTable.userAgent] = r.userAgent.take(512)
                this[AccessLogTable.reason] = r.reason.take(200)
                this[AccessLogTable.block] = r.block.take(20)
            }
            merge(StatsHourlyTable, hourly)
            merge(StatsDailyTable, daily)
            mergeTops(tops)
            mergeLatency(latency)
        }
    }

    /**
     * Adds counts to the top lists, at most [TOP_LIST_SIZE] keys per list and day. When a list is full, a new key takes
     * the place of the smallest one and starts at its count (space saving algorithm), so the heavy hitters stay in
     * the list even when they show up late in the day.
     */
    private fun mergeTops(tops: Map<Triple<String, Long, TopKind>, Map<String, Long>>) {
        tops.forEach { (group, counts) ->
            val (domain, day, kind) = group
            val stored = StatsTopTable.selectAll()
                .where { (StatsTopTable.domain eq domain) and (StatsTopTable.day eq day) and (StatsTopTable.kind eq kind.name) }
                .associate { it[StatsTopTable.key] to it[StatsTopTable.count] }.toMutableMap()
            val changed = HashSet<String>()
            counts.entries.sortedByDescending { it.value }.forEach { (key, count) ->
                changed += key
                when {
                    key in stored -> stored[key] = stored.getValue(key) + count
                    stored.size < TOP_LIST_SIZE -> stored[key] = count
                    else -> {
                        val smallest = stored.minBy { it.value }
                        stored.remove(smallest.key)
                        changed -= smallest.key
                        StatsTopTable.deleteWhere {
                            (StatsTopTable.domain eq domain) and (StatsTopTable.day eq day) and (StatsTopTable.kind eq kind.name) and (StatsTopTable.key eq smallest.key)
                        }
                        stored[key] = smallest.value + count
                    }
                }
            }
            // Only the keys of this batch, the list holds up to 100 rows and most of them did not change
            StatsTopTable.batchUpsert(stored.entries.filter { it.key in changed }, shouldReturnGeneratedValues = false) { (key, count) ->
                this[StatsTopTable.domain] = domain
                this[StatsTopTable.day] = day
                this[StatsTopTable.kind] = kind.name
                this[StatsTopTable.key] = key
                this[StatsTopTable.count] = count
            }
        }
    }

    private fun mergeLatency(latency: Map<Pair<String, Long>, LongArray>) {
        latency.forEach { (key, counts) ->
            LatencyTable.selectAll().where { (LatencyTable.domain eq key.first) and (LatencyTable.bucket eq key.second) }.firstOrNull()
                ?.let { row -> parseHistogram(row[LatencyTable.histogram]).forEachIndexed { i, c -> if (i < counts.size) counts[i] += c } }
            LatencyTable.upsert {
                it[domain] = key.first
                it[bucket] = key.second
                it[histogram] = counts.joinToString(",")
            }
        }
    }

    /** Adds [counters] to the stored rows. Only this writer changes statistics, so read, add, write is safe. */
    private fun merge(table: StatsTable, counters: Map<Pair<String, Long>, Counter>) {
        counters.forEach { (key, counter) ->
            table.selectAll().where { (table.domain eq key.first) and (table.bucket eq key.second) }.firstOrNull()?.let { row ->
                counter.requests += row[table.requests]
                counter.s2 += row[table.status2xx]
                counter.s3 += row[table.status3xx]
                counter.s4 += row[table.status4xx]
                counter.s5 += row[table.status5xx]
                counter.bytesIn += row[table.bytesIn]
                counter.bytesOut += row[table.bytesOut]
                counter.durationSum += row[table.durationSum]
                counter.durationMax = maxOf(counter.durationMax, row[table.durationMax])
                counter.blocked += row[table.blocked]
                counter.redirected += row[table.redirected]
            }
        }
        table.batchUpsert(counters.entries, shouldReturnGeneratedValues = false) { (key, c) ->
            this[table.domain] = key.first
            this[table.bucket] = key.second
            this[table.requests] = c.requests
            this[table.status2xx] = c.s2
            this[table.status3xx] = c.s3
            this[table.status4xx] = c.s4
            this[table.status5xx] = c.s5
            this[table.bytesIn] = c.bytesIn
            this[table.bytesOut] = c.bytesOut
            this[table.durationSum] = c.durationSum
            this[table.durationMax] = c.durationMax
            this[table.blocked] = c.blocked
            this[table.redirected] = c.redirected
        }
    }

    /** Start of the hour of [time]. */
    fun hourStart(time: Long): Long = time - Math.floorMod(time, 3_600_000L)

    /** Start of the day of [time] in [zone]. */
    fun dayStart(time: Long): Long =
        Instant.ofEpochMilli(time).atZone(zone).toLocalDate().atStartOfDay(zone).toInstant().toEpochMilli()

    /**
     * The newest access log entries, newest first.
     *
     * @param domain Only this domain, `null` for all.
     * @param status Only this status class (`2` for 2xx), `null` for all.
     * @param search Only entries whose path, IP or domain contain this text.
     * @param limit Most entries returned.
     * @param blockedOnly Only requests Kovexy blocked.
     */
    fun latest(domain: String? = null, status: Int? = null, search: String? = null, limit: Int = 200, blockedOnly: Boolean = false): List<AccessRecord> = storage.tx {
        val query = AccessLogTable.selectAll()
        if (blockedOnly) query.andWhere { AccessLogTable.block neq "" }
        domain?.let { s -> query.andWhere { AccessLogTable.domain eq s } }
        status?.let { s -> query.andWhere { AccessLogTable.status.between(s * 100, s * 100 + 99) } }
        search?.takeIf { it.isNotBlank() }?.let { text ->
            // SQLite has no default escape character, so the pattern names its own
            val pattern = LikePattern("%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%", '\\')
            query.andWhere {
                (AccessLogTable.path like pattern) or (AccessLogTable.clientIp like pattern) or (AccessLogTable.host like pattern)
            }
        }
        query.orderBy(AccessLogTable.id, SortOrder.DESC).limit(limit).map { row ->
            AccessRecord(
                time = row[AccessLogTable.time], clientIp = row[AccessLogTable.clientIp], method = row[AccessLogTable.method],
                host = row[AccessLogTable.host], path = row[AccessLogTable.path], status = row[AccessLogTable.status],
                bytesIn = row[AccessLogTable.bytesIn], bytesOut = row[AccessLogTable.bytesOut], durationMs = row[AccessLogTable.durationMs],
                domain = row[AccessLogTable.domain], route = row[AccessLogTable.route], backend = row[AccessLogTable.backend],
                userAgent = row[AccessLogTable.userAgent], reason = row[AccessLogTable.reason], block = row[AccessLogTable.block],
            )
        }
    }

    /**
     * Deletes access log entries and hourly statistics older than their retention. The top IP lists follow the access log,
     * the other daily statistics stay forever.
     */
    suspend fun applyRetention(accessLog: Duration, hourlyStats: Duration, now: Long) = storage.writeLock.withLock {
        storage.tx {
            AccessLogTable.deleteWhere { AccessLogTable.time less (now - accessLog.inWholeMilliseconds) }
            StatsHourlyTable.deleteWhere { StatsHourlyTable.bucket less (now - hourlyStats.inWholeMilliseconds) }
            LatencyTable.deleteWhere { LatencyTable.bucket less (now - hourlyStats.inWholeMilliseconds) }
            // IP addresses are personal data, the top IP lists go with the access log, the other lists stay
            StatsTopTable.deleteWhere { (StatsTopTable.kind eq TopKind.IP.name) and (StatsTopTable.day less (now - accessLog.inWholeMilliseconds)) }
        }
    }
}

/**
 * Aggregated values of one statistics bucket.
 *
 * @property bucket Start of the hour or day, Unix milliseconds.
 * @property blocked Requests Kovexy blocked (see [bayern.kickner.kovexy.access.BlockKind]).
 * @property redirected Plain HTTP requests answered with the redirect to HTTPS.
 */
data class StatsRow(
    val domain: String,
    val bucket: Long,
    val requests: Long,
    val status2xx: Long,
    val status3xx: Long,
    val status4xx: Long,
    val status5xx: Long,
    val bytesIn: Long,
    val bytesOut: Long,
    val durationSum: Long,
    val durationMax: Long,
    val blocked: Long = 0,
    val redirected: Long = 0,
) {
    /** Mean response time in milliseconds. */
    val durationAvg: Long get() = if (requests == 0L) 0 else durationSum / requests
}

/**
 * Reads statistics.
 *
 * @param hourly `true` for hourly, `false` for daily rows.
 * @param from First bucket, inclusive.
 * @param domains Only these domains, `null` for all.
 */
fun Storage.statistics(hourly: Boolean, from: Long, domains: List<String>? = null): List<StatsRow> = tx {
    val table: StatsTable = if (hourly) StatsHourlyTable else StatsDailyTable
    val query = table.selectAll().where { table.bucket greaterEq from }
    domains?.let { list -> query.andWhere { table.domain inList list } }
    query.orderBy(table.bucket).map { row ->
        StatsRow(
            row[table.domain], row[table.bucket], row[table.requests], row[table.status2xx], row[table.status3xx],
            row[table.status4xx], row[table.status5xx], row[table.bytesIn], row[table.bytesOut], row[table.durationSum],
            row[table.durationMax], row[table.blocked], row[table.redirected],
        )
    }
}

/** A stored histogram, counts separated by commas. */
private fun parseHistogram(text: String): List<Long> = text.split(',').map { it.toLongOrNull() ?: 0 }

/** The sum of several histograms. */
fun sumHistograms(histograms: Collection<LongArray>): LongArray {
    val sum = LongArray(LATENCY_BOUNDS.size + 1)
    histograms.forEach { h -> h.forEachIndexed { i, c -> if (i < sum.size) sum[i] += c } }
    return sum
}

/**
 * The top lists of a time range, summed over its days.
 *
 * @param from First day, inclusive.
 * @param domain Only this domain, `null` for all.
 * @param limit Entries per kind.
 */
fun Storage.topLists(from: Long, domain: String?, limit: Int = 10): Map<TopKind, List<Pair<String, Long>>> = tx {
    val query = StatsTopTable.selectAll().where { StatsTopTable.day greaterEq from }
    domain?.let { s -> query.andWhere { StatsTopTable.domain eq s } }
    query.groupBy({ TopKind.entries.firstOrNull { k -> k.name == it[StatsTopTable.kind] } }, { it[StatsTopTable.key] to it[StatsTopTable.count] })
        .filterKeys { it != null }
        .mapKeys { it.key!! }
        .mapValues { (_, rows) -> rows.groupBy({ it.first }, { it.second }).mapValues { it.value.sum() }.entries.sortedByDescending { it.value }.take(limit).map { it.key to it.value } }
}

/**
 * Response time histograms per hour from [from] on, summed over the domains (or only [domain]).
 *
 * @return start of the hour to the histogram.
 */
fun Storage.latencyHistograms(from: Long, domain: String?): Map<Long, LongArray> = tx {
    val query = LatencyTable.selectAll().where { LatencyTable.bucket greaterEq from }
    domain?.let { s -> query.andWhere { LatencyTable.domain eq s } }
    val result = HashMap<Long, LongArray>()
    query.forEach { row ->
        val counts = parseHistogram(row[LatencyTable.histogram])
        val target = result.getOrPut(row[LatencyTable.bucket]) { LongArray(LATENCY_BOUNDS.size + 1) }
        counts.forEachIndexed { i, c -> if (i < target.size) target[i] += c }
    }
    result
}
