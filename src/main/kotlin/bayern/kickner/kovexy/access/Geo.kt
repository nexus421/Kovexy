package bayern.kickner.kovexy.access

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.writeAtomically
import bayern.kickner.kovexy.OWNER_ONLY_FILE
import bayern.kickner.kovexy.ensurePrivateDir
import bayern.kickner.kovexy.setPermissions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import java.io.File
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.HexFormat
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private const val TAG = "Geo"

/** Base URL of the country data (sapics/ip-location-db, `user-country`, license PDDL). */
const val GEO_DOWNLOAD_BASE = "https://github.com/sapics/ip-location-db/releases/download"

/** The two files Kovexy uses, IPv4 and IPv6. */
val GEO_FILES = listOf("user-country-ipv4.csv", "user-country-ipv6.csv")

/** Time between two checks of the published checksums. */
val GEO_CHECK_INTERVAL = 24.hours

/** After a failed check the next one comes sooner. */
val GEO_RETRY_INTERVAL = 1.hours

/** Largest file accepted, the real ones are about 10 and 17 MB. */
private const val MAX_GEO_FILE_BYTES = 64L * 1024 * 1024

/**
 * Rows per file Kovexy loads at most. The real files have far fewer (2026: about 300.000), the limit keeps a broken or
 * forged file from filling the heap on every start (audit run-2).
 */
private const val MAX_GEO_ROWS = 1_500_000

/** A growing list of primitive longs, a `List<Long>` would box every value. */
private class LongList {
    private var items = LongArray(1024)
    var size = 0
        private set

    operator fun plusAssign(value: Long) {
        if (size == items.size) items = items.copyOf(size * 2)
        items[size++] = value
    }

    fun toArray(): LongArray = items.copyOf(size)
}


/**
 * IP ranges with their country, loaded from the CSV files (`start,end,CC`). Lookups are a binary search.
 *
 * @property rows Number of ranges.
 */
class GeoDatabase private constructor(
    private val v4Start: LongArray,
    private val v4End: LongArray,
    private val v4Country: Array<String>,
    private val v6StartHi: LongArray,
    private val v6StartLo: LongArray,
    private val v6EndHi: LongArray,
    private val v6EndLo: LongArray,
    private val v6Country: Array<String>,
) {
    val rows: Int get() = v4Start.size + v6StartHi.size

    /** The ISO code of the country of [address], `null` if no range contains it. */
    fun country(address: InetAddress): String? {
        val bytes = address.address
        return if (bytes.size == 4) {
            val value = toV4(bytes)
            var low = 0
            var high = v4Start.size - 1
            while (low <= high) {
                val mid = (low + high) ushr 1
                when {
                    value < v4Start[mid] -> high = mid - 1
                    value > v4End[mid] -> low = mid + 1
                    else -> return v4Country[mid]
                }
            }
            null
        } else {
            val hi = toLong(bytes, 0)
            val lo = toLong(bytes, 8)
            var low = 0
            var high = v6StartHi.size - 1
            while (low <= high) {
                val mid = (low + high) ushr 1
                when {
                    compare128(hi, lo, v6StartHi[mid], v6StartLo[mid]) < 0 -> high = mid - 1
                    compare128(hi, lo, v6EndHi[mid], v6EndLo[mid]) > 0 -> low = mid + 1
                    else -> return v6Country[mid]
                }
            }
            null
        }
    }

    companion object {
        /**
         * Reads the IPv4 and IPv6 CSV files. Lines that cannot be read are skipped, the files are sorted by range start.
         */
        fun load(ipv4: File, ipv6: File): GeoDatabase {
            listOf(ipv4, ipv6).forEach { check(it.length() <= MAX_GEO_FILE_BYTES) { "${it.name} is larger than ${MAX_GEO_FILE_BYTES / 1024 / 1024} MB" } }
            val countries = HashMap<String, String>()
            fun intern(code: String) = countries.getOrPut(code) { code }
            val s4 = LongList()
            val e4 = LongList()
            val c4 = ArrayList<String>()
            ipv4.useLines { lines ->
                lines.forEach { line ->
                    check(c4.size < MAX_GEO_ROWS) { "${ipv4.name} has more than $MAX_GEO_ROWS rows" }
                    val parts = line.split(',')
                    if (parts.size < 3) return@forEach
                    val start = runCatching { toV4(InetAddress.getByName(parts[0]).address) }.getOrNull() ?: return@forEach
                    val end = runCatching { toV4(InetAddress.getByName(parts[1]).address) }.getOrNull() ?: return@forEach
                    s4 += start
                    e4 += end
                    c4 += intern(parts[2].trim().uppercase())
                }
            }
            val sh = LongList()
            val sl = LongList()
            val eh = LongList()
            val el = LongList()
            val c6 = ArrayList<String>()
            ipv6.useLines { lines ->
                lines.forEach { line ->
                    check(c6.size < MAX_GEO_ROWS) { "${ipv6.name} has more than $MAX_GEO_ROWS rows" }
                    val parts = line.split(',')
                    if (parts.size < 3 || ':' !in parts[0]) return@forEach
                    val start = runCatching { InetAddress.getByName(parts[0]).address }.getOrNull()?.takeIf { it.size == 16 } ?: return@forEach
                    val end = runCatching { InetAddress.getByName(parts[1]).address }.getOrNull()?.takeIf { it.size == 16 } ?: return@forEach
                    sh += toLong(start, 0)
                    sl += toLong(start, 8)
                    eh += toLong(end, 0)
                    el += toLong(end, 8)
                    c6 += intern(parts[2].trim().uppercase())
                }
            }
            return GeoDatabase(
                s4.toArray(), e4.toArray(), c4.toTypedArray(),
                sh.toArray(), sl.toArray(), eh.toArray(), el.toArray(), c6.toTypedArray(),
            )
        }

        private fun toV4(bytes: ByteArray): Long =
            ((bytes[0].toLong() and 0xFF) shl 24) or ((bytes[1].toLong() and 0xFF) shl 16) or ((bytes[2].toLong() and 0xFF) shl 8) or (bytes[3].toLong() and 0xFF)

        private fun toLong(bytes: ByteArray, offset: Int): Long {
            var value = 0L
            for (i in offset until offset + 8) value = (value shl 8) or (bytes[i].toLong() and 0xFF)
            return value
        }

        /** Compares two unsigned 128 bit numbers given as high and low half. */
        private fun compare128(aHi: Long, aLo: Long, bHi: Long, bLo: Long): Int {
            val hi = java.lang.Long.compareUnsigned(aHi, bHi)
            return if (hi != 0) hi else java.lang.Long.compareUnsigned(aLo, bLo)
        }
    }
}

/**
 * State of the country data, for the admin UI.
 *
 * @property loaded Whether data is in memory.
 * @property rows Number of ranges.
 * @property updatedAt Unix milliseconds of the data in use (file time).
 * @property lastCheck Unix milliseconds of the last check against GitHub.
 * @property lastError Message of the last failed check or load.
 */
data class GeoStatus(val loaded: Boolean, val rows: Int, val updatedAt: Long?, val lastCheck: Long?, val lastError: String?)

/**
 * The country data, always loaded because the statistics show countries too (decided on 18.11.2026): Kovexy reads
 * `<dataDir>/geo/`, compares the published SHA-256 sums with GitHub once a day and downloads a file only when its sum
 * changed. Every download is checked against the published sum before it replaces the old file.
 *
 * While no data is loaded every IP has an unknown country, country rules then have no effect (like Zoraxy).
 *
 * @param dir `<dataDir>/geo`.
 * @param fetch Downloads a URL into a file and returns the HTTP status, replaceable in tests.
 * @param clock Unix milliseconds.
 */
class Geo(
    private val dir: File,
    private val fetch: (url: String, target: File) -> Int = ::download,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    @Volatile
    private var database: GeoDatabase? = null

    @Volatile
    private var lastCheck: Long? = null

    @Volatile
    private var lastError: String? = null

    /** The country of [address], `null` if unknown or no data is loaded. A binary search, fast enough without a cache. */
    fun country(address: InetAddress): String? = database?.country(address)

    /** Whether data is loaded. */
    val loaded: Boolean get() = database != null

    /** The state for the admin UI. */
    fun status(): GeoStatus = GeoStatus(
        loaded = database != null,
        rows = database?.rows ?: 0,
        updatedAt = GEO_FILES.map { File(dir, it) }.filter { it.isFile }.maxOfOrNull { it.lastModified() },
        lastCheck = lastCheck,
        lastError = lastError,
    )

    /** Starts the update loop in [scope]. */
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (true) {
            runCatching { round() }.onFailure {
                lastError = it.message ?: it.toString()
                staticLog(KLogger.Level.ERROR, TAG) { "Country data round failed: ${it.stackTraceToString()}" }
            }
            delay(10.minutes)
        }
    }

    /** One round: load from disk, check GitHub when due. Public for tests. */
    fun round() {
        if (database == null && GEO_FILES.all { File(dir, it).isFile }) loadFromDisk()
        val now = clock()
        val due = lastCheck?.let { last -> now - last >= (if (lastError == null) GEO_CHECK_INTERVAL else GEO_RETRY_INTERVAL).inWholeMilliseconds } ?: true
        if (due) update(now)
    }

    private fun update(now: Long) {
        lastCheck = now
        ensurePrivateDir(dir)
        var changed = false
        val result = runCatching {
            GEO_FILES.forEach { name ->
                val remoteSum = remoteChecksum(name)
                val local = File(dir, name)
                val localSum = File(dir, "$name.sha256").takeIf { it.isFile }?.readText()?.trim()
                if (local.isFile && localSum == remoteSum) return@forEach
                val temp = File(dir, ".$name.download")
                try {
                    val status = fetch("$GEO_DOWNLOAD_BASE/latest/$name", temp)
                    check(status == 200) { "Download of $name answered $status" }
                    val actual = fileSha256(temp)
                    check(actual == remoteSum) { "Checksum of $name does not match the published one" }
                    setPermissions(temp.toPath(), OWNER_ONLY_FILE)
                    Files.move(temp.toPath(), local.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                    writeAtomically(File(dir, "$name.sha256"), remoteSum)
                    changed = true
                } finally {
                    temp.delete()
                }
            }
        }
        result.onSuccess {
            lastError = null
            if (changed || database == null) loadFromDisk()
            if (changed) staticLog(KLogger.Level.INFO, TAG) { "Country data updated" }
        }.onFailure {
            lastError = it.message ?: it.toString()
            staticLog(KLogger.Level.WARN, TAG) { "Country data update failed: $lastError. ${if (database == null) "Country rules have no effect until data is loaded." else "The old data stays in use."}" }
        }
    }

    private fun remoteChecksum(name: String): String {
        val temp = File(dir, ".$name.sha256.download")
        try {
            val status = fetch("$GEO_DOWNLOAD_BASE/checksum/$name.sha256", temp)
            check(status == 200) { "Checksum of $name answered $status" }
            val sum = temp.readText().trim().substringBefore(' ').lowercase()
            check(sum.length == 64 && sum.all { it in '0'..'9' || it in 'a'..'f' }) { "Checksum of $name is malformed" }
            return sum
        } finally {
            temp.delete()
        }
    }

    private fun loadFromDisk() {
        val started = clock()
        runCatching { GeoDatabase.load(File(dir, GEO_FILES[0]), File(dir, GEO_FILES[1])) }
            .onSuccess { db ->
                database = db
                staticLog(KLogger.Level.INFO, TAG) { "Country data loaded: ${db.rows} ranges in ${clock() - started} ms" }
            }
            .onFailure {
                lastError = "Cannot read the country data: ${it.message}"
                staticLog(KLogger.Level.ERROR, TAG) { lastError!! }
            }
    }
}

private fun fileSha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            digest.update(buffer, 0, n)
        }
    }
    return HexFormat.of().formatHex(digest.digest())
}

/** GitHub release downloads redirect to its storage, only https targets are followed. */
private val geoHttp: HttpClient by lazy {
    HttpClient.newBuilder().connectTimeout(15.seconds.toJavaDuration()).followRedirects(HttpClient.Redirect.NORMAL).build()
}

/** Downloads [url] into [target], at most [MAX_GEO_FILE_BYTES]. */
private fun download(url: String, target: File): Int {
    val request = HttpRequest.newBuilder(URI(url)).timeout(5.minutes.toJavaDuration()).GET().build()
    val response = geoHttp.send(request, HttpResponse.BodyHandlers.ofInputStream())
    check(response.uri().scheme == "https") { "Redirected to a non https address" }
    response.body().use { input ->
        if (response.statusCode() != 200) return response.statusCode()
        target.outputStream().use { out ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                total += n
                check(total <= MAX_GEO_FILE_BYTES) { "File larger than ${MAX_GEO_FILE_BYTES / 1024 / 1024} MB" }
                out.write(buffer, 0, n)
            }
        }
    }
    return 200
}
