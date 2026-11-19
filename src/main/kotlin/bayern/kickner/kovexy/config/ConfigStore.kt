package bayern.kickner.kovexy.config

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.OWNER_ONLY_FILE
import bayern.kickner.kovexy.audit.Actor
import bayern.kickner.kovexy.ensurePrivateDir
import bayern.kickner.kovexy.setPermissions
import bayern.kickner.kovexy.sha256Hex
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import bayern.kickner.kovexy.ResultOf2
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardWatchEventKinds
import java.nio.file.WatchService
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

private const val TAG = "ConfigStore"

/** Name of the config file in the data directory. */
const val CONFIG_FILE_NAME = "kovexy.json"

/** Number of config copies kept in `<dataDir>/backups`. */
const val CONFIG_BACKUPS_KEPT = 10

/** Time the file has to stay unchanged before a change by hand is read, editors write in several steps. */
private const val WATCH_SETTLE_MILLIS = 300L

/**
 * Strict JSON for the config file: unknown keys are errors, so a typo never silently falls back to a default.
 * Defaults are not written, the file only holds what differs from them.
 */
val configJson = Json {
    ignoreUnknownKeys = false
    explicitNulls = false
    encodeDefaults = false
    prettyPrint = true
    classDiscriminator = "type"
}

/**
 * A validated config together with the SHA-256 of the file text it came from. The version lets the admin UI notice
 * that the file changed between showing a form and saving it.
 *
 * @property config The config.
 * @property version SHA-256 of the file text.
 */
data class LoadedConfig(val config: KovexyConfig, val version: String)

/** Where a config change came from. */
enum class ChangeSource {
    /** Saved by the admin UI or a command line action. */
    SAVE,

    /** The file was edited by hand or restored from a backup. */
    FILE,
}

/** Why saving a config failed. */
sealed interface SaveError {
    /** The new config is invalid, nothing was written. */
    data class Invalid(val problems: List<String>) : SaveError

    /** The file changed since the caller read it, nothing was written. */
    data object Conflict : SaveError

    /** Writing the file failed. */
    data class Io(val message: String) : SaveError
}

/**
 * Parses and validates a config text.
 *
 * @return the config, or every problem found. A parse error is reported alone and only with the first line of the
 *   parser's message, never with the document, which may hold secrets.
 */
fun parseConfig(text: String): ResultOf2<KovexyConfig, List<String>> {
    val config = runCatching { configJson.decodeFromString<KovexyConfig>(text) }.getOrElse {
        val reason = if (it is SerializationException) sanitizeParseError(it.message) else it.toString()
        return ResultOf2.Failure(listOf("Cannot parse $CONFIG_FILE_NAME: $reason"))
    }
    val problems = validateConfig(config)
    return if (problems.isEmpty()) ResultOf2.Success(config) else ResultOf2.Failure(problems)
}

/** Keeps the first line of a kotlinx.serialization message, the rest is a hint or the offending document. */
private fun sanitizeParseError(message: String?): String =
    message?.substringBefore("JSON input")?.lineSequence()?.first()?.trim()?.ifEmpty { null } ?: "invalid JSON"

/** The config as file text, without default values. */
fun encodeConfig(config: KovexyConfig): String = configJson.encodeToString(KovexyConfig.serializer(), config) + "\n"

/**
 * Owns `<dataDir>/kovexy.json`: reads and validates it, writes it atomically with a backup of the previous version,
 * and watches it for changes by hand. Every accepted change goes to the registered listeners, which apply it while
 * running. An invalid file changes nothing.
 *
 * @param dataDir The data directory.
 * @param followLinks `false` for the command line: symbolic links for the config file or the backup directory are
 *   refused instead of followed.
 */
class ConfigStore(val dataDir: File, private val followLinks: Boolean = true) {
    /** The config file. */
    val file = File(dataDir, CONFIG_FILE_NAME)

    /** Copies of earlier versions, the last [CONFIG_BACKUPS_KEPT]. */
    val backupDir = File(dataDir, "backups")

    @Volatile
    private var loaded: LoadedConfig? = null

    /** Version of a file text that was rejected, so the same broken text is reported only once. */
    @Volatile
    private var rejectedVersion: String? = null

    private val listeners = CopyOnWriteArrayList<(old: KovexyConfig?, new: KovexyConfig, source: ChangeSource, actor: Actor) -> Unit>()
    private val invalidListeners = CopyOnWriteArrayList<(problems: List<String>) -> Unit>()
    private var watcher: WatchService? = null
    private val backupCounter = java.util.concurrent.atomic.AtomicInteger()

    /** The active config. Only valid after [load] succeeded. */
    val current: LoadedConfig get() = checkNotNull(loaded) { "Config not loaded" }

    /** Registers a listener for every accepted change. It runs on the thread that saved or noticed the change. */
    fun onChange(listener: (old: KovexyConfig?, new: KovexyConfig, source: ChangeSource, actor: Actor) -> Unit) {
        listeners += listener
    }

    /** Registers a listener for a file that was changed by hand and rejected. */
    fun onInvalid(listener: (problems: List<String>) -> Unit) {
        invalidListeners += listener
    }

    /**
     * Reads the file without making it active. A missing file is the empty config, which the first start writes.
     *
     * @return the config and its version, or every problem found.
     */
    fun read(): ResultOf2<LoadedConfig, List<String>> {
        if (file.exists().not()) return ResultOf2.Success(LoadedConfig(KovexyConfig(), ""))
        val text = runCatching { readFileText() }
            .getOrElse { return ResultOf2.Failure(listOf("Cannot read ${file.absolutePath}: ${it.message}")) }
        return when (val parsed = parseConfig(text)) {
            is ResultOf2.Success -> ResultOf2.Success(LoadedConfig(parsed.value, sha256Hex(text)))
            is ResultOf2.Failure -> ResultOf2.Failure(parsed.value)
        }
    }

    /**
     * Reads the file and makes it the active config, without notifying listeners. Used once at startup.
     *
     * @return the config, or every problem found.
     */
    fun load(): ResultOf2<LoadedConfig, List<String>> = read().also { if (it is ResultOf2.Success) loaded = it.value }

    /**
     * Changes the config: applies [change] to the active config, validates the result, keeps a copy of the current
     * file in [backupDir], writes the new file atomically and notifies the listeners.
     *
     * @param expectedVersion The version the caller based the change on. If the file changed in the meantime nothing
     *   is written and [SaveError.Conflict] is returned. `null` skips the check (command line actions).
     * @param actor Who made the change, for the audit log.
     * @return the new active config, or why nothing was saved.
     */
    fun update(expectedVersion: String? = null, actor: Actor = Actor.SYSTEM, change: (KovexyConfig) -> KovexyConfig): ResultOf2<LoadedConfig, SaveError> {
        val result = synchronized(this) {
            val before = loaded ?: when (val read = read()) {
                is ResultOf2.Success -> read.value
                is ResultOf2.Failure -> return ResultOf2.Failure(SaveError.Invalid(read.value))
            }
            if (expectedVersion != null && expectedVersion != before.version) return ResultOf2.Failure(SaveError.Conflict)
            // A hand edit the watcher has not picked up yet must not be overwritten silently
            if (expectedVersion != null && file.isFile && runCatching { sha256Hex(readFileText()) }.getOrNull() != before.version) {
                return ResultOf2.Failure(SaveError.Conflict)
            }

            val next = change(before.config)
            val problems = validateConfig(next)
            if (problems.isNotEmpty()) return ResultOf2.Failure(SaveError.Invalid(problems))

            val text = encodeConfig(next)
            val written = runCatching {
                backupCurrentFile()
                writeAtomically(file, text)
            }
            written.exceptionOrNull()?.let { return ResultOf2.Failure(SaveError.Io(it.message ?: it.toString())) }
            val now = LoadedConfig(next, sha256Hex(text))
            loaded = now
            // Inside the lock, so two changes are applied in the order they were saved
            listeners.forEach { listener -> runCatching { listener(before.config.takeIf { before.version.isNotEmpty() }, next, ChangeSource.SAVE, actor) }.onFailure { logListenerFailure(it) } }
            now
        }
        return ResultOf2.Success(result)
    }

    /**
     * Reads the file again after it changed on disk. A valid new version becomes active and goes to the listeners,
     * an invalid one is logged and reported once, the active config stays.
     */
    fun reloadFromDisk() {
        if (file.exists().not()) return
        val text = runCatching { file.readText() }.getOrElse {
            staticLog(KLogger.Level.ERROR, TAG) { "Cannot read ${file.absolutePath}: ${it.message}" }
            return
        }
        val version = sha256Hex(text)
        synchronized(this) {
            if (version == loaded?.version || version == rejectedVersion) return
            when (val parsed = parseConfig(text)) {
                is ResultOf2.Failure -> {
                    rejectedVersion = version
                    staticLog(KLogger.Level.ERROR, TAG) {
                        "${file.absolutePath} changed but was rejected, the running config stays:\n" + parsed.value.joinToString("\n") { "- $it" }
                    }
                    invalidListeners.forEach { runCatching { it(parsed.value) }.onFailure(::logListenerFailure) }
                    return
                }

                is ResultOf2.Success -> {
                    val previous = loaded
                    loaded = LoadedConfig(parsed.value, version)
                    rejectedVersion = null
                    staticLog(KLogger.Level.INFO, TAG) { "${file.absolutePath} changed on disk, applying it" }
                    listeners.forEach { listener -> runCatching { listener(previous?.config, parsed.value, ChangeSource.FILE, Actor.FILE) }.onFailure(::logListenerFailure) }
                }
            }
        }
    }

    /**
     * Watches the data directory for changes of the config file on a daemon thread. Every change event waits until the
     * file was quiet for a moment, then [reloadFromDisk] decides whether anything changed.
     */
    fun startWatching() {
        val service = FileSystems.getDefault().newWatchService()
        dataDir.toPath().register(
            service,
            StandardWatchEventKinds.ENTRY_CREATE,
            StandardWatchEventKinds.ENTRY_MODIFY,
            StandardWatchEventKinds.ENTRY_DELETE,
        )
        watcher = service
        thread(isDaemon = true, name = "config-watcher") {
            runCatching {
                while (true) {
                    val key = service.take()
                    val relevant = key.pollEvents().any { (it.context() as? java.nio.file.Path)?.toString() == CONFIG_FILE_NAME }
                    key.reset()
                    if (relevant.not()) continue
                    // Collect the burst of events an editor or an atomic rename produces
                    while (true) {
                        val next = service.poll(WATCH_SETTLE_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS) ?: break
                        next.pollEvents()
                        next.reset()
                    }
                    reloadFromDisk()
                }
            }.onFailure {
                if (it !is java.nio.file.ClosedWatchServiceException && it !is InterruptedException) {
                    staticLog(KLogger.Level.ERROR, TAG) { "Config watcher stopped: ${it.stackTraceToString()}" }
                }
            }
        }
    }

    /** Stops watching the file. */
    fun stopWatching() {
        runCatching { watcher?.close() }
    }

    /** Copies the current file into [backupDir] and keeps only the newest [CONFIG_BACKUPS_KEPT] copies. */
    private fun backupCurrentFile() {
        if (file.exists().not()) return
        check(followLinks || Files.isSymbolicLink(backupDir.toPath()).not()) { "${backupDir.absolutePath} is a symbolic link, the command line does not follow it" }
        val created = backupDir.exists().not()
        ensurePrivateDir(backupDir)
        // Created by a command line action as root, the directory must stay writable for the service
        if (created) copyOwner(from = dataDir, to = backupDir)
        val stamp = backupStampFormat.format(Instant.now())
        // The counter keeps saves within the same millisecond apart
        val target = File(backupDir, "kovexy-$stamp-${String.format(java.util.Locale.ROOT, "%03d", backupCounter.getAndIncrement() % 1000)}.json")
        openFile().use { Files.copy(it, target.toPath(), StandardCopyOption.REPLACE_EXISTING) }
        setPermissions(target.toPath(), OWNER_ONLY_FILE)
        copyOwner(from = dataDir, to = target)
        backupDir.listFiles { f -> f.name.startsWith("kovexy-") && f.name.endsWith(".json") }
            ?.sortedByDescending { it.name }
            ?.drop(CONFIG_BACKUPS_KEPT)
            ?.forEach { it.delete() }
    }

    /**
     * Opens the config file. With `followLinks = false` (the command line, which may run as root) a symbolic link is
     * refused: whoever controls the data directory must not make root read or copy another file (decided on
     * 19.11.2026). The service follows links like any program.
     */
    private fun openFile(): java.io.InputStream =
        if (followLinks) file.inputStream() else Files.newInputStream(file.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)

    private fun readFileText(): String = openFile().use { it.readBytes().decodeToString() }

    private fun logListenerFailure(error: Throwable) {
        staticLog(KLogger.Level.ERROR, TAG) { "Applying the config failed: ${error.stackTraceToString()}" }
    }
}

/** Sortable file name stamp with milliseconds, in UTC so the order survives a DST change. */
private val backupStampFormat = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS").withZone(java.time.ZoneOffset.UTC)

/**
 * Writes [text] to [target] so the file is never half written: into a temporary file in the same directory, with
 * mode `0600`, then renamed over the target.
 *
 * The new file gets the owner of the old file (or of the directory). This matters when a command line action runs
 * as root next to a service with `DynamicUser`: the file must stay writable for the service.
 */
fun writeAtomically(target: File, text: String) = writeAtomically(target, text.toByteArray())

/** Byte variant of [writeAtomically]. */
fun writeAtomically(target: File, bytes: ByteArray) {
    val dir = target.absoluteFile.parentFile
    dir.mkdirs()
    val temp = Files.createTempFile(dir.toPath(), ".${target.name}.", ".tmp")
    try {
        setPermissions(temp, OWNER_ONLY_FILE)
        Files.write(temp, bytes)
        // On disk before the rename, so a power cut never leaves an empty file behind
        java.nio.channels.FileChannel.open(temp, java.nio.file.StandardOpenOption.WRITE).use { it.force(true) }
        copyOwner(from = if (target.exists()) target else dir, to = temp.toFile())
        Files.move(temp, target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } finally {
        Files.deleteIfExists(temp)
    }
}

/** Gives [to] the numeric owner and group of [from] if they differ. Only root may do that, otherwise nothing happens. */
fun copyOwner(from: File, to: File) {
    runCatching {
        val uid = Files.getAttribute(from.toPath(), "unix:uid") as Int
        val gid = Files.getAttribute(from.toPath(), "unix:gid") as Int
        if (Files.getAttribute(to.toPath(), "unix:uid") != uid) Files.setAttribute(to.toPath(), "unix:uid", uid)
        if (Files.getAttribute(to.toPath(), "unix:gid") != gid) Files.setAttribute(to.toPath(), "unix:gid", gid)
    }
}
