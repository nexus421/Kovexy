package bayern.kickner.kovexy.backup

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.Kovexy
import bayern.kickner.kovexy.OWNER_ONLY_FILE
import bayern.kickner.kovexy.config.CONFIG_FILE_NAME
import bayern.kickner.kovexy.config.KovexyConfig
import bayern.kickner.kovexy.config.SaveError
import bayern.kickner.kovexy.config.parseConfig
import bayern.kickner.kovexy.config.writeAtomically
import bayern.kickner.kovexy.ensurePrivateDir
import bayern.kickner.kovexy.setPermissions
import bayern.kickner.kovexy.stats.DATABASE_FILE_NAME
import bayern.kickner.kovexy.ResultOf2
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

private const val TAG = "Backup"

/** Largest backup accepted for a restore, compressed. */
const val MAX_BACKUP_BYTES = 512L * 1024 * 1024

/** Largest sum of the unpacked entries, so a zip bomb cannot fill the disk or the heap. */
private const val MAX_UNPACKED_BYTES = 1024L * 1024 * 1024

/** Most entries in a backup. */
private const val MAX_ENTRIES = 10_000

/** Restore points kept in `<dataDir>/backups`. */
private const val RESTORE_POINTS_KEPT = 10

/** The only certificate files a backup may contain: a key or chain in a domain directory or the ACME account key. */
private val certEntry = """certs/(?!\.{1,2}/)[a-z0-9.-]{1,253}/(fullchain|privkey|account)\.pem""".toRegex()

private val stampFormat = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault())

/** Restore point names in UTC with milliseconds, so they sort right across a DST change and never collide. */
private val restorePointFormat = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS").withZone(ZoneOffset.UTC)

/** File name of a backup download. */
fun backupFileName(now: Long): String = "kovexy-backup-${stampFormat.format(Instant.ofEpochMilli(now))}.zip"

/**
 * Writes a backup ZIP like Zoraxy's: `kovexy.json`, every file below `certs/` and, if [includeDatabase], a consistent
 * copy of `kovexy.db`. Not encrypted, it holds the private keys of the certificates. Every file is streamed, the
 * database can be larger than the heap.
 */
fun Kovexy.writeBackup(out: OutputStream, includeDatabase: Boolean) {
    ZipOutputStream(out).use { zip ->
        if (configStore.file.isFile) zip.add(CONFIG_FILE_NAME, configStore.file)
        certStore.dir.walkTopDown().filter { it.isFile && it.name.endsWith(".pem") }.forEach { file ->
            zip.add("certs/" + file.relativeTo(certStore.dir).invariantSeparatorsPath, file)
        }
        if (includeDatabase) {
            val copy = File(dataDir, ".backup-${System.nanoTime()}.db")
            try {
                storage.copyTo(copy)
                zip.add(DATABASE_FILE_NAME, copy)
            } finally {
                copy.delete()
            }
        }
    }
}

private fun ZipOutputStream.add(name: String, file: File) {
    putNextEntry(ZipEntry(name))
    file.inputStream().use { it.copyTo(this) }
    closeEntry()
}

/**
 * Restores a backup while running. The ZIP is checked completely first: only known entries, a valid config, size
 * limits. Then the current state is saved as restore point in `<dataDir>/backups`, the certificates and the
 * database (if contained) are replaced and the config is applied like any other change. The fallback certificate is
 * kept, it is generated per installation. A restored database ends every admin login, the restoring admin
 * logs in again.
 *
 * @param zip The uploaded backup on disk.
 * @return `null` on success, else why nothing was restored.
 */
suspend fun Kovexy.restoreBackup(zip: File): String? {
    val database = File(dataDir, ".restore-${System.nanoTime()}.db")
    try {
        val entries = runCatching { readEntries(zip, database) }.getOrElse { return it.message ?: "Not a valid backup ZIP" }
        val configText = entries[CONFIG_FILE_NAME]?.decodeToString() ?: return "The backup has no $CONFIG_FILE_NAME"
        val config: KovexyConfig = when (val parsed = parseConfig(configText)) {
            is ResultOf2.Success -> parsed.value
            is ResultOf2.Failure -> return "The configuration in the backup is invalid: " + parsed.value.joinToString(", ")
        }

        saveRestorePoint()
        entries.filterKeys { certEntry.matches(it) && it.startsWith("certs/fallback/").not() }.forEach { (name, bytes) ->
            val target = File(certStore.dir, name.removePrefix("certs/"))
            ensurePrivateDir(target.parentFile)
            writeAtomically(target, bytes)
        }
        if (database.isFile) {
            storage.restoreFrom(database)
            bans.reload()
            // Sessions in the backup may have been ended since (logout, password change, removed subject). Restoring
            // them would let them back in, so a restore ends every admin login, the own one too (audit run-2)
            sessions.removeAll()
        }
        certificates.loadStored()
        return when (val result = configStore.update(null) { config }) {
            is ResultOf2.Success -> {
                staticLog(KLogger.Level.INFO, TAG) { "Backup restored" }
                null
            }

            is ResultOf2.Failure -> when (val error = result.value) {
                is SaveError.Invalid -> "The configuration in the backup is invalid: " + error.problems.joinToString(", ")
                is SaveError.Io -> "Writing the configuration failed: ${error.message}"
                SaveError.Conflict -> "The configuration changed meanwhile, try again"
            }
        }
    } finally {
        database.delete()
    }
}

/**
 * Reads and checks every entry of a backup. The config and the certificates are small and kept in memory, the
 * database is unpacked into [database].
 */
private fun readEntries(zipFile: File, database: File): Map<String, ByteArray> {
    val entries = mutableMapOf<String, ByteArray>()
    var count = 0
    var total = 0L
    val buffer = ByteArray(64 * 1024)
    ZipInputStream(zipFile.inputStream().buffered()).use { zip ->
        while (true) {
            val entry = zip.nextEntry ?: break
            if (entry.isDirectory) continue
            val name = entry.name
            require(name == CONFIG_FILE_NAME || name == DATABASE_FILE_NAME || certEntry.matches(name)) { "Unexpected file in the backup: $name" }
            require(++count <= MAX_ENTRIES) { "Too many files in the backup" }
            val out = if (name == DATABASE_FILE_NAME) database.outputStream() else ByteArrayOutputStream()
            out.use {
                while (true) {
                    val n = zip.read(buffer)
                    if (n < 0) break
                    total += n
                    require(total <= MAX_UNPACKED_BYTES) { "The backup unpacks to more than 1 GiB" }
                    it.write(buffer, 0, n)
                }
            }
            if (out is ByteArrayOutputStream) entries[name] = out.toByteArray()
        }
    }
    require(count > 0) { "The file is no backup ZIP" }
    if (database.isFile) setPermissions(database.toPath(), OWNER_ONLY_FILE)
    return entries
}

/** Saves the current state as `backups/restore-<time>.zip` and keeps the newest [RESTORE_POINTS_KEPT]. */
private fun Kovexy.saveRestorePoint() {
    val dir = ensurePrivateDir(File(dataDir, "backups"))
    val file = File(dir, "restore-${restorePointFormat.format(Instant.ofEpochMilli(clock()))}.zip")
    file.outputStream().use { writeBackup(it, includeDatabase = true) }
    setPermissions(file.toPath(), OWNER_ONLY_FILE)
    dir.listFiles { f -> f.name.startsWith("restore-") && f.name.endsWith(".zip") }
        ?.sortedByDescending { it.name }?.drop(RESTORE_POINTS_KEPT)?.forEach { it.delete() }
}
