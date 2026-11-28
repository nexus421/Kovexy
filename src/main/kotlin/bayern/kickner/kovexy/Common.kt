package bayern.kickner.kovexy

import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.HexFormat
import java.util.Locale

/**
 * Format of every timestamp this project prints, e.g. `15.10.2026 19:40:12 CEST`. Pinned to [Locale.ENGLISH] so the
 * zone abbreviation stays the same on every host.
 */
val timestampFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss z", Locale.ENGLISH)

/** Formats Unix milliseconds with [timestampFormat] in the host's time zone. */
fun formatTimestamp(epochMillis: Long): String =
    Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault()).format(timestampFormat)

/** Version and build time for the start banner and the page footer. */
val appVersion: String = "${BuildConfig.VERSION} (built ${formatTimestamp(BuildConfig.BUILD_TIME)})"

/** One shared generator. `SecureRandom()` uses the non-blocking system source on Linux. */
val secureRandom: SecureRandom = SecureRandom()

/** URL-safe Base64 without padding, the encoding of tokens. */
private val base64Url = Base64.getUrlEncoder().withoutPadding()

/** Encodes as URL-safe Base64 without padding. */
fun ByteArray.toBase64Url(): String = base64Url.encodeToString(this)

/** Returns [bytes] random bytes encoded as URL-safe Base64. Used for session tokens and generated passwords. */
fun randomToken(bytes: Int = 32, random: SecureRandom = secureRandom): String =
    ByteArray(bytes).also(random::nextBytes).toBase64Url()

/** SHA-256 of the UTF-8 bytes of [text] as lower case hex. */
fun sha256Hex(text: String): String = sha256Hex(text.toByteArray())

/** SHA-256 of [bytes] as lower case hex. */
fun sha256Hex(bytes: ByteArray): String =
    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))

/** Overwrites the array with zeros. Best effort only: the JVM may have copied the contents before. */
fun CharArray.wipe() = fill('\u0000')

/** `rw-------`, for every file Kovexy writes that may hold a secret. */
val OWNER_ONLY_FILE: Set<PosixFilePermission> = PosixFilePermissions.fromString("rw-------")

/** `rwx------`, for directories holding keys and backups. */
val OWNER_ONLY_DIR: Set<PosixFilePermission> = PosixFilePermissions.fromString("rwx------")

/**
 * Limits [file] to its owner (`0600`). Defense in depth next to `UMask=0077` in the systemd unit, ignored on file
 * systems without POSIX permissions.
 */
fun restrictToOwner(file: File) = setPermissions(file.toPath(), OWNER_ONLY_FILE)

/** Creates [dir] if needed and limits it to its owner (`0700`). */
fun ensurePrivateDir(dir: File): File {
    dir.mkdirs()
    setPermissions(dir.toPath(), OWNER_ONLY_DIR)
    return dir
}

/** Sets POSIX permissions, ignored on file systems without them. */
fun setPermissions(path: Path, permissions: Set<PosixFilePermission>) {
    runCatching { Files.setPosixFilePermissions(path, permissions) }
}

/**
 * Reads the stream up to its end, but at most [max] bytes. Everything a remote server sends is untrusted, a
 * compromised server could otherwise stream until the heap is gone.
 *
 * @return the bytes, or `null` if the stream holds more than [max] bytes.
 */
fun InputStream.readAtMost(max: Int): ByteArray? {
    val bytes = readNBytes(max + 1)
    return if (bytes.size > max) null else bytes
}

private val whitespace = "\\s+".toRegex()

/** Control characters such as line breaks and tabs, they become a space so the words around them stay apart. */
private val controlChar = "\\p{Cc}".toRegex()

/** Invisible formatting characters such as U+202E, which turns the text after it around on screen. */
private val formatChar = "\\p{Cf}".toRegex()

/**
 * Untrusted text as it may be shown and logged: no control or formatting characters (which could hide or reorder
 * text, or forge log lines), whitespace collapsed, at most [max] characters.
 *
 * @return the cleaned text, `null` if nothing is left.
 */
fun cleanText(raw: String, max: Int): String? = raw
    .replace(controlChar, " ")
    .replace(formatChar, "")
    .replace(whitespace, " ").trim().take(max).trim().ifEmpty { null }

/**
 * Makes one log message safe for a line based log: control characters become escape sequences (`\u001b`), so a
 * value from a request can never forge a log line or move the cursor of a terminal. Line breaks stay, every
 * following line is indented, so a stack trace still reads as one entry. Tabs become four spaces.
 */
fun escapeLogMessage(message: String): String = buildString(message.length + 16) {
    var index = 0
    while (index < message.length) {
        val char = message[index]
        when {
            char == '\r' && message.getOrNull(index + 1) == '\n' -> Unit
            char == '\n' || char == '\r' -> append("\n    ")
            char == '\t' -> append("    ")
            Character.getType(char) == Character.CONTROL.toInt() || Character.getType(char) == Character.FORMAT.toInt() ->
                append("\\u").append(String.format(Locale.ROOT, "%04x", char.code))
            else -> append(char)
        }
        index++
    }
}

/**
 * Whether [this] means the visitor closed the connection while Kovexy still wrote to it, for example "Broken pipe" or
 * an HTTP/2 reset. Jetty reports both as `EofException`, which only its server side throws, so a failing backend never
 * counts as such. A visitor who leaves is no error of Kovexy and is never logged with a stack trace.
 */
fun Throwable.isVisitorDisconnect(): Boolean = generateSequence(this) { it.cause }.any { it is org.eclipse.jetty.io.EofException }
