package bayern.kickner.kovexy

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.slf4j.slf4jBridge
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.auth.generatePassword
import bayern.kickner.kovexy.auth.hashPassword
import bayern.kickner.kovexy.config.ConfigStore
import bayern.kickner.kovexy.config.LoginMode
import bayern.kickner.kovexy.config.SaveError
import kotnexlib.ResultOf2
import java.io.File
import java.net.BindException
import java.util.concurrent.CountDownLatch
import kotlin.system.exitProcess

private const val TAG = "Main"

/** Default data directory, the `StateDirectory` of the systemd unit. */
const val DEFAULT_DATA_DIR = "/var/lib/kovexy"

/** Exit code for an unknown argument (`EX_USAGE` from sysexits.h), like KNot. */
const val EXIT_USAGE = 64

/** Exit code for a rejected config or a port that cannot be bound (`EX_CONFIG`), systemd does not restart on it. */
const val EXIT_CONFIG = 78

private const val USAGE = "Usage: java -jar kovexy.jar [dataDir=<path>] [check | reset-password | login-mode=password]"

/**
 * Entry point.
 *
 * Arguments are `key=value` pairs and bare words, like KNot and Dirl:
 * - `dataDir=<path>` data directory, default [DEFAULT_DATA_DIR].
 * - `check` validates `kovexy.json` and exits.
 * - `reset-password` sets a new random admin password, prints it once and exits. A running service picks it up.
 * - `login-mode=password` switches the login to password only, e.g. when the OIDC provider is down. A running
 *   service picks it up.
 *
 * Exit codes: `0` success, `1` unexpected failure, [EXIT_USAGE] unknown argument, [EXIT_CONFIG] rejected config or
 * a port that cannot be bound, `143` after `systemctl stop` (SIGTERM).
 */
fun main(args: Array<String>) {
    val unknown = args.filterNot(::isKnownArgument)
    if (unknown.isNotEmpty()) {
        System.err.println("Unknown argument(s): ${unknown.joinToString(" ")}. $USAGE")
        exitProcess(EXIT_USAGE)
    }
    val dataDir = File(args.firstOrNull { it.startsWith("dataDir=") }?.substringAfter('=') ?: DEFAULT_DATA_DIR)
    val store = ConfigStore(dataDir)
    // Command line actions often run as root, they never follow symbolic links in the data directory
    val cliStore = ConfigStore(dataDir, followLinks = false)

    when {
        "reset-password" in args -> exitProcess(resetPassword(cliStore))
        args.any { it.startsWith("login-mode=") } -> exitProcess(setPasswordLogin(cliStore))
        "check" in args -> exitProcess(check(cliStore))
    }

    when (val loaded = store.load()) {
        is ResultOf2.Success -> Unit
        is ResultOf2.Failure -> {
            System.err.println("${store.file.absolutePath} rejected:")
            loaded.value.forEach { System.err.println("  - $it") }
            exitProcess(EXIT_CONFIG)
        }
    }
    if (dataDir.exists().not()) ensurePrivateDir(dataDir)
    configureLogging(File(dataDir, "logs"))
    staticLog(KLogger.Level.INFO, TAG) { "Kovexy $appVersion starting, data in ${dataDir.absolutePath}" }
    ensureAdminPassword(store)

    val kovexy = createKovexy(store, latestRelease = ::fetchLatestRelease)
    runCatching { kovexy.start() }.onFailure {
        val bindFailed = generateSequence(it) { e -> e.cause }.any { e -> e is BindException }
        staticLog(KLogger.Level.CRASH, TAG) { "Kovexy could not start: ${if (bindFailed) it.message else it.stackTraceToString()}" }
        KLogger.flush()
        exitProcess(if (bindFailed) EXIT_CONFIG else 1)
    }
    val stopped = CountDownLatch(1)
    Runtime.getRuntime().addShutdownHook(Thread {
        staticLog(KLogger.Level.INFO, TAG) { "Shutting down" }
        kovexy.stop()
        KLogger.flush()
        stopped.countDown()
    })
    stopped.await()
}

/** True for every argument Kovexy knows. */
private fun isKnownArgument(arg: String) =
    arg == "check" || arg == "reset-password" || arg == "login-mode=password" || arg.startsWith("dataDir=")

/** Validates the config file and prints the result. */
private fun check(store: ConfigStore): Int = when (val result = store.read()) {
    is ResultOf2.Success -> {
        println("${store.file.absolutePath} is valid")
        0
    }

    is ResultOf2.Failure -> {
        System.err.println("${store.file.absolutePath} rejected:")
        result.value.forEach { System.err.println("  - $it") }
        EXIT_CONFIG
    }
}

/** Sets a new random password and prints it once on stdout, so `PW=$(... reset-password)` captures only it. */
private fun resetPassword(store: ConfigStore): Int {
    val password = generatePassword()
    val hash = hashPassword(password)
    return report(store, store.update { it.copy(admin = it.admin.copy(passwordHash = hash)) }) {
        System.err.println("New admin password, shown only this once. A running Kovexy uses it at once and ends every session:")
        println(password)
    }
}

/** Switches the login to password only. */
private fun setPasswordLogin(store: ConfigStore): Int =
    report(store, store.update { it.copy(admin = it.admin.copy(loginMode = LoginMode.PASSWORD)) }) {
        println("Login mode set to password only. A running Kovexy uses it at once.")
    }

private fun report(store: ConfigStore, result: ResultOf2<*, SaveError>, onSuccess: () -> Unit): Int = when (result) {
    is ResultOf2.Success -> {
        onSuccess()
        0
    }

    is ResultOf2.Failure -> {
        when (val error = result.value) {
            is SaveError.Invalid -> {
                System.err.println("${store.file.absolutePath} rejected, nothing changed:")
                error.problems.forEach { System.err.println("  - $it") }
            }

            is SaveError.Io -> System.err.println("Cannot write the config: ${error.message}")
            SaveError.Conflict -> System.err.println("The config changed meanwhile, try again")
        }
        EXIT_CONFIG
    }
}

/**
 * On the first start the config has no password hash yet: a random password is created, its hash saved and the
 * password printed once to the log.
 */
private fun ensureAdminPassword(store: ConfigStore) {
    if (store.current.config.admin.passwordHash.isNotEmpty()) return
    val password = generatePassword()
    val hash = hashPassword(password)
    when (val result = store.update { it.copy(admin = it.admin.copy(passwordHash = hash)) }) {
        is ResultOf2.Success -> staticLog(KLogger.Level.WARN, TAG) {
            "No admin password set yet. Created one, it is shown only this once: $password (change it in the admin UI under Settings)"
        }

        is ResultOf2.Failure -> staticLog(KLogger.Level.ERROR, TAG) { "Cannot save the initial admin password: ${result.value}" }
    }
}

/**
 * Console (journald) plus a rotating `app.log`. Every line goes through [escapeLogMessage], so values from requests
 * cannot forge log lines. Libraries log through SLF4J into Klogger, Jetty and Exposed only from WARN on.
 */
private fun configureLogging(logDir: File) {
    ensurePrivateDir(logDir)
    val logFile = File(logDir, "app.log")
    val base = KLogger.defaultFormat()
    KLogger.configure {
        logToConsole()
        logToFile(logFile, maxFileSize = 5L * 1024 * 1024)
        format { level, tag, message -> base(level, tag, escapeLogMessage(message)) }
        slf4jBridge {
            minLevel = KLogger.Level.INFO
            level("org.eclipse.jetty", KLogger.Level.WARN)
            level("Exposed", KLogger.Level.WARN)
            level("org.jetbrains.exposed", KLogger.Level.WARN)
            level("io.ktor", KLogger.Level.WARN)
            level("org.shredzone.acme4j", KLogger.Level.WARN)
        }
    }
    if (logFile.exists().not()) logFile.createNewFile()
    restrictToOwner(logFile)
}
