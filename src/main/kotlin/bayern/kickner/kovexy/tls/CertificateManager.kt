package bayern.kickner.kovexy.tls

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.LETS_ENCRYPT_PRODUCTION
import bayern.kickner.kovexy.config.LETS_ENCRYPT_STAGING
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.formatTimestamp
import bayern.kickner.kovexy.notify.Event
import bayern.kickner.kovexy.notify.EventSink
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private const val TAG = "Certificates"

/** Time between two maintenance rounds, like Caddy. */
val MAINTENANCE_INTERVAL = 10.minutes

/**
 * Waiting times after the 1st, 2nd, ... failed attempt, exactly Caddy's `retryIntervals` (certmagic `async.go`, copy
 * in the concept's evidence). After the last entry every further attempt waits 6 hours.
 */
val RETRY_INTERVALS: List<Duration> = listOf(
    1.minutes, 2.minutes, 2.minutes, 5.minutes,
    10.minutes, 10.minutes, 10.minutes, 20.minutes,
    20.minutes, 20.minutes, 20.minutes,
    30.minutes, 30.minutes, 30.minutes, 30.minutes, 30.minutes, 30.minutes,
    1.hours, 1.hours, 1.hours,
    2.hours, 2.hours,
    3.hours, 3.hours,
    6.hours,
)

/** After failing for this long, Kovexy stops trying until the domain changes or somebody renews it by hand. */
val MAX_RETRY_DURATION = 30.days

/**
 * State of one domain's certificate, for the admin UI.
 *
 * @property domain The domain.
 * @property notBefore Start of validity of the installed certificate, Unix milliseconds, `null` without one.
 * @property notAfter End of validity, Unix milliseconds.
 * @property issuer Issuer of the installed certificate.
 * @property lastError Message of the last failed attempt, `null` after a success.
 * @property failingSince Unix milliseconds of the first failure in a row.
 * @property nextAttempt Unix milliseconds of the next attempt after a failure.
 * @property gaveUp Retried for [MAX_RETRY_DURATION] without success, no further attempts.
 * @property wanted Whether a domain still uses the domain. Unused certificates are kept but not renewed.
 */
data class CertificateStatus(
    val domain: String,
    val notBefore: Long?,
    val notAfter: Long?,
    val issuer: String?,
    val lastError: String?,
    val failingSince: Long?,
    val nextAttempt: Long?,
    val gaveUp: Boolean,
    val wanted: Boolean,
)

/** Failures in a row of one domain. */
private data class Failures(val count: Int, val since: Long, val nextAttempt: Long, val lastError: String, val gaveUp: Boolean)

/**
 * Keeps one certificate per domain valid, like Caddy:
 *
 * - every [MAINTENANCE_INTERVAL] and after every config change it checks every wanted domain,
 * - a domain without certificate, or in the last third of its certificate's lifetime, gets a new one,
 * - a failure is retried after the waiting times in [RETRY_INTERVALS], for at most [MAX_RETRY_DURATION],
 * - while a domain fails against Let's Encrypt production, the retries run against Let's Encrypt staging so the
 *   production rate limits are not hit. After a success on staging the real certificate comes from production.
 *
 * New certificates go to disk and into the [DynamicKeyManager] at once, nothing restarts. A certificate of a domain
 * that is no longer wanted stays until it expires, so a domain that comes back reuses it (Let's Encrypt allows only
 * five identical certificates per week). Once expired it is deleted (decided on 18.11.2026).
 *
 * @param store Certificates on disk.
 * @param keyManager Certificates in use.
 * @param issuer Orders certificates.
 * @param events Receives issued and failed events.
 * @param directory The ACME directory from the config, read on every attempt.
 * @param onRemoved Called with the domain after an expired, unused certificate was deleted, for the audit log.
 * @param clock Unix milliseconds.
 */
class CertificateManager(
    private val store: CertStore,
    private val keyManager: DynamicKeyManager,
    private val issuer: CertificateIssuer,
    private val events: EventSink,
    private val directory: () -> String,
    private val onRemoved: (String) -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
) {
    @Volatile
    private var wanted: Set<String> = emptySet()
    private val failures = ConcurrentHashMap<String, Failures>()
    private val wakeUp = Channel<Unit>(Channel.CONFLATED)

    /** Installs every certificate from disk. Called once at startup, before the TLS port opens. */
    fun loadStored() {
        store.storedDomains().forEach { domain ->
            store.load(domain)?.let { keyManager.install(domain, it.key, it.chain) }
        }
    }

    /**
     * Sets the domains that need a certificate (every domain of an enabled domain on the TLS listener) and checks them
     * soon. A domain that is wanted again starts with a fresh retry budget.
     */
    fun setWanted(domains: Set<String>) {
        val added = domains - wanted
        added.forEach { failures.remove(it) }
        wanted = domains
        wakeUp.trySend(Unit)
    }

    /** Clears the failure state of [domain] and checks it at once, even if its certificate is still fresh. */
    fun renewNow(domain: String) {
        failures.remove(domain)
        forced += domain
        wakeUp.trySend(Unit)
    }

    private val forced = ConcurrentHashMap.newKeySet<String>()

    /** Starts the maintenance loop in [scope]. */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    fun start(scope: CoroutineScope): Job = scope.launch(Dispatchers.IO) {
        while (true) {
            runCatching { maintain() }.onFailure {
                staticLog(KLogger.Level.ERROR, TAG) { "Certificate maintenance failed: ${it.stackTraceToString()}" }
            }
            select {
                wakeUp.onReceive { }
                onTimeout(nextWakeUp()) { }
            }
            // Several config saves in a row should lead to one round
            delay(200)
        }
    }

    /** Time until the next due retry or the next regular round, whatever comes first. */
    private fun nextWakeUp(): Long {
        val now = clock()
        val retry = failures.values.filter { it.gaveUp.not() }.minOfOrNull { it.nextAttempt - now }
        return listOfNotNull(retry, MAINTENANCE_INTERVAL.inWholeMilliseconds).min().coerceAtLeast(1000)
    }

    /** One round over every wanted domain, then removal of expired unused certificates. Public for tests. */
    fun maintain() {
        removeExpiredUnused()
        wanted.sorted().forEach { domain ->
            if (needsCertificate(domain).not()) return@forEach
            val failure = failures[domain]
            val isForced = forced.remove(domain)
            if (isForced.not() && failure != null && (failure.gaveUp || clock() < failure.nextAttempt)) return@forEach
            obtain(domain, failure)
        }
    }

    private fun removeExpiredUnused() {
        val now = clock()
        (keyManager.domains() + store.storedDomains()).filter { it !in wanted }.forEach { domain ->
            val notAfter = (keyManager.certificateOf(domain) ?: store.load(domain)?.chain?.firstOrNull())?.notAfter?.time ?: return@forEach
            if (notAfter > now) return@forEach
            keyManager.remove(domain)
            store.delete(domain)
            failures.remove(domain)
            staticLog(KLogger.Level.INFO, TAG) { "Removed the expired certificate of $domain, no domain uses it any more" }
            onRemoved(domain)
        }
    }

    /** Whether [domain] has no certificate, or one in the last third of its lifetime, or one that is not wanted. */
    private fun needsCertificate(domain: String): Boolean {
        if (domain in forced) return true
        val cert = keyManager.certificateOf(domain) ?: return true
        val start = cert.notBefore.time
        val end = cert.notAfter.time
        val renewAt = start + (end - start) * 2 / 3
        return clock() >= renewAt
    }

    private fun obtain(domain: String, failure: Failures?) {
        val configured = directory()
        val retryOnStaging = failure != null && configured == LETS_ENCRYPT_PRODUCTION
        val result = runCatching {
            if (retryOnStaging) {
                staticLog(KLogger.Level.INFO, TAG) { "Retrying $domain against Let's Encrypt staging first" }
                issuer.issue(domain, LETS_ENCRYPT_STAGING)
            }
            issuer.issue(domain, configured)
        }
        result.onSuccess { bundle ->
            // Installed first: a failed save must not lead to ordering again and again (Let's Encrypt limits duplicates)
            keyManager.install(domain, bundle.key, bundle.chain)
            failures.remove(domain)
            runCatching { store.save(domain, bundle) }.onFailure { error ->
                recordFailure(domain, null, IllegalStateException("issued but not saved, it is lost on restart: ${error.message}"))
            }
            events.emit(
                Event(
                    WebhookEvent.CERT_ISSUED,
                    "Certificate for $domain issued",
                    "The certificate for $domain is valid until ${formatTimestamp(bundle.leaf.notAfter.time)}.",
                    domain = domain,
                    time = clock(),
                )
            )
        }
        result.onFailure { error -> recordFailure(domain, failure, error) }
    }

    private fun recordFailure(domain: String, previous: Failures?, error: Throwable) {
        val now = clock()
        val count = (previous?.count ?: 0) + 1
        val since = previous?.since ?: now
        val wait = RETRY_INTERVALS.getOrElse(count - 1) { RETRY_INTERVALS.last() }
        val gaveUp = now - since >= MAX_RETRY_DURATION.inWholeMilliseconds
        val message = error.message ?: error.toString()
        failures[domain] = Failures(count, since, now + wait.inWholeMilliseconds, message, gaveUp)
        val next = if (gaveUp) "Kovexy stops trying after 30 days, renew it by hand in the admin UI." else "Next attempt at ${formatTimestamp(now + wait.inWholeMilliseconds)}."
        staticLog(KLogger.Level.WARN, TAG) { "Certificate for $domain failed (attempt $count): $message. $next" }
        events.emit(
            Event(
                WebhookEvent.CERT_FAILED,
                "Certificate for $domain failed",
                "Attempt $count failed: $message\n$next",
                domain = domain,
                time = now,
            )
        )
    }

    /** Status of every wanted domain and every stored certificate, sorted by domain. */
    fun status(): List<CertificateStatus> {
        val domains = (wanted + keyManager.domains()).sorted()
        return domains.map { domain ->
            val cert = keyManager.certificateOf(domain)
            val failure = failures[domain]
            CertificateStatus(
                domain = domain,
                notBefore = cert?.notBefore?.time,
                notAfter = cert?.notAfter?.time,
                issuer = cert?.issuerX500Principal?.name,
                lastError = failure?.lastError,
                failingSince = failure?.since,
                nextAttempt = failure?.nextAttempt?.takeIf { failure.gaveUp.not() },
                gaveUp = failure?.gaveUp == true,
                wanted = domain in wanted,
            )
        }
    }
}
