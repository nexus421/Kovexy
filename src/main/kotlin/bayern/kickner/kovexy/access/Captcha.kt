package bayern.kickner.kovexy.access

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.CaptchaConfig
import bayern.kickner.kovexy.config.RecaptchaVersion
import bayern.kickner.kovexy.randomToken
import bayern.kickner.kovexy.secureRandom
import bayern.kickner.kovexy.toBase64Url
import kotlinx.coroutines.future.await
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.util.Base64
import bayern.kickner.kovexy.config.parseIpLiteral
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private const val TAG = "Captcha"

/** Google's verification endpoint (Zoraxy `GoogleRecaptchaAPIv2v3`). */
const val GOOGLE_SITEVERIFY = "https://www.google.com/recaptcha/api/siteverify"

/** Name of the captcha cookie. The captcha only runs over HTTPS (decided on 18.11.2026). */
const val CAPTCHA_COOKIE = "__Host-kovexy-captcha"


/** A captcha page is valid this long, then it asks again. */
val CAPTCHA_PAGE_LIFETIME = 10.minutes


/** Signs and checks short texts with a key that is new on every start. A restart only ends pages that are open. */
class Signer {
    private val key = SecretKeySpec(ByteArray(32).also(secureRandom::nextBytes), "HmacSHA256")

    /** `payload` with its signature appended, `payload.signature`. The payload must not contain dots. */
    fun sign(payload: String): String = payload + "." + mac(payload)

    /** The payload of a signed text, `null` if the signature does not match. */
    fun verify(signed: String): String? {
        val payload = signed.substringBeforeLast('.', "")
        if (payload.isEmpty()) return null
        val expected = mac(payload).toByteArray()
        return if (MessageDigest.isEqual(expected, signed.substringAfterLast('.').toByteArray())) payload else null
    }

    private fun mac(payload: String): String = Mac.getInstance("HmacSHA256").apply { init(key) }.doFinal(payload.toByteArray()).toBase64Url()
}

private val b64 = Base64.getUrlEncoder().withoutPadding()
private val b64Decode = Base64.getUrlDecoder()

/** Base64url without padding, so the value contains no dot and fits into a signed text. */
fun encodePart(text: String): String = b64.encodeToString(text.toByteArray())

/** Reverse of [encodePart], `null` for garbage. */
fun decodePart(text: String): String? = runCatching { b64Decode.decode(text).decodeToString() }.getOrNull()

/** Solved captchas Kovexy keeps at most. The oldest go first when it is full, those visitors solve once more. */
const val MAX_CAPTCHA_SESSIONS = 100_000

/** reCAPTCHA checks one address may have running at Google at the same time. */
const val MAX_GOOGLE_CHECKS_PER_ADDRESS = 2

/** Expired captcha entries are removed at most this often, never on every request (audit run-2). */
private const val CAPTCHA_PURGE_MILLIS = 30_000L

/**
 * Solved captchas, only in memory like Zoraxy: a random ID in the cookie, valid for one profile on one domain until
 * it expires. A restart asks once more (decided on 17.11.2026). At most [MAX_CAPTCHA_SESSIONS], the oldest go first.
 */
class CaptchaSessions(private val max: Int = MAX_CAPTCHA_SESSIONS, private val clock: () -> Long = System::currentTimeMillis) {
    private class Entry(val scope: String, val expiresAt: Long)

    private val sessions = ConcurrentHashMap<String, Entry>()

    /** IDs in the order they were created, for removing the oldest. Trimmed with every purge. */
    private val order = ConcurrentLinkedQueue<String>()
    private val lastPurge = AtomicLong(0)

    /** Number of sessions held. */
    val size: Int get() = sessions.size

    /** Creates a session for [scope] valid for [lifetimeMillis] and returns its ID. */
    fun create(scope: String, lifetimeMillis: Long): String {
        val now = clock()
        val last = lastPurge.get()
        if (now - last > CAPTCHA_PURGE_MILLIS && lastPurge.compareAndSet(last, now)) {
            sessions.values.removeIf { it.expiresAt <= now }
            order.removeIf { sessions.containsKey(it).not() }
        }
        while (sessions.size >= max) sessions.remove(order.poll() ?: break)
        val id = randomToken()
        sessions[id] = Entry(scope, now + lifetimeMillis)
        order.add(id)
        return id
    }

    /** Whether [id] is a valid session for [scope]. */
    fun isValid(id: String?, scope: String): Boolean {
        val entry = id?.let { sessions[it] } ?: return false
        if (entry.expiresAt <= clock()) {
            sessions.remove(id)
            return false
        }
        return entry.scope == scope
    }
}

/**
 * Checks reCAPTCHA answers at Google on the server, like Zoraxy: `secret`, `response` and `remoteip` as form, `success`
 * must be true, for v3 the score must reach the threshold.
 *
 * @param endpoint Google's endpoint, tests pass a fake.
 */
class GoogleVerifier(private val endpoint: String = GOOGLE_SITEVERIFY) {
    private val http: HttpClient by lazy { HttpClient.newBuilder().connectTimeout(10.seconds.toJavaDuration()).followRedirects(HttpClient.Redirect.NEVER).build() }
    private val json = Json { ignoreUnknownKeys = true }
    private val running = ConcurrentHashMap<String, Int>()

    /**
     * [verify] with at most [MAX_GOOGLE_CHECKS_PER_ADDRESS] checks of one address (IPv6 per /64) at the same time, each
     * costs a call with the operator's key (decided on 19.11.2026).
     *
     * @return `null` if the address already has that many checks running.
     */
    suspend fun verifyLimited(config: CaptchaConfig, token: String, remoteIp: String): Boolean? {
        val key = parseIpLiteral(remoteIp)?.let { addressKey(java.net.InetAddress.getByAddress(it)) } ?: remoteIp
        var taken = true
        running.compute(key) { _, count -> ((count ?: 0) + 1).let { if (it > MAX_GOOGLE_CHECKS_PER_ADDRESS) count.also { taken = false } else it } }
        if (taken.not()) return null
        return try {
            verify(config, token, remoteIp)
        } finally {
            running.compute(key) { _, count -> count?.minus(1)?.takeIf { it > 0 } }
        }
    }

    suspend fun verify(config: CaptchaConfig, token: String, remoteIp: String): Boolean {
        if (token.isBlank()) return false
        val form = listOf("secret" to config.secretKey, "response" to token, "remoteip" to remoteIp)
            .joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, Charsets.UTF_8)}" }
        val request = HttpRequest.newBuilder(URI(endpoint)).timeout(10.seconds.toJavaDuration())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(form)).build()
        return runCatching {
            val response = http.sendAsync(request, HttpResponse.BodyHandlers.ofString()).await()
            val body = json.parseToJsonElement(response.body().take(100_000)).jsonObject
            val success = body["success"]?.jsonPrimitive?.booleanOrNull == true
            val score = body["score"]?.jsonPrimitive?.doubleOrNull ?: 0.0
            success && (config.recaptchaVersion == RecaptchaVersion.V2 || score >= config.recaptchaScore)
        }.onFailure { staticLog(KLogger.Level.WARN, TAG) { "reCAPTCHA verification failed: ${it.message}" } }.getOrDefault(false)
    }
}

/**
 * Everything the captcha needs: sessions, the Google check, and the signed page token that carries the profile, the
 * domain and the address to return to through the form.
 */
class CaptchaService(
    val google: GoogleVerifier = GoogleVerifier(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val signer = Signer()

    /** Solved captchas. */
    val sessions = CaptchaSessions(clock = clock)

    /** The scope of a session: one profile on one domain. */
    fun scope(profile: String, domain: String) = "$profile|$domain"

    /** The signed token of a captcha page. */
    fun pageToken(profile: String, domain: String, returnTo: String): String =
        signer.sign("${encodePart(profile)}~${encodePart(domain)}~${encodePart(returnTo)}~${clock() + CAPTCHA_PAGE_LIFETIME.inWholeMilliseconds}")

    /** Profile, domain and return address of a page token, `null` if forged or expired. */
    fun readPageToken(token: String): Triple<String, String, String>? {
        val parts = signer.verify(token)?.split('~')?.takeIf { it.size == 4 } ?: return null
        if ((parts[3].toLongOrNull() ?: 0) < clock()) return null
        return Triple(decodePart(parts[0]) ?: return null, decodePart(parts[1]) ?: return null, decodePart(parts[2]) ?: return null)
    }
}

/**
 * Whether [path] is protected by the captcha: [CaptchaConfig.protectedPaths] (empty means all, prefixes at path
 * boundaries like locations) and not excepted.
 */
fun captchaApplies(config: CaptchaConfig, path: String, excepted: Boolean): Boolean {
    if (excepted) return false
    if (config.protectedPaths.isEmpty()) return true
    return config.protectedPaths.any { p -> p == "/" || path == p.trimEnd('/') || path.startsWith(p.trimEnd('/') + "/") }
}

/** A return address is only taken when it is a path on the same host, never `//host` or a full URL. */
fun safeReturnPath(value: String?): String {
    val text = value.orEmpty()
    return if (text.startsWith("/") && text.startsWith("//").not() && '\\' !in text && text.none { it.isISOControl() }) text else "/"
}
