package bayern.kickner.kovexy.notify

import bayern.kickner.klogger.KLogger
import bayern.kickner.klogger.staticLog
import bayern.kickner.kovexy.config.WebhookConfig
import bayern.kickner.kovexy.config.WebhookEvent
import bayern.kickner.kovexy.formatTimestamp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.await
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private const val TAG = "Webhooks"

/** Waits between the three attempts, like KNot's mail delivery. */
private val RETRY_DELAYS = listOf(1.seconds, 3.seconds)

/** Events that can come in large numbers and are bundled. */
val BUNDLED_EVENTS = setOf(WebhookEvent.IP_BANNED, WebhookEvent.ADMIN_LOGIN_FAILED)

/** Most items listed in one bundled message. */
private const val MAX_BUNDLE_ITEMS = 50

/** Most items a bundle keeps, further ones are only counted. Anonymous failed logins could otherwise fill the memory. */
private const val MAX_BUNDLE_KEPT = 100

private val http: HttpClient by lazy {
    HttpClient.newBuilder().connectTimeout(10.seconds.toJavaDuration()).followRedirects(HttpClient.Redirect.NEVER).build()
}

/** The placeholder name of an event, its JSON name, e.g. `certIssued`. */
val WebhookEvent.key: String
    get() = WebhookEvent::class.java.getField(name).getAnnotation(SerialName::class.java)?.value ?: name

/**
 * Fills the placeholders of [template]. Values are escaped as JSON string content, so a template like
 * `{"subject": "{{subject}}"}` stays valid JSON whatever the text contains.
 */
fun fillTemplate(template: String, event: Event): String {
    val values = mapOf(
        "event" to event.type.key,
        "subject" to event.subject,
        "body" to event.body,
        "time" to formatTimestamp(event.time),
        "site" to event.site,
    )
    return values.entries.fold(template) { text, (name, value) -> text.replace("{{$name}}", jsonEscape(value)) }
}

/** [value] escaped as the content of a JSON string, without the quotes. */
fun jsonEscape(value: String): String = Json.encodeToString(JsonPrimitive.serializer(), JsonPrimitive(value)).removeSurrounding("\"")

/** Open bundle of one webhook and event type. */
private class Bundle(val until: Long, val items: MutableList<Event> = mutableListOf()) {
    /** Items beyond [MAX_BUNDLE_KEPT], only counted. */
    var dropped = 0
}

/**
 * Sends events to the configured webhooks. Each target gets a `POST` with its filled template for the events it
 * selected. Delivery runs in the background, three attempts with 1 and 3 seconds in between.
 *
 * Events in [BUNDLED_EVENTS] are bundled per target: the first one goes out at once, further ones of the same kind
 * within the target's `bundleWindow` are sent together at its end, e.g. "37 more failed admin logins".
 *
 * @param scope Runs deliveries and bundle timers.
 * @param targets The webhooks of the current config, read for every event.
 * @param clock Unix milliseconds.
 * @param send Sends one request and returns the status code, replaceable in tests.
 */
class Webhooks(
    private val scope: CoroutineScope,
    private val targets: () -> List<WebhookConfig>,
    private val clock: () -> Long = System::currentTimeMillis,
    private val send: suspend (WebhookConfig, String) -> Int = ::post,
) : EventSink {
    private val bundles = ConcurrentHashMap<Pair<String, WebhookEvent>, Bundle>()

    override fun emit(event: Event) {
        targets().filter { event.type in it.events }.forEach { target ->
            if (event.type in BUNDLED_EVENTS) bundle(target, event) else deliver(target, event)
        }
    }

    private fun bundle(target: WebhookConfig, event: Event) {
        val key = target.name to event.type
        val now = clock()
        var started: Bundle? = null
        bundles.compute(key) { _, open ->
            if (open != null && open.until > now) {
                if (open.items.size < MAX_BUNDLE_KEPT) open.items += event else open.dropped++
                open
            } else {
                Bundle(now + target.bundleWindow.inWholeMilliseconds).also { started = it }
            }
        }
        val bundle = started ?: return
        deliver(target, event)
        scope.launch {
            delay(target.bundleWindow)
            // Only this window: a newer one may already be in the map. Its own items are sent even if it was replaced
            bundles.remove(key, bundle)
            if (bundle.items.isEmpty()) return@launch
            deliver(target, summary(event.type, bundle.items, bundle.dropped))
        }
    }

    private fun summary(type: WebhookEvent, items: List<Event>, dropped: Int): Event {
        val what = when (type) {
            WebhookEvent.IP_BANNED -> "IPs banned"
            WebhookEvent.ADMIN_LOGIN_FAILED -> "failed admin logins"
            else -> type.label
        }
        val listed = items.take(MAX_BUNDLE_ITEMS).joinToString("\n") { "${formatTimestamp(it.time)}: ${it.item.ifEmpty { it.subject }}" }
        val total = items.size + dropped
        val more = if (total > MAX_BUNDLE_ITEMS) "\n... and ${total - MAX_BUNDLE_ITEMS} more" else ""
        return Event(type, "$total more $what", listed + more, time = items.last().time)
    }

    /** Sends a test message to [target], whatever events it selected. One attempt, the admin waits for the answer. */
    suspend fun test(target: WebhookConfig): Boolean {
        val event = Event(WebhookEvent.CONFIG_CHANGED, "Kovexy test message", "This is a test message from Kovexy.", time = clock())
        return attempt(target, fillTemplate(target.template, event), tries = 1)
    }

    private fun deliver(target: WebhookConfig, event: Event) {
        val body = fillTemplate(target.template, event)
        scope.launch(Dispatchers.IO) { attempt(target, body) }
    }

    private suspend fun attempt(target: WebhookConfig, body: String, tries: Int = RETRY_DELAYS.size + 1): Boolean {
        repeat(tries) { index ->
            val result = runCatching { send(target, body) }
            val status = result.getOrNull()
            if (status != null && status in 200..299) return true
            val reason = status?.let { "status $it" } ?: result.exceptionOrNull()?.let { it.message ?: it::class.simpleName }
            staticLog(KLogger.Level.WARN, TAG) { "Webhook \"${target.name}\" attempt ${index + 1} failed: $reason" }
            if (index < tries - 1) RETRY_DELAYS.getOrNull(index)?.let { delay(it) }
        }
        return false
    }
}

/** Sends [body] as `POST` to the webhook, `application/json` unless the target sets its own `Content-Type`. */
private suspend fun post(target: WebhookConfig, body: String): Int {
    val builder = HttpRequest.newBuilder(URI(target.url))
        .timeout(10.seconds.toJavaDuration())
        .POST(HttpRequest.BodyPublishers.ofString(body))
    if (target.headers.keys.none { it.equals("Content-Type", ignoreCase = true) }) builder.header("Content-Type", "application/json")
    target.headers.forEach { (name, value) -> builder.header(name, value) }
    return http.sendAsync(builder.build(), HttpResponse.BodyHandlers.discarding()).await().statusCode()
}
