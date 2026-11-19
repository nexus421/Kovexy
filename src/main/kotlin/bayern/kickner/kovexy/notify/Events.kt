package bayern.kickner.kovexy.notify

import bayern.kickner.kovexy.config.WebhookEvent

/**
 * Something worth a notification.
 *
 * @property type Kind of event, webhooks select by it.
 * @property subject Short summary, one line.
 * @property body Details, may span several lines.
 * @property site The domain the event belongs to, empty if none.
 * @property time Unix milliseconds.
 * @property item What the event is about (an IP, a user name), collected into the summary when events are bundled.
 */
data class Event(
    val type: WebhookEvent,
    val subject: String,
    val body: String,
    val site: String = "",
    val time: Long,
    val item: String = "",
)

/** Receives events. Implementations return at once and never throw. */
fun interface EventSink {
    /** Hands [event] over for delivery. */
    fun emit(event: Event)

    companion object {
        /** Drops every event, for tests and command line actions. */
        val NONE = EventSink { }
    }
}
