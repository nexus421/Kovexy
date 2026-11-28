package bayern.kickner.kovexy.access

/** Reason of the access log entry for a plain HTTP request that was only redirected to HTTPS. */
const val REASON_HTTPS_REDIRECT = "https redirect"

/**
 * Why Kovexy blocked a request. Counted in the statistics (blocked requests and the top list "Blocked by"), [name] is
 * what the database stores.
 *
 * @property label Shown in the admin UI.
 */
enum class BlockKind(val label: String) {
    BANNED("Banned address"),
    IP_RULES("IP or country block list"),
    ALLOW_LIST("Not on the allow list"),
    EXPLOIT("Exploit filter"),
    AI_CRAWLER("AI crawler"),
    TRAP("Trap path"),
    RATE_LIMIT("Rate limit"),
    METHOD("Method not allowed"),
    CAPTCHA("Captcha required"),
    BASIC_AUTH("Basic Auth failed"),
    ORIGIN("WebSocket from another origin"),
    MALFORMED("Malformed request"),
    MISDIRECTED("Misdirected request"),
}
