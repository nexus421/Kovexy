package bayern.kickner.kovexy.web

import kotlinx.html.ButtonType
import bayern.kickner.kovexy.i18n.t
import kotlinx.html.FlowContent
import kotlinx.html.button
import kotlinx.html.span

/**
 * The text behind a help button (a small question mark) next to a field.
 *
 * @property what What the field is.
 * @property effect What a change does, `null` if the first sentence says it all.
 * @property recommended What to choose, `null` if there is no general advice.
 */
class HelpText(val what: String, val effect: String? = null, val recommended: String? = null)

/**
 * Help texts by field. The key is the name of the form field, a few fields that share a name with another page have
 * their own key (for example `route.path`, `webhook.url`) which the page passes explicitly.
 */
private val HELP: Map<String, HelpText> = mapOf(
    // Settings: login
    "loginMode" to HelpText(
        "How you sign in to this admin UI.",
        "Password only uses the admin password. OIDC only uses your identity provider. OIDC, then password asks for both, so a hole at the provider alone does not let anybody in.",
        "Password only for a homelab. OIDC, then password if you already run an identity provider and the UI can be reached from the internet.",
    ),
    "issuer" to HelpText(
        "The address of your OIDC identity provider, exactly as the provider reports it.",
        "A wrong value makes every OIDC login fail.",
        "Copy it from the provider's settings, character for character.",
    ),
    "clientId" to HelpText("The client ID the identity provider gave to Kovexy."),
    "clientSecret" to HelpText(
        "The client secret that belongs to the client ID.",
        "It is stored in kovexy.json and never shown again. Leave the field empty to keep the stored one.",
    ),
    "allowedSubjects" to HelpText(
        "The user IDs (the sub claim) that may log in, one per line.",
        "Empty lets in everybody the provider lets through.",
        "Fill it, or restrict the client to a group at the provider.",
    ),
    "scopes" to HelpText("The scopes Kovexy asks the provider for, separated by spaces.", recommended = "openid profile is enough."),
    "forceReauth" to HelpText(
        "Makes the provider ask for the login again.",
        "On: the provider asks every time, even if you are signed in there. Off: a running session at the provider logs you in without asking.",
        "On.",
    ),
    // Settings: admin UI
    "language" to HelpText(
        "The language of the admin UI.",
        "It applies to every page at once. Logs, error messages of the configuration check, webhook texts and what visitors see stay English.",
        "The language you read most easily.",
    ),
    "adminHost" to HelpText(
        "The address the admin UI listens on.",
        "127.0.0.1 means only this computer, 0.0.0.0 means every network. A change moves the UI at once, you may lose the connection.",
        "127.0.0.1, and reach the UI through a domain with an access profile.",
    ),
    "adminPort" to HelpText("The port of the admin UI. It must not be 80 or 443.", "A change moves the UI at once."),
    "publicUrl" to HelpText(
        "The address you type in the browser when the admin UI is reached through a domain of Kovexy, for example https://proxy.example.com.",
        "It is the only other origin the UI accepts besides the local address, and OIDC needs it for the callback. Without it the login only works on localhost.",
        "Leave it empty for local use only.",
    ),
    "idleTimeout" to HelpText("How long you can do nothing before you are logged out.", recommended = "1h."),
    "maxAge" to HelpText("The longest time a login lasts, even while you keep working.", recommended = "12h."),
    // Settings: proxy and limits
    "trustedProxies" to HelpText(
        "IP addresses or ranges of proxies in front of Kovexy, for example a CDN, whose X-Forwarded-For header Kovexy believes.",
        "Behind such a proxy this is how Kovexy learns the real address of a visitor for bans, rate limits and lists. A wrong entry lets visitors fake their address.",
        "Empty if visitors reach Kovexy directly.",
    ),
    "backendConnectTimeout" to HelpText(
        "How long Kovexy waits to connect to a backend server.",
        "A longer time makes visitors wait longer when a server is down.",
        "3s.",
    ),
    "backendKeepAlive" to HelpText(
        "How long an unused connection to a backend stays open for the next request.",
        "A longer time saves connection setups, a shorter one frees resources.",
        "2m, and below the keep-alive time of your backend.",
    ),
    "clientIdleTimeout" to HelpText(
        "How long Kovexy waits for a visitor who neither sends nor reads anything before it closes the connection. It also covers a client that stops sending its request headers.",
        "A shorter time frees connections from slow or stuck clients sooner, but cuts off visitors on a bad line.",
        "5m.",
    ),
    "maxRequestHeaderBytes" to HelpText(
        "The largest size of all request headers together, in bytes.",
        "Requests with larger headers are refused. Raise it only for very large cookies or tokens, every connection can then use more memory.",
        "16384.",
    ),
    "maxConnections" to HelpText(
        "The most open connections on the proxy ports in total. More are closed at once. 0 is unlimited.",
        "Keeps a flood of connections from filling the memory.",
        "10000.",
    ),
    "maxConnectionsPerAddress" to HelpText(
        "The most open connections from one address (IPv6 per /64). 0 is unlimited. Loopback and trusted proxies are not limited.",
        "Stops one client from using all connections. Many users behind one shared address, like an office, share this limit.",
        "256.",
    ),
    "maxAcceptsPerSecond" to HelpText(
        "How many new connections per second Kovexy accepts in total. 0 is off.",
        "The limit is shared by everybody, so during an attack it keeps normal visitors out too.",
        "Off, unless a flood of new connections is a real problem for you.",
    ),
    "webSocketCloseDelay" to HelpText(
        "After a config change, open WebSockets are closed after this time so they pick up the new rules.",
        "0s closes them at once, a longer time lets running chats and streams finish first.",
        "0s.",
    ),
    // Settings: data
    "retentionAccessLog" to HelpText(
        "How long single requests are kept in the access log.",
        "Older entries are deleted. The statistics are not affected. The top lists of IP addresses go with the access log, because IP addresses are personal data.",
        "As short as you need.",
    ),
    "retentionHourly" to HelpText(
        "How long the hourly statistics are kept. They feed the charts for 24 hours and 7 days. Daily statistics are kept forever.",
    ),
    "retentionAudit" to HelpText("How long the audit log of changes is kept."),
    "retentionSecurity" to HelpText("How long security events like bans, blocks and failed logins are kept."),
    "updateCheck" to HelpText(
        "Asks GitHub at most once an hour whether a newer Kovexy exists, while somebody uses the admin UI.",
        "GitHub then sees the address of your server.",
    ),
    "database" to HelpText(
        "Adds the database to the backup: access log, statistics, sessions and bans.",
        "The backup gets larger and holds the IP addresses of your visitors.",
        "Off for a routine backup of the configuration and certificates.",
    ),
    // Domains and routes
    "names" to HelpText(
        "The domain names this entry serves, one per line, for example example.com and www.example.com. No wildcards.",
        "Every name gets its own certificate from Let's Encrypt. The name must point to this server and port 80 must be reachable from the internet. A name can belong to one domain only.",
    ),
    "domain.dyndns" to HelpText(
        "Makes this domain the address your routers report their IP to.",
        "The domain then answers only /nic/update and everything else with a 404. It must have no routes. Its access profile still applies, so a profile with an allow list locks the routers out.",
        "Use a name of its own, for example dyndns.example.com, without an access profile or with one that only limits the request rate.",
    ),
    "dyndns.client" to HelpText(
        "The user name the router logs in with.",
        "Letters, digits, dots, underscores and hyphens. It cannot be changed later, delete the client and add it again instead.",
    ),
    "dyndns.profiles" to HelpText(
        "The access profiles that let this client's reported IP in.",
        "Kovexy adds the address the client reports to the allow list of each ticked profile, next to the entries you wrote yourself. Your own entries are never changed. A ticked profile without an allow list of its own lets nobody in by IP until one of its clients has reported, only its countries and local addresses still get in.",
        "Tick only the profiles of services that are meant for this location.",
    ),
    "domain.enabled" to HelpText("Turns the domain on or off.", "A disabled domain is treated as if it did not exist. Visitors get the fallback and its certificates are not renewed."),
    "accessLog" to HelpText(
        "Writes the requests of this domain to the access log.",
        "Off keeps the log shorter. The statistics still count every request.",
        "On.",
    ),
    "access" to HelpText(
        "The access profile that protects this domain or route.",
        "A route with its own profile replaces the profile of the domain completely, it does not add to it.",
        "Give every domain that is not meant for the whole internet a profile.",
    ),
    "rootBackend" to HelpText("Creates the route / and sends it to this backend. You can add more routes later."),
    "route.path" to HelpText(
        "The path this route handles, starting with /.",
        "With the match Prefix it also covers everything below, so /api covers /api/users but not /apix. The most specific route wins, the order does not matter.",
    ),
    "match" to HelpText(
        "Prefix covers the path and everything below it. Exact covers only this one path.",
        recommended = "Prefix for apps, exact for single files like /robots.txt.",
    ),
    "route.enabled" to HelpText("Turns the route on or off.", "A disabled route is ignored, requests fall to the next most specific route."),
    "targetType" to HelpText(
        "What answers the request: a backend, static files, a redirect or a block page.",
        "Only the settings of the chosen kind are used.",
    ),
    "backend" to HelpText("The backend that receives the request. Create backends on the page Backends."),
    "stripPrefix" to HelpText(
        "Removes the path of the route before the request goes to the backend.",
        "/api/users then reaches the backend as /users. Needed when the app does not know it lives under /api.",
        "Off, unless the app expects to be at the root.",
    ),
    "root" to HelpText(
        "The directory with the files to serve, absolute or relative to the data directory.",
        "Files whose name starts with a dot are never served, except .well-known.",
    ),
    "directoryListing" to HelpText(
        "Shows a list of the files for a directory without an index file.",
        "A listing can reveal files you did not mean to share.",
        "Off.",
    ),
    "redirectUrl" to HelpText(
        "The address visitors are sent to.",
        "With Keep the path and query the path of the request is added to it.",
    ),
    "redirectStatus" to HelpText(
        "307 is a temporary redirect that browsers do not remember. 301 is permanent and browsers cache it.",
        "A cached 301 is hard to take back.",
        "307 until you are sure.",
    ),
    "keepPath" to HelpText(
        "Adds the path and query of the request to the target address.",
        "/old/page?x=1 then goes to <address>/page?x=1.",
    ),
    "denyStatus" to HelpText(
        "The HTTP status code of the block answer.",
        recommended = "404 hides that something is here, 403 says that it is forbidden.",
    ),
    "html" to HelpText("Your own HTML page for the block answer. Empty gives a neutral page."),
    "requestHeaders" to HelpText(
        "Changes to the headers Kovexy sends to the backend, one per line: set Name: value, add Name: value or remove Name.",
        "Set replaces a header, add adds another one, remove deletes it.",
    ),
    "responseHeaders" to HelpText(
        "Changes to the headers sent to the visitor, in the same format. Remove only works for answers from a backend.",
        recommended = "The button Add security headers adds HSTS, nosniff and a referrer policy.",
    ),
    // Backends
    "backend.name" to HelpText("The name routes and the fallback use for this backend.", "Renaming updates every place that uses it."),
    "servers" to HelpText(
        "The servers behind this backend. Kovexy spreads requests over them.",
        "Weight sets the share of requests, 0 makes a backup server that only gets requests when no other server is up. Max connections limits the requests a server handles at once, more wait, 0 is unlimited. HTTPS makes Kovexy speak TLS to the server. Any certificate accepts every certificate, for example a self-signed one, and turns the certificate check off.",
        "Use Any certificate only for servers on a network you trust.",
    ),
    "sticky" to HelpText(
        "Sends a visitor to the same server again, using a cookie.",
        "Useful for apps that keep the session in the memory of one server. If that server is down, the visitor gets another one.",
        "Off, unless the app needs it.",
    ),
    "healthPath" to HelpText(
        "A path Kovexy requests from every server regularly.",
        "Without a path servers are only checked passively: a connection error marks a server down and it is tried again every 30 seconds. With a path Kovexy also notices a server that answers wrongly.",
        "The health page of your app, if it has one.",
    ),
    "expectStatus" to HelpText("The status code a healthy server answers with.", recommended = "200."),
    "interval" to HelpText("How often the servers are checked.", recommended = "30s."),
    "timeout" to HelpText("How long a check may take before the server counts as down.", recommended = "5s."),
    // Fallback
    "fallback.type" to HelpText(
        "What visitors get when they ask for a name that no domain serves: static files, a backend, a redirect, a 404 page or an empty answer that closes the connection.",
        "Scanners probe with IP addresses and made-up names, they all end up here.",
        "The neutral page or a 404 page. Do not send unknown names to a real app.",
    ),
    // Access profiles
    "profile.name" to HelpText("The name domains and routes use for this profile.", "Renaming updates every place that uses it."),
    "denyIps" to HelpText(
        "IP addresses or ranges that always get 403, one per line, for example 203.0.113.7 or 198.51.100.0/24.",
    ),
    "denyCountries" to HelpText(
        "Countries that get 403.",
        "It only counts when Kovexy knows the country of the address from its downloaded country data.",
    ),
    "allowIps" to HelpText(
        "IP addresses or ranges that may get in, one per line. When an allow list is filled, everybody else gets 403.",
        "An address listed here is never banned by a trap path, and a ban does not stop it on domains that use this profile. The other checks, like the exploit filter, the rate limit, the captcha and Basic Auth, still apply.",
        "Use it for admin areas and private services.",
    ),
    "allowCountries" to HelpText(
        "Only visitors from these countries may get in.",
        "An address whose country is unknown gets in when only countries are listed.",
    ),
    "allowLocal" to HelpText(
        "Addresses of your own network, like 192.168.x.x, 10.x.x.x and 127.0.0.1, pass the allow list even when they are not listed.",
        recommended = "On if you also use the service from your home network.",
    ),
    "commonExploits" to HelpText(
        "Blocks requests that match known attack patterns in the query string or the user agent: SQL and file injection, script tags and known scanner tools.",
        "A rare false match blocks a normal request. Every block is in the access log.",
        "On for public domains.",
    ),
    "aiBots" to HelpText(
        "Blocks the crawlers of AI companies by their user agent, using the list of ai.robots.txt.",
        "Crawlers that fake their user agent are not caught.",
    ),
    "exploitResponse" to HelpText(
        "What a blocked request gets: an error code, or an empty answer followed by closing the connection.",
        "A 404 or an empty answer tells a scanner less than a 403.",
    ),
    "add" to HelpText("Extra parts of a user agent that count as AI crawler, one per line. Upper and lower case do not matter."),
    "ignore" to HelpText("Names of the shipped list that should no longer count as AI crawler, one per line."),
    "trapsEnabled" to HelpText(
        "Bans the address of whoever requests a trap path, a path that real visitors never use, like /wp-login.php or /.env.",
        "The ban counts for all domains. A request a browser sends on behalf of another site is only refused, and so is one from an address on the allow list of the profile.",
        "On for public domains.",
    ),
    "trapPaths" to HelpText(
        "The path prefixes that act as traps, one per line.",
        "A route with the match Exact for exactly that path disarms the trap.",
        "Keep the defaults. Never list a path one of your apps serves.",
    ),
    "banDuration" to HelpText("How long a banned address stays banned. IPv6 addresses are banned per /64.", recommended = "1h."),
    "rateEnabled" to HelpText("Limits how many requests one address may send.", "Requests above the limit get 429."),
    "rps" to HelpText(
        "The most requests per second from one address for this profile, counted in windows of one second.",
        "Too low a value blocks normal pages that load many files. Requests to Kovexy's own paths for the captcha count too.",
        "20 for normal sites.",
    ),
    "ipv6Prefix" to HelpText(
        "IPv6 addresses count together per prefix. A household usually has a whole /64.",
        recommended = "64.",
    ),
    "basicEnabled" to HelpText(
        "Asks visitors for a user name and a password (Basic Auth).",
        "Passwords are stored as hashes. Kovexy removes the Authorization header, so the password never reaches the backend.",
        "A quick lock for a private service.",
    ),
    "realm" to HelpText("The text some browsers show in the login box."),
    "exceptions" to HelpText(
        "Paths or networks that need no login, one per line: path /public or cidr 192.168.1.0/24.",
    ),
    "captchaEnabled" to HelpText(
        "Asks visitors to solve a Google reCAPTCHA first.",
        "Visitor data goes to Google. Visitors see a check page with 403 until they pass it.",
        "Only if bots are a real problem.",
    ),
    "captchaDuration" to HelpText(
        "How long a solved captcha counts for this profile on this domain.",
        "Then the visitor is asked again. Solved captchas live in memory, so a restart asks everybody once more.",
        "1h.",
    ),
    "captchaPaths" to HelpText("Only these path prefixes ask for the captcha, one per line. Empty protects the whole domain."),
    "captchaExceptions" to HelpText(
        "No captcha for these, one per line: path /api or cidr 192.168.1.0/24.",
        recommended = "Add paths that scripts and apps use.",
    ),
    "siteKey" to HelpText("The public key of your reCAPTCHA registration at Google."),
    "secretKey" to HelpText(
        "The private key of your reCAPTCHA registration.",
        "It is stored in kovexy.json and never shown again. Leave the field empty to keep the stored one.",
    ),
    "recaptchaVersion" to HelpText("v2 shows a checkbox. v3 is invisible and rates every visitor with a score."),
    "recaptchaScore" to HelpText("The lowest v3 score that passes, from 0 to 1.", recommended = "0.5, as Google suggests."),
    // Certificates
    "staging" to HelpText(
        "Uses the test servers of Let's Encrypt.",
        "Their certificates are not trusted by browsers, but the rate limits are generous.",
        "Only while you test a setup.",
    ),
    "email" to HelpText("An optional contact address for the certificate authority.", "Let's Encrypt can warn you there about certificates that are about to expire."),
    "acme.directory" to HelpText("The ACME directory URL. Empty means Let's Encrypt production."),
    // Incus
    "incus.enabled" to HelpText(
        "Finds Incus containers that ask for a domain.",
        "Discovered containers only go live after your click. The Incus socket gives root access to the host, so the service must run as root.",
        "Off, unless you use Incus.",
    ),
    "socket" to HelpText("The Incus API socket."),
    "projects" to HelpText("Only containers of these Incus projects count, separated by commas.", "In restricted projects normal users may create containers and set their keys."),
    "interface" to HelpText("The network interface of the container. Its first global IPv4 address becomes the target."),
    // Webhooks
    "webhook.name" to HelpText("A name to tell your webhooks apart."),
    "webhook.url" to HelpText("The address Kovexy sends the POST request to."),
    "webhook.headers" to HelpText(
        "Extra HTTP headers, one per line as Name: value, for example an API key.",
        "Without a Content-Type Kovexy sends application/json.",
    ),
    "template" to HelpText(
        "The body of the POST request. Placeholders: {{event}}, {{subject}}, {{body}}, {{time}} and {{domain}}.",
        "Values are escaped for JSON strings. Empty sends every placeholder as JSON.",
    ),
    "webhook.events" to HelpText("Which events are sent to this webhook.", "Events marked bundled arrive as one message when they come in quickly."),
    // Access log and statistics: filters
    "accessLog.domain" to HelpText(
        "Shows only the requests of this domain.",
        "Fallback shows the requests for names no domain serves, also the HTTPS redirects of such names.",
    ),
    "accessLog.status" to HelpText(
        "Shows only answers of this status class.",
        "Blocked shows the requests Kovexy refused, with the reason. HTTPS redirects shows the plain HTTP requests on port 80 that were sent on to HTTPS.",
    ),
    "accessLog.q" to HelpText(
        "Shows only entries whose path, client IP or requested name contain this text.",
        "The query string is never stored, so it cannot be searched.",
    ),
    "stats.domain" to HelpText(
        "Shows the statistics of one domain only.",
        "Fallback holds the requests for names no domain serves.",
    ),
    "stats.range" to HelpText(
        "The time span of the charts and lists.",
        "24 hours and 7 days show hourly values, 30 and 365 days daily values. Hourly values are kept as long as Settings say, daily values forever.",
    ),
    "bundleWindow" to HelpText(
        "The first IP ban or failed login is sent at once. Further ones within this time arrive as one message at its end.",
        recommended = "60s.",
    ),
)

/** The help for the field [key], `null` if it has none. */
fun helpFor(key: String): HelpText? = HELP[key]

/** Every key with a help text, for the test that checks the texts. */
fun helpKeys(): Set<String> = HELP.keys

/**
 * A small question mark next to a label. Hover or keyboard focus (a tap on a phone) shows the text of [key], nothing is
 * drawn when there is none. [label] names the button for screen readers.
 */
fun FlowContent.helpButton(key: String, label: String) {
    val help = helpFor(key) ?: return
    span("help") {
        button(type = ButtonType.button, classes = "help-btn") {
            attributes["aria-label"] = t("Help: {0}", t(label))
            +"?"
        }
        span("help-pop") {
            attributes["role"] = "tooltip"
            span("help-line") { +t(help.what) }
            help.effect?.let { span("help-line") { +t(it) } }
            help.recommended?.let { span("help-line") { span("help-lead") { +"${t("Recommended:")} " }; +t(it) } }
        }
    }
}
