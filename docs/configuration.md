# Configuration

## Command line

Arguments are `key=value` pairs or single words. An unknown argument ends Kovexy with exit code 64.

| Argument | Effect |
|---|---|
| `dataDir=<path>` | Data directory, default `/var/lib/kovexy` |
| `check` | Validates `kovexy.json` and exits |
| `reset-password` | Creates a new random admin password, prints it once and saves its hash. A running Kovexy uses it at once and ends every session |
| `login-mode=password` | Switches the login back to password only, e.g. when the OIDC provider is down |

| Exit code | Meaning |
|---|---|
| `0` | Success |
| `1` | Unexpected failure |
| `64` | Unknown argument |
| `78` | Config rejected or a port cannot be bound. systemd does not restart on it |
| `143` | Normal end after `systemctl stop` |

`reset-password` and `login-mode=` usually run as root next to a service with `DynamicUser`. The new file gets the
owner of the old one, so the service can still write it.

## The config file

Everything lives in `<dataDir>/kovexy.json`, there is no file under `/etc`. The admin UI writes it, edits by hand are
picked up as well. Every change is checked completely and applied while running:

- Unknown fields are errors, so a typo never falls back to a default silently.
- All problems are reported at once.
- A file is taken whole or not at all. An invalid file changes nothing, the error goes to the log and to the webhook
  event `configInvalid`.
- Missing fields take their default. Kovexy writes only values that differ from the default.
- Before every save the previous file is copied to `<dataDir>/backups/` (the last 10 are kept), then the new file is
  written to a temporary file and renamed, so it is never half written.
- Durations are text like `"30s"`, `"5m"`, `"12h"` or `"90d"`.

[kovexy.example.json](../kovexy.example.json) shows every field.

### Top level

| Field | Default | Meaning |
|---|---|---|
| `admin` | see below | Admin UI |
| `acme` | see below | Certificates |
| `listeners` | 80 plain, 443 TLS | Fixed in this version, a different value is an error. More ports per domain are deferred |
| `trustedProxies` | `[]` | IPs or CIDR ranges whose `X-Forwarded-*` headers are believed |
| `fallback` | static files from `<dataDir>/www` | Answer for requests to names that no domain serves |
| `accessProfiles` | `[]` | Reusable access profiles, see below |
| `aiCrawlers` | no changes | Changes to the shipped AI crawler list for every profile, see below |
| `incus` | off | Discovery of Incus containers, see below |
| `backends` | `[]` | Named backends with their servers |
| `domains` | `[]` | Domains with their names and routes |
| `webhooks` | `[]` | Webhook targets |
| `limits` | see below | Timeouts and sizes |
| `retention` | see below | How long data is kept |
| `updateCheck` | `true` | Asks GitHub for a newer release while somebody uses the admin UI |
| `language` | `"en"` | Language of the admin UI, `"en"` or `"de"`. Applies at once. Only the admin UI is translated, logs, error messages of the configuration check, webhook texts, the docs and what visitors see stay English |
| `webSocketCloseDelay` | `"0s"` | Time open WebSockets get after a config change before they are closed, like Caddy |

### `admin`

| Field | Default | Meaning |
|---|---|---|
| `host` | `"127.0.0.1"` | Address of the admin UI. With `0.0.0.0` or `::` the local address counts as loopback. If the address cannot be bound at start, Kovexy does not start (exit code 78). A later change that cannot be bound keeps the old address |
| `port` | `8000` | Port, must not be 80 or 443 |
| `publicUrl` | empty | Address in the browser when the admin UI is reached through a domain, e.g. `https://proxy.example.com`. The only `Origin` accepted besides the local address |
| `loginMode` | `"password"` | `"password"`, `"oidc"` or `"both"` (OIDC first, then the password). OIDC needs `oidc` and `publicUrl`, `both` also a password |
| `passwordHash` | empty | Argon2id hash. Empty on the first start, Kovexy then creates a password and prints it once to the log |
| `oidc` | empty | `issuer`, `clientId`, `clientSecret`, `allowedSubjects` (empty: everybody the provider lets through), `forceReauth` (default `true`), `scopes` (default `["openid", "profile"]`), like Dirl. Callback URL: `<publicUrl>/auth/callback` |
| `session.idleTimeout` | `"60m"` | |
| `session.maxAge` | `"12h"` | |

Host and port can change while running, the admin connector moves at once.

### `acme`

| Field | Default | Meaning |
|---|---|---|
| `directory` | Let's Encrypt production | ACME directory URL |
| `staging` | `false` | Uses Let's Encrypt staging instead |
| `email` | empty | Optional contact address |

Using ACME means agreeing to the terms of service of the CA, like with Caddy.

### `backends[]`

| Field | Default | Meaning |
|---|---|---|
| `name` | required | Unique, targets refer to it |
| `servers[].address` | required | `host:port`, IPv6 as `[address]:port` |
| `servers[].tls` | `false` | HTTPS to the server. The `Host` header then carries the server address, like Caddy since 2.11, `X-Forwarded-Host` keeps the original name |
| `servers[].skipCertVerify` | `false` | Accepts any certificate, e.g. self-signed. Without it the certificate must come from a trusted CA and name the address: an IP address as IP entry, a name as DNS entry. A server configured by IP with a certificate for its name needs the name as address |
| `servers[].weight` | `1` | `0` makes a backup server |
| `servers[].maxConnections` | `0` | Concurrent requests, more wait. `0` is unlimited |
| `stickySession` | `false` | Cookie `kovexy_sticky_<hash>`, one day |
| `healthCheck.path` | empty | Without a path only passive checks |
| `healthCheck.interval` | `"30s"` | |
| `healthCheck.timeout` | `"5s"` | |
| `healthCheck.expectStatus` | `200` | |

### `domains[]` and `routes[]`

| Field | Default | Meaning |
|---|---|---|
| `names` | required | Exact lower case domain names, no wildcards. A name may belong to one domain only. Domains are reachable over HTTPS only, port 80 answers every request except ACME challenges with `308` to HTTPS (there is no per-domain switch) |
| `access` | empty | Name of an access profile for the whole domain |
| `enabled` | `true` | |
| `accessLog` | `true` | Writes requests to the access log. Statistics count them anyway |
| `routes[].path` | required | Starts with `/`. A prefix path has no trailing slash |
| `routes[].match` | `"prefix"` | `"prefix"` or `"exact"` |
| `routes[].stripPrefix` | `false` | Only for backend targets |
| `routes[].target` | required | See below |
| `routes[].requestHeaders` | `[]` | `{ "action": "set" \| "add" \| "remove", "name": "...", "value": "..." }` |
| `routes[].responseHeaders` | `[]` | Same format |
| `routes[].access` | empty | Access profile that replaces the one of the domain completely |
| `routes[].enabled` | `true` | |

`target` is one of:

| `type` | Fields |
|---|---|
| `"backend"` | `backend` |
| `"static"` | `root` (absolute or relative to the data directory), `directoryListing` (default `false`). Hidden files (starting with a dot) are never served, except `.well-known` |
| `"redirect"` | `url`, `status` (`307` default or `301`), `keepPath` (default `true`) |
| `"deny"` | `status` (default `404`), `html` (optional own page) |

### `fallback`

`{ "type": "static" | "backend" | "redirect" | "notFound" | "noResponse", ... }` with the same fields as the
targets. `static` with an empty `root` serves `<dataDir>/www`, where Kovexy puts a neutral page on the first start.
A redirect to the requested domain itself is answered with 500, it would loop. `noResponse` answers with an empty
`204` and closes the connection.

### `webhooks[]`

| Field | Default | Meaning |
|---|---|---|
| `name` | required | Unique |
| `url` | required | Target of the `POST` |
| `headers` | `{}` | E.g. `X-API-Key` for KNot. Without `Content-Type` Kovexy sends `application/json` |
| `template` | every placeholder as JSON | Placeholders `{{event}}`, `{{subject}}`, `{{body}}`, `{{time}}`, `{{domain}}`, escaped for JSON strings |
| `events` | all | `certIssued`, `certFailed`, `backendDown`, `backendUp`, `ipBanned`, `adminLoginFailed`, `configChanged`, `configInvalid`, `incusDetected`, `incusApproved`, `incusRemoved` |
| `bundleWindow` | `"60s"` | `ipBanned` and `adminLoginFailed` are sent at once the first time, further ones within the window as one message at its end |

Delivery is tried three times, with 1 and 3 seconds in between.

### `limits`

| Field | Default | Source |
|---|---|---|
| `backendConnectTimeout` | `"3s"` | Caddy |
| `backendKeepAlive` | `"2m"` | Caddy |
| `clientIdleTimeout` | `"5m"` | Caddy |
| `maxRequestHeaderBytes` | `16384` | Caddy |
| `maxConnections` | `10000` | Open connections on the proxy ports in total, `0` is unlimited. More are closed at once. 10000 idle TLS connections took about 90 MB of heap in a test |
| `maxConnectionsPerAddress` | `256` | Open connections on the proxy ports of one address, IPv6 per /64, `0` is unlimited. Loopback and `trustedProxies` are not limited |
| `maxAcceptsPerSecond` | `0` (off) | New connections per second on the proxy ports. Shared by everybody, so off by default |

Not limited: waiting for the response headers of a backend, the request body, the lifetime of an active WebSocket.
WebSocket frames are limited to 1 MiB from visitors and 16 MiB from backends. At most 128 WebSockets are open at
once, 16 per visitor address, more get 503.
A WebSocket without any traffic for 60 minutes is closed. Jetty
has no separate timeout for reading the request headers, `clientIdleTimeout` covers a client that stops sending them.

### `retention`

| Field | Default |
|---|---|
| `accessLog` | `"90d"` |
| `hourlyStats` | `"90d"` |
| `audit` | `"90d"` |
| `securityEvents` | `"90d"` |

Daily statistics are kept forever, like Zoraxy. The daily top lists of IP addresses are personal data and go with
`accessLog`, the other top lists stay. Response time histograms (for the percentiles) go with `hourlyStats`.

### `accessProfiles[]`

A domain or route uses a profile by name, a route with its own profile replaces the one of the domain completely.
The checks run in this order (Zoraxy): block lists, allow lists, exploit filter and trap paths, rate limit, allowed
methods, captcha, Basic Auth. A refused visitor sees a neutral page, the reason goes to the access log and the security events.

| Field | Default | Meaning |
|---|---|---|
| `name` | required | Unique |
| `denyIps` | `[]` | IPs and CIDR ranges that get 403 |
| `denyCountries` | `[]` | ISO 3166 codes that get 403, only when the country of the IP is known |
| `allowIps` | `[]` | If this or `allowCountries` is filled, only matching visitors get in. An address listed here is never banned by a trap path, and a ban does not stop it on a domain and route that use this profile |
| `allowCountries` | `[]` | Like `allowIps`. An IP whose country is unknown gets in when only countries are listed |
| `allowLocal` | `false` | Private and loopback addresses get in despite the allow lists |
| `exploitFilter.commonExploits` | `false` | Patterns of Nginx Proxy Manager against query and user agent |
| `exploitFilter.aiBots` | `false` | AI crawlers by user agent (list of ai.robots.txt) |
| `exploitFilter.response` | `"forbidden"` | `"forbidden"` (403), `"notFound"` (404), `"badRequest"` (400), `"drop"` (empty 204, connection closed). There is no captcha answer on purpose: a crawler could solve it |
| `trapPaths.enabled` | `false` | Bans whoever calls a trap path, for all domains. A request a browser sends for another site is only refused, and so is one from an address in `allowIps` of the profile |
| `trapPaths.paths` | 15 typical scanner targets | Path prefixes. A route with `match: "exact"` for exactly that path disarms the trap |
| `trapPaths.banDuration` | `"1h"` | IPv6 addresses are banned per /64 |
| `rateLimit.requestsPerSecond` | required if set | Per IP and profile in fixed one second windows, more get 429 |
| `rateLimit.ipv6Prefix` | `64` | IPv6 addresses count per prefix |
| `allowedMethods` | `[]` (all) | Others get 405 |
| `basicAuth.users` | required if set | `{ "name": "...", "hash": "..." }`, bcrypt (cost 14 like Caddy) or Argon2id. The admin UI hashes the password. Any length works, below 12 characters the admin UI shows a hint |
| `basicAuth.realm` | `"Restricted"` | |
| `basicAuth.exceptions` | `[]` | `{ "pathPrefix": "/public" }` (at path boundaries) or `{ "cidr": "192.168.1.0/24" }` |
| `captcha.sessionDuration` | `"1h"` | 1m to 30d. A solved captcha counts this long for this profile on this domain. Kept in memory, a restart asks once more |
| `captcha.protectedPaths` | `[]` (all) | Path prefixes that ask for the captcha |
| `captcha.exceptions` | `[]` | Like `basicAuth.exceptions` |
| `captcha.siteKey`, `captcha.secretKey` | required if set | Keys of the Google reCAPTCHA site |
| `captcha.recaptchaVersion` | `"v2"` | `"v2"` (checkbox) or `"v3"` (invisible) |
| `captcha.recaptchaScore` | `0.5` | Lowest v3 score that passes |

After a successful Basic Auth login Kovexy removes the `Authorization` header, the password never reaches the
backend.

#### AI crawler list

`exploitFilter.aiBots` uses the list of ai.robots.txt shipped with Kovexy (updated with every release) and the
top level `aiCrawlers`, the same for every profile:

| Field | Default | Meaning |
|---|---|---|
| `aiCrawlers.add` | `[]` | Extra user agent parts that count as AI crawler |
| `aiCrawlers.ignore` | `[]` | Names of the shipped list that no longer count |

A name counts when it appears anywhere in the user agent, upper or lower case does not matter. Entries must not be
empty and have at most 200 characters, 1000 entries in all. The Access page edits both lists and shows the shipped one.

#### Captcha

The captcha works because every domain is reachable over HTTPS only (its cookie is `Secure`). The rate limit of the profile also counts requests to Kovexy's own paths
under `/.kovexy/`. That path belongs to Kovexy on every domain and never reaches a backend.

The captcha is Google reCAPTCHA, Kovexy has no captcha of its own. A visitor without a valid captcha cookie sees a
neutral check page with 403 (like Zoraxy). It posts to `/.kovexy/captcha/verify` on the same domain and goes back to
the requested address. The answer is checked at Google on the server, which sends visitor data to Google. The captcha
page has its own content security policy, only there Google's scripts and frames are allowed.

Kovexy puts no login in front of apps. Apps that need one protect themselves, or sit behind a Basic Auth profile.
Visitors cannot name a user towards an app either: `X-Forwarded-User`, `X-Forwarded-Email` and
`X-Forwarded-Preferred-Username` are removed from every request.

### `incus`

Kovexy finds Incus containers that ask for a domain and puts them live after a click in the admin UI (page Incus),
never on its own. It only reads, through the Incus socket, which gives root access to the host: with `enabled` the
service must run as root, otherwise the config is rejected (exit code 78 at the start).

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns discovery on |
| `socket` | `"/var/lib/incus/unix.socket"` | The Incus API socket |
| `projects` | `["default"]` | Only instances of these projects count. In restricted projects non-admins may create instances and set keys |
| `interface` | `"eth0"` | Its first global IPv4 address is the target |

Keys the admin sets on the host, only in the instance's own config (keys from Incus profiles are ignored, they would
apply to every instance of the profile):

| Key | Required | Meaning |
|---|---|---|
| `user.kovexy.domains` | yes | Comma separated |
| `user.kovexy.port` | yes | Port in the container |
| `user.kovexy.tls` | no, `false` | The container speaks HTTPS. It is reached by IP address, its certificate is not checked |
| `user.kovexy.access` | no | Name of an access profile |

```bash
incus config set web1 user.kovexy.domains=app.example.com user.kovexy.port=8080
```

Approvals and rejections live in the database, not in `kovexy.json`. An approval counts for exactly the approved
domains, address, port, HTTPS and access profile, a change of any of them needs a new click. Loopback, link-local
and the host's own addresses are refused as targets. Only running instances with an address get a domain, a stopped one loses it at
once and gets it back when it starts. A domain set up by hand wins over a container with the same name. Kovexy listens
to the Incus events and fetches the list again after every instance event and after every reconnect (every 10 s
while Incus is away). An approved container gets a domain (HTTPS only, port 80 redirects) and a backend
backend named `incus:<project>/<instance>`, that prefix is reserved.

### Country data

Kovexy always downloads `user-country` (IPv4 and IPv6, about
26 MB) from https://github.com/sapics/ip-location-db to `<dataDir>/geo/`, checks the published SHA-256 sums once a day
and downloads again only when they changed. Every file is checked against its sum before it is used. While no data is
loaded, country rules have no effect, IP rules always do. The statistics use the data as well, that is why it is
loaded even without country rules (decided on 18.11.2026). It is never part of the JAR.
