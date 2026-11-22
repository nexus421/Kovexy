# Using Kovexy

## The admin UI

The navigation has four groups: Overview (Status, Statistics, Access log), Routing (Domains, Backends, Certificates,
Fallback, Incus), Protection (Access, Security) and System (Webhooks, Audit, Settings). On a computer it is a
sidebar, on a phone the button "Menu" opens it. The number tiles on the status page link to the page behind them. Long forms
fold their sections away (the note beside a title shows the state, for example "on" or "3 entries"), the Save button
stays at the lower edge of the window while the form is longer than the screen. The OIDC fields on the settings page only show
while the login mode uses OIDC. A small question mark next to a field shows, on hover or keyboard focus (a tap on a phone),
what the field is, what a change does and what is recommended.
The language of the admin UI (English or German) is set under Settings, Admin UI, and applies at once.

| Page | What it does |
|---|---|
| Status | Domains, backend servers with their state, certificates with expiry, requests, blocked requests (with the reason), HTTPS redirects and 5xx answers today, latest errors. Updates every 5 seconds over Server-Sent Events |
| Domains | Domains with their names and routes, each route with target and headers. The button "Add security headers" adds HSTS, `nosniff` and a referrer policy as response headers |
| Backends | Groups of servers with weights, backups, sticky sessions and health check |
| Fallback | Answer for unknown domains |
| Certificates | Every domain with state, expiry and issuer, "Renew now", ACME settings |
| Statistics | Charts per domain for 24 hours, 7, 30 and 365 days: requests by status class, blocked requests, response time with median, 95th and 99th percentile, traffic, and daily top lists of IPs, countries, paths, user agents, referers, methods, backend servers and refusals by reason |
| Access log | The latest requests, filtered by domain, status class (or only blocked requests, or only HTTPS redirects) and text. A blocked request shows why it was blocked |
| Access | Access profiles: IP and country rules, exploit filter, trap paths, rate limit, methods, captcha, Basic Auth, the state of the country data, and changes to the AI crawler list for every profile |
| DynDNS | Clients such as a router that report their current IP, each with its own password and access profiles. See [DynDNS](#dyndns) |
| Webhooks | Targets with template and events, the KNot preset and a test message |
| Security | Active bans with "Lift", the latest security events by kind |
| Audit | Who changed what and when, config changes with a diff, secrets as `***` |
| Incus | Detected containers with "Approve" and "Reject", approved ones with "Remove", copy-ready `incus config set` commands for running containers without keys, the Incus settings |
| Settings | Login mode and OIDC provider, password, sessions, admin address, trusted proxies, limits, retention, update check, backup and restore |

Every save is checked, applied at once and logged. If the configuration changed in the meantime (another tab or an
edit of the file), the save is refused and the page asks to reload. As long as only the password protects the admin
UI, every page shows a warning.

## How a request is handled

In this order:

1. On port 80 `/.well-known/acme-challenge/` is answered at once.
2. Banned addresses (from trap paths) get 403, for all domains. Except an address that the access profile of this domain and route names in `allowIps`.
3. A `Host` that names another domain than the request's authority gets 400. Then plain HTTP gets `308` to HTTPS, for every host. Port 80 never reaches a domain or the fallback.
4. The domain is chosen by the requested name, any other name goes to the fallback. Then Kovexy's own paths under `/.kovexy/` (captcha),
   they never reach a backend.
5. The most specific route: longer paths before shorter ones, exact before prefix. A prefix only matches at path
   boundaries, `/api` matches `/api` and `/api/users` but not `/apix`. Upper and lower case count like in Caddy, `/Admin` is not
   `/admin`. An app that treats paths without case (some Windows or PHP apps) needs a rule for every spelling or a
   profile on `/`. Rules see the decoded and cleaned path, so
   `/a/../admin` and `/%61dmin` hit a rule for `/admin`. The backend gets the original path. A domain without a
   matching route answers 404.
6. The access profile of the route, or else of the domain. It also runs when no route matches, so a trap path
   fires on a domain that does not serve that path.
7. Request headers, 8. the target, 9. response headers.
10. Access log and statistics, written in the background.

## Backends

- Requests are spread by weight at random (Zoraxy). Servers with weight 0 only get requests when no other server is
  up.
- A backend with a single server always tries it, even when it is marked down, so a restarting service is reachable
  again at once.
- A connection error marks a server down (passive check). Without an active check it is tried again with a TCP
  connect every 30 seconds.
- With `healthCheck.path` Kovexy sends a `GET` every `interval` (Caddy). A status other than `expectStatus` marks the
  server down, one good answer marks it up.
- There are no automatic retries of failed requests (Caddy). An unreachable backend gets a neutral 502 page.
- Up and down changes go to the webhook events `backendDown` and `backendUp`.
- WebSockets are detected and relayed without any setting. If the backend refuses the handshake, the visitor gets
  its status (for example 403). An active WebSocket has no time limit, one without any traffic for 60 minutes is
  closed. After a config change open WebSockets are closed with `1001 Going Away` after `webSocketCloseDelay`.

## Certificates

Every name of an enabled domain gets its own certificate. Kovexy checks every 10 minutes and
renews in the last third of the lifetime (Caddy). After a failure it waits 1, 2, 2, 5, 10 minutes and so on, up to six
hours between attempts, for at most 30 days, exactly like Caddy. After 30 days it stops until "Renew now" or until the
domain is added again. While a domain fails against Let's Encrypt production the retries run
against Let's Encrypt staging first, so the production limits are not hit. "Renew now" starts at once.

Unknown names and clients without SNI get a self-signed fallback certificate. Certificates of removed domains stay on
disk without renewal until they expire, so a domain that comes back reuses its certificate (Let's Encrypt allows only
five identical certificates per week). Expired ones are deleted, the audit log records it.

## DynDNS

Routers and DynDNS clients (FRITZ!Box, OPNsense, ddclient, anything that speaks dyndns2) report their current IP to
Kovexy, and Kovexy adds it to the allow list of the access profiles you chose for that client. That is how a service
stays reachable from home although the IP changes, without an external DynDNS provider.

1. Add a domain and tick "Use for DynDNS". It answers only `/nic/update`, everything else gets a 404, and it has no
   routes. Use a name of its own, for example `dyndns.example.com`.
2. Under DynDNS add a client: a name and the access profiles. The page shows the password **once**, together with the
   ready settings for the FRITZ!Box (*Internet, Freigaben, DynDNS, Benutzerdefiniert*) and for other clients. A lost
   password is replaced with "New password".
3. Put the settings into the router. The router now reports whenever its IP changes.

Each update replaces all addresses of that client. A client that sends IPv4 and IPv6 in separate requests (inadyn,
pfSense) should be two clients. Parameters: `myip` (IPv4 and IPv6, comma separated, FRITZ!Box `<ipaddr>,<ip6lanprefix>`),
`myipv4`, `ip`, `myipv6`, `myip6`, `ipv6`. Without one the source address is used. IPv4 must be a public single
address, IPv6 a global host or a prefix from /48 to /128 (host bits are cleared).

| Answer | HTTP | Meaning |
|---|---|---|
| `good <ip>` | 200 | The addresses changed and are on the allow lists |
| `nochg <ip>` | 200 | Same addresses as before |
| `badauth` | 401 | Wrong name or password |
| `badrequest <reason>` | 400 | Invalid or private address, broken query |

Two things the admin owns:

- A profile whose allow list is empty lets everybody in. That includes a profile that only has DynDNS clients and none
  of them has reported yet.
- Do not give the DynDNS domain a profile with an allow list or a DynDNS client. The routers would be locked out
  before they can report.

The page shows the last addresses and the time of the last update per client. Every request to `/nic/update` is in
the access log with its status, a wrong password shows as 401.

## Backup

Settings, Backup downloads a ZIP with `kovexy.json` and the certificates, optionally with the database. It is not
encrypted and holds the private keys. Restore uploads such a ZIP: the current state is saved to
`<dataDir>/backups/restore-<time>.zip` first, then everything is replaced and applied at once. A restore with
database ends every admin login, also your own, you log in again.

## Login

The login mode is chosen under Settings:

- **Password only**: every page warns about it.
- **OIDC only**: Kovexy sends the browser to the provider (Authorization Code Flow with PKCE, like Dirl). Register
  `<publicUrl>/auth/callback` as callback URL and restrict the client to a group at the provider. `allowedSubjects`
  is a second, optional barrier.
- **OIDC, then password**: after the provider Kovexy asks for the password as well, a second barrier in case the
  provider has a hole.

If the provider is down, `java -jar kovexy.jar login-mode=password` switches back on the server.
