# Using Kovexy

## The admin UI

The navigation has four groups: Overview (Status, Statistics, Access log), Routing (Sites, Upstreams, Certificates,
Default site, Incus), Protection (Access, Security) and System (Webhooks, Audit, Settings). On a computer it is a
sidebar, on a phone the button "Menu" opens it.

| Page | What it does |
|---|---|
| Status | Sites, upstream servers with their state, certificates with expiry, requests and 5xx answers today, latest errors. Updates every 5 seconds over Server-Sent Events |
| Sites | Sites with domains and their locations with target and headers. The button "Add security headers" adds HSTS, `nosniff` and a referrer policy as response headers |
| Upstreams | Groups of servers with weights, backups, sticky sessions and health check |
| Default site | Answer for unknown domains |
| Certificates | Every domain with state, expiry and issuer, "Renew now", ACME settings |
| Statistics | Charts per site for 24 hours, 7, 30 and 365 days: requests by status class, response time with median, 95th and 99th percentile, traffic, and daily top lists of IPs, countries, paths, user agents, referers, methods, upstream servers and refusals by reason |
| Access log | The latest requests, filtered by site, status class and text |
| Access | Access profiles: IP and country rules, exploit filter, trap paths, rate limit, methods, captcha, Basic Auth, the state of the country data, and changes to the AI crawler list for every profile |
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
2. Banned addresses (from trap paths) get 403, for all sites.
3. A `Host` that names another domain than the request's authority gets 400. Then plain HTTP gets `308` to HTTPS, for every host. Port 80 never reaches a site or the default site.
4. The site is chosen by domain, any other domain goes to the default site. Then Kovexy's own paths under `/.kovexy/` (captcha),
   they never reach an upstream.
5. The most specific location: longer paths before shorter ones, exact before prefix. A prefix only matches at path
   boundaries, `/api` matches `/api` and `/api/users` but not `/apix`. Upper and lower case count like in Caddy, `/Admin` is not
   `/admin`. An app that treats paths without case (some Windows or PHP apps) needs a rule for every spelling or a
   profile on `/`. Rules see the decoded and cleaned path, so
   `/a/../admin` and `/%61dmin` hit a rule for `/admin`. The upstream gets the original path. A site without a
   matching location answers 404.
6. The access profile of the location, or else of the site. It also runs when no location matches, so a trap path
   fires on a site that does not serve that path.
7. Request headers, 8. the target, 9. response headers.
10. Access log and statistics, written in the background.

## Upstreams

- Requests are spread by weight at random (Zoraxy). Servers with weight 0 only get requests when no other server is
  up.
- A group with a single server always tries it, even when it is marked down, so a restarting service is reachable
  again at once.
- A connection error marks a server down (passive check). Without an active check it is tried again with a TCP
  connect every 30 seconds.
- With `healthCheck.path` Kovexy sends a `GET` every `interval` (Caddy). A status other than `expectStatus` marks the
  server down, one good answer marks it up.
- There are no automatic retries of failed requests (Caddy). An unreachable upstream gets a neutral 502 page.
- Up and down changes go to the webhook events `upstreamDown` and `upstreamUp`.
- WebSockets are detected and relayed without any setting. If the upstream refuses the handshake, the visitor gets
  its status (for example 403). An active WebSocket has no time limit, one without any traffic for 60 minutes is
  closed. After a config change open WebSockets are closed with `1001 Going Away` after `webSocketCloseDelay`.

## Certificates

Every domain of an enabled site gets its own certificate. Kovexy checks every 10 minutes and
renews in the last third of the lifetime (Caddy). After a failure it waits 1, 2, 2, 5, 10 minutes and so on, up to six
hours between attempts, for at most 30 days, exactly like Caddy. After 30 days it stops until "Renew now" or until the
domain is added again. While a domain fails against Let's Encrypt production the retries run
against Let's Encrypt staging first, so the production limits are not hit. "Renew now" starts at once.

Unknown names and clients without SNI get a self-signed fallback certificate. Certificates of removed domains stay on
disk without renewal until they expire, so a domain that comes back reuses its certificate (Let's Encrypt allows only
five identical certificates per week). Expired ones are deleted, the audit log records it.

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
