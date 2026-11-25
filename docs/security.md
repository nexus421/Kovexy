# Security

## Admin login

- Three login modes: password only, OIDC only, OIDC and then the password. The local password is stored as Argon2id
  hash (64 MiB, 3 passes) in `kovexy.json`. In the mode password only every page of the admin UI, the login page and
  the log at start warn about it.
- OIDC is Dirl's client: Authorization Code Flow with PKCE S256, `state` and `nonce`, a confidential client with
  `client_secret_basic`, the login attempt in a signed cookie so the server keeps no state for it, at most 4 calls to
  the provider at the same time. The ID token comes straight from the token endpoint over TLS, `iss`, `aud`, `azp`,
  `exp`, `iat` and `nonce` are checked. Restrict the client to a group at the provider, `allowedSubjects` is a
  second barrier.
- If the admin address cannot be bound at start, Kovexy does not start (exit code 78), systemd shows why.
- In the mode `both` a signed cookie of 5 minutes carries the OIDC identity to the password step. In the mode
  `password` the OIDC callback creates no session, a change of the login mode ends OIDC logins that were started
  before it.
- After 5 failed logins from one address it is locked out for 15 minutes. IPv6 addresses count per /64. Every attempt
  counts before the password is checked, so parallel requests get no extra guesses, and at most two password checks
  run at the same time. A login that finds no free check within 5 seconds gets 503 and does not count as a failure.
  Every failure is logged and sent as webhook event `adminLoginFailed` (bundled).
- An OIDC login whose token exchange ends after a change of the login mode or the provider creates no session. The
  password step of the mode `both` checks `allowedSubjects` again. One address gets two calls to the provider at a
  time, so a single visitor cannot hold the four provider slots other logins need. A refusal for that reason is no
  failed login.
- Sessions live in SQLite, only the SHA-256 of the token is stored. The cookie `__Host-kovexy-session` is `Secure`,
  `HttpOnly`, `SameSite=Strict`. Sessions end after 60 idle minutes or 12 hours.
- Changing the password or the login mode in the admin UI ends every other session, a restore of a backup that brings
  another password or login mode too. A change of either in
  `kovexy.json` (also through `reset-password` and `login-mode=password`, which work in an emergency) ends every
  session. Sessions of subjects removed from `allowedSubjects` end at once. The live status stream stops when its
  session ends.

## Web hardening (taken from Dirl)

- New routes are protected by default, only `/login`, `/auth/start`, `/auth/callback`, `/healthz` and `/static/` are
  public.
- Every request other than GET and HEAD needs an `Origin` of the admin UI itself (with `127.0.0.1`, `localhost` and
  `[::1]` when it listens on loopback) or of `publicUrl`. Together with
  `SameSite=Strict` this is the CSRF protection.
- Strict CSP: scripts and styles only from the admin UI itself, no inline code, no `eval`. htmx runs with
  `allowEval` off and without injected styles.
- `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Permissions-Policy`, `Cache-Control: no-store`,
  HSTS when `publicUrl` is HTTPS.
- kotlinx.html escapes all text, no raw HTML, no `innerHTML`. Messages after a redirect come from fixed keys.
- Forms carry the config version, a save based on an outdated version is refused.

## The proxy

- `Host` passes unchanged. `X-Forwarded-For`, `-Proto` and `-Host` are set by Kovexy, incoming values are only kept
  from `trustedProxies` (empty by default), so a client cannot fake its address. Other headers (`Forwarded`,
  `X-Real-IP`, `X-Forwarded-Port`, `-Prefix`, `-Server`) pass unchanged like in Caddy (decided on 19.11.2026): a
  visitor can set them, apps must take the address from `X-Forwarded-For`.
- Hop-by-hop headers (`Connection` and every header it names, `Keep-Alive`, `Proxy-*`, `Te`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`) are never forwarded.
- Rules match the decoded and cleaned path, so encodings, dot segments and path parameters (`/admin;x`) cannot slip
  past a block. A path with an invalid encoding or NUL gets 400, so does a request target that is no path
  (`OPTIONS *`). Jetty refuses ambiguous paths such as empty segments
  (`//admin`) with 400. When `stripPrefix` cannot use the raw path, the cleaned path is encoded again, so a backend
  never decodes twice.
- A profile that cannot read the visitor's address refuses the request instead of skipping its checks.
- Static files never leave their root, also not through symbolic links, the index file of a directory included. Hidden files and directories (`.git`, `.env`)
  are never served or listed, only `.well-known` is. Directory listings are off by default.
- WebSocket frames from visitors are relayed up to 1 MiB, frames from backends up to 16 MiB, a bigger frame closes
  the connection. The reader reserves a whole frame as soon as its header arrives, so at most 128 WebSockets are open
  in total and 16 per visitor address (IPv6 per /56), one more gets 503. The place is taken before the handshake, so
  parallel handshakes cannot get past the limit. A browser sends each message as one frame, an app that sends more
  than 1 MiB per message from the browser does not work behind Kovexy. The relay waits until each frame is written,
  so a side that stops reading slows the other side down instead of filling the memory.
- HTTPS or nothing: port 80 answers ACME challenges and otherwise only redirects (`308`), no domain and not the fallback
  is ever served over plain HTTP. `Location` is only built from a valid domain name or IP address in `Host`, anything
  else gets 400, so a crafted `Host` cannot turn the redirect into an open redirect.
- HTTPS backends without `skipCertVerify` must present a certificate from a trusted CA that names the configured
  address in its subject alternative names: an IP address as IP entry, a name as DNS entry (`*.` for one label). The
  common name does not count. Kovexy checks this itself, Ktor's client checks names too loosely.
- A refused backend certificate is logged as warning with the reason, at most every 10 minutes per server.
- Known limit: Ktor's HTTP client has no limit for the response headers of a backend. A backend that sends
  endless header lines can fill Kovexy's memory and end the process. Backends are chosen by the admin and Incus
  containers need an approval, only approve containers whose owner you trust that far (decided on 19.11.2026).
- Active health checks only read the status, never the body.
- A ban also cuts responses from backends (downloads, server-sent events) the address already receives, like its
  WebSockets. Static files that are being sent finish.
- The domain is picked by the request's authority, a `Host` header naming another domain gets 400 (HTTP/2 without
  `:authority` would otherwise reach the fallback with the `Host` of a protected one).
- `X-Forwarded-User`, `-Email`, `-Preferred-Username` and the other headers Kovexy removes are also removed in
  spellings with `_`, `.` or any other character instead of `-`, which CGI style servers read as the same header.
- The neutral error pages never show internals.
- Forms are read with a size limit (1 MiB in the admin UI, 16 KiB on proxied domains), a bigger body counts as an
  empty form and is never read into memory as a whole.
- Paths under `/.kovexy/` are recognized on the cleaned path, `/%2Ekovexy/` is Kovexy's too and never reaches an
  backend.
- Kovexy's own cookie (captcha) is removed from the `Cookie` header before a request goes to a backend, an app never
  sees a session it could replay. `X-Forwarded-User`, `-Email` and `-Preferred-Username` from the visitor are always
  removed. Kovexy sets none of them (it has no login in front of apps), so an app that trusts them behind Kovexy is not
  fooled by a visitor.

## Data on disk

- `kovexy.json` holds the password hash and webhook secrets, it is `0600`. Every file Kovexy writes is `0600`,
  directories with keys `0700`, the unit sets `UMask=0077`.
- The backup ZIP holds the private keys and is not encrypted (like Zoraxy). Keep it safe.
- A restore only accepts `kovexy.json`, `kovexy.db` and `.pem` files in certificate directories, with size limits,
  and checks the config completely before anything is replaced. Upload and database are streamed through files, never
  held in memory. The database is restored with SQLite's backup API, bans are reloaded at once. A restored database
  ends every admin login, also the one of the admin who restores: sessions in the backup may have been ended
  since.
- A stored key that does not match its certificate is not loaded, the domain gets a new certificate.
- The command line (`reset-password`, `login-mode`, `check`) usually runs as root and never follows a symbolic link
  inside the data directory: not for `kovexy.json`, `backups/`, the backup copies or the temporary file. It works on
  the opened directory, creates its files exclusively and changes owner and mode only without following links, so
  whoever controls the data directory cannot make it read, write, chmod or chown another file, also not by swapping a
  link in while it runs. Hard links to files of others are refused by the kernel (`fs.protected_hardlinks`, on by
  default in Debian).
- Webhook URLs show only scheme and host in the audit log and in error messages of the config check, Discord, Slack
  and Telegram carry the token in the path.
- The access log never stores the query string, it often holds tokens. The program log never holds passwords, keys,
  tokens or cookies. Control characters from requests are escaped, so they cannot forge log lines.

## Update check

At most once an hour, and only while somebody uses the admin UI, Kovexy asks `api.github.com` for the newest release.
It reads at most 1 MiB, follows no redirects, only accepts a tag like `v1.2.3` and downloads nothing. It can be
turned off under Settings.

## Access profiles

- Block and allow lists by IP, range and country. Without country data country rules have no effect, IP rules always
  do. The country data is always downloaded (the statistics use it), checked against the published SHA-256 sum and
  stored as `0600`.
- The country data files are downloaded and loaded up to 64 MiB and 1.5 million rows each, a broken file cannot fill
  the heap.
- The exploit filter uses the patterns of Nginx Proxy Manager (MIT) on the raw and the decoded query and on the user
  agent, and the list of ai.robots.txt (MIT) for AI crawlers. Nothing is taken from Zoraxy, it is AGPL. Patterns of
  the form `a.*b.*c` are checked as ordered parts in linear time, as a regex they would cost minutes of CPU on a
  crafted 16 KiB query. Patterns with a repeated group are written without it, the group overflowed the stack.
- A ban also closes the WebSockets the address already has open.
- Trap paths ban the address (IPv6 per /64) for all domains. Bans are checked before anything else, live in SQLite and
  survive a restart. They expire on their own or are lifted under Security. A request a browser sends for another site
  (`Sec-Fetch-Site` other than `none` and `same-origin`, or a foreign `Origin` or `Referer`, over plain HTTP also a
  browser like `Accept`) is only refused, never banned: otherwise any web page could get its visitors banned with an
  image pointing to `/.env`. This is best effort: a scanner that sends such headers is refused but not banned.
- Basic Auth like Caddy: passwords of any length (below 12 characters the admin UI hints at it), bcrypt with cost 14
  or Argon2id, unknown users are checked against a fake hash so the answer time tells nothing, successful checks are
  remembered for 10 minutes after its last use under a hash of user, password and stored hash (never the password
  itself). A remembered login passes before the lockout is checked, parallel requests with the same login wait for one
  check. 5 failures from one address lock it out of that profile for 15 minutes,
  other profiles are not affected. At most 4 hash checks run at the same time for all profiles, a request that waits
  longer than 2 seconds for one gets 503 and does not count as a failure. Kovexy's Basic Auth credentials are removed
  before the request goes to the backend, also on excepted paths and routes with another profile.
- Rate limits count per profile and address in one second windows.
- Captcha: page tokens are signed with an HMAC key that is new on every start, the return address only takes paths on
  the same host (never `//host` or a URL). Solved captchas are random IDs in memory, valid for one profile on one
  domain, the cookie is `__Host-`, `HttpOnly`, `SameSite=Lax` and `Secure`, the captcha only runs over HTTPS, which is the
  only way a domain is reachable. At most 100.000 solved captchas are kept, the oldest go first. The exploit filter never answers with
  a captcha, a crawler could solve it. The rate limit of the profile also covers `/.kovexy/`. reCAPTCHA answers are
  checked at Google on the server, at most 2 of one address at a time. A WebSocket that the captcha lets in needs an
  `Origin` of the same domain, a foreign page cannot open it with the visitor's cookies.
- Incus: the socket gives root access to the host, Kovexy only reads it and needs root for it. Only the projects in
  `incus.projects` count, only keys of the instance itself (not of profiles), and nothing goes live without a click.
  An approval covers the domains, the address, the port, HTTPS and the access profile shown on the page, a change of
  any of them needs a new click. Loopback, link-local and the host's own addresses are never a target, a guest
  controls the addresses Incus reports for it. A guest cannot set its own keys, `/dev/incus/sock` does not allow it.
  Removing an Incus domain also closes the WebSockets it admitted. Kovexy reads only the configured projects, at most 16 MiB
  per project and 1 MiB per event, users of a project choose what goes into these answers. A container that is not
  approved cannot take an approved domain offline by claiming the same name, it only gets a warning.
  A container whose keys are too long to be stored (domains over 1000, access profile over about 580 characters) can
  always be rejected, but never approved.
- Connection limits on the proxy ports: `limits.maxConnections` closes connections above the total at once,
  `limits.maxConnectionsPerAddress` (256 by default, IPv6 per /64) those of one address above its share, so a single
  host cannot take all connections. Loopback and `trustedProxies` are not limited per address.
  `limits.maxAcceptsPerSecond` pauses accepting. Kovexy counts open TCP connections itself, because Jetty's
  `ConnectionLimit` did not count TLS connections with ALPN.

## DynDNS

A domain with `dyndns` answers only `GET /nic/update`, after the access profile of the domain has run. The endpoint
can do one thing: add reported addresses to the allow lists of the profiles of the client that logged in.

- Passwords are generated (24 random bytes), shown once and stored as SHA-256. They are high entropy, so a fast hash is
  enough, and the hash is compared in constant time (also for an unknown name). A failed login counts as blocked
  request in the statistics and is a security event `BASIC_AUTH_FAILED`, the rate limit of the domain's profile
  applies as for any request.
- A report is written to the state file before it counts. If the file cannot be written the client gets `911` and
  nothing changes.
- Reported addresses must be public: IPv4 a single host, IPv6 a global host or a prefix from /48 to /128. Private,
  loopback, documentation and link-local addresses are refused, and nothing is ever resolved by name.
- Log lines and access log never hold passwords, the `Authorization` header or query values.
- A profile with clients fails closed: without any reported address and without `allowIps` of its own nobody gets
  in by IP (lost or broken state file included). Countries and `allowLocal` of the profile still apply.
- Known limits: a profile without clients and with an empty allow list lets everybody in, so removing the last client
  of such a profile opens it (the client page warns). A client that is compromised can put any public address on the
  allow lists of its profiles. Give a client only the profiles of services that are meant for its location, and use
  every login on one device only.

## Audit log and security events

- The audit log records logins, logouts, failed logins, every config change (from the admin UI with the admin's name,
  a change of the file on disk as "File on disk", which also covers command line actions), issued certificates,
  backup downloads and restores, password changes, lifted bans, removed expired certificates and Incus approvals,
  rejections and removals. Config changes come with a line diff, every secret
  shows as `***` and a changed secret is only named.
- Security events record bans, blocked requests by kind, failed Basic Auth and admin logins. Rate limit events are
  recorded at most once per address, domain and minute.
- Both live in SQLite and are kept 90 days by default.
