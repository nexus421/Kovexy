# Development

Kotlin 2.4.21 on the JVM, Gradle wrapper, toolchain Amazon Corretto 25 with bytecode 21. Code, KDoc and docs are
English, the German concept lives outside the repository.

## Build and test

```bash
./gradlew build shadowJar
```

The fat JAR is `build/libs/kovexy.jar`.

The tests use real ports: a small Ktor CIO server plays the backend, requests go over plain sockets and TLS with
SNI. Covered: certificate per domain and fallback, certificate swaps under load without errors, admin port moved
while running, HTTP/2 (needs `curl`), WebSocket through an idle timeout and closing after a config change, 50 MB
download and 20 MB upload streamed, an invalid file changing nothing, routing, headers, redirects, static files,
fallback, load balancing, health checks, sticky sessions, admin UI guards and forms, backup, renewal backoff,
webhook bundling. Phase 2: IP lists, route profile replacing the domain profile, trap paths banning for all domains
with lift and expiry, exploit filter, AI crawlers, rate limit, methods, Basic Auth, connection limit changed while
running (with TLS), OIDC login in the modes `oidc` and `both` against a mock provider, audit diff without secrets,
country data refused on a wrong checksum. Phase 3: reCAPTCHA end to end against a fake Google endpoint (v2 and v3, wrong
answer, scope per profile and domain, cookie not forwarded), no captcha way past the exploit filter, the rate limit on
`/.kovexy/`, forged identity headers dropped, no login paths of Kovexy on a domain, Incus discovery against a fake Incus API on a unix socket (Ktor CIO server: events
before the list, approve, stop, start, changed domains, remove, reconnect), top lists with the space saving limit,
percentiles, retention of top IPs, IPv6 peers without brackets. After the Phase 2 decisions: expired certificates of
unused domains removed, Basic Auth passwords of any length with hint, AI crawler list changed live.

### ACME with Pebble

`PebbleAcmeTest` issues a real certificate through HTTP-01 against [Pebble](https://github.com/letsencrypt/pebble),
never against Let's Encrypt. Without Pebble it is skipped. CI installs it
(`go install ...pebble/v2/cmd/pebble@<version>`,
pinned in `.github/workflows/build.yml`) and maps `kovexy.localhost` to 127.0.0.1 in `/etc/hosts`. Take care that
`pebble` is the ACME test server and not Canonical's service manager of the same name.

```bash
KOVEXY_PEBBLE=/path/to/pebble ./gradlew test --tests '*PebbleAcmeTest*'
```

The test domain must resolve to 127.0.0.1 for Pebble, by default `kovexy.localhost`, set `KOVEXY_PEBBLE_DOMAIN` for
another one.

## Run locally

```bash
./gradlew devRun
```

Proxy on 18080 (plain) and 18443 (TLS), admin UI on `http://localhost:18000` with the login mode `oidc` against the
mock OIDC provider from the test sources on port 18001 (pick a user, no password), two demo backends behind
`http://app.localhost:18080` with the access profile `demo-protection`. The password `kovexy dev password only` is set
as well, for switching the login mode. Data in `build/dev`, delete it to start over. ACME uses Let's
Encrypt staging there and fails, because nobody can reach the machine, that is expected.

## Release

Publish a release on GitHub with the tag `v<version>` from `build.gradle.kts`. The workflow checks the tag, runs the
tests, builds `kovexy.jar` and attaches it with its SHA-256 sum.

## Fat JAR check

```bash
unzip -p build/libs/kovexy.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider
```

must print `bayern.kickner.klogger.slf4j.KloggerServiceProvider`, Jetty logs through SLF4J.

## Updating dependencies

Versions are pinned in `gradle.lockfile`. After changing a version in `build.gradle.kts`:

```bash
./gradlew dependencies --write-locks
```

htmx and its SSE extension are vendored under `src/main/resources/static/vendor/htmx`. Update them from the npm
tarballs, check the `integrity` value of the registry and update `SHA256SUMS`.

## Project layout

| Package | Content |
|---|---|
| `bayern.kickner.kovexy` | `Main.kt` (command line), `Kovexy.kt` (wiring, live apply), `Common.kt`, `UpdateCheck.kt` |
| `config` | Data model, validation, `ConfigStore` (atomic writes, backups, file watcher), network helpers |
| `tls` | `DynamicKeyManager`, `CertStore`, `CertificateManager` (renewal, backoff), acme4j issuer |
| `proxy` | Jetty server and connectors, routing table, `ProxyHandler`, backend state, load balancing, health checks, WebSocket relay, headers |
| `site` | Static files, neutral pages |
| `web` | Admin UI: guards, layout, pages, SVG charts |
| `auth` | Password hashing, sessions, login lockout |
| `stats` | SQLite through Exposed, access log and statistics writer |
| `notify` | Events and webhooks |
| `access` | Access profiles: country data, exploit patterns, rate limit, bans, Basic Auth, captcha |
| `incus` | Incus discovery: API over the unix socket, claims, decisions, dynamic domains |
| `audit` | Audit log, security events, config diff |
| `backup` | Backup and restore |

## Endpoints of the admin UI

| Path | Purpose |
|---|---|
| `GET /login`, `POST /login`, `POST /logout` | Login |
| `GET /auth/start`, `GET /auth/callback` | OIDC login of the admin, public |
| `/access`, `/access/{name}` | Access profiles |
| `/security`, `POST /security/lift` | Bans and security events |
| `/audit` | Audit log |
| `GET /`, `GET /status/events` | Status page and its SSE stream |
| `/domains`, `/domains/{i}`, `/domains/{i}/routes/{j}` | Domains and routes |
| `/backends`, `/backends/{name}` | Backends |
| `/fallback` | Fallback |
| `/certificates`, `POST /certificates/acme`, `POST /certificates/renew` | Certificates |
| `/statistics`, `/statistics/chart.svg` | Statistics and charts |
| `/access-log` | Access log |
| `/webhooks`, `/webhooks/{name}`, `POST /webhooks/{name}/test` | Webhooks |
| `/incus`, `POST /incus/settings`, `POST /incus/approve`, `POST /incus/reject`, `POST /incus/remove` | Incus discovery |
| `/settings`, `POST /settings/login`, `POST /settings/app-login`, `POST /settings/password`, `POST /settings/backup`, `POST /settings/restore` | Settings |
| `GET /healthz`, `/static/*` | Public |

On every proxied domain Kovexy owns `/.kovexy/`: `captcha.js`, `POST captcha/verify`, `auth/start`, `auth/callback`,
`auth/logout`.

## Verification status

| What | How |
|---|---|
| Proxy, TLS, WebSocket, HTTP/2, live changes, admin UI | Integration tests with real ports |
| ACME issuance | `PebbleAcmeTest`, only with Pebble installed |
| UI at desktop and phone width, light and dark | Checked in the browser with `devRun` |
| 10000 idle TLS connections, connection limit at 10000 | Load test against `devRun` on 18.11.2026: about 90 MB heap, the 10001st connection is closed |
| Download of the real country data | Checked with `devRun` on 18.11.2026 |
| Phase 3 pages at desktop and phone width | Checked in the browser with `devRun` on 18.11.2026 (Incus only without containers) |
| Incus with a real Incus, real reCAPTCHA | Not tested |
| Real Let's Encrypt, real OIDC provider, long running operation, throughput | Not tested |
