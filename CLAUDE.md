# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Kovexy, a reverse proxy in Kotlin (Ktor with the Jetty engine, Ktor client CIO towards backends, acme4j, Exposed
with SQLite, kotlinx.html with htmx). All three phases are implemented, not yet run in real operation. The German
concept and the phase specifications live outside the repository in `../kotlin-reverse-proxy/` (`KONZEPT.md`, `SPEZIFIKATION-PHASE1.md` to
`-PHASE3.md`) and are the source of every design decision.

**Start every session with `../kotlin-reverse-proxy/UMSETZUNG.md`**: current state, open points, decisions still to
be confirmed, next step and working rules (for example: no git until the user says so). Update it at the end of
every piece of work. Until 1.0.0 is published, breaking changes (config fields, behavior, database) are fine, no
compatibility code, but every break must be announced (commit message, answer, docs). Rule of the concept: nothing is
implicit, ask instead of deciding. [README.md](README.md)
is the short project page, details live in [docs/](docs). Read [docs/security.md](docs/security.md) before changing
security relevant code (admin guards, login, sessions, config writing, backup restore, static files, header
handling).

## Commands

Use the Gradle wrapper.

```bash
./gradlew build shadowJar
```

```bash
./gradlew devRun
```

`devRun` starts Kovexy with two demo backends: proxy on 18080 (plain) and 18443 (TLS), admin UI on
`http://localhost:18000` with login through the mock OIDC provider on 18001 (pick a user), data in `build/dev`. `.claude/launch.json` has it
as `kovexy-dev`.

```bash
KOVEXY_PEBBLE=/path/to/pebble ./gradlew test
```

The ACME integration test needs Pebble (`KOVEXY_PEBBLE` or `pebble` on the `PATH`) and is skipped without it. JUnit
silently skips test methods that do not return `Unit`, so write `fun x(): Unit = runBlocking { ... }`.

Dependencies are locked (`gradle.lockfile`). After a version change run `./gradlew dependencies --write-locks`.

The fat JAR is `build/libs/kovexy.jar`. After changing dependencies or the Shadow config, check that
`unzip -p build/libs/kovexy.jar META-INF/services/org.slf4j.spi.SLF4JServiceProvider` prints
`bayern.kickner.klogger.slf4j.KloggerServiceProvider`.

## Toolchain

- Kotlin 2.4.21, Gradle 9.9.1, Shadow 9.6.1, Ktor 3.6.1 (Jetty 12.1.13), Exposed 1.6.1, acme4j 5.1.0. Toolchain
  Amazon Corretto 25, bytecode and API level 21 (`-Xjdk-release=21`) because the target runs Debian 13's OpenJDK 21.
- `bayern.kickner` library from `https://maven.kickner.bayern/releases`: Klogger 0.5.0 (with SLF4J provider).
- BouncyCastle is pinned to 1.87 through its BOM.
- `BuildConfig` (`VERSION`, `BUILD_TIME`) is generated into `build/` on every build, never commit it.
- `src/main/resources/ai-bots/robots.json` comes from ai.robots.txt with `ORIGIN.txt` and `SHA256SUMS`, update it
  with every release. The country data is never shipped, Kovexy downloads it at runtime (see docs/configuration.md).
- htmx and its SSE extension are vendored under `src/main/resources/static/vendor/htmx` with `SHA256SUMS`. Update
  them from the npm tarballs and verify the registry integrity value.

## Architecture

`Main.kt` handles the command line, `createKovexy` in `Kovexy.kt` wires everything into one `Kovexy` object that all
parts receive (it takes a `clock` and the proxy ports for tests). Packages: `config`, `tls`, `proxy`, `site`, `web`,
`auth`, `stats`, `notify`, `backup`, `access`, `audit`, `incus`, see docs/development.md "Project layout". The routing
table is built from `kovexy.json` plus approved Incus containers (`Kovexy.rebuildRouting`).

One Jetty server serves everything: plain and TLS proxy ports and the admin connector. `web/Module.kt` sends every
request on a proxy port to `ProxyHandler` before routing, everything else is the admin UI.

Invariants, keep them when adding code:

- No restart, ever. Every config change goes through `ConfigStore.update` (validates, keeps a backup, writes
  atomically, notifies) or a change of the file on disk (watched). `Kovexy.apply` must apply every field live.
- New admin routes are protected by default. `web/Security.kt` (`checkAdminRequest`) requires a session for
  everything outside `/login`, `/auth/start`, `/auth/callback`, `/healthz` and `/static/`, and an allowed `Origin` for every request other than GET
  and HEAD. Keep `Referrer-Policy: same-origin`.
- Never `unsafe {}` or raw HTML in kotlinx.html, never `innerHTML` in JavaScript, no inline scripts or styles (CSP).
  Success messages after a redirect go through the fixed `?done=` keys in `web/Layout.kt`.
- Forms carry the config version (`versionField`), saving with a stale version is refused.
- The proxy path never waits for SQLite: `AccessLog.record` only queues.
- Never log passwords, keys, tokens, cookies or query strings. The access log stores the path without query.
- Config changes go through `call.saveConfig` in the admin UI, so the audit log knows who. Secrets never reach the
  audit log (`audit/ConfigDiff.kt` masks them), new secret fields must be added to `maskSecrets` and `secretChanges`.
- Nothing from Zoraxy (AGPL) is copied. Third party data and patterns are listed in `NOTICE` with their license.
- No Jetty bean is added while the server runs, connectors that already run do not pick it up. Limits live in
  `ConnectionGate`, created before the start, only its values change.
- `/.kovexy/` on proxied domains belongs to Kovexy (`proxy/ReservedPaths.kt`) and never reaches a backend. Kovexy's
  own captcha cookie and the `X-Forwarded-User` family from visitors are removed before forwarding. Kovexy has no
  login in front of apps, apps protect themselves.
- Header handling follows Caddy: `Host` unchanged, `X-Forwarded-*` replaced unless the peer is a trusted proxy,
  hop-by-hop headers removed.

## Code style

Same conventions as [DemoAiProject](https://github.com/nexus421/DemoAiProject) and Dirl: `.not()` instead of `!`,
small `if`s without braces, `runCatching` by default, expected outcomes as `ResultOf2` (own type in `ResultOf2.kt`) and sealed types instead of
exceptions, injectable `clock`, `staticLog` with `private const val TAG`, timestamps through `timestampFormat` in
`Common.kt`, KDoc on every public declaration. No em dashes, no en dashes and no semicolons in prose (README, KDoc,
comments, UI strings). Code, KDoc, comments and README are English, the concept stays German.

UI: building blocks (`page`, `pageHeader`, `card`, `fold` for sections that fold away, `postButton`, form fields) are in `web/Layout.kt`, styles in
`static/app.css` (based on Dirl, light and dark through CSS variables, tables stack on phones). The navigation is a
sidebar with four groups (`Nav` and `NavGroup` in `web/Layout.kt`), on phones a `<details>` menu without
JavaScript. A new page needs a `Nav` entry in its group. Check new pages in the browser at desktop and phone width.
Green, yellow and red are kept for status.

Deliberate deviations from DemoAiProject and Dirl, decided in the concept: Shadow instead of the Ktor Gradle plugin,
Klogger's SLF4J provider, kotlinx.html with htmx instead of Compose, Jetty instead of CIO as server engine, no Docker,
the whole config in `<dataDir>/kovexy.json` instead of a read-only file under `/etc`.

Keep the README short: no implementation details there, they belong into docs/. Update docs/ and KDoc in the same
change as the code.
