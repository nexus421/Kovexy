# DynDNS in Kovexy: design

Status: waiting for approval. Size: small to medium, as little new code in existing parts as possible.

## Intent

Kovexy gets what the plugin [zoraxy-dyndns](../../../../../zoraxy-dyndns) does for Zoraxy. Routers and DynDNS clients (FRITZ!Box, OPNsense, ddclient, anything that speaks dyndns2) report their current IP, and Kovexy adds it to the allow list of the access profiles chosen for that client. Use case: a service that is only reachable from home or a few sites although their IPs change, without an external DynDNS provider.

## Goals

- A sidebar page "DynDNS" (group Protection, next to Access) with any number of clients. Each client has a name, its own password and one or more access profiles.
- Reported IPs act as additional `allowIps` of the client's profiles, live, no restart.
- Behavior of the plugin is kept where it still makes sense: dyndns2 answers, parameters, IPv4 and IPv6 rules, one replace-all update per client, password generated, shown once and stored only as SHA-256, router settings (FRITZ!Box and other clients) shown ready to copy.
- Everything is English, the German UI text goes into `i18n/de.json` like every other text.

## Non-goals and accepted limits

- No modes (`enforce`, `warn`, `open_when_empty`), no warnings page. `allowIps` stays as it is.
- ~~No special protection for an empty allow list. A profile whose `allowIps` and `allowCountries` are both empty lets everybody in, also while its DynDNS clients have not reported yet. The admin owns that, the docs say so.~~ **Replaced on 22.11.2026:** a profile that DynDNS clients use fails closed while it has no address at all (internal entry `0.0.0.0/32` in the routing table), its countries and `allowLocal` still apply. The client page warns when deleting the client or unticking the profile would open a profile. See `docs/usage.md` and KONZEPT section 2.
- Putting a profile with an allow list (including a DynDNS client) on the DynDNS domain locks the routers out. Accepted, the docs and the domain form say so.
- No own activity log and no "last answer" per client (KISS). The access log already shows every request to `/nic/update` with its status, a wrong password shows there as 401.
- No host name resolution, no second IPv4 or IPv6 per update, no per-client rate limit (the profile's rate limit applies).
- No change to any security function (access checks, admin guards, CSP, audit).

## Approaches

1. **A route target "DynDNS"** on a domain. Rejected: needs a route, the exact path and a target per domain, and a wrong setup can expose a backend.
2. **A flag on the domain** (chosen): `dyndns: true`. The domain answers only `/nic/update`, everything else gets the neutral 404 page. One click, nothing to misconfigure.
3. **Write reported IPs into `allowIps` in `kovexy.json`.** Rejected: every router update would change the config version, backups and the audit log, and would break open admin forms.

Reported IPs live in their own state file instead.

## Design

**Domain flag.** `DomainConfig.dyndns: Boolean = false`. Validation refuses `routes` on such a domain. The normal flow stays: HTTPS only, certificate, the access profile of the domain (step 6 in `ProxyHandler`). After the access check, the domain does not route but calls the DynDNS handler for `GET /nic/update` and answers every other path with the neutral 404. Several domains may carry the flag.

**Clients in config.** New `KovexyConfig.dyndnsClients: List<DyndnsClient>` with `name`, `passwordHash` (SHA-256 hex of a generated password, 24 random bytes as hex like the plugin) and `profiles` (names of access profiles, at least one). Validation: unique names (letters, digits, `.`, `_`, `-`, at most 64), profiles must exist. Deleting a profile that a client uses is refused like for domains. Changes go through `call.saveConfig`, so the audit log knows who. `passwordHash` is added to `maskSecrets` and `secretChanges`.

**Reported IPs in a state file.** `<dataDir>/dyndns-state.json`, owner only, written atomically, holds per client the last IPv4, IPv6 and the time of the last update. A missing or broken file means an empty state. The file is not part of the config backup (it is runtime state).

**Effective allow list.** The allow list of a profile is `allowIps` plus the addresses of all clients that use the profile. The routing table is rebuilt when a client reports a changed address or the client set changes, so `AccessChecker` and the trap exemption (`allowsIp`) see the same list. Entries of the config are never touched and clients never touch each other, an address stays while any client reports it. A client removed from the config drops out of the state at the next reconcile.

**Endpoint.** `GET /nic/update` with Basic Auth (client name and password, constant time comparison of the SHA-256), parameters `myip`, `myipv4`, `ip`, `myipv6`, `myip6`, `ipv6`, `hostname` ignored. Address rules as in the plugin: IPv4 a public single address, IPv6 a global host or prefix /48 to /128 with host bits cleared, without a parameter the source address is used. Answers `good <ip>`, `nochg <ip>`, `badauth` (401), `badrequest <reason>` (400), as text/plain. Never log passwords, query values or the Authorization header. The access log keeps its path without query.

**Admin page** `/dyndns` (`Nav.DYNDNS`, group Protection, `web/DyndnsRoutes.kt`):
- Clients table: name, profiles, last addresses, time of the last update.
- Add client (name, profile checkboxes), change profiles, new password, delete. Replace and delete ask for a second click.
- After add and new password the page shows the password once with the router settings and Copy buttons (update URL, domain, user), using the first domain with the flag. Without a flagged domain a hint says to tick "use for DynDNS" on a domain.
- Domain form: checkbox "Use for DynDNS" with its help text, including the lock-out warning. Help texts in `web/Help.kt`, German in `de.json`.

**Docs.** New section in `docs/usage.md` and `docs/configuration.md` (fields, state file, the two accepted limits), `docs/security.md` (what the endpoint may do: only add reported IPs to allow lists), README feature line, `UMSETZUNG.md` entry. New fields only, so no breaking change.

## Left to the builder

Names of classes and files beyond the ones above, how the routing table gets the merged lists (a rebuild with copied profiles is the expected way), the layout of the page, tests (parameter parsing, address rules and the answers ported from the plugin's tests, validation, merged allow list, `/nic/update` through the proxy on a flagged domain, the other paths answering 404). Code style as in `CLAUDE.md`.
