# Kovexy

A small reverse proxy for the homelab, written in Kotlin. Domains, backends, certificates and webhooks are managed in
a web UI, every change applies at once without a restart.

WARNING: This is currently only a proof of concept, not ready for production.

Kovexy runs as a single fat JAR with systemd, no Docker. It takes its ideas from [Zoraxy](https://github.com/tobychui/zoraxy)
(features, admin UI) and [Caddy](https://caddyserver.com) (protocol details, certificates).

## Features

- Routing by domain and path. The most specific route wins, a prefix only matches at path boundaries.
- One certificate per domain from Let's Encrypt (ACME, HTTP-01), renewed automatically and swapped without restart.
- HTTPS or nothing: port 80 only answers ACME challenges and redirects everything else to HTTPS. HTTP/2, WebSockets, streaming of large bodies in both directions.
- Load balancing with weights, backup servers, sticky sessions, active and passive health checks.
- Static files, redirects, blocked paths and a fallback for unknown domains.
- Request and response headers per route, with a template for security headers.
- Access profiles: IP and country rules, exploit filter, AI crawlers, trap paths with automatic bans, rate limit,
  allowed methods, Google reCAPTCHA, Basic Auth.
- DynDNS: routers report their changing IP and Kovexy adds it to the allow list of chosen access profiles.
- Incus discovery: containers with `user.kovexy.*` keys go live after one click.
- Admin login with password, OIDC or both, audit log and security events.
- Admin UI with live status, statistics as charts with percentiles and top lists, access log, light and dark mode.
- Backup and restore, webhooks with a ready preset for [KNot](https://github.com/nexus421/KNot).

## Status

All three phases are implemented: core, protection, and captcha, Incus discovery and extended
statistics. Not yet run in real operation. As long as only a password protects the admin UI, every page says so.

## Quick start

Needs Java 21 or newer.

```bash
sudo mkdir -p /opt/kovexy
sudo cp kovexy.jar /opt/kovexy/
sudo cp deploy/kovexy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kovexy
journalctl -u kovexy | grep "admin password"
```

Open the admin UI on the server at `http://127.0.0.1:8000` (for example through an SSH tunnel) and log in with the
password from the log. Then add a backend and a domain.

## Documentation

- [Usage](docs/usage.md): the admin UI and how requests are handled
- [Configuration](docs/configuration.md): command line, `kovexy.json`, every field
- [Deployment](docs/deployment.md): systemd, directories, reaching the admin UI with TLS
- [Security](docs/security.md): what Kovexy protects and how
- [Development](docs/development.md): build, tests, project layout
  

Kovexy is written with AI. Code, tests and documentation were created with Claude by Anthropic, directed by me.

## License

[Apache-2.0](LICENSE)
