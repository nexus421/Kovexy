# Deployment

Kovexy is a fat JAR with a systemd unit, there is no Docker image. It needs Java 21 or newer (Debian 13:
`apt install openjdk-21-jre-headless`).

## Install

```bash
sudo mkdir -p /opt/kovexy
sudo cp kovexy.jar /opt/kovexy/
sudo chmod 0644 /opt/kovexy/kovexy.jar
sudo cp deploy/kovexy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kovexy
```

The first start creates an admin password and prints it once:

```bash
journalctl -u kovexy | grep "admin password"
```

`sudo java -jar /opt/kovexy/kovexy.jar dataDir=/var/lib/kovexy reset-password` creates a new one at any time.

## Two units

| Unit | User | When |
|---|---|---|
| `deploy/kovexy.service` | `DynamicUser=yes` with `CAP_NET_BIND_SERVICE` for ports 80 and 443 | Default |
| `deploy/kovexy-root.service` | root | Only for the Incus discovery (`incus.enabled`), which is refused without root |

With `DynamicUser` systemd makes the file system read only (`ProtectSystem=strict`). Kovexy only writes to the
`StateDirectory` `/var/lib/kovexy`. That is why `kovexy.json` lives there and not under `/etc`: systemd does not hand
`ConfigurationDirectory` to the service user, and the admin UI must write the file. Both units set
`LimitNOFILE=1048576` like Caddy's unit, otherwise the default limit of open files caps the number of connections.

## Directories

| Path | Content | Mode |
|---|---|---|
| `/opt/kovexy/kovexy.jar` | Program | `0644` |
| `/var/lib/kovexy/kovexy.json` | Whole configuration | `0600` |
| `/var/lib/kovexy/kovexy.db` | SQLite: access log, statistics, sessions | `0600` |
| `/var/lib/kovexy/certs/` | Certificates, keys, ACME account key | `0700` / `0600` |
| `/var/lib/kovexy/www/` | Fallback | `0755` |
| `/var/lib/kovexy/logs/app.log` | Program log, also in the journal | `0600` |
| `/var/lib/kovexy/backups/` | Copies before every save, restore points | `0700` |

## Reaching the admin UI with TLS

The admin UI listens on `127.0.0.1:8000`. To reach it under a domain with a certificate, like Zoraxy:

1. Add a backend `kovexy-admin` with the server `127.0.0.1:8000`.
2. Add a domain `proxy.example.com` with the route `/` to that backend.
3. Set Settings, Public URL to `https://proxy.example.com`.

Requests then reach the admin UI from `127.0.0.1`. Kovexy's proxy hands the real visitor address (after
`trustedProxies`) to the admin UI in a header signed with a secret of the running process, so login lockouts and logs
see the real address. `X-Forwarded-For` is never believed by the admin UI, any local process could set it. Restrict that domain with an access profile, e.g. an allow list for
your home network.

## Ports

Ports 80 and 443 must be reachable from the internet for every domain that should get a certificate. If a port or the
admin address cannot be bound at start, Kovexy ends with exit code 78 and systemd does not restart it.

## Outgoing connections

Kovexy only connects to the outside for:

- the ACME CA (Let's Encrypt by default),
- `api.github.com` for the update check (can be turned off),
- `github.com` for the country data, only while an access profile uses countries,
- the OIDC provider, when OIDC is set up,
- webhook targets.

## Memory

The units are sized for a host with 2 to 4 cores and 4 to 8 GB of memory: at most 1 GB of heap (`-Xmx1g`) with the
G1 collector. `G1PeriodicGCInterval` and the two `HeapFreeRatio` flags hand memory that is no longer needed back to
the system, so the process stays small while there is little traffic. In a test 10000 idle TLS connections (the default
of `limits.maxConnections`) needed about 90 MB of heap, the loaded country data (595025 ranges) about 22 MB (both
measured on 18.11.2026).

On a small host (1 core, 1 GB of memory) use the serial collector and a smaller heap in `ExecStart`:

```
/usr/bin/java -Xmx384m -XX:+UseSerialGC -XX:MinHeapFreeRatio=10 -XX:MaxHeapFreeRatio=30 -XX:+ExitOnOutOfMemoryError --enable-native-access=ALL-UNNAMED -jar /opt/kovexy/kovexy.jar dataDir=/var/lib/kovexy
```

`-XX:+ExitOnOutOfMemoryError` ends Kovexy when the heap runs full, systemd starts it again after 2 seconds
(`RestartSec`). `StartLimitIntervalSec=0` keeps systemd from giving up after several restarts in a row. Exit code 78
(rejected config, port that cannot be bound) is still never restarted, a restart does not fix either. After editing
`kovexy.json` by hand, check it before a restart:

```bash
sudo java -jar /opt/kovexy/kovexy.jar dataDir=/var/lib/kovexy check
```

## OIDC with Pocket ID

1. Create an OIDC client in Pocket ID with the callback URL `https://proxy.example.com/auth/callback` and restrict it
   to a user group ("Selected user groups").
2. In Kovexy under Settings set the public URL, then issuer, client ID and client secret, and choose the login mode.
3. Keep a shell on the server at hand: `java -jar /opt/kovexy/kovexy.jar dataDir=/var/lib/kovexy login-mode=password`
   switches back if the provider is down.

## Updates

The admin UI shows a newer release in the footer (at most one question to GitHub per hour, only while somebody uses
the UI, nothing is downloaded). Replace the JAR and run `sudo systemctl restart kovexy`.
