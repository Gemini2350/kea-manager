# KEA DHCP Manager

A web-based management interface for ISC KEA DHCP4 server, packaged as a lightweight Docker container.

## Features

- **Live Lease View** (start page): leases read straight from the running
  server via the KEA control socket — grouped per subnet with pool ranges,
  search, vendor lookup (offline IEEE OUI database), and a status bar with
  real server state, uptime and quick actions; updates are pushed to the
  browser via server-sent events (HTML5 `EventSource`), so changes appear
  within seconds without page reloads — search text, scroll position and
  collapsed groups survive every update
- **Lease Actions**: delete single leases or turn them into static
  reservations directly from the lease table (no service restart needed);
  already-reserved leases are flagged
- **Subnet Management**: add, edit and delete subnets — pools, relay
  (`giaddr`), gateway, DNS, domain — reservations and ids survive edits;
  checkboxes allow deleting several subnets at once, and a global "Main
  DNS Servers" setting serves every subnet without its own DNS entry;
  a count field creates several consecutive subnets in one go
  (10.1.1.0/24, 10.1.2.0/24, …) with pool/gateway/relay rebased into
  each network and name/zone numbered; /30 and /31 (RFC 3021)
  point-to-point subnets derive everything from one choice — which of
  the two usable IPs is the relay/gateway, the other being the single
  DHCP address
- **Subnet Groups**: free-form groups (name + color, e.g. "Amber"/"Studio")
  assignable per subnet; bulk reservations can target a whole group with the
  host part re-based into each subnet
- **Zone Subdomains**: set a main domain globally and a subdomain per subnet
  (`studio1` → `studio1.example.lan`), handed out as domain, DNS search list
  (option 119) and DDNS suffix; renaming the main domain re-bases all zones
- **Static Reservations**: per subnet or group, keyed on MAC address or
  on the relay circuit-id (DHCP option 82) to pin an IP to a switch port
  regardless of the connected device; with override handling and
  collapsible per-subnet lists
- **Option-82 Mode per Subnet**: a subnet toggle for port-based setups —
  KEA records the relay-agent info in every lease
  (`store-extended-info`), the lease view gains a "Port (Opt 82)" column,
  the Reserve dialog can pin the port instead of the MAC, and new
  reservations in that subnet default to circuit-id
- **Dynamic DNS**: forward and reverse zones (PTR records), TSIG keys,
  qualifying suffix and conflict-resolution mode — all from the GUI
- **Client Identification Switch**: identify clients by MAC only
  (`match-client-id: false`) — essential when cloned VMs share a
  machine-id/DUID and would otherwise evict each other's leases
- **Log Viewer**: live tail of the KEA/DDNS/web service logs in the browser
- **Configuration Editor**: direct JSON editing with validation, plus
  config import/export
- **Secure Authentication**: SQLite-based user management with password
  reset; persistent session key (logins survive container restarts)
- **Service Control**: restart the KEA DHCP service from the web interface

## Quick Start

### Using Docker

```bash
# Pull and run the container
docker run -d \
  --name kea-manager \
  --hostname kea-manager \
  --network host \
  -e TZ=UTC \
  -v ./kea-config:/etc/kea \
  -v ./kea-leases:/var/lib/kea \
  --restart always \
  gemini2350/kea-manager:latest
```

### Using Docker Compose

```yaml
services:
  kea-manager:
    image: gemini2350/kea-manager:latest
    container_name: kea-manager
    hostname: kea-manager
    network_mode: host
    environment:
      - TZ=UTC
    volumes:
      - ./kea-config:/etc/kea    # config, auth.db, session key
      - ./kea-leases:/var/lib/kea # lease database
    restart: always
```

A ready-to-use `docker-compose.yml` is included in the repository.

## Initial Setup

1. Access the web interface at `http://localhost:5000`
2. Complete the initial setup by creating an admin account
3. Review the global settings (main domain, timers, interfaces)
4. Configure your first DHCP subnet and pool — saving applies the
   configuration and restarts the DHCP service automatically

## Configuration

The container exposes `/etc/kea` as a volume where all configuration files are stored:

- `kea-dhcp4.conf` - Main KEA DHCP configuration
- `kea-dhcp-ddns.conf` - DDNS daemon configuration (zones, TSIG keys)
- `manager.json` - App settings (subnet group definitions)
- `auth.db` - User authentication database
- `password_reset.key` - Temporary password reset keys
- `secret.key` - Auto-generated Flask session key (created on first start)

## HTTPS for the Web UI

The web UI serves plain HTTP until a certificate is present; with one it
serves HTTPS on the same port (5000). Two ways to provide it:

**Manual:** place `cert.pem` (full chain) and `key.pem` into `tls/` inside
the `/etc/kea` volume (paths overridable via `KEA_TLS_CERT` / `KEA_TLS_KEY`).
The app watches the certificate file and restarts itself when it changes,
so renewals are picked up automatically.

**Automatic via ACME** (e.g. an internal [step-ca](https://smallstep.com/docs/step-ca/)
or any other ACME CA):

```yaml
    environment:
      - ACME_DOMAIN=dhcp.example.lan
      - ACME_DIRECTORY_URL=https://ca.example.lan:9000/acme/acme/directory
      - ACME_CA_BUNDLE=/etc/kea/tls/root_ca.crt   # root cert of a private CA
```

On start the container obtains the certificate itself (acme.sh, HTTP-01
standalone -- port 80 must be free on the host and the domain must resolve
to it) and renews it automatically (check every 6 hours); the web UI
reloads on renewal. ACME account and certificates live in the `/etc/kea`
volume. For a private CA, drop its root certificate into the volume first
(path above). If issuance fails the UI stays on HTTP and the container
logs a warning.

Note on short-lived certificates: acme.sh renews 60 days after issuance
by default. If your CA issues shorter-lived certificates (step-ca
defaults to 24 h!), either raise the CA's certificate lifetime (step-ca:
`maxTLSCertDuration` on the provisioner, e.g. `2160h`) and set
`ACME_RENEW_DAYS` below it (e.g. `30`), or at minimum set
`ACME_RENEW_DAYS=1`.

**Behind a reverse proxy** (Caddy, nginx, ... terminating TLS): leave the
`ACME_*`/`KEA_TLS_*` settings unset, point the proxy at port 5000 and set
`KEA_BEHIND_PROXY=1` so the app honours the proxy's `X-Forwarded-*`
headers (correct scheme in redirects and client IPs in logs). Keep it
unset without a proxy -- those headers are client-controllable then.

## Password Recovery

If you forget your admin credentials:

1. Access the container: `docker exec -it kea-manager sh`
2. Generate a reset key from the web UI ("Forgot Password")
3. Read the reset key: `cat /etc/kea/password_reset.key`
4. Use the key in the web interface to reset both username and password

## Network Configuration

**Host networking is strongly recommended** for DHCP servers because:

- DHCP relies on broadcast packets that may not work properly with Docker's bridge networking
- Direct access to network interfaces is required for proper DHCP relay and client discovery
- Eliminates potential issues with DHCP packet forwarding and NAT

Access the web interface at `http://HOST_IP:5000` when using host networking.

## Ports

When using host networking, these ports are exposed directly on the host:

- `5000/tcp` - Web management interface
- `67/udp` - DHCP server port

## Environment Variables

- `TZ` - Timezone (default: UTC)
- `SECRET_KEY` - Flask session secret. Optional: if not set, a key is generated
  on first start and persisted as `secret.key` in the `/etc/kea` volume, so
  logins survive container restarts. Set it only if you want to manage the key
  yourself.

## Building from Source

```bash
git clone <repository-url>
cd kea-manager
docker build -t kea-manager .
```

## Local Development

You can run just the Flask web UI on your own machine — no Docker and no real
KEA server required. Handy for working on templates and routes.

```bash
git clone <repository-url>
cd kea-manager
./run-local.sh
```

The script creates a virtualenv, installs the dependencies from
`requirements.txt`, seeds a throwaway sandbox under `./dev/` (a copy of the
sample config plus a demo lease file), and starts the app on
<http://localhost:5000>.

Under the hood it sets a few environment variables that make the app portable:

| Variable       | Purpose                                            | Default          |
|----------------|----------------------------------------------------|------------------|
| `KEA_DEV`      | Dev mode: skip real `kea-dhcp4` calls; validate config structurally; no service restarts. Auto-enabled when the `kea-dhcp4` binary isn't on `PATH`. | off in Docker |
| `KEA_ETC_DIR`  | Directory for `kea-dhcp4.conf`, `kea-dhcp-ddns.conf`, `auth.db` | `/etc/kea`   |
| `KEA_VAR_DIR`  | Directory for the lease database                   | `/var/lib/kea`   |
| `KEA_RUN_DIR`  | Directory of the kea4-ctrl-socket (lease delete)   | `/run/kea`       |
| `KEA_LOG_DIR`  | Directory of the service logs for the Logs page    | `/var/log/supervisor` |
| `OUI_CSV`      | Path to the IEEE OUI database for vendor lookup    | `/app/oui.csv`   |
| `SECRET_KEY`   | Flask session secret                               | auto-generated   |

The `dev/` sandbox is git-ignored, so you can delete it any time to start fresh.

### Editor tips (VS Code)

The app is a single Flask module in `app/app.py` with Jinja templates in
`app/templates/`. For syntax highlighting of the `.conf` files (they're JSON),
add to your workspace settings:

```json
{
  "files.associations": { "*.conf": "json" },
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python"
}
```

## Project Layout

```
kea-manager/
├── app/
│   ├── app.py              # Flask app: routes, config/lease/DDNS logic
│   ├── static/             # Favicon
│   └── templates/          # Jinja2 templates (leases, settings, logs, ...)
├── assets/                 # Bundled IEEE OUI snapshot (build fallback)
├── config/                 # Sample KEA + supervisord configs (image defaults)
├── Dockerfile              # Alpine image: KEA daemons + Python + supervisord
├── docker-compose.yml      # Deployment (pulls the published image)
├── entrypoint.sh           # Seeds config into the volume, validates, starts supervisord
├── requirements.txt        # Python deps for local development
├── run-local.sh            # One-command local dev server
└── .github/workflows/      # CI: build + push image to Docker Hub
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Support

For issues and questions, please use the GitHub Issues page.
