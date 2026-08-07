# KEA DHCP Manager

A web-based management interface for ISC KEA DHCP4 server, packaged as a lightweight Docker container.

## Features

- **Web UI Management**: Modern, responsive web interface for KEA DHCP configuration
- **Subnet Management**: Add, delete, and configure DHCP subnets with pools and options
- **Static Reservations**: Manage MAC-to-IP static reservations
- **Lease Monitoring**: View active DHCP leases in real-time, delete single
  leases via the KEA control socket (no service restart)
- **Log Viewer**: Live tail of the KEA/DDNS/web service logs in the browser
- **Configuration Editor**: Direct JSON configuration editing with validation
- **Secure Authentication**: SQLite-based user management with password reset functionality
- **Service Control**: Restart KEA DHCP service from the web interface

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
3. Configure your first DHCP subnet and pool
4. Start the KEA DHCP service

## Configuration

The container exposes `/etc/kea` as a volume where all configuration files are stored:

- `kea-dhcp4.conf` - Main KEA DHCP configuration
- `auth.db` - User authentication database
- `password_reset.key` - Temporary password reset keys
- `secret.key` - Auto-generated Flask session key (created on first start)

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
│   └── templates/          # Jinja2 templates (dashboard, leases, settings, ...)
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
