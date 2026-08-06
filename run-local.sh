#!/usr/bin/env bash
#
# Run the KEA Manager web UI locally for development -- no Docker, no real
# KEA server needed. Creates a throwaway sandbox under ./dev/ with a copy of
# the sample config and starts Flask on http://localhost:5000.
#
# Usage:
#   ./run-local.sh
#
set -euo pipefail
cd "$(dirname "$0")"

DEV_DIR="dev"
ETC_DIR="$DEV_DIR/etc/kea"
VAR_DIR="$DEV_DIR/var/lib/kea"

mkdir -p "$ETC_DIR" "$VAR_DIR"

# Seed the DHCP4 config from the repo sample on first run.
if [ ! -f "$ETC_DIR/kea-dhcp4.conf" ]; then
    cp config/kea-dhcp4.conf "$ETC_DIR/kea-dhcp4.conf"
    echo "Seeded $ETC_DIR/kea-dhcp4.conf from config/"
fi
if [ ! -f "$ETC_DIR/kea-dhcp-ddns.conf" ]; then
    cp config/kea-dhcp-ddns.conf "$ETC_DIR/kea-dhcp-ddns.conf"
fi

# Optional: a fake lease file so the Leases page shows something.
if [ ! -f "$VAR_DIR/kea-leases4.csv" ]; then
    cat > "$VAR_DIR/kea-leases4.csv" <<'CSV'
address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state
10.1.1.150,7c:2e:0d:aa:bb:cc,,3600,4102444800,1,0,0,demo-laptop,0
10.1.2.160,b8:27:eb:11:22:33,,3600,4102444800,2,0,0,demo-pi,0
CSV
    echo "Seeded a demo lease file"
fi

# Set up a virtualenv on first run.
if [ ! -d ".venv" ]; then
    echo "Creating virtualenv (.venv) and installing dependencies..."
    python3 -m venv .venv
    ./.venv/bin/pip install --quiet --upgrade pip
    ./.venv/bin/pip install --quiet -r requirements.txt
fi

export KEA_DEV=1
export KEA_ETC_DIR="$PWD/$ETC_DIR"
export KEA_VAR_DIR="$PWD/$VAR_DIR"
export OUI_CSV="$PWD/app/oui.csv"   # optional; missing file just disables vendor lookup
export SECRET_KEY="dev-secret-not-for-production"

echo
echo "Starting KEA Manager (dev mode) on http://localhost:5000"
echo "  config dir: $KEA_ETC_DIR"
echo "  Ctrl-C to stop."
echo
exec ./.venv/bin/python app/app.py
