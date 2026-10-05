#!/bin/sh

# Create and set permissions for KEA runtime directory
mkdir -p /run/kea /var/log/supervisor
chmod 750 /run/kea
chown kea:kea /run/kea

# Remove stale PID files from an unclean container stop. No KEA process can
# be running yet at this point, and a leftover PID may now belong to an
# unrelated process -- kea-dhcp4 would then refuse to start
# (DHCP4_ALREADY_RUNNING) until supervisord gives up with FATAL.
rm -f /run/kea/*.pid

# Copy default configs if none exist
if [ ! -f "/etc/kea/kea-dhcp4.conf" ]; then
    echo "No DHCP4 configuration found, copying default..."
    cp /etc/kea/kea-dhcp4.conf.default /etc/kea/kea-dhcp4.conf
    chown kea:kea /etc/kea/kea-dhcp4.conf
fi

if [ ! -f "/etc/kea/kea-dhcp-ddns.conf" ]; then
    echo "No DDNS configuration found, copying default..."
    cp /etc/kea/kea-dhcp-ddns.conf.default /etc/kea/kea-dhcp-ddns.conf
    chown kea:kea /etc/kea/kea-dhcp-ddns.conf
fi

# Bind-mounted volumes are created root-owned by Docker on first start;
# the kea-dhcp4/ddns services run as the unprivileged kea user and need
# to read /etc/kea and write the lease database in /var/lib/kea.
chown -R kea:kea /etc/kea /var/lib/kea

# Migrate existing configs: the web UI deletes leases via the lease_cmds
# hook, so make sure it is loaded even in configs created before the
# hook was added to the default config.
python3 - <<'PYEOF'
import json

CONF = '/etc/kea/kea-dhcp4.conf'
HOOK = '/usr/lib/kea/hooks/libdhcp_lease_cmds.so'
try:
    with open(CONF) as f:
        cfg = json.load(f)
    hooks = cfg['Dhcp4'].setdefault('hooks-libraries', [])
    if not any(h.get('library') == HOOK for h in hooks):
        hooks.append({'library': HOOK})
        with open(CONF, 'w') as f:
            json.dump(cfg, f, indent=2)
        print('entrypoint: added lease_cmds hook to kea-dhcp4.conf')
except Exception as e:
    print(f'entrypoint: lease_cmds hook migration skipped: {e}')
PYEOF
chown kea:kea /etc/kea/kea-dhcp4.conf

# Validate configuration
echo "Validating KEA DHCP4 configuration..."
kea-dhcp4 -t /etc/kea/kea-dhcp4.conf

if [ $? -ne 0 ]; then
    echo "ERROR: DHCP4 config validation failed -- using default"
    cp /etc/kea/kea-dhcp4.conf.default /etc/kea/kea-dhcp4.conf
    chown kea:kea /etc/kea/kea-dhcp4.conf
fi

echo "Validating KEA DDNS configuration..."
kea-dhcp-ddns -t /etc/kea/kea-dhcp-ddns.conf

if [ $? -ne 0 ]; then
    echo "ERROR: DDNS config validation failed -- using default"
    cp /etc/kea/kea-dhcp-ddns.conf.default /etc/kea/kea-dhcp-ddns.conf
    chown kea:kea /etc/kea/kea-dhcp-ddns.conf
fi

echo "Starting services with supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
