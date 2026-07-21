#!/bin/sh

# Create and set permissions for KEA runtime directory
mkdir -p /run/kea /var/log/supervisor
chmod 750 /run/kea
chown kea:kea /run/kea

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
