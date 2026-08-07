FROM alpine:latest

LABEL author="cyb3rdoc" maintainer="cyb3rdoc@proton.me"

# Install KEA DHCP and Python
RUN apk add --no-cache \
    kea \
    kea-dhcp4 \
    kea-dhcp-ddns \
    kea-ctrl-agent \
    kea-hook-lease-cmds \
    python3 \
    py3-flask \
    py3-werkzeug \
    supervisor \
    ca-certificates \
    libcap

# Create kea user
RUN adduser -D -u 1000 kea 2>/dev/null || true && \
    mkdir -p /var/lib/kea /var/log/kea /run/kea /etc/kea && \
    chown -R kea:kea /var/lib/kea /var/log/kea /run/kea

# Allow the unprivileged 'kea' user to bind to UDP/67 (CAP_NET_BIND_SERVICE)
# and to use raw sockets if the config requests raw socket type (CAP_NET_RAW).
RUN setcap 'cap_net_bind_service,cap_net_raw=+ep' /usr/sbin/kea-dhcp4

# Download IEEE OUI database for offline MAC-to-vendor lookup.
# The CSV (~4-5 MB) is baked into the image so no runtime internet access is needed.
RUN mkdir -p /app && \
    apk add --no-cache --virtual .oui-deps curl && \
    curl -fsSL --retry 3 -o /app/oui.csv https://standards-oui.ieee.org/oui/oui.csv && \
    apk del .oui-deps

# Copy application files
COPY app/ /app/
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY config/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.default
COPY config/kea-dhcp-ddns.conf /etc/kea/kea-dhcp-ddns.conf.default
COPY entrypoint.sh /entrypoint.sh

# The Alpine kea packages ship their own example configs in /etc/kea;
# overwrite them so fresh volumes are seeded with ours, not the stock ones.
RUN cp /etc/kea/kea-dhcp4.conf.default /etc/kea/kea-dhcp4.conf && \
    cp /etc/kea/kea-dhcp-ddns.conf.default /etc/kea/kea-dhcp-ddns.conf

# Set permissions
RUN chmod +x /entrypoint.sh && \
    chown -R kea:kea /app

ENV TZ=UTC
VOLUME ["/etc/kea"]
EXPOSE 67/udp 5000

ENTRYPOINT ["/entrypoint.sh"]
