#!/bin/sh
set -e

# The daemon runs unprivileged; it gets CAP_NET_BIND_SERVICE ambiently from the
# unit rather than running as root to bind 53.
if ! getent group cgdns >/dev/null 2>&1; then
    groupadd --system cgdns
fi
if ! getent passwd cgdns >/dev/null 2>&1; then
    useradd --system --gid cgdns --home-dir /var/lib/cgdns \
            --shell /usr/sbin/nologin \
            --comment "cgdns recursive DNS resolver" cgdns
fi

chown root:cgdns /etc/cgdns /etc/cgdns/cgdns.yaml 2>/dev/null || true
chmod 0750 /etc/cgdns 2>/dev/null || true
chmod 0640 /etc/cgdns/cgdns.yaml 2>/dev/null || true
[ -d /etc/cgdns/tls ] && chown root:cgdns /etc/cgdns/tls && chmod 0750 /etc/cgdns/tls
[ -d /var/lib/cgdns ] && chown cgdns:cgdns /var/lib/cgdns && chmod 0750 /var/lib/cgdns

systemctl daemon-reload >/dev/null 2>&1 || true

# A hand-placed unit in /etc shadows the packaged one, so the node keeps running
# whatever that unit points at and the install looks like it took when it did
# not. Worse, removing it later leaves the enable symlink dangling and the node
# does not come back from a reboot.
if [ -f /etc/systemd/system/cgdns.service ]; then
    cat <<'MSG'

warning: /etc/systemd/system/cgdns.service exists and overrides the packaged
unit, so this node is still running whatever that file points at. To adopt the
packaged unit:

    rm /etc/systemd/system/cgdns.service
    systemctl daemon-reload
    systemctl reenable cgdns      # the old enable symlink is now dangling
    systemctl restart cgdns

MSG
fi

# Restart only a node that was already running, so an upgrade carries over. The
# service is deliberately not enabled or started on a first install: the shipped
# config has no listen addresses, and anycast would route production traffic at
# a node the moment it came up.
if systemctl is-active --quiet cgdns 2>/dev/null; then
    systemctl restart cgdns >/dev/null 2>&1 || true
else
    cat <<'MSG'

cgdns installed. It is not started: the shipped config has no listen addresses.

  1. edit  /etc/cgdns/cgdns.yaml
  2. check  cgdns -config /etc/cgdns/cgdns.yaml -check
  3. start  systemctl enable --now cgdns

An admin API token is minted to /var/lib/cgdns/bootstrap.token on first start.
Read it once and delete the file.

MSG
fi

exit 0
