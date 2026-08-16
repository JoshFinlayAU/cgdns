#!/bin/sh
set -e

# On an upgrade the postinstall restarts a running node; stopping here would
# withdraw the anycast prefix for the whole install rather than for the restart.
case "$1" in
    upgrade|1) exit 0 ;;
esac

if systemctl is-active --quiet cgdns 2>/dev/null; then
    systemctl stop cgdns >/dev/null 2>&1 || true
fi
systemctl disable cgdns >/dev/null 2>&1 || true

exit 0
