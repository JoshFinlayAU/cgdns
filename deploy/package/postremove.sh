#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# Only a purge removes state. /var/lib/cgdns holds the RFC 5011 trust-anchor
# state and the control store, so deleting it on a plain remove would make an
# upgrade or reinstall re-bootstrap the anchor and lose the node's config.
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/cgdns
    if getent passwd cgdns >/dev/null 2>&1; then
        userdel cgdns >/dev/null 2>&1 || true
    fi
    if getent group cgdns >/dev/null 2>&1; then
        groupdel cgdns >/dev/null 2>&1 || true
    fi
fi

exit 0
