#!/bin/sh
systemd-sysusers /usr/lib/sysusers.d/limdm-server.conf >/dev/null 2>&1 || true
# the service user reads its config and TLS key, nobody else
chown root:limdm /etc/limdm-server /etc/limdm-server/server.env 2>/dev/null || true
chmod 0750 /etc/limdm-server 2>/dev/null || true
chmod 0640 /etc/limdm-server/server.env 2>/dev/null || true
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl try-restart limdm-server.service >/dev/null 2>&1 || true
