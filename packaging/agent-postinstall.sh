#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
if [ -f /etc/limdm/agent.json ]; then
    systemctl try-restart limdm-agent.service >/dev/null 2>&1 || true
else
    echo "LiMDM: enroll with: limdm-agent enroll --server URL --fingerprint FP --token TOKEN"
fi
