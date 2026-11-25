#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
if [ -f /etc/limdm/device.pem ]; then
    systemctl try-restart limdm-agent.service >/dev/null 2>&1 || true
elif [ -f /etc/limdm/enroll.conf ]; then
    # mass deployment: the config was placed before the package was installed
    if limdm-agent enroll --config /etc/limdm/enroll.conf; then
        systemctl enable --now limdm-agent.service >/dev/null 2>&1 || true
    else
        echo "LiMDM: enrollment with /etc/limdm/enroll.conf failed; fix it and run: systemctl enable --now limdm-agent"
    fi
else
    echo "LiMDM: place /etc/limdm/enroll.conf and run: systemctl enable --now limdm-agent"
fi
