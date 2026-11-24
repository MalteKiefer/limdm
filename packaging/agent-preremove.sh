#!/bin/sh
# Only on removal, not on upgrade (deb: "remove", rpm: $1 = 0).
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    systemctl disable --now limdm-agent.service >/dev/null 2>&1 || true
    # PAM integration must not outlive the helper binary
    if [ -f /usr/share/pam-configs/limdm ]; then
        pam-auth-update --package --remove limdm || true
        rm -f /usr/share/pam-configs/limdm
    fi
    if [ -f /var/lib/limdm/authselect.prev ]; then
        authselect select $(cat /var/lib/limdm/authselect.prev) --force || true
    fi
    rm -f /var/lib/limdm/pam.installed
fi
