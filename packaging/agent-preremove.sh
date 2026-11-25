#!/bin/sh
# Removal (deb "remove"/"purge", rpm $1 = 0) needs a release from the
# console (Actions, Allow uninstall), valid for one hour. Upgrades pass.
set -e
case "$1" in
    remove|purge|0) ;;
    *) exit 0 ;;
esac
release=/var/lib/limdm/uninstall-allowed
if [ ! -f "$release" ] || [ $(( $(date +%s) - $(stat -c %Y "$release") )) -gt 3600 ]; then
    limdm-agent tamper-report "package removal attempted without release from the console" >/dev/null 2>&1 || true
    echo "LiMDM: removal refused. Ask IT to allow the uninstall for this device in the console." >&2
    exit 1
fi
limdm-agent tamper-report "package removed with release from the console" >/dev/null 2>&1 || true
# lift the stop protection for this removal only (runtime drop in, gone after reboot)
for unit in limdm-agent.service limdm-watchdog.service; do
    mkdir -p "/run/systemd/system/$unit.d"
    printf '[Unit]\nRefuseManualStop=no\n' > "/run/systemd/system/$unit.d/release.conf"
done
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl disable --now limdm-watchdog.timer >/dev/null 2>&1 || true
systemctl disable --now limdm-agent.service >/dev/null 2>&1 || true
# PAM integration must not outlive the helper binary (the profile file
# itself belongs to the package and is removed by dpkg)
if [ -f /usr/share/pam-configs/limdm ]; then
    pam-auth-update --package --remove limdm || true
fi
if [ -f /var/lib/limdm/authselect.prev ]; then
    authselect select $(cat /var/lib/limdm/authselect.prev) --force || true
fi
rm -f /var/lib/limdm/pam.installed
