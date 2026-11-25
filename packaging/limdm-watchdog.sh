#!/bin/sh
# LiMDM watchdog (limdm-watchdog.timer). Plain shell on purpose: it must work
# even when a freshly installed agent binary does not start.
#
# Rollback: if an agent update is still unconfirmed 15 minutes after it was
# started, the previous binary from /var/lib/limdm/rollback is restored and
# the outcome is left for the agent to report. Then the agent's own watchdog
# checks (service enabled and running, watchdog timer) run.
set -u
state=/var/lib/limdm
marker=$state/update-pending.json
saved=$state/rollback/limdm-agent

if [ -f "$marker" ] && [ $(( $(date +%s) - $(stat -c %Y "$marker") )) -gt 900 ]; then
    from=$(sed -n 's/.*"from":"\([^"]*\)".*/\1/p' "$marker")
    to=$(sed -n 's/.*"to":"\([^"]*\)".*/\1/p' "$marker")
    running=$(timeout 10 /usr/bin/limdm-agent version 2>/dev/null || true)
    if [ "$running" = "$from" ]; then
        # the package never got installed: nothing to roll back
        printf '{"from":"%s","to":"%s","ok":false,"detail":"package installation did not complete"}\n' "$from" "$to" > "$state/update-result.json"
    elif [ -x "$saved" ]; then
        install -m 0755 "$saved" /usr/bin/limdm-agent.rollback && mv -f /usr/bin/limdm-agent.rollback /usr/bin/limdm-agent
        printf '{"from":"%s","to":"%s","ok":false,"rolled_back":true,"detail":"agent %s did not check in within 15 minutes"}\n' "$from" "$to" "$to" > "$state/update-result.json"
        systemctl kill --signal=SIGTERM limdm-agent.service >/dev/null 2>&1 || systemctl start limdm-agent.service >/dev/null 2>&1 || true
    fi
    chmod 0600 "$state/update-result.json" 2>/dev/null || true
    rm -f "$marker"
fi
exec /usr/bin/limdm-agent watchdog
