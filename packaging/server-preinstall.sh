#!/bin/sh
# Before an upgrade the installed (old) server backs up, because migrations
# cannot be undone (docs/backup.md). Only when backups are configured; a
# failed backup stops the upgrade. LIMDM_SKIP_UPGRADE_BACKUP=1 skips it.
case "$1" in
upgrade | 2) ;;
*) exit 0 ;;
esac
[ -x /usr/bin/limdm-server ] && [ -r /etc/limdm-server/server.env ] || exit 0
[ "$LIMDM_SKIP_UPGRADE_BACKUP" = "1" ] && exit 0
# versions before the backup command have nothing to run
/usr/bin/limdm-server backup 2>&1 | grep -q -- -if-configured || exit 0
if ! runuser -u limdm -- /usr/bin/limdm-server backup -env /etc/limdm-server/server.env create -reason upgrade -if-configured; then
	echo "limdm-server: the backup before the upgrade failed; fix it or set LIMDM_SKIP_UPGRADE_BACKUP=1" >&2
	exit 1
fi
