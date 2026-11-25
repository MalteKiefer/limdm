#!/bin/sh
# deb: on purge remove configuration, device identity and state.
# rpm erase ($1 = 0) keeps them, like other rpm packages keep modified config.
set -e
if [ "$1" = "purge" ]; then
    rm -rf /etc/limdm /var/lib/limdm /var/cache/limdm
fi
