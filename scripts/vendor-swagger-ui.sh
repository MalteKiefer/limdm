#!/bin/sh
# Vendors Swagger UI (Apache 2.0) for the API reference at /api/v1/docs into
# internal/server/web/static/vendor/swagger-ui. Exact version; npm verifies
# the registry integrity hash of the tarball. The first run writes SHA256SUMS,
# later runs refuse files that differ from it. Commit the directory.
set -eu

SWAGGER_UI=5.34.1

cd "$(dirname "$0")/.."
dst=internal/server/web/static/vendor/swagger-ui
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
command -v npm >/dev/null 2>&1 || { echo "npm is required" >&2; exit 1; }

(cd "$tmp" && npm pack --silent "swagger-ui-dist@$SWAGGER_UI" >/dev/null)
mkdir -p "$tmp/out"
tar -xzf "$tmp/swagger-ui-dist-$SWAGGER_UI.tgz" -C "$tmp"
# the bundle includes React and every plugin; the standalone preset (top bar
# with its URL field) is left out on purpose
cp "$tmp/package/swagger-ui-bundle.js" "$tmp/package/swagger-ui.css" "$tmp/package/LICENSE" "$tmp/package/NOTICE" "$tmp/out/"
printf 'swagger-ui-dist %s (Apache-2.0, see LICENSE and NOTICE)\nfrom the npm registry, vendored by scripts/vendor-swagger-ui.sh\n' \
    "$SWAGGER_UI" > "$tmp/out/VERSION"
# source maps are not shipped; drop their references so browsers do not ask for them
sed -i.bak -e '/^\/\/# sourceMappingURL=/d' -e 's|/\*# sourceMappingURL=[^*]*\*/||' "$tmp/out/swagger-ui-bundle.js" "$tmp/out/swagger-ui.css"
rm -f "$tmp/out/"*.bak

if [ -f "$dst/SHA256SUMS" ]; then
    (cd "$tmp/out" && sha256sum -c "$OLDPWD/$dst/SHA256SUMS") || { echo "vendored files differ from $dst/SHA256SUMS" >&2; exit 1; }
fi
mkdir -p "$dst"
cp "$tmp/out/"* "$dst/"
(cd "$dst" && sha256sum swagger-ui-bundle.js swagger-ui.css LICENSE NOTICE VERSION > SHA256SUMS)
echo "vendored into $dst"
