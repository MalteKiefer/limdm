#!/bin/sh
# Vendors xterm.js (MIT) for the console terminal of the remote shell into
# internal/server/web/static/vendor/xterm. Exact versions; npm verifies the
# registry integrity hash of every tarball. The first run writes SHA256SUMS,
# later runs refuse files that differ from it. Commit the directory.
set -eu

XTERM=5.5.0
FIT=0.10.0
CANVAS=0.7.0 # renders to a canvas: the DOM renderer needs inline styles, which the CSP forbids

cd "$(dirname "$0")/.."
dst=internal/server/web/static/vendor/xterm
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
command -v npm >/dev/null 2>&1 || { echo "npm is required" >&2; exit 1; }

for spec in "@xterm/xterm@$XTERM" "@xterm/addon-fit@$FIT" "@xterm/addon-canvas@$CANVAS"; do
    (cd "$tmp" && npm pack --silent "$spec" >/dev/null)
done
mkdir -p "$tmp/xterm" "$tmp/fit" "$tmp/canvas" "$tmp/out"
tar -xzf "$tmp"/xterm-xterm-"$XTERM".tgz -C "$tmp/xterm"
tar -xzf "$tmp"/xterm-addon-fit-"$FIT".tgz -C "$tmp/fit"
tar -xzf "$tmp"/xterm-addon-canvas-"$CANVAS".tgz -C "$tmp/canvas"
cp "$tmp/xterm/package/lib/xterm.js" "$tmp/xterm/package/css/xterm.css" "$tmp/out/"
cp "$tmp/fit/package/lib/addon-fit.js" "$tmp/canvas/package/lib/addon-canvas.js" "$tmp/out/"
cp "$tmp/xterm/package/LICENSE" "$tmp/out/LICENSE"
printf 'xterm.js %s, @xterm/addon-fit %s, @xterm/addon-canvas %s (MIT, see LICENSE)\nfrom the npm registry, vendored by scripts/vendor-xterm.sh\n' \
    "$XTERM" "$FIT" "$CANVAS" > "$tmp/out/VERSION"
# source maps are not shipped; drop their references so browsers do not ask for them
sed -i.bak '/^\/\/# sourceMappingURL=/d' "$tmp/out/"*.js && rm -f "$tmp/out/"*.bak

if [ -f "$dst/SHA256SUMS" ]; then
    (cd "$tmp/out" && sha256sum -c "$OLDPWD/$dst/SHA256SUMS") || { echo "vendored files differ from $dst/SHA256SUMS" >&2; exit 1; }
fi
mkdir -p "$dst"
cp "$tmp/out/"* "$dst/"
(cd "$dst" && sha256sum xterm.js xterm.css addon-fit.js addon-canvas.js LICENSE VERSION > SHA256SUMS)
echo "vendored into $dst"
