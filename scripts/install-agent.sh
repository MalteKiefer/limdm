#!/bin/sh
# Install the LiMDM agent with its mandatory dependency osquery.
#
#   sudo LIMDM_RELEASE_PUBLIC_KEY=<hex> sh install-agent.sh ./limdm-agent_<version>_<arch>.deb|.rpm
#   (Debian, Ubuntu, Fedora, RHEL, openSUSE, SLES)
#
# Checks the package against limdm_<version>_SHA256SUMS and its Ed25519
# signature limdm_<version>_SHA256SUMS.sig from the same release, both next to
# the package, with the release public key in LIMDM_RELEASE_PUBLIC_KEY (the
# RELEASE_KEY line of your server's /install.sh). LIMDM_SKIP_SIGNATURE=true
# skips this for packages you built yourself.
# Adds the official osquery repository, trusting only the embedded signing key
# (fingerprint 1484 120A C4E9 F8A1 A577  AEEE 97A8 0C63 C9D8 B80B), then installs
# osquery and the given agent package. Enroll afterwards with `limdm-agent enroll`.
set -eu

pkg=${1:?usage: install-agent.sh <limdm-agent package file>}
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$pkg" ] || { echo "package $pkg not found" >&2; exit 1; }

# verify_sums KEY SUMS SIG: the Ed25519 release signature (hex) over
# "limdm SHA256SUMS v1\n" and the sums file, with the hex public KEY.
hex2bin() { tr -d ' \n\r' | awk '{ h = "0123456789abcdef"; s = tolower($0); for (i = 1; i < length(s); i += 2) printf "\\%03o", (index(h, substr(s, i, 1)) - 1) * 16 + index(h, substr(s, i + 1, 1)) - 1 }'; }
verify_sums() {
    d=$(mktemp -d)
    printf "$(printf '302a300506032b6570032100%s' "$1" | hex2bin)" > "$d/key.der"
    printf "$(hex2bin < "$3")" > "$d/sig"
    { printf 'limdm SHA256SUMS v1\n'; cat "$2"; } > "$d/msg"
    ok=0
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$d/key.der" -rawin -in "$d/msg" -sigfile "$d/sig" >/dev/null 2>&1 || ok=1
    rm -rf "$d"
    return $ok
}

if [ "${LIMDM_SKIP_SIGNATURE:-}" = true ]; then
    echo "warning: release signature not checked (LIMDM_SKIP_SIGNATURE=true)" >&2
else
    key=${LIMDM_RELEASE_PUBLIC_KEY:-}
    case "$key" in ''|*[!0-9a-fA-F]*) echo "set LIMDM_RELEASE_PUBLIC_KEY to the release public key (hex), or LIMDM_SKIP_SIGNATURE=true for your own builds" >&2; exit 1 ;; esac
    [ ${#key} -eq 64 ] || { echo "LIMDM_RELEASE_PUBLIC_KEY: 64 hex characters" >&2; exit 1; }
    for c in openssl awk sha256sum; do command -v "$c" >/dev/null 2>&1 || { echo "$c is required" >&2; exit 1; }; done
    file=$(basename "$pkg")
    ver=$(printf '%s' "$file" | sed -n 's/^limdm-agent_\([^_]*\)_linux_.*/\1/p')
    sums=$(dirname "$pkg")/limdm_${ver}_SHA256SUMS
    [ -n "$ver" ] && [ -f "$sums" ] && [ -f "$sums.sig" ] || { echo "place limdm_${ver}_SHA256SUMS and limdm_${ver}_SHA256SUMS.sig of the release next to the package" >&2; exit 1; }
    verify_sums "$key" "$sums" "$sums.sig" || { echo "release signature of $sums invalid (needs OpenSSL 3)" >&2; exit 1; }
    want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$sums")
    got=$(sha256sum "$pkg" | cut -d ' ' -f 1)
    [ -n "$want" ] && [ "$want" = "$got" ] || { echo "checksum mismatch for $file" >&2; exit 1; }
fi

key=$(cat <<'KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=4n44
-----END PGP PUBLIC KEY BLOCK-----
KEY
)

if command -v apt-get >/dev/null 2>&1; then
    install -d -m 0755 /etc/apt/keyrings
    printf '%s\n' "$key" > /etc/apt/keyrings/limdm-osquery.asc
    chmod 0644 /etc/apt/keyrings/limdm-osquery.asc
    cat > /etc/apt/sources.list.d/limdm-osquery.sources <<'SRC'
# Managed by LiMDM. Local changes are overwritten.
Types: deb
URIs: https://pkg.osquerypackages.com/deb
Suites: deb
Components: main
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/limdm-osquery.asc
SRC
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q osquery "$(readlink -f "$pkg")"
elif command -v dnf >/dev/null 2>&1; then
    install -d -m 0755 /etc/pki/rpm-gpg
    printf '%s\n' "$key" > /etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery
    cat > /etc/yum.repos.d/limdm-osquery.repo <<'REPO'
# Managed by LiMDM. Local changes are overwritten.
[limdm-osquery]
name=osquery
baseurl=https://pkg.osquerypackages.com/rpm/$basearch/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery
REPO
    dnf install -y -q osquery "$(readlink -f "$pkg")"
elif command -v zypper >/dev/null 2>&1; then
    # openSUSE Leap, Tumbleweed, SLES: the osquery rpm repository works with zypper;
    # the key is imported into rpm first, so zypper does not ask whether to trust it
    install -d -m 0755 /etc/pki/rpm-gpg
    printf '%s\n' "$key" > /etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery
    cat > /etc/zypp/repos.d/limdm-osquery.repo <<'REPO'
# Managed by LiMDM. Local changes are overwritten.
[limdm-osquery]
name=osquery
baseurl=https://pkg.osquerypackages.com/rpm/$basearch/
enabled=1
autorefresh=1
type=rpm-md
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery
REPO
    zypper --non-interactive refresh limdm-osquery
    # the agent package is not signed itself; its checksum comes from the release
    zypper --non-interactive install --allow-unsigned-rpm osquery "$(readlink -f "$pkg")"
else
    echo "unsupported distribution: needs apt-get, dnf or zypper" >&2
    exit 1
fi
echo "installed. enroll with: limdm-agent enroll --server URL --fingerprint FP --token TOKEN"
