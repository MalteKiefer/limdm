# Network profiles and device certificates

The `com.limdm.network` declaration puts WLAN, wired 802.1X and VPN connections on
devices. The agent writes them as NetworkManager keyfiles, so they show up in the desktop's
network menu like any other connection. For EAP-TLS the server issues a device certificate
from its own network CA; the private key never leaves the device.

## Requirements

* NetworkManager 1.20 or newer with `nmcli` (Ubuntu 20.04, Debian 11, Fedora, openSUSE and
  newer). Devices without it report the declaration as not achieved.
* OpenVPN profiles need the NetworkManager OpenVPN plugin (`network-manager-openvpn` on
  Debian and Ubuntu, `NetworkManager-openvpn` on Fedora and openSUSE). Add it with a
  packages item.
* EAP profiles pin the RADIUS server's CA. Put that CA into a `com.limdm.certificates` item
  in the same blueprint and reference it by name in `ca_cert`.

## The declaration

A list type: items in a blueprint are merged by profile `name`, the item evaluated last wins.

```json
{"profiles": [
  {"name": "office", "type": "wifi", "ssid": "Corp", "security": "wpa2-enterprise",
   "eap": {"method": "tls", "ca_cert": "corp-root", "server_domain": "radius.example.com"}},
  {"name": "guest", "type": "wifi", "ssid": "Corp Guest", "security": "wpa3-personal",
   "psk": "change me please", "auto_connect": false},
  {"name": "lan", "type": "ethernet", "security": "802.1x",
   "eap": {"method": "peap", "identity": "host-lan", "password": "...", "ca_cert": "corp-root",
           "server_domain": "radius.example.com"}},
  {"name": "vpn", "type": "wireguard", "wireguard": {"addresses": ["10.8.0.2/32"], "dns": ["10.8.0.1"],
   "peers": [{"public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", "endpoint": "vpn.example.com:51820",
              "allowed_ips": ["10.0.0.0/8"], "persistent_keepalive": 25}]}},
  {"name": "branch", "type": "openvpn", "openvpn": {"content": "client\nremote vpn.example.com 1194\n..."}}
]}
```

| Field | Meaning |
|---|---|
| `name` | lower case letters, digits, `.`, `_`, `-`; the connection name and the file `limdm-<name>.nmconnection` |
| `type` | `wifi`, `ethernet`, `wireguard` or `openvpn` |
| `auto_connect` | default `true`; not for OpenVPN, which the user starts |
| `ssid`, `hidden` | WLAN name (1 to 32 bytes of printable text) and whether it is hidden |
| `security` | WLAN: `wpa2-personal`, `wpa3-personal` (SAE), `wpa2-enterprise`, `wpa3-enterprise` (802.1X with protected management frames); ethernet: `802.1x`. Open networks are not supported. |
| `psk` | personal security: 8 to 63 printable ASCII characters, WPA2 also 64 hex digits |
| `eap.method` | `tls` (device certificate), `peap` (MSCHAPv2) or `ttls` (`phase2` `mschapv2` or `pap`) |
| `eap.identity` | PEAP and TTLS: required. TLS: default the certificate's common name (the device ID) |
| `eap.anonymous_identity` | outer identity for PEAP and TTLS |
| `eap.password` | PEAP and TTLS; leave it empty to let the user enter the password in the network menu |
| `eap.ca_cert` | required: name of a certificate in a CA certificates item |
| `eap.server_domain` | required: the RADIUS server certificate must match this domain (`domain-suffix-match`) |
| `wireguard.interface` | default `wg-<name>`, at most 15 characters |
| `wireguard.addresses`, `dns`, `mtu` | CIDR addresses of the tunnel, DNS servers, MTU 1280 to 9000 |
| `wireguard.peers` | `public_key`, optional `preshared_key`, `endpoint` (host:port), `allowed_ips` (CIDR), `persistent_keepalive` |
| `openvpn.content` | the .ovpn file, inline `<ca>`, `<cert>`, `<key>` and `<tls-crypt>` allowed. Directives that run programs (`up`, `down`, `script-security`, `plugin` and similar) are refused. |

CA pinning and the server domain are mandatory for every EAP method: without them any
access point could pose as the network and collect credentials.

## On the device

* Each profile is written to `/etc/NetworkManager/system-connections/limdm-<name>.nmconnection`
  (root, 0600) with a stable UUID, then `nmcli connection reload` runs. Files with the
  `limdm-` prefix that are no longer declared are removed, which disconnects them. Local
  changes to managed files are overwritten at the next check in.
* A profile that cannot be written right now (its CA is missing, the device certificate is
  not issued yet) keeps its previous file and is reported on the declaration.
* **WireGuard**: the agent generates the key pair on the device
  (`/var/lib/limdm/network/wg-<name>.key`, 0600) and reports the public key. The device page
  (**Network**, **WireGuard keys**) shows it; add it as a peer on the VPN server. The key stays
  the same as long as the profile exists and is deleted with it.
* **OpenVPN**: the file is kept in `/var/lib/limdm/network/limdm-<name>.ovpn` (0600) and
  imported with `nmcli connection import type openvpn`. A changed file is imported again.
  The connection is called `limdm-<name>`.

## Secrets

Pre shared keys, EAP passwords, WireGuard preshared keys and OpenVPN files travel only inside
the signed declaration over the mTLS channel. They are masked:

* in the library editor: secrets show as `••••••`; saving the mask unchanged keeps the stored
  value, a new value replaces it;
* in the audit log entry of a saved item;
* in the desktop app and in `limdm profiles`, like every other secret.

On the device they are stored in the root only keyfiles, as NetworkManager requires.

## Device certificates for EAP-TLS

When a device's declarations contain an EAP-TLS profile, the agent creates an ECDSA P-256 key
(`/var/lib/limdm/network/device.key`, 0600), sends a CSR over mTLS
(`POST /api/v1/network-cert`) and stores the certificate in `/var/lib/limdm/network/device.crt`.
It renews 30 days before expiry with a new key. The server issues only to devices that have
an EAP-TLS profile, at most 5 requests per 10 minutes and device, and records each issue in
the audit log (`network.cert_issue`).

The server ignores everything in the CSR except the key and fills in:

| Field | Value |
|---|---|
| Subject | `CN=<device ID>, O=LiMDM network` |
| SAN URI | `urn:limdm:device:<device ID>` |
| SAN DNS | the device's host name, when it is a valid DNS name |
| SAN email | the primary user's email, else the first assigned user's, when known |
| Validity | 90 days |
| Key usage | digital signature, extended key usage client authentication |

### Network CA

The server creates `network-ca.crt` and `network-ca.key` (ECDSA P-384, 15 years) next to the
device CA in `LIMDM_CA_DIR` at the first start. Back them up together with the device CA. It
is a root of its own and not an intermediate of the device CA: the device CA is limited to
path length zero, and keeping the two apart means the agents' mTLS certificates can never be
used for network access.

Configure the RADIUS server to accept client certificates from the network CA only. Download
it under **Network certificates** (`/network`, linked from a device's **Network** tab) or
`/network/ca.pem`. FreeRADIUS example (`mods-available/eap`, `tls-config tls-common`):

```
ca_file = ${certdir}/limdm-network-ca.pem
check_crl = yes
ca_path = ${certdir}/crl
```

### Revocation

Retiring a device and sending it a wipe revoke all its valid network certificates. The CRL of
the network CA lists them until they expire; it is valid for 7 days and signed fresh on every
download.

* Console: **Network certificates**, **Download CRL** (any signed in role).
* Automated: create a token on the same page (shown once, stored as a hash) and fetch
  `https://<console>/network/crl.pem` with `Authorization: Bearer <token>`, for example daily
  from cron on the RADIUS server:

```
curl -fsS -H "Authorization: Bearer lmc_..." https://mdm.example.com/network/crl.pem \
  -o /etc/freeradius/certs/crl/limdm-network.crl.pem && c_rehash /etc/freeradius/certs/crl
```

Failed token attempts are rate limited per address (20 per 5 minutes). OCSP is not offered;
the CRL is short enough for a daily fetch.

### SCEP and ACME

Not implemented. The built in issuance replaces them: the agent already has an authenticated
channel to the server, so a separate enrollment protocol with its own shared secrets would
add attack surface without adding assurance.
