# Security

## Agent channel

* **mTLS only, TLS 1.3.** The server runs its own device CA (ECDSA P-384). The agent
  creates its key locally (P-256) and only sends a certificate signing request. It pins the
  CA by SHA-256 fingerprint at enrollment and trusts nothing else afterwards, no system
  CAs. A TLS terminating proxy cannot sit in between.
* **Revocation without CRLs:** the server accepts only the certificate serial currently
  registered for a device. Retiring a device or rotating its certificate revokes the old
  one at once.
* **Rotation:** certificates last 90 days and rotate 30 days before expiry with a new key.
  A device that was offline past expiry may still renew for 180 days: the handshake proves
  possession of the key and the serial must still be the registered one. This exception
  applies to the renewal endpoint only; every other endpoint verifies the certificate
  against the device CA in the server, not only in the handshake.
* **Agent updates** need an Ed25519 signature from an offline release key compiled into
  the agent. Downgrades are refused.
* **Signed commands.** Every command (lock, wipe, script, message …) is signed when it
  is created, with an Ed25519 key in `command.key` next to the CA key, never in the
  database. The signature covers device, command ID, type, creation time and payload. The
  agent pins the public key at its first check in with a signing server and from then on
  runs only commands with a valid signature; refused ones are reported and logged. Whoever
  can only write to the database cannot make a device run anything. Recovery keys for lost
  mode travel beside the signed payload, inside the mTLS channel. Back up `command.key`
  with the CA: a new key makes every device refuse commands until it is re-enrolled.
* **Fallback DNS.** When the system resolver cannot resolve the server's name or none of
  its addresses answers, the agent asks Cloudflare (1.1.1.1, 1.0.0.1) and Google (8.8.8.8,
  8.8.4.4) over DNS over HTTPS, by IP and with their certificates checked; plain DNS on
  port 53 is never used for this. A wrong answer cannot redirect the agent: TLS still
  verifies the server's name against the pinned CA. `"no_fallback_dns": true` in
  `/etc/limdm/config.json` turns it off for networks that must not reach public resolvers.

## Console

* **Network lists.** **Settings**, **Console access by network** limits the console to
  allowed networks (addresses or CIDR ranges) and refuses blocked ones, even when allowed.
  Loopback is always allowed, saving a list that would lock out your own address is
  refused, and the agent API, health check, SCIM and the install script are not affected.
  Behind a reverse proxy on the same host the address comes from X-Forwarded-For.

* HTTPS only. Without its own certificate the console binds to loopback and runs behind a
  local TLS proxy such as Caddy.
* OIDC with PKCE, nonce, `email_verified` and domain checks. Roles are read from the
  database on every request, so removing someone takes effect immediately.
* Local accounts: argon2id password and TOTP (RFC 6238, codes usable once), one time
  recovery codes stored as SHA-256 hashes, lockout after 5 failures for 15 minutes, per IP
  rate limit (client IPs from `X-Forwarded-For` are only trusted from a loopback proxy).
* Sessions: sealed cookies, 30 minutes idle and 8 hours absolute timeout, CSRF tokens on
  every form, `SameSite=Lax`, `Secure`, `HttpOnly`; the sign in form uses a separate `SameSite=Strict` token.
* Headers: strict Content Security Policy (`default-src 'self'`, no inline script or
  style), HSTS, `Referrer-Policy: same-origin`, no framing. The console works without
  JavaScript except the visual blueprint editor.
* Secrets in the database (OIDC client secret, Google service account key) are sealed with
  AES-256-GCM; recovery keys too, bound to device and volume. Keys derive from
  `LIMDM_SESSION_KEY` with HKDF.

## Database

Connections to non loopback hosts must use `sslmode=verify-full`; the server refuses to
start otherwise. Schema changes run as versioned migrations under an advisory lock.

## Audit log

Append only (a trigger blocks `UPDATE`, `DELETE` and `TRUNCATE`) and hash chained. Recorded:
console actions, settings changes, sign ins (also failed ones: local, and OIDC as
`login.failed` with the reason `state`, `code exchange`, `id token` or `claims` and the
client address, never codes or tokens; at most 30 per minute, the process log has all),
enrollments, certificate rotations, commands, tamper events, recovery key escrow and every
recovery key view, policy actions, exports.

**Keyed chain.** Each entry stores `prev` (the hash of the entry before) and `hash`:

```
hash = HMAC-SHA256(key, prev || be64(at_us) || be64(len(actor)) || actor || be64(len(action)) || action
                        || be64(len(target)) || target || be64(len(detail)) || detail)
```

`at_us` is the time in Unix microseconds, `be64` an unsigned 64 bit big endian integer; the
first entry has 32 zero bytes as `prev`. The key is derived from `command.key` with HKDF
(SHA-256, info `limdm audit chain v1`), so it never lives in the database: whoever can only
write to the database cannot recompute the chain after changing a row. Entries written
before the keyed chain was introduced use plain SHA-256 over the same bytes; the first keyed entry is recorded in
`audit-keyed-from` next to `command.key` and as the entry `audit.keyed`. Back up the CA
directory: without `command.key` and that file, keyed entries cannot be verified. Stop all
server instances for the upgrade, an old instance would write plain entries after the
switch.

**Verification.** The audit page verifies incrementally from the last checkpoint, a
background run verifies the whole chain daily, and **Verify whole chain** does it on demand
(audited as `audit.verify`). A break shows the first changed entry.

**Export and outside verification.** The page filters by text, actor, action, target and
date and pages through the whole log. **CSV** and **JSON Lines** export the filtered entries
with `prev` and `hash`; JSON Lines has the raw values (`at_us`, the fields, `prev`, `hash`
in hex, `scheme`). Recompute an export on the server, or give the key to an auditor:

```sh
limdm-server audit verify limdm-20261126-audit.jsonl   # reads LIMDM_CA_DIR
limdm-server audit key                                 # key=<hex> keyed_from=<id>
limdm-server audit -key <hex> -keyed-from <id> verify limdm-20261126-audit.jsonl
```

An export of a date range starts in the middle of the chain: the first entry's `prev` is
taken as given and every following entry must continue it. Whoever holds the key can
compute valid hashes, so hand it only to the verifying auditor.

**Commands** are linked through the chain alone: the enqueue entry (`command.<type>`, actor
the admin) and the result entry (`command.result`, actor `device:<id>`) both have the device
as target and start with `command <id>`; the result adds the type, `ok` or `failed` and, for
failures, the last line of the output.

**SIEM.** With `LIMDM_SYSLOG=udp://host:514` or `tcp://host:514` (octet counting framing)
the server forwards new audit entries (`MSGID audit`, structured data `id`, `actor`,
`action`, `target`, `hash`) and device events (`MSGID event`) as RFC 5424 messages, facility
13 (log audit). Control characters in values are replaced, structured data is escaped.
Forwarding starts with the entries written after the server started and retries unsent
ones; there is no TLS, so use it on a trusted network or a local relay. The copy outside
the database is the external anchor of the chain.

Routine agent events (every change the agent makes on a device, desktop logins) are high
volume and kept separately in `device_events`: append only, 365 days, shown on the device
page (Commands tab). They do not take part in the hash chain.

## Devices

* The agent validates every payload again before applying it, independent of the server.
* Generated configuration (sudoers, polkit rules, proxy, GRUB) only contains values
  checked against strict patterns; sudoers are additionally checked with `visudo`, sshd
  with `sshd -t`.
* The desktop socket authorizes by peer credentials and active local session.
* Secrets on the device (`device.pem`, login configuration, state) are root only, 0600.

## Host hardening

Firewall (ufw, firewalld, nftables), fail2ban and CrowdSec rules for failed sign ins and agent
port scans, Caddy, PostgreSQL and a checklist: [installation.md](installation.md#hardening-the-host).
Failed local and OIDC sign ins and rejected enrollments are logged with the client address
(`local login failed`, `oidc login failed`, `enroll rejected`).

## Privacy

* By default the agent reports everything, including IP addresses, DNS, routes and logged
  in users. `com.limdm.privacy` switches items off per blueprint.
* The server records the public address of every check in (the agent port is never behind
  a proxy) and looks up its location (country, region, city, provider) at
  `LIMDM_GEOIP_URL`, default `https://ipwho.is/`. Only the address is sent, and only when it
  changed. `LIMDM_GEOIP_URL=off` disables the lookup; the address is still shown. Devices
  with `network_info: false` get neither: the server stores no public address or location
  for them and deletes what was stored.
* Outbound connections: the server talks to the configured OIDC provider, the Google
  Directory API (if configured), the webhook URL (if configured), GitHub for agent releases
  and the location service. Devices talk to the
  LiMDM server, the identity provider during desktop login, their package repositories and
  the osquery repository. `/install.sh` downloads from GitHub.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
