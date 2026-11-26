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
* **Agent updates** need an Ed25519 signature from the release key whose public half is
  compiled into the agent; an agent built without it refuses self updates (fail closed).
  The private key is a CI secret of the protected `release` environment, not an offline
  key, and the release fails without it. Downgrades are refused.
* **Signed commands.** Every command (lock, wipe, script, message …) is signed when it
  is created, with an Ed25519 key in `command.key` next to the CA key, never in the
  database. The signature covers device, command ID, type, creation time and payload. The
  agent pins the public key at its first check in with a signing server and from then on
  runs only commands with a valid signature; refused ones are reported and logged. Whoever
  can only write to the database cannot make a device run anything. Recovery keys for lost
  mode travel beside the signed payload, inside the mTLS channel. Back up `command.key`
  with the CA: a new key makes every device refuse commands until it is re-enrolled.
* **Network CA.** EAP-TLS device certificates come from a second root, `network-ca.crt` and
  `network-ca.key` next to the device CA, so mTLS certificates never authenticate to the
  network and network certificates never reach the agent API. Agents send only a CSR; the
  server sets subject and SANs. Retire and wipe revoke them on the CRL. See
  [Network profiles](network.md).
* **Fallback DNS (opt in).** Off by default. When an admin turns on **Settings, Security,
  Privacy, public DNS over HTTPS resolvers**, agents learn it at their next check in and
  remember it. Then, when the system resolver cannot resolve the server's name or none of
  its addresses answers, the agent asks Cloudflare (1.1.1.1, 1.0.0.1) and Google (8.8.8.8,
  8.8.4.4) over DNS over HTTPS, by IP and with their certificates checked; plain DNS on
  port 53 is never used for this. A wrong answer cannot redirect the agent: TLS still
  verifies the server's name against the pinned CA. `"no_fallback_dns": true` in
  `/etc/limdm/agent.json` keeps it off on a device whatever the server setting says.

## Console

* **Network lists.** **Settings**, **Console access by network** limits the console to
  allowed networks (addresses or CIDR ranges) and refuses blocked ones, even when allowed.
  Loopback is always allowed, saving a list that would lock out your own address is
  refused, and the agent API, health check, SCIM and the install script are not affected.
  Behind a reverse proxy on the same host the address comes from X-Forwarded-For.

* HTTPS only. Without its own certificate the console binds to loopback and runs behind a
  local TLS proxy such as Caddy.
* OIDC with PKCE, nonce, `email_verified` and domain checks, optionally multi factor
  authentication from the `amr` or `acr` claim ([configuration.md](configuration.md#console-settings)).
  Roles and scopes are read from the database on every request, so removing someone takes
  effect immediately.
* Local accounts: argon2id password and TOTP (RFC 6238, codes usable once), one time
  recovery codes stored as SHA-256 hashes, lockout after 5 failures for 15 minutes, per IP
  rate limit (client IPs from `X-Forwarded-For` are only trusted from a loopback proxy).
* Sessions: sealed cookies, 30 minutes idle and 8 hours absolute timeout, CSRF tokens on
  every form, `SameSite=Lax`, `Secure`, `HttpOnly`; the sign in form uses a separate `SameSite=Strict` token.
* Admin API and metrics: bearer tokens only, no cookies. Tokens carry a role, always expire,
  are stored as SHA-256 hashes, are shown once and can be revoked; creation, revocation,
  failed authentication and role denials are audited, and requests are rate limited per
  token and failures per client address. See [admin-api.md](admin-api.md).
* Headers: strict Content Security Policy (`default-src 'self'`, no inline script or
  style), HSTS, `Referrer-Policy: same-origin`, no framing. The console works without
  JavaScript except the visual blueprint editor.
* Secrets in the database (OIDC client secret, Google service account key, notification
  credentials, the desktop login client secret) are sealed with AES-256-GCM; recovery keys
  too, bound to device and volume. Keys derive from `LIMDM_SESSION_KEY` with HKDF.

## Four eyes approval

**Settings**, **Security**, **Four eyes approval** makes a second administrator approve:
wipe, lost mode, scripts and role changes of console users, and optionally recovery key
views. The action is stored as a request under **Approvals** (with an optional reason;
for recovery keys the reason or ticket reference is required) and announced as
`approval.request`. Another admin approves or rejects it; the requester can never decide
their own request. An approved command or role change runs at once, in the name of the
requester, with the approval number and the approver in its audit entry. An approved
recovery key view opens for the requester once, within one hour. Requests nobody decides
expire after 24 hours. Request, approval, rejection, expiry and use are audited. Bulk
scripts create one request per device; commands from the admin API create a request too
and answer `202` with its ID ([admin-api.md](admin-api.md#commands)).

The setting can only be switched on with at least two active administrators (with one,
nobody could approve), and while it is on the second to last admin cannot be demoted or
disabled. With the setting off everything runs directly as before. Roles derived from
directory groups follow the directory, not this approval.

## Database

Connections to non loopback hosts must use `sslmode=verify-full`; the server refuses to
start otherwise. Schema changes run as versioned migrations under an advisory lock.

## Audit log

Append only (a trigger blocks `UPDATE` and `TRUNCATE` always, `DELETE` outside the retention
job) and hash chained. Recorded:
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

**Retention.** The audit log is kept forever unless **Settings**, **Security**, **Audit log
retention** sets 365 days or more. Then, once a day and only after the whole chain verified
intact, entries older than the period are deleted. The id and hash of the last deleted entry
are stored as the cut, with an HMAC under the audit chain key (the HKDF key from
`command.key` above), and the incremental, daily and on demand verification start from there;
entries behind the cut keep their scheme (plain before `audit-keyed-from`, keyed after it).
The prune itself is an audit entry (`audit.prune`). A cut whose HMAC does not match is
ignored, so the first remaining entry shows as broken; losing `command.key` therefore shows
the chain as broken from the cut on. Rows of `audit_log` and
`device_events` can only be deleted in a transaction that sets `limdm.retention`, which only
the retention job and the device deletion do; a database administrator can still bypass
any trigger, which the hash chain makes visible for the audit log. Finished commands are
deleted after 180 days, except lock, lost mode and wipe, which the device page shows.

**Deleting devices.** A retired device can be deleted on its page (admins, confirmed with
the host name): the device row with its events, metrics, commands, recovery keys and app
requests is removed. Audit entries naming the device stay until the audit retention
removes them; the deletion is one of them (`device.delete`).

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

* **Diagnostics.** Log bundles (the **Collect logs** command) are redacted on the device
  before they leave it, capped at 512 KiB, kept for the newest 10 per device and only
  downloadable by admins and the helpdesk; each download is audited. Redaction is pattern
  based: review a bundle before passing it on outside IT.

* By default the agent reports everything, including IP addresses, DNS, routes and logged
  in users. `com.limdm.privacy` switches items off per blueprint.
* The server records the public address of every check in (the agent port is never behind
  a proxy). Looking up its location (country, region, city, provider) is opt in: off by
  default, turned on in **Settings, Security, Privacy**. Then the server asks
  `LIMDM_GEOIP_URL`, default `https://ipwho.is/`, a third party possibly outside the EU.
  Only the address is sent, and only when it changed. `LIMDM_GEOIP_URL=off` disables the
  lookup regardless of the setting; the address is still shown. Devices
  with `network_info: false` get neither: the server stores no public address or location
  for them and deletes what was stored.
* Outbound connections: the server talks to the configured OIDC provider, the Google
  Directory API (if configured), the webhook URL (if configured), GitHub for agent releases
  and the location service (only when geolocation is on). Devices talk to the
  LiMDM server, the identity provider during desktop login, their package repositories and
  the osquery repository. `/install.sh` downloads from GitHub.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
