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

## Console

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

Append only (a trigger blocks `UPDATE`, `DELETE` and `TRUNCATE`) and hash chained; the audit
page verifies the whole chain and shows where it breaks. Recorded: console actions,
settings changes, sign ins (also failed ones), enrollments, certificate rotations, command
results, tamper events, recovery key escrow and every recovery key view, policy actions.

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

## Privacy

* By default the agent reports everything, including IP addresses, DNS, routes and logged
  in users. `com.limdm.privacy` switches items off per blueprint.
* The server records the public address of every check in (the agent port is never behind
  a proxy) and looks up its location (country, region, city, provider) at
  `LIMDM_GEOIP_URL`, default `https://ipwho.is/`. Only the address is sent, and only when it
  changed. `LIMDM_GEOIP_URL=off` disables the lookup; the address is still shown.
* Outbound connections: the server talks to the configured OIDC provider, the Google
  Directory API (if configured), the webhook URL (if configured), GitHub for agent releases
  and the location service. Devices talk to the
  LiMDM server, the identity provider during desktop login, their package repositories and
  the osquery repository. `/install.sh` downloads from GitHub.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
