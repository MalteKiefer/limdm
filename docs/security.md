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
  key, and the release fails without it. Downgrades are refused. First installations check
  the same signature: `/install.sh` embeds the release public key of the server and refuses
  sums without a valid signature, and `install-agent.sh` needs the key in
  `LIMDM_RELEASE_PUBLIC_KEY`.
* **Signed commands.** Every command (lock, wipe, script, message …) is signed when it
  is created, with an Ed25519 key in `command.key` next to the CA key, never in the
  database. The signature covers device, command ID, type, creation time and payload. The
  agent pins the public key at its first check in with a signing server and from then on
  runs only commands with a valid signature; refused ones are reported and logged. Recovery keys for lost
  mode travel beside the signed payload, inside the mTLS channel. Back up `command.key`
  with the CA. A new key reaches devices only through a rotation: the server announces it
  with a rollover record signed by the pinned key, and the agent refuses any other key
  change ([keys.md](keys.md#command-key)).
* **Signed declarations.** Everything else a device acts on as root is signed with the same
  key when an admin saves it, never when it is delivered: library items (name, type,
  payload), catalog apps (ID, name, mode, sources with their package repositories, detect
  names), managed Flatpak remotes and the user list of each device (bound to the device,
  with the admin flags). The server checks the signature before it delivers anything and
  leaves out what fails, with an error in its log. The agent checks catalog apps, remotes and
  the user list again with its pinned key once the server announces that it signs them
  (`signed_data` in the check in answer): entries without a valid signature are dropped, an
  unsigned user list is refused and the last one stays, and the refusal is reported as an
  event. Older agents ignore the signatures; they get no user list while the stored one does
  not verify. A change that keeps signed fields (allowing or blocking a remote, opening up an
  app on request) is refused when the stored entry no longer verifies, so a database change
  is never signed later by accident. Rows that existed before these signatures are signed
  once per installation, at the first start of 0.17, recorded in the database
  (`settings` key `data-signed-v1`); an instance added or rebuilt later signs nothing.
  Each signature also covers a sequence number that grows with every signed change of the
  entry (the database clock in microseconds, so it keeps growing after a restore). The agent
  keeps the highest number it accepted per app, remote and user list and refuses a lower
  one, so an older signed state written back into the database (an earlier repository, a
  revoked admin flag) is not applied again. Not covered: a deleted catalog entry written
  back with its old signature on a device that never saw a newer state of it.

  Whoever can only write to the database cannot make a device run, install or trust anything
  an admin did not sign. They can still change which signed items and apps reach which
  device (blueprint assignment, approved app requests), stop delivery (a broken signature
  withholds the entry), and change what grants nothing on a device: summary, category and
  icon of apps, branding, the store switches (which only restrict), risk exceptions (which
  only exclude compliance checks), the public DNS fallback switch (TLS to the pinned CA still
  applies) and requests to rotate escrowed recovery keys (the device makes the new key itself).
* **Keys and HSM.** Device CA, network CA and command key can live in a PKCS#11 HSM
  (`LIMDM_KEY_PROVIDER=pkcs11` with `LIMDM_PKCS11_MODULE`, `LIMDM_PKCS11_TOKEN`,
  `LIMDM_PKCS11_PIN`; separate build with `-tags pkcs11`). The private keys then never
  leave the HSM; release checksums can be signed there with `limdm-server sign -pkcs11
  LABEL`. Every key, including the session key and the webhook signing secret, can be
  rotated without enrolling devices again (`limdm-server keys status|rotate|finish`,
  **Settings**, **Security**, **Keys**, global administrators only). Inventory, runbooks
  and the compromise procedure are in [keys.md](keys.md).
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

* HTTPS only. Without its own certificate the console binds to loopback and runs behind a
  local TLS proxy such as Caddy.
* **Network lists.** **Settings**, **General**, **Console access by network** limits the
  console to allowed networks (addresses or CIDR ranges) and refuses blocked ones, even when
  allowed. The lists also cover the admin API and `/metrics`, which share the console
  listener. Loopback is always allowed, saving a list that would lock out your own address
  is refused, and the agent API, `/healthz`, `/readyz`, SCIM and `/install.sh` are not
  affected. Refused requests are logged with the parsed address. SCIM has its own list,
  **SCIM allowed networks** (empty: every network), for the identity provider's
  provisioning addresses; outside it `/scim/` answers 403 before the token is checked. The
  SCIM token can manage directory people and groups but never create a console
  administrator: a role mapping to `admin` ignores groups known only from SCIM
  ([configuration.md](configuration.md#role-groups)).
* **Client address.** `X-Forwarded-For` is used only when the peer is loopback or in
  `LIMDM_TRUSTED_PROXIES`; then the last entry counts. Network lists, rate limits and audit
  entries use this address.
* **OIDC** with PKCE, nonce, `email_verified` and domain checks. **Settings**, **SSO**,
  **Require multi factor authentication** refuses sign ins whose id token shows no second
  factor: `amr` must contain `mfa` or `mca`, or two distinct methods of which one is a
  second factor (RFC 8176: `otp`, `hwk`, `swk`, `sms`, `tel`, `sc`, `pop`, `fpt`, `face`,
  `iris`, `retina`, `vbm`). With **Accepted acr values** set, LiMDM requests them and the
  `acr` claim must be one of them instead. A refused sign in is audited as `login.denied`
  ([configuration.md](configuration.md#console-settings)).
* Local accounts: argon2id password and TOTP (RFC 6238, codes usable once), one time
  recovery codes stored as SHA-256 hashes. Sign in attempts are rate limited per client
  address first (see below); after 5 failures an account is locked for 15 minutes for that
  client network only (address, IPv6 per /64), stored in the database so it counts across
  instances. Somebody who knows the name of a break glass account can therefore lock it
  only for their own network, never for the administrators who need it. A reset of the
  credentials clears every lockout of the account.
* Sessions: sealed cookies, 30 minutes idle and 8 hours absolute timeout, CSRF tokens on
  every form, `SameSite=Lax`, `Secure`, `HttpOnly`; the sign in form uses a separate
  `SameSite=Strict` token. Signing out ends the sessions of the account everywhere.
  A page opened without a session sends the browser to the sign in with its own path as
  `next`; after the sign in it returns there. Only a path of the console origin is
  accepted (no other host, no `//`, no backslash or control characters, not the sign in
  pages or the API); anything else lands on the start page, so `next` is no open redirect.
* Console app (`/app/`): its HTML is served to signed in sessions only, its hashed scripts,
  styles and fonts are the public build and are cached for a year. It calls the admin API
  with the session cookie; the API then requires a same origin request (`Sec-Fetch-Site`,
  `Origin`) and, for every change, the session's CSRF token in `X-CSRF-Token`
  ([admin-api.md](admin-api.md#console-app)). It runs under the same CSP as every console
  page, which a Playwright test checks for every page and component.
* Admin API and metrics for automation: bearer tokens. Tokens carry a role (`admin`,
  `helpdesk`, `auditor`, `metrics`), optional scope tags, always expire, are stored as
  SHA-256 hashes, are shown once and can be revoked; creation, revocation, failed
  authentication and role denials are audited. See [admin-api.md](admin-api.md).
* Headers on console and agent API: `Content-Security-Policy: default-src 'self';
  frame-ancestors 'none'; form-action 'self'; base-uri 'none'` (no inline script or style),
  `Strict-Transport-Security: max-age=63072000; includeSubDomains`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, `Cache-Control: no-store`. The console works without
  JavaScript except the visual blueprint editor and the remote shell terminal.

### Rate limits

| What | Limit |
|---|---|
| Local sign in | 10 attempts per 5 minutes per client address |
| Admin API | 600 requests per minute per token; 20 failed authentications per 5 minutes per address, then refused before the token is checked |
| SCIM | 20 failed authentications per 5 minutes per address |
| Enrollment | 20 failed attempts per 5 minutes per address (successful enrollments do not count, so a rollout behind one NAT is not blocked) |
| Network CRL download | 20 failed authentications per 5 minutes per address |
| Device: network certificate | 5 requests per 10 minutes per device |
| Device: app catalog search | 30 requests per 10 minutes per device |

IPv6 addresses count per /64. These counters live in memory per instance: with several
instances an address gets up to that many times the budget
([high-availability.md](high-availability.md)). The local account lockout is in the database.

### Sealed values

Secrets in the database are sealed with AES-256-GCM. Each purpose has its own key, derived
with HKDF from `LIMDM_SESSION_KEY`, and every ciphertext is bound to its field or record, so
sealed values cannot be swapped between fields or rows:

| Value | Bound to |
|---|---|
| OIDC client secret | its settings field |
| Google service account key | its settings field |
| Webhook signing secret (settings row `webhook`) | its settings field |
| Notification channel credentials (Slack, Discord and webhook URLs, SMTP password) | the channel |
| Desktop login client secret in `com.limdm.login` items and their version history | the field (the item signature covers the sealed form) |
| Disk recovery keys | device and volume |

`LIMDM_SESSION_KEY` may list several comma separated keys, the new one first: values are
opened with any of them and sealed again with the first in the background
([keys.md](keys.md#session-key)).

## Roles and device scopes

Console roles are `admin`, `helpdesk` and `auditor` ([configuration.md](configuration.md#console-users-and-roles)).
Role, scope and tenant are read from the database on every request, so a change or removal
takes effect immediately.

* **Admin:** everything, never scoped.
* **Helpdesk:** reads and runs the device commands sync, update, reboot, shutdown, lock,
  unlock, message, user password, user lock and unlock, and log collection; remote shells
  only with the helpdesk switch of the remote shell setting. No wipe, lost mode, scripts,
  audit log, exports or administration pages.
* **Auditor:** reads, including the audit log and exports; changes nothing.

Helpdesk and auditor accounts and API tokens can be limited to device tags or directory
groups (of the device's primary user). Roles can also come from directory groups or the
OIDC `groups` claim (**Settings**, **SSO**, **Console roles from groups**; explicit console
users win). One condition (`scopeCond`) builds the device filter for every listing, device
page, command, export, compliance history, recovery key, remote shell and admin API path;
a device outside the scope is not found (deny by default).

## Tenant isolation

With several tenants ([tenants.md](tenants.md)) isolation is deny by default on two levels.
A session or API token bound to a tenant reaches only the console routes on an explicit
list (`tenantRoutes` in `tenant.go`); every other route, including routes added later,
answers 403. The listed handlers filter by tenant: devices through the same central filter
as the device scopes (`scopeCond`), so device lists, pages, commands, exports, compliance
history, the remote shell, recovery keys and the admin API share one condition, and every
route with a device ID checks that device before its handler runs. Other tables are
filtered by their tenant column, and the shared save and delete functions of the console
and the API refuse objects of other tenants. Objects of other tenants answer 404.
Blueprints cannot reference another tenant's library items, and declaration resolution
loads only items of the device's tenant and of Default. A test walks every console route as
an admin of one tenant against the data of another.

The tenant of an account is read from the database on every request; the tenant a super
admin switched to is kept in the signed session cookie and checked against the tenants
table. A disabled tenant ends the sessions and API tokens of its accounts and stops its
enrollment tokens. Metrics, server settings, keys, the directory and the network CRL are
global only.

## Four eyes approval

**Settings**, **Security**, **Four eyes approval** makes a second administrator approve:
wipe, lost mode, scripts, role changes of console users, every change to an administrator
account (adding one, disabling or enabling one, resetting a local administrator's
credentials), admin API tokens, risk exceptions (the approving admin is recorded as their
approver), and optionally recovery key views and remote shell sessions.
It also covers the declarations that act like a script, so one administrator cannot reach
root on devices without a second one:

* saving or rolling back a library item (console and admin API) of the types
  `com.limdm.scripts`, `com.limdm.sudo`, `com.limdm.localusers`, `com.limdm.repositories`,
  `com.limdm.login` (desktop login and its PAM setup), `com.limdm.ssh`, `com.limdm.polkit`,
  `com.limdm.certificates` (system trust anchors), `com.limdm.artifacts` (installs uploaded
  packages as root; the upload itself needs its own approval), and `com.limdm.files` when a path needs
  `allow_scripts` on the device (outside `/etc/motd`, `/etc/issue`, `/etc/issue.net`,
  `/etc/motd.d/`, `/srv/`, `/etc/opt/`, `/var/opt/`). Other types (packages from the
  configured repositories, firewall, updates, compliance and so on) are saved directly;
* catalog apps that are required or bring a vendor package repository (an icon uploaded
  with the request is not kept; Flathub icons are fetched again);
* console administrators from group mappings: while the setting is on, a mapping of a
  directory group or OIDC `groups` claim to `admin` is ignored, the person gets the strongest
  other mapped role or none, and accounts from groups do not count as administrators. Add
  administrators explicitly, which needs an approval.

The item, app or token is validated when requested and signed or created when approved, in
the name of the requester. A new admin API token is shown once to the approving admin, who
hands it over. Assigning an approved item to a blueprint needs no further approval. New local
administrator credentials after an approved add or reset are shown once to the approving
admin, who hands them over, so the requester never holds a second administrator account. A
remote shell approval names the local user: an approval for one account never opens a shell
as another. The action is stored as a request under **Approvals** (with an optional reason;
for recovery keys the reason or ticket reference is required) and announced as
`approval.request`. Another admin approves or rejects it; the requester can never decide
their own request, also not through an API token they created. An approved command or role change runs at once, in the name of the
requester, with the approval number and the approver in its audit entry. An approved
recovery key view or remote shell opens for the requester once, within one hour. Requests nobody decides
expire after 24 hours. Request, approval, rejection, expiry and use are audited. Bulk
scripts create one request per device; commands from the admin API create a request too
and answer `202` with its ID ([admin-api.md](admin-api.md#commands)).

The setting can only be switched on with at least two active administrators (with one,
nobody could approve), and while it is on the second to last admin cannot be demoted or
disabled. The recovery key and remote shell options require the main switch. With the
setting off everything runs directly as before. Roles derived from directory groups follow
the directory, except that they never grant the admin role while the setting is on. While it is on, the approver of a
[risk exception](compliance.md#risk-exceptions) must be someone other than the admin who
records it. With several tenants a request belongs to the requester's tenant (for a global
administrator: the tenant of the device or user concerned) and is decided there.

## Database

Connections to non loopback hosts must use `sslmode=verify-full`; the server refuses to
start otherwise. Schema changes run as versioned migrations under an advisory lock.

## Audit log

Append only (a trigger blocks `UPDATE` and `TRUNCATE` always, `DELETE` outside the retention
job) and hash chained. Recorded:
console actions, settings changes, sign ins (also failed ones: local as
`login.local.failed`, and OIDC as `login.failed` with the reason `state`, `code exchange`,
`id token` or `claims` and the client address, never codes or tokens; failed ones at most
30 per minute each, lockouts always, the process log has all),
refused MFA sign ins (`login.denied`), enrollments, certificate rotations, commands, tamper
events, recovery key escrow and every recovery key view, policy actions, exports
(`export`, `export.done` with SHA-256), four eyes requests and decisions (`approval.*`),
risk exceptions, key rotations (`keys.rotate`), notification channel changes, remote shell
sessions (start and end), audit verification, key segments and pruning (`audit.verify`,
`audit.keyed`, `audit.key_rotate`, `audit.prune`).

**Keyed chain.** Each entry stores `prev` (the hash of the entry before) and `hash`:

```
hash = HMAC-SHA256(key, prev || be64(at_us) || be64(len(actor)) || actor || be64(len(action)) || action
                        || be64(len(target)) || target || be64(len(detail)) || detail)
```

`at_us` is the time in Unix microseconds, `be64` an unsigned 64 bit big endian integer; the
first entry has 32 zero bytes as `prev`. An entry that belongs to a tenant
([tenants.md](tenants.md)) appends `be64(len(tenant)) || tenant` with the tenant ID in
decimal; entries without a tenant (all from before tenants existed) hash as above. CSV and
JSON Lines exports carry `tenant_id`. The key is derived from `command.key` with HKDF
(SHA-256, info `limdm audit chain v1`), so it never lives in the database: whoever can only
write to the database cannot recompute the chain after changing a row. Entries written
before the keyed chain was introduced use plain SHA-256 over the same bytes; the first keyed entry is recorded in
`audit-keyed-from` next to `command.key` and as the entry `audit.keyed`. Back up the CA
directory: without `command.key` and that file, keyed entries cannot be verified. Stop all
server instances for the upgrade, an old instance would write plain entries after the
switch.

**Key rotation.** A command key rotation starts a new segment: the first server started with
the new key records the first entry of the segment in `audit-keys` (one line per segment:
first entry, key id, and the key of every earlier segment) and writes `audit.key_rotate`
under the new key, and signs the retention cut again. The table `audit_key` names the
current key; an instance with another key refuses to write entries until it restarts, fails
`/readyz` and leaves background jobs to the other instances, so the chain never mixes keys. With an HSM command key the audit key is derived from a
deterministic Ed25519 signature over the label instead of the seed ([keys.md](keys.md)).

**Verification.** The audit page verifies incrementally from the last checkpoint, a
background run verifies the whole chain daily, and **Verify whole chain** does it on demand
(audited as `audit.verify`). A break shows the first changed entry.

**Export and outside verification.** The page filters by text, actor, action, target and
date and pages through the whole log. **CSV** and **JSON Lines** export the filtered entries
with `prev` and `hash`; JSON Lines has the raw values (`at_us`, the fields, `prev`, `hash`
in hex, `scheme`). Recompute an export on the server, or give the key to an auditor:

```sh
limdm-server audit verify limdm-20261126-audit.jsonl   # reads LIMDM_CA_DIR
limdm-server audit key                                 # key=<hex> keyed_from=<id>, one line per segment
limdm-server audit -key <hex> -keyed-from <id> verify limdm-20261126-audit.jsonl
```

`audit verify` prints `<n> entries, <first> to <last>: chain intact` or names the first
broken entry and exits with an error. `-ca DIR` (default `LIMDM_CA_DIR`, else
`/var/lib/limdm-server/ca`) reads every segment from `command.key`, `audit-keyed-from` and
`audit-keys` (with an HSM through `LIMDM_KEY_PROVIDER`). `-key` covers one segment only: an
export that spans a command key rotation is verified with the CA directory, or split at the
segment start. An export of a date range starts in the middle of the chain: the first
entry's `prev` is taken as given and every following entry must continue it. Whoever holds the key can
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
* The desktop socket authorizes by peer credentials and active local session. A process of
  the same user in an SSH session (remote logind session or below the SSH service) may
  read status and catalog, gets no journal or agent log lines, and is refused every change:
  app install, removal and requests, recovery key escrow, SSO confirmation, reboot deferral
  and ending a remote support session. A process started
  through the user's systemd manager belongs to no session and is not told apart.
* The SSO device flow starts only at the device: never from `su` or `sudo`, never with
  `PAM_RHOST`, a pseudo terminal or a remote parent session
  ([desktop-login.md](desktop-login.md)).
* Secrets on the device (`device.pem`, login configuration, state) are root only, 0600.
* **Custom compliance checks** run no shell. A query check starts `osqueryi` with one read
  only `SELECT` over an allowlist of local tables (validated on server and agent, enforced
  again with `--enable_tables` and `--disable_tables`, no extensions, 30 seconds; only row
  counts and a bounded compared value go back to the server); file, sysctl,
  package and service tests are evaluated by the agent itself. Expressions are RE2 (linear
  time). See [compliance.md](compliance.md#custom-checks-comlimdmcustomchecks).

### Known limitations of the agent

* **SSH sessions of a user who is also logged in locally.** The desktop socket refuses app
  changes, key escrow, SSO confirmation, reboot deferral, ending remote support and journal
  lines from processes in an SSH or
  other remote session. A process the same user starts outside any session (`systemd-run
  --user`, under `user@.service`), or a descriptor passed on by a process that already
  exited, is not recognized as remote. The check keeps casual misuse out; it is no barrier
  against the user's own account.
* **Symlinks in managed file paths** are refused on every device (no symlink is followed
  when root writes), including the usr-merge links `/lib`, `/bin`, `/sbin`; declare the real
  path.
* **polkit SSO on GNOME and KDE Plasma.** The SSO device flow for polkit runs only inside a
  local logind session with a seat. On GNOME and Plasma the polkit helper runs outside the
  user's session (under `user@.service` or socket activated), so the device flow does not
  run there and pam_unix applies: SSO only accounts without a local password cannot answer
  polkit prompts. Login, lock screen and display managers are not affected.
* **OpenSSL 3.** Devices without OpenSSL 3 (Ubuntu 20.04, Debian 11, RHEL 8 and its
  rebuilds) cannot install agents from 0.17 on, neither with the installers nor as an
  update of the package.

## Remote shell

The remote shell ([remote-shell.md](remote-shell.md)) is remote code execution by design;
these controls keep it narrow:

* **Two opt ins.** The device must be enrolled with `allow_remote_shell` (local file, not
  changeable from the server) and **Settings**, **Security**, **Remote shell** must be on.
  Helpdesk and root need their own switches. Without the root switch the agent also
  refuses accounts with admin rights (uid 0, `sudo`, `wheel` or `admin` group, sudoers
  rules including `NOPASSWD`; on the agent also the root equivalent groups `docker`, `lxd`,
  `incus-admin`, `libvirt` and `disk`). With the remote shell option of
  [four eyes approval](#four-eyes-approval) a second admin approves each session first.
* **Signed and fresh.** The `shell` command is signed like every command, and the agent
  runs it only with a pinned command key and when it is younger than 10 minutes. Someone
  who can write to the database cannot open a shell.
* **No inbound port.** The device connects out over the existing mTLS agent channel; the
  server pairs it only with the device the session was created for. The session ID is 256
  random bits.
* **Console side.** The WebSocket needs a valid console session of the user who started it,
  the role and setting at that moment, the exact `Origin` and the CSRF token, so another
  site cannot open it (cross site WebSocket hijacking). Access is checked again every
  minute while the session runs.
* **Visible and bounded.** The signed in user is notified and can end the session
  (`limdm support end`); maximum duration (default 60 minutes) and idle timeout (default 15
  minutes) are enforced on server and device; the whole process group is hung up at the end.
* **Several instances.** When console and device reach different server instances, the
  session traffic is relayed through PostgreSQL notifications (channel `limdm_shell`).
  Terminal input and output then pass through the database (TLS with `verify-full` to non
  loopback hosts); whoever can listen on the database server can read them.
* **Accountable.** `shell.start` and `shell.end` go to the hash chained audit log, the
  output is stored (1 MiB per session, 365 days) and only admins and auditors can read it.
  Transcripts can contain whatever the session displayed, including secrets; treat them as
  confidential.
* The WebSocket server is a small RFC 6455 implementation without extensions (masked
  client frames only, 64 KiB per message, UTF-8 checked); the terminal (xterm.js) is
  served from the console, so the CSP stays `default-src 'self'`.

## Host hardening

Firewall (ufw, firewalld, nftables), fail2ban and CrowdSec rules for failed sign ins and agent
port scans, Caddy, PostgreSQL and a checklist: [installation.md](installation.md#hardening-the-host).
Failed local and OIDC sign ins and rejected enrollments are logged with the client address
(`local login failed`, `oidc login failed`, `enroll rejected`).

## Privacy

* **Diagnostics.** Log bundles (the **Collect logs** command) are redacted on the device
  before they leave it, capped at 512 KiB, kept for the newest 10 per device and only
  downloadable by admins and the helpdesk; each download is audited. Redaction masks
  private keys, `key=value` pairs with secret names (password, token, secret, API key,
  preshared key, cookie and others), `Authorization` and `Proxy-Authorization` values,
  bearer, basic and token credentials, user info and token query parameters in URLs
  (`key`, `sig`, `code`, `access_token`, signed URL parameters), JWTs, GitHub, GitLab,
  Slack, AWS and `sk-` keys, recovery keys, and the user fields of failed logins (pam_unix
  `user=`, `ruser=`, `logname=`, sshd `invalid user`, `Failed password for`, `login`
  `FOR '...'`, sudo `password for [...]`), because users often type their password into
  the user name field. Redaction is pattern based: review a bundle before passing it on
  outside IT.

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
* Notification channels and the compliance webhook never reach loopback, link local or
  metadata addresses; private networks only from global channels with the setting for it,
  never from tenant channels ([notifications.md](notifications.md#delivery)). Tenant
  channels sign with their own secret.
* Outbound connections: the server talks to the configured OIDC provider, the Google
  Directory API (if configured), the compliance webhook and notification channels (if
  configured: Slack, Discord, webhook URLs, SMTP servers), the syslog target
  (`LIMDM_SYSLOG`), GitHub for agent releases, Flathub for the app catalog and the location
  service (only when geolocation is on). Devices talk to the
  LiMDM server, the identity provider during desktop login, their package repositories and
  the osquery repository. `/install.sh` downloads from GitHub and verifies the release
  signature before it installs.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
