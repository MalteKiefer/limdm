# LiMDM

[![CI](https://github.com/MalteKiefer/limdm/actions/workflows/ci.yml/badge.svg)](https://github.com/MalteKiefer/limdm/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MalteKiefer/limdm/actions/workflows/codeql.yml/badge.svg)](https://github.com/MalteKiefer/limdm/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MalteKiefer/limdm/badge)](https://scorecard.dev/viewer/?uri=github.com/MalteKiefer/limdm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Declarative device management for Linux clients (Debian, Ubuntu, Fedora), modelled on
Apple's Declarative Device Management. Administrators declare the desired state in
blueprints; the agent converges to it on its own, also while offline, and reports
status back. Compliance checks map to BSI IT-Grundschutz, CIS Benchmarks (Level 1
and 2) and ISO/IEC 27001:2022 Annex A.

> **Status:** early. The protocol, server and tests are complete; the agent has not
> yet been exercised on real Debian, Ubuntu and Fedora machines. See
> [Limitations](#limitations).

## Architecture

```
 Admin browser ── HTTPS + OIDC (Google Workspace, …) ──► limdm-server :8443 ─┐
                                                                             ├─ PostgreSQL (TLS verify-full)
 limdm-agent ─────── mTLS, TLS 1.3, pinned device CA ──► limdm-server :8444 ─┘
   (root service on every device)
```

| Concept | Meaning |
|---|---|
| Declaration | One piece of desired state: `identifier`, `type`, `payload`. Any change changes its `server_token`. |
| Library item | A reusable, validated declaration payload, for example "CIS Level 1 baseline" or "Proxy Berlin". |
| Blueprint | An assignment map: library items plus `if` nodes with rules on device facts (OS, version, architecture, desktop, vendor, model, hostname, tags, directory groups, department), nested freely. A blueprint can inherit from a parent, whose map is evaluated first. Each device has exactly one blueprint: set explicitly, through the group of its primary user, or `default`. The server merges the selected items into one declaration per type (lists are combined, otherwise the last item wins). |
| Directory | People and groups from SCIM 2.0 (Okta, Entra ID, authentik, JumpCloud) or Google Workspace (Directory API, hourly). Groups map to blueprints; people become primary users of devices. |
| Compliance policy | The compliance item carries a grace period, a signed webhook notification and optional automatic lock and unlock. |
| Status | The agent reports per declaration whether it is `valid` and `active`, with reasons, plus status items (inventory, compliance checks). It only sends status when its hash changes. |
| Command | One off actions only: `sync`, `update`, `reboot`, `shutdown`, `lock`, `unlock`, `script` (scripts only if allowed on the device at enrollment). |
| Inventory | Hardware, disks, volumes with encryption state, memory, OS, desktop environment, packages, and (with consent via the privacy declaration) accounts and network interfaces. Collected with [osquery](https://osquery.io), which the agent requires. |

### Declaration types

| Type | Payload |
|---|---|
| `com.limdm.agent` | `{"checkin_seconds": 300}` |
| `com.limdm.compliance` | `{"level": 1, "remediate": true, "exclude": ["net.forwarding"]}` |
| `com.limdm.updates` | `{"mode": "security", "window": "02:00-05:00", "reboot": false}` |
| `com.limdm.packages` | `{"install": ["htop"], "remove": ["telnet"]}` |
| `com.limdm.services` | `{"enable": [], "disable": ["cups"]}` |
| `com.limdm.files` | `{"files": [{"path": "/etc/issue", "content": "...", "mode": "0644"}]}` |
| `com.limdm.firewall` | `{"enforce": true, "allow": ["22/tcp"]}` |
| `com.limdm.osversion` | `{"min": {"ubuntu": "24.04", "debian": "12", "fedora": "42"}}` |
| `com.limdm.screenlock` | `{"idle_seconds": 300}` (GNOME, locked against user changes) |
| `com.limdm.login` | `{"issuer": "https://accounts.google.com", "client_id": "...", "client_secret": "...", "allowed_domain": "example.com"}` |
| `com.limdm.privacy` | `{"network_info": false, "logged_in_users": false}` |
| `com.limdm.repositories` | signed package sources with a pinned key (https only) |
| `com.limdm.certificates` | CA certificates for the system trust store |
| `com.limdm.sysctl`, `com.limdm.kernelmodules` | kernel parameters, blocked modules |
| `com.limdm.ssh`, `com.limdm.banner` | hardening sshd options (allowlist), login banner |
| `com.limdm.dns`, `com.limdm.ntp`, `com.limdm.proxy` | resolvers, time servers, system proxy |
| `com.limdm.flatpak`, `com.limdm.scripts` | Flatpak apps, recurring scripts (only where scripts are allowed) |
| `com.limdm.diskencryption` | `{"escrow": true, "rotate_after_view": true}`: LUKS recovery keys stored on the server |
| `com.limdm.polkit` | polkit rules per action or namespace and group, e.g. let users manage networks or printers |
| `com.limdm.sudo` | sudo rules (principals, run as, absolute commands, NOPASSWD) checked with `visudo` before install |
| `com.limdm.bootloader` | GRUB superuser and password; the console stores only the PBKDF2 hash, default entries stay bootable |

The console shows an example payload for every type.

Payloads are validated strictly (unknown fields, package and unit names against option
injection, paths against traversal), by the server on save and again by the agent
before applying them.

## Security

* **Agent channel is mTLS only, TLS 1.3.** The server runs its own device CA (ECDSA
  P-384). The agent creates its key locally (P-256) and only sends a CSR. It pins the
  CA by SHA-256 fingerprint at enrollment and afterwards trusts nothing else, no system
  CAs. A TLS terminating proxy cannot sit in between.
* **Revocation without CRLs:** the server accepts only the certificate serial currently
  registered for a device. Retiring or rotating revokes the old certificate at once.
  Certificates last 90 days and rotate automatically 30 days before expiry, with a new key.
  A device that was offline past expiry may still renew for 180 days; the TLS handshake
  proves possession of the key and the serial must still be the registered one. Client
  certificates are verified against the device CA by the server itself, not only in the
  handshake, so this exception applies to the renewal endpoint alone.
* **Admin UI** over HTTPS only (without its own certificate it binds to loopback only,
  behind a local TLS proxy). OIDC with PKCE, nonce, `email_verified` and domain checks.
  Optional local admins as fallback (`LIMDM_LOCAL_LOGIN=true`): generated password
  (argon2id) plus TOTP, single use codes, lockout after 5 failures, per IP rate limit.
  Roles `admin` and `auditor` (read only). HMAC signed sessions, 30 min idle and 8 h
  absolute timeout, CSRF tokens, strict CSP, HSTS, no JavaScript.
* **Database** connections outside loopback must use `sslmode=verify-full`, otherwise
  the server refuses to start.
* **Audit log** is append only (a trigger blocks UPDATE, DELETE, TRUNCATE) and hash
  chained; the audit page verifies the full chain. It records admin actions, logins,
  enrollments, certificate rotations, command results, every change the agent makes on
  a device and desktop logins.
* **Agent updates** require an Ed25519 signature from an offline release key compiled
  into the agent. No downgrades.
* **Privacy:** IP addresses and logged in users are only collected when a
  `com.limdm.privacy` declaration allows it. Default: off. No third party calls except
  the configured identity provider.
* **CSV exports** neutralise formula injection.

## Compliance

The agent runs the checks of the declared level (CIS Level 1 baseline, Level 2 for high
protection needs) and remediates where that is safe. Every check references BSI
IT-Grundschutz, CIS Benchmark and ISO/IEC 27001:2022 Annex A. The compliance page shows
coverage per framework; CSV exports serve as audit evidence.

| Check | L | Remediation | BSI | ISO 27001 |
|---|---|---|---|---|
| `os.supported` | 1 | | SYS.2.1, OPS.1.1.3 | A.8.8 |
| `updates.auto`, `updates.security`, `updates.reboot` | 1 | maintenance window | SYS.2.1, SYS.2.3, OPS.1.1.3 | A.8.8, A.8.32 |
| `disk.encryption` (LUKS) | 1 | | SYS.2.1, CON.1 | A.8.1, A.8.24, A.7.10 |
| `firewall.active` | 1 | yes | SYS.2.1, SYS.2.3 | A.8.20 |
| `mac.enabled` / `mac.enforcing` | 1 / 2 | | SYS.2.3, SYS.1.3 | A.8.7, A.8.9 |
| `boot.secureboot` | 2 | | SYS.2.1 | A.8.1, A.8.9 |
| `kernel.*`, `net.*` (sysctl) | 1/2 | yes | SYS.2.3 | A.8.9, A.8.20 |
| `modules.*` (filesystems, USB storage, protocols) | 1/2 | yes | SYS.2.1, SYS.2.3 | A.7.10, A.8.9, A.8.12 |
| `ssh.baseline` / `ssh.strict` | 1 / 2 | yes, `sshd -t` with rollback | SYS.2.3, SYS.1.3 | A.8.5, A.8.20 |
| `accounts.empty_passwords`, `accounts.uid0` | 1 | partly | ORP.4, SYS.2.3 | A.5.17, A.8.2, A.8.5 |
| `accounts.admins`, `auth.sso` | 1 | yes | ORP.4, SYS.2.1 | A.5.15, A.5.16, A.5.18, A.8.2, A.8.5 |
| `accounts.pwquality` | 1 | yes | ORP.4 | A.5.17 |
| `time.sync` | 1 | yes | OPS.1.2.6, OPS.1.1.5 | A.8.17 |
| `logging.journald`, `logging.sudo` | 1 | yes | OPS.1.1.5, ORP.4 | A.8.2, A.8.15 |
| `logging.auditd` | 2 | yes | OPS.1.1.5, SYS.2.3 | A.8.15, A.8.16 |
| `desktop.screenlock` | 1 | yes | SYS.2.1 | A.7.7, A.8.1 |

Exceptions are declared in `compliance.exclude` as documented risk acceptance and show
as `excepted`, never as passed.

ISO 27001 and BSI IT-Grundschutz certify an organisation's ISMS, not a tool. LiMDM
provides the technical controls and evidence for Linux clients; organisational
requirements (policies, roles, risk analysis, training) stay with the ISMS.

## Operation

### Server

1. Provide PostgreSQL with TLS (`sslmode=verify-full`).
2. Create two OAuth clients in Google Cloud:
   * **Web application** for the admin UI, redirect `https://mdm.example.com/auth/callback`.
   * **TVs and Limited Input devices** for desktop login (device flow); put it into the
     `com.limdm.login` declaration.
3. Copy [`packaging/server.env.example`](packaging/server.env.example) to
   `/etc/limdm-server/server.env` (mode 0600) and fill it in.
4. `systemctl enable --now limdm-server`. Expose port 8444 directly (no TLS terminating
   proxy) and 8443 for the admin UI.
5. Without OIDC, or as break glass access, create a local admin. The credentials
   (password and an `otpauth://` URI for an authenticator app) go to a new 0600 file:

   ```sh
   sudo sh -c 'umask 077; sudo -u limdm limdm-server local-admin -env /etc/limdm-server/server.env add alice > /root/limdm-alice.txt'
   ```

   `reset`, `disable`, `enable` and `list` manage existing accounts.
6. Everything else (OIDC, local login, stale threshold, compliance webhook, console users,
   directory connections) is configured in the console under **Settings**, **Users** and
   **Directory**. Secrets are stored encrypted with a key derived from `LIMDM_SESSION_KEY`.
   The console is available in English and German.

### Behind Caddy

On a host install let the admin UI listen on loopback without its own
certificate and put Caddy in front for automatic HTTPS ([`deploy/Caddyfile`](deploy/Caddyfile)):

```sh
LIMDM_LISTEN=127.0.0.1:8080
LIMDM_PUBLIC_URL=https://mdm.example.com
```

The agent port 8444 stays exposed directly; never terminate its mTLS in a proxy.
`LIMDM_AGENT_HOSTS` adds extra names to the agent certificate, for example the IP
address older agents enrolled with.

### Docker

[`deploy/docker/compose.yaml`](deploy/docker/compose.yaml) runs PostgreSQL (unix
socket only), the server image `ghcr.io/maltekiefer/limdm-server` and Caddy. All
images are pinned by digest; release images carry a build provenance attestation:

```sh
gh attestation verify oci://ghcr.io/maltekiefer/limdm-server:<version> --repo MalteKiefer/limdm
```

### Release key and builds

```sh
limdm-server keygen -out release.key
```

Store the public key as the repository variable `UPDATE_PUBKEY`; tagged releases embed
it. Local builds:

```sh
make build VERSION=1.0.0 UPDATE_PUBKEY=<public key>
```

Publish an agent self update (signature made offline, directory copied to the server):

```sh
limdm-server release -key release.key -version 1.0.1 -dir releases amd64=dist/limdm-agent-linux-amd64 arm64=dist/limdm-agent-linux-arm64
```

### Installing the agent

osquery is a hard dependency and comes from the official osquery repository.
`install-agent.sh` (attached to every release) adds that repository, trusting only
the embedded signing key `1484 120A C4E9 F8A1 A577 AEEE 97A8 0C63 C9D8 B80B`, then
installs osquery and the agent package:

```sh
sudo sh install-agent.sh ./limdm-agent_<version>_amd64.deb
```

If osquery is removed later, the agent reinstalls it from the same repository
(retried hourly) and reports `agent.osquery` as failing until it is back. Only
`osqueryi` is used; no osquery daemon is enabled.

### Enrolling a device

Create a token on the Enrollment page, then on the device as root:

```sh
limdm-agent enroll --server https://mdm.example.com:8444 --fingerprint <CA SHA-256> --token lmt_...
systemctl enable --now limdm-agent
```

Local report without changes: `limdm-agent check --level 2`.

### Disk recovery keys

With `com.limdm.diskencryption` and `escrow` the agent reports every LUKS volume without an
escrowed key. Only the user knows a current passphrase, so the desktop helper
`limdm-desktop` (XDG autostart, runs as the user) shows a dialog with the company name and
logo from the console settings, at login and then once a day, and on demand from the
applications menu entry "Disk recovery key". It uses zenity (GNOME) or kdialog (KDE); no
terminal is needed.

The helper talks to the agent over `/run/limdm/agent.sock`. The agent checks the caller's
peer credentials, answers only users with an active local session and allows five wrong
passphrases per 15 minutes. It adds a generated recovery key in the systemd format, verifies
it and sends it over mTLS. The server stores it sealed with AES-256-GCM; admins and helpdesk
can reveal it on the device page, every view is audited. With `rotate_after_view` the device
replaces a viewed key at its next check in and removes the old one only after the server
confirmed the new key. Administrators can also run `sudo limdm-agent recovery-key`.

### Desktop login

With a `com.limdm.login` declaration the agent creates the users assigned to the device,
manages `sudo`/`wheel` membership, and inserts `pam_exec` before `pam_unix` via
`pam-auth-update` (Debian, Ubuntu) or its own `authselect` profile (Fedora). At login,
GDM or the console shows a URL and code; the user confirms with their Workspace account
on a second device. The agent verifies signature, issuer, audience, verified email,
mapping to the local user and domain. Local unmanaged accounts keep password login.
Removed users are locked; home directories stay.

## Development

```sh
make test
make lint
make integration DB=postgres://limdm@127.0.0.1:5432/limdm
make snapshot
```

## Limitations

* **Not yet run on real systems.** Unit and integration tests cover protocol, mTLS, SQL
  and UI; the agent is built for Linux but not yet exercised on Debian 12, Ubuntu
  22.04/24.04 or Fedora. Test PAM (GDM, lock screen, SELinux context of `pam_exec` on
  Fedora), `authselect` and the `sshd` drop in on a VM per distribution first.
* **BSI mapping is at module level.** Requirement IDs (for example SYS.2.3.Ax) and the
  mapping to Grundschutz++ (BSI Standard 300-1) still need review by an information
  security officer.
* Official CIS Benchmarks exist for Ubuntu and Debian; Fedora uses the RHEL
  recommendations as reference.
* No offline login for centrally managed users.
* The CA key is a 0600 file, no HSM/PKCS#11 yet; the agent key is a file, no TPM binding.
* The desktop login client secret is stored unencrypted in the database and on the device
  (0600, root only).
* Console roles (admin, helpdesk, auditor) are assigned per user in the console, not yet from directory groups.

## License

[MIT](LICENSE)
