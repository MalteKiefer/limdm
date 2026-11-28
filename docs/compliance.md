# Compliance

The agent runs the checks of the declared level, remediates where that is safe and reports
the result at every check in. Every built in check references BSI IT-Grundschutz and
ISO/IEC 27001:2022 Annex A; most also reference a CIS Benchmark recommendation (see
[Framework mapping](#framework-mapping)). The **Compliance** page shows pass and fail per
check, filters by state, level and framework, shows coverage by framework, the most failing
checks, risk exceptions and the exports.

ISO 27001 and BSI IT-Grundschutz certify an organisation's ISMS, not a tool. LiMDM provides
technical controls and evidence for Linux clients. Policies, roles, risk analysis and
training stay with the ISMS.

## Levels

The `level` of the [compliance policy](#policy-comlimdmcompliance) selects the checks:

* **Level 1:** the baseline for every client (CIS Level 1, BSI basic requirements).
* **Level 2:** Level 1 plus strict checks for high protection needs (CIS Level 2). They can
  limit how a device is used (USB storage blocked, SSH keys only).

A device without a compliance library item runs no checks.

## Checks

Results are `pass`, `fail`, `na` (not applicable on this device), `excepted` (excluded by
policy or a risk exception, never counted as passed) and `advisory` (failed, but marked
advisory, so not counted). A result fixed by the agent carries `remediated`.

Built in checks carry no severity; `severity` exists only for
[custom checks](#custom-checks-comlimdmcustomchecks). The titles below are the exact titles the
agent reports (the console shows them translated).

| Check | Title | Level | Remediation |
|---|---|---|---|
| `agent.osquery` | osquery inventory source installed | 1 | the agent installs osquery, retried hourly; `na` on Arch and Alpine |
| `os.supported` | Operating system version is supported | 1 | none; minimum from `com.limdm.osversion` |
| `updates.auto` | Automatic updates are declared | 1 | declare `com.limdm.updates` |
| `updates.security` | Security updates are installed | 1 | installed in the maintenance window of `com.limdm.updates` |
| `updates.security_age` | No security update pending longer than allowed | 1 | installed in the maintenance window; the limit is `security_max_days` of `com.limdm.updates` (14 days when unset) |
| `updates.reboot` | No pending reboot older than 7 days | 1 | reboot in the maintenance window |
| `disk.encryption` | System disk is encrypted | 1 | none (needs reinstallation with LUKS) |
| `firewall.active` | Host firewall is active | 1 | yes |
| `mac.enabled` | Mandatory access control is enabled (AppArmor/SELinux) | 1 | none |
| `mac.enforcing` | Mandatory access control is enforcing | 2 | none |
| `disk.recovery` | Disk encryption recovery keys are escrowed | 1 | the desktop helper asks the user; `na` without escrow declared |
| `disk.tpm` | LUKS volumes are bound to the TPM | 1 | bound with the next recovery key rotation or `limdm-agent recovery-key --all` (with a PIN the user runs it) |
| `agent.tpm_key` | Device key is held in the TPM | 2 | the next certificate renewal creates the key in the TPM; `na` without TPM 2.0 |
| `boot.password` | Boot loader is password protected | 1 | via `com.limdm.bootloader` |
| `boot.secureboot` | Secure Boot is enabled | 2 | none |
| `kernel.aslr` | Full ASLR is enabled | 1 | yes (sysctl) |
| `kernel.ptrace` | ptrace is restricted | 1 | yes (sysctl; a stricter value is kept) |
| `kernel.coredumps` | Core dumps are restricted | 1 | yes (sysctl) |
| `kernel.dmesg` | Kernel log and pointers are restricted | 2 | yes (sysctl) |
| `net.forwarding` | IP forwarding is disabled | 1 | yes (sysctl) |
| `net.redirects` | ICMP redirects and source routing are disabled | 1 | yes (sysctl) |
| `net.tcp` | TCP SYN cookies, martian logging, broadcast ICMP ignored | 1 | yes (sysctl) |
| `modules.filesystems` | Unused filesystems are disabled | 1 | yes (modprobe) |
| `modules.udf` | UDF is disabled | 2 | yes (modprobe) |
| `modules.usbstorage` | USB mass storage is blocked | 2 | yes (modprobe) |
| `modules.netproto` | Unused network protocols are disabled | 2 | yes (modprobe) |
| `ssh.baseline` | SSH server is hardened | 1 | yes, `sshd -t` with rollback |
| `ssh.crypto` | SSH offers no weak algorithms or host keys | 1 | yes, `sshd -t` with rollback |
| `ssh.strict` | SSH allows keys only and no forwarding | 2 | yes, `sshd -t` with rollback |
| `accounts.empty_passwords` | No accounts with empty passwords | 1 | yes (such accounts are locked) |
| `accounts.uid0` | Only root has UID 0 | 1 | none |
| `accounts.admins` | Admin rights only for centrally approved users | 1 | none; central login syncs its own users, other members of the admin group are reported; `na` without central login |
| `accounts.pwquality` | Password quality (minimum length 14) | 1 | yes |
| `auth.sso` | Desktop login through the central identity provider | 1 | yes (PAM); `na` without desktop login declared |
| `time.sync` | Time synchronisation is active | 1 | yes |
| `logging.journald` | System log is persistent | 1 | yes |
| `logging.sudo` | sudo logs and uses a PTY | 1 | yes |
| `logging.auditd` | auditd is active with LiMDM rules | 2 | yes |
| `desktop.screenlock` | Screen lock on idle is enforced | 1 | yes |

`disk.tpm` is `na` unless `com.limdm.diskencryption` declares `tpm2`. Without `require`
an unbound volume or a missing TPM 2.0 is reported as `na`; with `require` it fails. See
[TPM unlock](disk-encryption.md#tpm-unlock).

`limdm-agent check` prints the same report locally without changing anything;
`--level 1` or `--level 2` overrides the declared level.

## Framework mapping

The catalog has a version (`CatalogVersion` in `internal/agent/checks.go`, currently
`2026.11.3`). The agent reports it with every result. The evidence export and the
compliance history carry it, so a result can always be tied to the mapping it was
made with. The version is raised whenever a check, its level or a reference changes.

* **CIS:** recommendation number and title of the **CIS Ubuntu Linux 24.04 LTS Benchmark
  v1.0.0** (field `cis_benchmark` of each result). The titles are shared by the Debian and
  RHEL family benchmarks, whose numbers differ.
* **BSI:** IT-Grundschutz-Kompendium Edition 2023. Every check names the module; where a
  single requirement fits, it is named as well.
* **ISO:** ISO/IEC 27001:2022 Annex A controls.

| Check | CIS (Ubuntu 24.04 v1.0.0) | BSI | ISO/IEC 27001 Annex A |
|---|---|---|---|
| `agent.osquery` | none | SYS.2.1 | A.5.9, A.8.9 |
| `os.supported` | 1.2.2.1 | SYS.2.1, OPS.1.1.3, SYS.2.3.A4 | A.8.8 |
| `updates.auto` | none | SYS.2.1, OPS.1.1.3, SYS.2.1.A3, OPS.1.1.3.A15 | A.8.8, A.8.32 |
| `updates.security` | 1.2.2.1 | SYS.2.1, SYS.2.3, OPS.1.1.3, SYS.2.3.A4, OPS.1.1.3.A15 | A.8.8 |
| `updates.security_age` | none | OPS.1.1.3, OPS.1.1.3.A15 | A.8.8 |
| `updates.reboot` | none | OPS.1.1.3, OPS.1.1.3.A15 | A.8.8 |
| `disk.encryption` | none | SYS.2.1, CON.1 | A.8.1, A.8.24, A.7.10 |
| `firewall.active` | 4.1.1, 4.2.3 | SYS.2.1, SYS.2.3 | A.8.20 |
| `mac.enabled` | 1.3.1.1, 1.3.1.2 | SYS.2.3, SYS.1.3, SYS.2.3.A8 | A.8.7, A.8.9 |
| `mac.enforcing` | 1.3.1.4 | SYS.2.3, SYS.1.3, SYS.2.3.A8 | A.8.7, A.8.9 |
| `disk.recovery` | none | CON.1 | A.8.24, A.8.13 |
| `disk.tpm` | none | CON.1, SYS.2.1 | A.8.24, A.7.10 |
| `agent.tpm_key` | none | CON.1, CON.1.A1 | A.8.24, A.5.17 |
| `boot.password` | 1.4.1, 1.4.2 | SYS.2.1, SYS.2.3 | A.8.2, A.8.9 |
| `boot.secureboot` | none | SYS.2.1 | A.8.1, A.8.9 |
| `kernel.aslr` | 1.5.1 | SYS.2.3 | A.8.9 |
| `kernel.ptrace` | 1.5.2 | SYS.2.3 | A.8.9 |
| `kernel.coredumps` | 1.5.3 | SYS.2.3 | A.8.9, A.8.12 |
| `kernel.dmesg` | none | SYS.2.3 | A.8.9 |
| `net.forwarding` | 3.3.1 | SYS.2.3 | A.8.20 |
| `net.redirects` | 3.3.2, 3.3.5, 3.3.8 | SYS.2.3 | A.8.20 |
| `net.tcp` | 3.3.4, 3.3.9, 3.3.10 | SYS.2.3 | A.8.20 |
| `modules.filesystems` | 1.1.1.1 to 1.1.1.5 | SYS.2.3 | A.8.9 |
| `modules.udf` | 1.1.1.8 | SYS.2.3 | A.8.9 |
| `modules.usbstorage` | 1.1.1.9 | SYS.2.1, SYS.2.3 | A.7.10, A.8.12 |
| `modules.netproto` | 3.2.1 to 3.2.4 | SYS.2.3 | A.8.20 |
| `ssh.baseline` | 5.1.7, 5.1.10, 5.1.11, 5.1.13, 5.1.16, 5.1.19, 5.1.20, 5.1.21 | SYS.2.3, SYS.1.3 | A.8.5, A.8.20 |
| `ssh.crypto` | 5.1.6, 5.1.12, 5.1.15 | SYS.2.3, SYS.1.3, CON.1, CON.1.A1 | A.8.24 |
| `ssh.strict` | 5.1.8 | SYS.2.3, SYS.1.3 | A.8.5 |
| `accounts.empty_passwords` | 7.2.2 | ORP.4, SYS.2.3, SYS.2.3.A9 | A.5.17, A.8.5 |
| `accounts.uid0` | 5.4.2.1 | ORP.4, SYS.2.3 | A.8.2 |
| `accounts.admins` | none | ORP.4, SYS.2.1, SYS.2.3.A1 | A.5.15, A.5.18, A.8.2 |
| `accounts.pwquality` | 5.3.3.2.2, 5.3.3.2.3 | ORP.4, SYS.2.3.A9 | A.5.17 |
| `auth.sso` | none | ORP.4 | A.5.16, A.8.5 |
| `time.sync` | 2.3.1.1 | OPS.1.2.6, OPS.1.1.5 | A.8.17 |
| `logging.journald` | title only: "Ensure journald is configured to write logfiles to persistent disk" | OPS.1.1.5, SYS.2.3, OPS.1.1.5.A3 | A.8.15 |
| `logging.sudo` | 5.2.2, 5.2.3 | OPS.1.1.5, ORP.4, OPS.1.1.5.A3 | A.8.2, A.8.15 |
| `logging.auditd` | 6.2.1.2, 6.2.3.1, 6.2.3.4, 6.2.3.8, 6.2.3.19 | OPS.1.1.5, SYS.2.3, OPS.1.1.5.A3 | A.8.15, A.8.16 |
| `desktop.screenlock` | 1.7.4, 1.7.5 | SYS.2.1 | A.8.1, A.7.7 |

BSI requirements used: `SYS.2.1.A3` automatic updates, `SYS.2.3.A1` authentication of
administrators, `SYS.2.3.A4` updates and patches, `SYS.2.3.A8` AppArmor or SELinux,
`SYS.2.3.A9` passwords, `OPS.1.1.3.A15` regular updates, `OPS.1.1.5.A3` logging
configuration, `CON.1.A1` cryptographic methods.

The mapping is a technical proposal. The CIS numbers and BSI requirement IDs have not been
reviewed by a certification body. The information security officer (ISB) must confirm them
for the own scope and the benchmark edition in use.

## Custom checks: `com.limdm.customchecks`

IT defines its own checks as a library item. They are reported, counted, excepted
(`exclude`), marked advisory, exported as evidence and trigger grace period, webhook and
automatic lock exactly like the built in checks. They have no automatic remediation.

```json
{"checks": [
  {"id": "custom.no_telnet", "title": "Telnet client is not installed", "severity": "medium", "level": 1,
   "refs": {"bsi": ["SYS.2.3.A1"], "cis": ["Ensure telnet client is not installed"], "iso": ["A.8.19"]},
   "package": {"name": "telnet", "state": "absent"}},
  {"id": "custom.shadow_mode", "title": "/etc/shadow is not readable by others", "severity": "high", "level": 1,
   "file": {"path": "/etc/shadow", "state": "present", "max_mode": "0640", "owner": "root"}},
  {"id": "custom.no_uid0", "title": "Only root has UID 0", "severity": "critical", "level": 1,
   "query": {"sql": "SELECT username FROM users WHERE uid = 0 AND username <> 'root'", "expect": "no_rows"}}
]}
```

| Field | Meaning |
|---|---|
| `id` | `custom.` followed by up to 56 lower case letters, digits, `.`, `_` or `-` (starting with a letter or digit); use it in `exclude`, `advisory` and risk exceptions |
| `title` | one line, up to 200 characters, shown on the device and compliance pages |
| `severity` | `low`, `medium`, `high` or `critical`; reported with the result and in the evidence |
| `level` | 1 or 2; the check runs when the compliance level is at least this |
| `refs` | free text framework references: `bsi`, `cis`, `iso` lists (one line, up to 200 characters each) |

An item holds at most 200 checks; an ID may appear once. Each check has exactly one test:

| Test | Fields | Passes when |
|---|---|---|
| `query` | `sql`, `expect` (`rows`, `no_rows`, `compare`), for compare `column`, `op`, `value` | the osquery result has rows, has none, or has rows and `column` of every row satisfies `op value` |
| `file` | `path` (absolute), `state` (`present`, `absent`), for present files optional `max_mode` (octal), `owner`, `group`, `contains`, `not_contains` (RE2, per line) | the file exists or not, its permission bits stay within `max_mode` (no setuid, setgid or sticky bit), owner and group match, a line matches `contains`, no line matches `not_contains` |
| `sysctl` | `key`, `op`, `value` | the kernel parameter compares as given; a parameter the kernel does not have is `na` |
| `package` | `name`, `state` (`installed`, `absent`) | the package is installed or not |
| `service` | `name`, `state` (`active`, `inactive`), optional `enabled` | the unit is active or not and, when set, enabled or not |

Operators: `eq`, `ne`, `contains`, `matches` (RE2) compare text; `lt`, `le`, `gt`, `ge`
compare numbers (a value that is no number fails the check).

Custom checks never run a shell. The only program a check starts is `osqueryi` with the
query, for at most 30 seconds, with extensions disabled. Server (on save) and agent (before
running) both accept only one read only statement of at most 4096 characters: it must start
with `SELECT` or `WITH` and may not contain a second statement (a trailing semicolon is
fine), comments, control characters, characters outside ASCII (except inside `'string'`
literals), `INSERT`, `UPDATE`, `DELETE`, `REPLACE` (the string function `replace()` is
allowed), `ATTACH`, `DETACH`, `PRAGMA`, `load_extension`, `writefile` or `readfile`.
The validator tokenizes the query like SQLite (quoted names `"x"`, `[x]` and `` `x` ``,
schema qualified `main.x`) and checks every table after `FROM`, `JOIN`, a comma in a
`FROM` clause and `IN` against an allowlist of local tables:
`apparmor_profiles`, `apt_sources`, `authorized_keys`, `block_devices`,
`cpu_info`, `crontab`, `deb_packages`, `disk_encryption`, `dns_resolvers`, `etc_hosts`,
`etc_protocols`, `etc_services`, `file`, `groups`, `hash`, `interface_addresses`,
`interface_details`, `iptables`, `kernel_info`, `kernel_modules`, `last`,
`listening_ports`, `logged_in_users`, `md_devices`, `memory_info`, `mounts`,
`npm_packages`, `os_version`, `osquery_info`, `pci_devices`, `platform_info`,
`portage_packages`, `process_open_sockets`, `processes`, `python_packages`, `routes`,
`rpm_packages`, `secureboot`, `selinux_settings`, `shadow`, `ssh_configs`,
`startup_items`, `sudoers`, `suid_bin`, `system_controls`, `system_info`,
`systemd_units`, `time`, `tpm_info`, `uptime`, `usb_devices`, `user_groups`,
`user_ssh_keys`, `users`, `yum_sources`, plus the common table expressions of a leading
`WITH`. Tables that reach the network (`curl`, `curl_certificate`, cloud metadata,
`prometheus_metrics`), carve files, read process environments or read any file (`augeas`, whose lenses parse `/etc/shadow` too) are refused. The agent
also starts `osqueryi` with `--enable_tables` set to the same allowlist and
`--disable_tables` for the network and carving tables, so osquery itself does not offer
them. The result sent to the server holds only the row count and, for `compare`, the
compared value of the first failing row (at most 64 characters); rows are never sent.
Without osquery on the device a query check fails. Items of several
blueprints are merged by `id`; the item evaluated last wins.

## Policy: `com.limdm.compliance`

```json
{"level": 1, "remediate": true, "exclude": ["net.forwarding"], "advisory": ["boot.secureboot"],
 "grace_hours": 72, "notify": true, "lock_after_hours": 0, "unlock_when_compliant": true}
```

| Field | Meaning |
|---|---|
| `level` | 1 or 2 |
| `remediate` | apply automatic fixes |
| `exclude` | checks excluded by policy; shown as `excepted`, never as passed. They have no reason or expiry: prefer [risk exceptions](#risk-exceptions) |
| `advisory` | reported but not counted against compliance |
| `grace_hours` | a failing device is `in grace` this long before it counts as non-compliant |
| `notify` | when the grace period is over, send the [compliance webhook](#webhook) and the `device.noncompliant` notification |
| `lock_after_hours` | lock the device this long after it became non-compliant, 0 = never |
| `unlock_when_compliant` | lift an automatic lock once all checks pass again |

The server evaluates `grace_hours`, `notify`, `lock_after_hours` and
`unlock_when_compliant`. Automatic lock and unlock use the same mechanism as the console
command (new logins blocked, sessions locked) and are written to the audit log as actor
`policy` (`compliance.notify`, `compliance.lock`, `compliance.unlock`). Removing
`lock_after_hours` from the policy lifts an automatic lock.

## Risk exceptions

**Compliance**, **Risk exceptions** documents accepted risks (ISO/IEC 27001 6.1.3, BSI
200-2 residual risk). An admin records:

| Field | Rule |
|---|---|
| Check ID | a built in or custom check |
| Mode | `exclude` (shown as `excepted`) or `advisory` (reported, not counted) |
| Device tag | one tag, or empty for every device |
| Reason | 1 to 1000 characters |
| Risk owner | 1 to 200 characters |
| Approver | the person who accepted the risk, 1 to 200 characters |
| Expires | a date within the next three years; the exception is valid through that day |

With [four eyes approval](security.md#four-eyes-approval) off an admin adds the exception
directly and names the approver. With it on, and always for the helpdesk (console app,
**Request exception**, or `POST /api/v1/exception-requests`), the exception is a request in
the inbox (approval action `exception.add`): another admin approves it and is recorded as its
approver, the requester as its creator. A helpdesk account limited to device tags asks for
one of its own tags.

Adding (`exception.add`) and revoking (`exception.revoke`) are audited. With several tenants an exception
belongs to its tenant.

The server merges the active exceptions into the compliance declaration it sends to each
device. An expired or revoked exception is no longer sent, so it stops applying at the next
check in. The agent only knows the resulting `exclude` and `advisory` lists and reports such
checks as `excluded by policy (exception)`. Lists written directly in a compliance library
item still work, but have no reason, owner or expiry.

## Webhook

The compliance webhook is set in **Settings**, **Notifications**, **Compliance webhook**
(global administrators only; tenant accounts do not see it). It is independent of the
[notification channels](notifications.md) on the same tab. When a device becomes
non-compliant after the grace period (and `notify` is on) the server posts:

```json
{"type": "device.noncompliant", "device_id": "...", "hostname": "pc1", "failing_checks": 3,
 "noncompliant_since": "2026-11-25T08:00:00Z", "console_url": "https://mdm.example.com/devices/..."}
```

Tamper reports are sent to the same URL as `{"type": "device.tamper", "device_id", "hostname",
"detail", "console_url"}`. The URL must be https. The webhook gets the events of every
tenant's devices.

Every request has the headers `X-LiMDM-Timestamp: <unix seconds>` and
`X-LiMDM-Signature: sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<raw body>`. The key is
the webhook signing secret, shown to admins as **Signing key** under the URL. It is its own
sealed value, independent of the session key, and rotates with
`limdm-server keys rotate webhook` or **Rotate** in **Settings**, **Security**, **Keys**
([keys.md](keys.md#webhook-signing-secret)). Signed notification channels use the same
secret. Verify the signature and reject timestamps older than five minutes (replay
protection):

```python
import hmac, hashlib, time
msg = ts.encode() + b"." + body
ok = hmac.compare_digest("sha256=" + hmac.new(bytes.fromhex(key), msg, hashlib.sha256).hexdigest(), sig) \
     and abs(time.time() - int(ts)) < 300
```

There is one attempt per event (10 second timeout); failures are only written to the server
log. Redirects are not followed, and loopback, link local and metadata addresses are
refused. For retries and a delivery log use a webhook [notification channel](notifications.md).

## Evidence

Exports are open to admins and auditors and follow the device scope and tenant of the
account.

* **Evidence CSV** (`/api/v1/exports/compliance.csv`): every current check result of every active
  device (custom checks included): device, host name, last seen, agent version, catalog
  version, check, level, status, detail, BSI, CIS and ISO references, CIS benchmark edition,
  the reason, owner, approver and expiry of the active risk exception that covers it, and the
  generation time.
* **Exceptions CSV** (`/api/v1/exports/exceptions.csv`): every risk exception with its state
  (`active`, `expired`, `revoked`), creator and creation time.
* **Compliance history** (Compliance page, **History**, `/app/compliance/history`): devices
  report only changes, and the server stores every change of a check result
  (`compliance_changes`, 365 days; the last state before the cutoff is kept, so the state at
  any date stays known). The page shows the state of all devices, or of one device with its
  changes, at the end of a chosen day. **Report as CSV**
  (`/api/v1/exports/compliance-history.csv?at=YYYY-MM-DD&device=ID`) has the same data with the time
  each state began, the catalog version and the generation time. Devices that reported before
  the history existed start with their last report as baseline.
* **Inventory CSV**, **Packages CSV** (device list), **Audit CSV** and the audit
  **JSON Lines** export for asset management and audits.
* **Signed evidence** (`evidence.json`, console app **Export evidence**, or
  `/api/v1/exports/evidence.json?days=90`): one bundle (format `limdm-evidence/1`) with the
  score and device states, the framework rates, every current check result per device with
  its catalog and agent version, all risk exceptions, the fleet history and every change of a
  check result within the window (1 to 365 days), and `generated_at` and `generated_by`. It
  is signed with the command key (Ed25519, an HSM key works too) over
  `limdm-evidence/1\n` followed by the compact payload. Check it offline with
  `limdm-server evidence [-ca DIR | -key HEX] verify evidence.json`, which also accepts the
  previous key during a key rotation.
* **Evidence report** (`evidence.pdf`): a PDF rendered on the server from such a bundle, in
  the language of the console, with score, frameworks, failing checks, active exceptions,
  versions, and the SHA-256, key ID and signature of the bundle. Each evidence export also
  writes `evidence.sign` with the bundle's SHA-256 and key ID.
* Every export writes two audit entries: `export` before (who, which file, which filter)
  and `export.done` after, with the row count and the SHA-256 of exactly the file sent, so a
  file handed to an auditor can be matched to its entry.
* The audit log is append only and keyed hash chained; it can be verified outside LiMDM
  ([security.md](security.md#audit-log)).

CSV exports neutralise formula injection.

The console app (`/app/compliance`) downloads the same files through
`GET /api/v1/exports/{kind}` and shows the SHA-256 of the downloaded file next to the
matching `export.done` audit entry. Its overview drills from a framework card to the
controls and checks, and from a check to the devices with their result, the remediation and
the active exceptions.
