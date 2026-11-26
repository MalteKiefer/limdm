# Compliance

The agent runs the checks of the declared level, remediates where that is safe and reports
the result at every check in. Every check references BSI IT-Grundschutz, the CIS
Benchmarks and ISO/IEC 27001:2022 Annex A. The **Compliance** page shows pass and fail per
check, filters by state, level and framework, and coverage per framework.

ISO 27001 and BSI IT-Grundschutz certify an organisation's ISMS, not a tool. LiMDM provides
technical controls and evidence for Linux clients; policies, roles, risk analysis and
training stay with the ISMS.

## Levels

* **Level 1:** CIS Level 1 baseline, suitable for every client.
* **Level 2:** additionally the strict checks for high protection needs.

## Checks

| Check | Level | Remediation |
|---|---|---|
| `agent.osquery` osquery inventory source installed | 1 | reinstalled hourly |
| `os.supported` OS version not below the `com.limdm.osversion` minimum | 1 | |
| `updates.auto`, `updates.security`, `updates.reboot` | 1 | maintenance window |
| `disk.encryption` system disk on LUKS | 1 | (needs reinstallation) |
| `disk.recovery` LUKS recovery keys escrowed | 1 | desktop helper asks the user |
| `boot.password` GRUB password set | 1 | via `com.limdm.bootloader` |
| `firewall.active` host firewall active | 1 | yes |
| `mac.enabled` / `mac.enforcing` AppArmor or SELinux | 1 / 2 | |
| `boot.secureboot` Secure Boot enabled | 2 | |
| `kernel.aslr`, `kernel.ptrace`, `kernel.coredumps` / `kernel.dmesg` | 1 / 2 | yes |
| `net.forwarding`, `net.redirects`, `net.tcp` | 1 | yes |
| `modules.filesystems` / `modules.udf`, `modules.usbstorage`, `modules.netproto` | 1 / 2 | yes |
| `ssh.baseline` / `ssh.strict` | 1 / 2 | yes, `sshd -t` with rollback |
| `accounts.empty_passwords`, `accounts.uid0` | 1 | partly |
| `accounts.admins` admin rights only for approved users | 1 | yes |
| `accounts.pwquality` password quality, minimum length 14 | 1 | yes |
| `auth.sso` desktop login through the identity provider | 1 | yes |
| `time.sync` time synchronisation active | 1 | yes |
| `logging.journald`, `logging.sudo` | 1 | yes |
| `logging.auditd` auditd with LiMDM rules | 2 | yes |
| `desktop.screenlock` screen lock on idle | 1 | yes |

`limdm-agent check --level 2` prints the same report locally without changing anything.

## Custom checks: `com.limdm.customchecks`

IT defines its own checks as a library item. They are reported, counted, excepted
(`exclude`), marked advisory, exported as evidence and trigger grace period, webhook and
automatic lock exactly like the built in checks. They have no automatic remediation.

```json
{"checks": [
  {"id": "custom.no_telnet", "title": "Telnet client is not installed", "severity": "medium", "level": 1,
   "refs": {"bsi": ["SYS.2.3.A1"], "cis": ["Ensure telnet client is not installed"], "iso": ["A.8.19"]},
   "package": {"name": "telnet", "state": "absent"}},
  {"id": "custom.no_uid0", "title": "Only root has UID 0", "severity": "critical", "level": 1,
   "query": {"sql": "SELECT username FROM users WHERE uid = 0 AND username <> 'root'", "expect": "no_rows"}}
]}
```

| Field | Meaning |
|---|---|
| `id` | `custom.` followed by lower case letters, digits, `.`, `_` or `-`; use it in `exclude` and `advisory` |
| `title` | one line, shown on the device and compliance pages |
| `severity` | `low`, `medium`, `high` or `critical`; reported with the result |
| `level` | 1 or 2; the check runs when the compliance level is at least this |
| `refs` | free text framework references: `bsi`, `cis`, `iso` lists |

Each check has exactly one test:

| Test | Fields | Passes when |
|---|---|---|
| `query` | `sql`, `expect` (`rows`, `no_rows`, `compare`), for compare `column`, `op`, `value` | the osquery result has rows, has none, or has rows and `column` of every row satisfies `op value` |
| `file` | `path`, `state` (`present`, `absent`), for present files optional `max_mode` (octal), `owner`, `group`, `contains`, `not_contains` (RE2, per line) | the file exists or not, its permission bits stay within `max_mode` (no setuid, setgid or sticky bit), owner and group match, a line matches `contains`, no line matches `not_contains` |
| `sysctl` | `key`, `op`, `value` | the kernel parameter compares as given; a parameter the kernel does not have is `na` |
| `package` | `name`, `state` (`installed`, `absent`) | the package is installed or not |
| `service` | `name`, `state` (`active`, `inactive`), optional `enabled` | the unit is active or not and, when set, enabled or not |

Operators: `eq`, `ne`, `contains`, `matches` (RE2) compare text; `lt`, `le`, `gt`, `ge`
compare numbers (a value that is no number fails the check).

Custom checks never run a shell. The only program a check starts is `osqueryi` with the
query, for at most 30 seconds, without extensions. Server (on save) and agent (before
running) both accept only one read only statement: it must start with `SELECT` or `WITH`,
may not contain a semicolon (except a trailing one), comments, `INSERT`, `UPDATE`,
`DELETE`, `REPLACE INTO`, `ATTACH`, `PRAGMA`, `load_extension` or the osquery tables
`curl`, `curl_certificate` and `carves` (network requests and file carving). Without
osquery on the device a query check fails. Items of several blueprints are merged by `id`;
the item evaluated last wins.

## Policy: `com.limdm.compliance`

```json
{"level": 1, "remediate": true, "exclude": ["net.forwarding"], "advisory": ["boot.secureboot"],
 "grace_hours": 72, "notify": true, "lock_after_hours": 0, "unlock_when_compliant": true}
```

| Field | Meaning |
|---|---|
| `level` | 1 or 2 |
| `remediate` | apply automatic fixes |
| `exclude` | documented risk acceptance; shown as `excepted`, never as passed |
| `advisory` | reported but not counted against compliance |
| `grace_hours` | a failing device is `in grace` this long before it counts as non-compliant |
| `notify` | send the webhook once the grace period is over |
| `lock_after_hours` | lock the device after this long non-compliant, 0 = never |
| `unlock_when_compliant` | lift an automatic lock once all checks pass again |

Automatic lock and unlock use the same mechanism as the console command (new logins
blocked, sessions locked) and are written to the audit log as `policy` actions.

## Webhook

Configured in **Settings**. When a device becomes non-compliant after the grace period the
server posts:

```json
{"type": "device.noncompliant", "device_id": "...", "hostname": "pc1", "failing_checks": 3,
 "noncompliant_since": "2026-11-25T08:00:00Z", "console_url": "https://mdm.example.com/devices/..."}
```

with the headers `X-LiMDM-Timestamp: <unix seconds>` and `X-LiMDM-Signature: sha256=<hex>`,
the HMAC-SHA256 of `<timestamp>.<raw body>` with the signing key shown in the settings.
Verify the signature and reject timestamps older than five minutes (replay protection):

```python
import hmac, hashlib, time
msg = ts.encode() + b"." + body
ok = hmac.compare_digest("sha256=" + hmac.new(bytes.fromhex(key), msg, hashlib.sha256).hexdigest(), sig) \
     and abs(time.time() - int(ts)) < 300
```

The server does not follow redirects for webhook requests. Tamper events are sent the same
way with `"type": "device.tamper"` and a `detail` field.

## Evidence

* **Evidence CSV** (`/export/compliance.csv`): every check result per device, custom checks included.
* **Inventory CSV** and **Audit CSV** for asset management and audits.
* The audit log is append only and hash chained; the audit page verifies the chain
  ([security.md](security.md#audit-log)).

CSV exports neutralise formula injection.
