# Changelog

All notable changes, newest first. Versions follow [Semantic Versioning](https://semver.org).
Dates are release tag dates. **Breaking** marks changes that need action from operators or
change behavior they rely on.

## 0.20.0 (2026-11-27)

### Upgrade notes
- Agents report the source version of Debian packages, so every agent sends its package list once more after the update; CVE matches are recomputed at server start.

### Added
- Vulnerabilities page (main navigation, palette) with severity, remediation and top software cards, filters, sorting, paging, CSV export, column chooser, full screen and a detail sheet with packages, devices, CISA KEV and references.
- `GET /api/v1/vulnerabilities`, `/summary`, `/{cve}`, `POST /{cve}/accept` and `/{cve}/reopen`; risk acceptance per CVE (optionally one device or package) with reason and expiry, audited.
- CVE findings keep first detected, last seen and remediated; CVSS v3 scores from the Ubuntu OSV vectors; optional CISA KEV feed (off by default).

### Changed
- A distribution CVE feed is downloaded only while at least one device runs that distribution; the feed state shows "no devices, skipped".
- CVEs of pending dnf and zypper updates are recorded as findings.

### Fixed
- Debian packages whose binary version differs from the source version (postgresql 17+278+deb13u1 from postgresql-common 278+deb13u1) were matched as vulnerable; the agent now reports the source version and the matching compares it.
- Form fields line up with subgrid rows only in containers that hold nothing but fields; filter bars with other controls are no longer shifted.

## 0.19.1 (2026-11-27)

### Fixed
- A CVE feed switched on in the settings starts within five minutes instead of at the next full hour.
- Form fields of one row line up even when one of them shows an error; the required name of a new library item is flagged only after it was touched.

### Security
- The sign in return target only accepts pages of the console app (`/app/...`) and is rebuilt behind that prefix.

## 0.19.0 (2026-11-27)

### Upgrade notes
- Enrollment tokens are limited to 500 uses and 30 days. Existing tokens above these limits are cut down once at the first start.
- **Breaking:** EAP-TLS device certificates take the DNS SAN from the device ID under the new network certificate domain (Settings, Network; empty leaves it out) and the email SAN only from directory verified addresses. RADIUS policies that matched the reported host name must match the new names (see `docs/network.md`).
- CVE data feeds (Debian, Ubuntu, Arch, Alpine) are off by default. Switch each on under Settings, CVE data and watch disk and memory during the first import.
- A firewall declaration without zones, outbound filtering or templates runs exactly the commands it ran before.
- Agents up to 0.18 reject a firewall item that uses `keep` or `remove` (0.19.0-rc builds reject `remove`); update the agents before keeping or discarding foreign rules. A rule in a `remove` list is deleted in every agent cycle, so it stays gone after a reboot; the agent never reloads the nftables service (that would flush Docker, NetBird and CrowdSec tables).

### Added
- Update rings with waves, deferral, pause and resume and optional approval (`/api/v1/update-rings`, `/api/v1/update-waves`); devices get an update gate at check in.
- Update rules per source in `com.limdm.updates` (`os_security`, `os_all`, `third_party` with `repos`, `flatpak`; modes off, notify and install, each with its own window and ring) and `security_max_days`.
- Pending updates per device with versions, origin, security flag, severity and CVEs, and the last run per source (`GET /api/v1/devices/{id}/updates`).
- Fleet view of open security updates and CVEs and the installed versions of a package (`/api/v1/updates/fleet`, `/api/v1/updates/package-versions`); console area Updates and the device tab Updates.
- Daily import of CVE data: Debian Security Tracker, Ubuntu OSV, Arch Security Tracker and Alpine secdb (Settings, CVE data, a switch and URL per feed, download limit; Refresh now under Updates, Security; `GET /api/v1/updates/cve-feeds`, `POST /api/v1/updates/cve-feeds/refresh`). Installed versions are matched with the version rules of dpkg, pacman and apk; dnf and zypper devices report CVEs themselves.
- Compliance checks `updates.security_age` and `agent.tpm_key`; device commands `package_hold` and `package_downgrade` (four eyes).
- TPM bound agent key: with a TPM 2.0 the agent keeps its mTLS key in the TPM and the server attests it at enrollment (TPM2_Certify plus credential activation). Tenant and global setting "require TPM bound key"; the device page shows the key type.
- Settings, Enrollment with enrollment token limits and defaults; network certificate domain setting.
- Recurring scripts on a schedule (local times, weekdays, per device jitter), at most once per slot and optionally again when they change (`run_on_change`); the library editor lists the last run per device.
- File content and firewall rules as templates (hostname, ID, tags, tenant, primary user, custom device attributes), rendered per device on the server, with a preview for one device in the library editor.
- Custom device attributes (device edit dialog, `PATCH /api/v1/devices/{id}` `attributes`).
- Firewall zones (firewalld zones, interface and source rules on ufw and nftables) and outbound filtering (allow or deny with egress rules; DNS, DHCP, NTP and the LiMDM server stay reachable).
- Host firewall on Alpine with nftables.
- The device timeline shows compliance check changes and, with the audit permission, audit entries about the device (`kind=compliance|audit`).
- The device overview has cards for updates, firewall and connection.
- Shell transcripts replay in a read only terminal on the session page, with a plain text view and downloads of the raw bytes (.log) and the text (.txt); `GET /api/v1/shell-sessions/{sid}/transcript` returns the raw bytes of an ended session (admins and auditors, audited).
- Typography tokens (six size roles with line heights) in the console design tokens.
- Tab bars show a fade and arrow buttons where tabs are cut off.
- `limdm checks --strict` exits with code 2 when a check fails; checks are listed failing first, then by level and ID.

- Containers and VMs tab on the device page: Docker, Podman, LXC, LXD, Incus, Proxmox (pct, qm) and libvirt workloads with tool versions, a read only inventory per device and a fleet list (`GET /api/v1/devices/{id}/workloads`, `GET /api/v1/workloads`).
- Start, shut down and restart of containers and VMs (`workload_action`), off by default: needs `workload_control` in `com.limdm.agent` and the admin role (helpdesk when Settings, Approvals allow it), optional four eyes for stop and restart; graceful shutdown only, audited.
- `com.limdm.hostname` declaration: sets the host name from reverse DNS (forward confirmed), DNS, the DMI serial, a device template or a fixed name, with `/etc/hosts`, `/etc/mailname` and a pretty name; names from DNS apply only when stable over two check ins and at most hourly.
- Item editor preview of the computed host name for one device with a warning, and a host name card on the device page; agents report `hostname_info` and notes in the declaration status, including a warning when Postfix or Exim keeps another host name.
- Template variables `.Serial`, `.MAC`, `.Vendor` and `.Model` for file, firewall and hostname templates.
- Firewall inventory per device: the agent reports backend, default policies and every rule of ufw, firewalld, nftables or iptables (read only); the device page has a Firewall tab grouping managed, foreign and system rules (`GET /api/v1/devices/{id}/firewall`).
- Foreign firewall rules can be adopted into a firewall library item (a new item goes into a blueprint the admin picks, with a second confirmation for the global default or a blueprint that reaches more devices), kept as an exception (`keep` in `com.limdm.firewall`) or discarded through the new `remove` list of `com.limdm.firewall`: every agent deletes a listed foreign rule in every cycle, so it stays gone after a reboot; rules of LiMDM, container, VPN and protection tools are never removed, and items with a `remove` list need four eyes approval when it is on (`POST /api/v1/devices/{id}/firewall/rules/{rid}/{adopt|keep|remove}`). The signed command `firewall_remove_rule` removes one rule at once (running ruleset only for nftables and iptables).

### Changed
- Enrollment tokens default to 1 use and 1 day; every use is audited with the token it used.
- Flatpak is its own update source: mode `all` without rules still updates it, `security` does not.
- The agent reports the source package of packages (Debian source, Alpine origin, Arch pkgbase); every agent sends its package list once more after the update.
- Desktop users are edited as rows with directory and device account suggestions instead of free text lines.
- Device notices are ordered security, compliance, information and fold behind a button.
- Empty lists use the EmptyState component everywhere, with a next step where one exists.
- The bulk action bar is fixed to the bottom of the content column, keeps the last row visible and scrolls its actions sideways on phones.
- The tray shows the device state by badge shape (check mark, exclamation mark, cross) and in its tooltip, not by color alone, with a symbolic logo for light and dark panels.
- "Check In Now" is "Sync Now" in the tray, desktop app and CLI; the desktop app and the CLI say Blueprint (`limdm blueprint`, `limdm profiles` stays as an alias).
- Rules of Docker, Podman, libvirt, Kubernetes, VPN agents (NetBird, Tailscale, ZeroTier, wg-quick tables), fail2ban and CrowdSec are system rules in the firewall inventory: shown, never adopted, kept or removed. Rules on addresses of local container bridges (Docker hairpin NAT and masquerade) count as Docker's. LiMDM's own tables, `inet limdm_fw` of early agents included, are managed.

### Fixed
- An update run without changes is reported as "no updates", not "installed"; unattended-upgrade mail noise is filtered.
- The neutral status pill meets WCAG AA contrast in light and dark mode.
- The device header no longer repeats the operating system.
- Remove buttons in filter chips have a 24 px target.
- Software removal on the device page uses the console's dialog instead of the browser's confirm().
- The plain text of shell transcripts applies terminal line editing and strips every escape sequence, so shell redraws collapse to what was visible.
- The live remote shell terminal no longer triggers CSP violations from xterm's inline styles.
- The desktop app no longer rebuilds its page every minute and no longer drops typed text.

### Security
- EAP-TLS certificates no longer take the DNS SAN from the reported host name or the email SAN from device reported users.
- The desktop socket refuses `shell-end` and journal lines to SSH sessions.
- Docs state that `allow_scripts` is no protection against administrators and which controls apply instead (four eyes, signed commands, audit).

## 0.18.1 (2026-11-26)

### Changed
- Remote shells are allowed per policy: **Remote shell** in the **Agent** declaration (`com.limdm.agent`, `remote_shell`) instead of a local opt in on each device. The server refuses a start without it and the console says why in the start dialog; the local `allow_remote_shell` keeps working on the agent.

### Fixed
- Form fields in a row line up when their help texts differ in height.
- CrowdSec: `deploy/crowdsec/parsers/s02-enrich/limdm-console-whitelist.yaml` keeps `http-crawl-non_statics` from banning admins while the console loads icons and API responses.

## 0.18.0 (2026-11-26)

### Upgrade notes
- The console app under `/app/` is the only console. The classic server rendered console is removed; its page addresses redirect to the matching console app page.
- `limdm-server local-admin` needs the CA directory (`LIMDM_CA_DIR`, for example through `-env`) once a server has started, to key its audit entry; without it the command stops instead of breaking the audit chain.

### Added
- Console app (React, served by the server itself, strict CSP, German and English, light and dark, compact density, keyboard and screen reader support, down to 390 px): home, inbox, devices, compliance, configuration, activity, reports and settings, with a command palette and global search.
- Home: KPIs, tenant comparison, first steps with deep links, failed command trend, open security updates and current agents with daily history.
- Inbox, activity and reports pages; event annotations in the compliance history.
- Scheduled reports (daily, weekly, monthly) for saved report presets, sent as a link to notification channels or e-mail, run as the owner with current rights, audited.
- Devices area: list with query language (German aliases, `status:locked`, `kind`), side sheet, device page with six tabs, every device action, remote shell, bulk actions and the add device flow.
- Compliance area: score and trend, framework cards, checks and controls with drill down to devices, remediation hints, heatmap, risk exceptions, history at a date, policies and custom checks, evidence export with SHA-256 check.
- Signed evidence export (`evidence.json`, Ed25519 with the command key) and PDF evidence report (`evidence.pdf`), both audited; `limdm-server evidence verify FILE`.
- Risk exception requests through four eyes approval (`POST /api/v1/exception-requests`, approval action `exception.add`) for the helpdesk and admins.
- Configuration area: blueprints with a visual tree editor, library forms for all 33 declaration types, versions with diff, rollback and restore, software catalog and package repository; pilot rollout of blueprint changes (promote or abort).
- Titles, help texts, sections, choices, widgets and limits in English and German for every declaration schema; `lang` parameter, `/api/v1/schemas` with description, documentation link and four eyes flag.
- New library items start from the example payload of their type, or from a source or Flatpak remote a device reported (`GET /api/v1/config/library/template`).
- Settings area: every administration section, profile with the date notation, help and glossary.
- Audited tenant switch through the API (`tenant.switch`).
- Sign in returns to the page it started from through a checked `next` target.
- Admin API endpoints for all of the above: session API (`/api/v1/me`, live events, saved views), statistics (`/stats/fleet`, `/stats/compliance`, `/stats/attention`, `/stats/tenants`, `/stats/commands`, `/stats/updates`, `/stats/annotations`), `/onboarding`, `/commands`, `/activity`, `/audit/status`, `/audit/verify`, `/compliance`, `/compliance/history`, `/compliance/policies`, `/exports/{kind}`, `/report-schedules`, `/report-runs/{id}`, device detail, packages, timeline, retire, delete, agent update, recovery key view, remote shell, bulk actions, enrollment tokens, configuration and software, settings, users, tenants, keys, backup, notification channels, directory, network, agents and profile. Every endpoint is in `openapi.json`.

### Removed
- The classic server rendered console (templates, page handlers, `actions.js`, `blueprint-editor.js`, `shell.js`); old bookmarks redirect to the console app.

### Changed
- The tenant isolation test walks every admin API route.
- `@tanstack/react-table` stays on 8.x; Dependabot skips its major updates until the data grid is migrated.
- Console and API share one function per action (settings, users, tenants, backup, directory, agents, network, profile, channels, software, packages), so roles, scope, tenant, four eyes and audit are the same; rejected requests carry an HTTP status.
- Approval decisions take a reason (stored, audited); the console app requires one to reject.
- With four eyes approval on, adding a risk exception becomes a request; the approving admin is recorded as approver.
- `PATCH /api/v1/devices/{id}` also sets desktop users and the primary user; device list items carry desktop, memory_mb and auto_locked.

### Fixed
- `limdm-server local-admin` wrote its audit entry without the HMAC key, which broke a keyed audit chain; the audit function now refuses to write into a keyed chain without the key.
- Tenant and scoped accounts no longer see or assign directory people outside their devices.
- Device scoped callers are refused on every configuration route.
- A shadowed embedded field (`enabled` in login) appeared twice in the schema.

## 0.17.0 (2026-11-26)

### Upgrade notes
- **Breaking:** the agent needs OpenSSL 3. `/install.sh` and `scripts/install-agent.sh` stop at once with "this system is not supported by the LiMDM agent (OpenSSL 3 required)" when `openssl pkeyutl -rawin` (Ed25519) is missing, and the agent packages depend on `openssl >= 3` (`openssl-3` on SUSE). Ubuntu 20.04, Debian 11, RHEL, Rocky and Alma 8, CentOS Stream 8, openSUSE Leap 15, SLES 15 and Alpine 3.16 and older are no longer supported. `LIMDM_SKIP_SIGNATURE` is gone; sign your own builds with your own release key.
- **Breaking:** notification targets in private networks are refused unless the private networks option on **Settings, Notifications** (Compliance webhook card) is on. Global channels to an internal SIEM or mail relay need that setting.
- **Breaking:** tenant webhook channels sign with their own per tenant secret over `timestamp.tenant.body`; tenant receivers must switch to the new secret and message.
- **Breaking:** the audit log now defaults to a retention of 3 years instead of forever. Set **Settings, Data retention** before the upgrade if you must keep it longer.
- **Breaking:** declared file paths with symlink components (for example `/bin` on merged `/usr`) now fail; declare the real path.
- **Breaking:** osquery 4 or newer is required (`--enable_tables`).
- **Breaking:** PgBouncer is supported in session mode only; transaction or statement pooling breaks advisory locks and notifications.
- **Breaking:** once backups are configured, the server deb and rpm make a backup before every package upgrade, and a failed backup stops the upgrade (`LIMDM_SKIP_UPGRADE_BACKUP=1` in the environment of apt or dnf skips it). Check that the backup targets are reachable before upgrading.
- The first start migrates installed packages from `devices.packages` into `device_packages` and partitions `device_metrics` by day; at 50,000 devices plan a few minutes.
- `LIMDM_LOG_LEVEL`, `LIMDM_ACCESS_LOG`, `LIMDM_AUDIT_API_READS`, `LIMDM_UPDATE_DOWNLOADS`, `LIMDM_MAX_CHECKINS`, `LIMDM_AGENT_PROXY_PROTOCOL`, `LIMDM_SYSLOG` and `LIMDM_SYSLOG_CA` are only initial values of **Settings, Operations** now; once saved in the console the stored values win.
- Library item and blueprint names are unique per tenant instead of globally.

### Added
- `limdm-server backup create|list|verify|restore|restore-test` and scheduled backups: age encrypted, command key signed archives of database, CA directory and uploads to local, S3 (Object Lock, multipart), Backblaze B2, SFTP and WebDAV targets, with weekly checksum verification, audit entries, failure notifications and metrics.
- Several backup schedules in **Settings, Backup**: every N hours with offset, weekdays at times, monthly on a day, strict cron; each with its own targets, time zone (DST safe) and retention (keep last, days, daily, weekly, monthly, yearly), a general rule for archives outside a schedule, previews of the next runs and of what is kept. Create, edit, pause, resume, run now and delete in the console, audited.
- Backup before package upgrades (deb and rpm pre install script).
- Restore window that re-pins device certificates renewed after the backup; `-replay` re-applies revocations from an audit export or syslog.
- **Settings, Data retention**: a period per data type (audit log, device events, compliance history, commands, script results, diagnostics, shell transcripts, metrics, notification log).
- Package repository (**Software, Packages**) and the `com.limdm.artifacts` declaration: per tenant storage (local or S3) with quotas, four eyes approval of uploads, hash verified install on devices with `allow_scripts`.
- **Settings, Operations**: log level, access log, audited API reads, download and check in limits, PROXY protocol sources and syslog target with CA, applied at runtime on every instance and audited.
- Signatures for catalog apps, managed Flatpak remotes and device user lists, verified by server and agent (`signed_data`, `signed_users`).
- Four eyes approval for root effective library items (including `com.limdm.artifacts`), required catalog apps or apps with a package repository, and admin API tokens (console and admin API, `202` with the approval).
- SCIM allowed networks; per tenant webhook signing secret; setting to let global channels reach private networks; `LIMDM_RELEASE_PUBLIC_KEY`.
- Admin API for approvals, risk exceptions, API tokens and tenants; `/api/v1/docs` reference page; token scopes (`read`, `commands`, `library`, `audit`, `admin`).
- `Idempotency-Key` for command requests; `ETag` and `If-Match` for library items and blueprints, checked in the transaction of the save.
- `422` problem details name the request field (`errors: [{field, message}]`); all problem details carry `urn:limdm:problem:<code>` and `code`.
- Staggered agent rollout (`spread_hours`, default 24 h).
- `LIMDM_DB_MAX_CONNS`, PROXY protocol v2 on the agent listener, syslog over `tcp+tls://`.
- `X-Request-ID` on every answer; `limdm_http_request_duration_seconds` histogram.
- Sizing table in docs/operations.md; docs/backup.md, docs/retention.md, docs/packages.md.

### Changed
- Installed packages are stored in `device_packages` (one row per package) and written by diff at check in; package filters, the packages CSV export and the device page read it.
- Audit entries and device events of a check in are written at its commit.
- The schema is applied only when its hash changed; new indexes are built concurrently.
- `device_metrics` is partitioned by day; whole days are dropped by the metrics retention.
- Busy database and overload answer `503` with `Retry-After`.
- Agent honors `Retry-After`, backs off failed check ins, runs at lower CPU and I/O priority and keeps volatile values out of the status hash.
- Enrollment and API token failure limits count per address and token.
- Group mappings never grant admin through SCIM only groups, nor at all while four eyes is on.
- Local lockout per account and client network.
- `/install.sh` and `install-agent.sh` verify the release signature (OpenSSL 3 required).
- Without "Sessions may run as root" the remote shell also refuses accounts in sudo, wheel or admin and accounts with sudoers rules, NOPASSWD included.
- The desktop socket refuses app changes, key escrow, SSO confirmation and reboot deferral from SSH sessions of the same user.
- Archive names carry the schedule name; an existing daily backup hour becomes the schedule `daily`.
- Server settings, the package store and package uploads and deletes check the role inside their handlers, not only through the route.

### Fixed
- Database writes could make devices install packages, add repositories or grant sudo without a signature (contrary to docs/security.md).
- Custom compliance check queries are validated with a SQLite style tokenizer and may read only an allowlist of local osquery tables; quoted or schema qualified names no longer bypass the check. osqueryi runs with `--enable_tables` and `--disable_tables`, and check details carry only row counts and a bounded compared value.
- The helpdesk role can no longer reset, lock or unlock accounts with uid 0, admin group membership or sudo rules; accounts with uid 0 are refused for every role.
- The PAM SSO device flow no longer starts from `su`, `sudo`, with any `PAM_RHOST`, on a pseudo terminal or from a remote logind session; polkit needs a local seat session.
- Managed files are written and removed without following symlinks; undeclared files are removed only when they still hold the content LiMDM wrote.
- The remote lock no longer trusts `LockedHint` or running locker processes; sessions without a self locking desktop always get the agent's locker.
- Diagnostics redact the user fields of failed logins, tokens in URLs, all `Authorization` headers and common token formats.
- Discord markdown and links from device text.
- Unauthenticated permanent lockout of break glass accounts.
- docs/operations.md claimed that devices reconnect after any restore; devices that renewed their certificate after the backup were locked out.
- Pool deadlock in the check in under load.
- Syslog skipped device events committed out of order.
- The rate limiter dropped all counters at 50,000 keys.
- Over long device filters returned the whole fleet.
- Group blueprints crossed tenants.
- Concurrent first starts of a new version could deadlock.

## 0.16.0 (2026-11-26)

### Upgrade notes
- **Breaking:** stop every server instance before the first 0.16 instance starts. The audit chain switches to keyed hashes with a recorded switch point; an instance with an outdated audit key refuses to write entries. See [docs/operations.md](docs/operations.md#upgrading-from-015-to-016).
- **Breaking:** `/healthz` is a liveness check only. Point load balancers and monitoring at `/readyz`.
- **Breaking:** the release workflow needs the variable `UPDATE_PUBKEY` and the secret `RELEASE_SIGNING_KEY`; agent self updates fail closed without a release key.
- Set `LIMDM_TRUSTED_PROXIES` when the reverse proxy is not on loopback. New variables: `LIMDM_DRAIN_SECONDS`, `LIMDM_MULTI_TENANT`, `LIMDM_SYSLOG`, `LIMDM_KEY_PROVIDER`, `LIMDM_PKCS11_*`.
- The webhook signing secret is migrated automatically: receivers keep working.
- Key rotation needs agents 0.16 or newer.

### Added
- Multi tenancy for MSPs and groups of companies, off by default (`LIMDM_MULTI_TENANT=true` shows the tenant pages and switcher). Tenant list for global administrators (create, rename, disable), tenant switcher and global audit view.
- Per tenant branding (company name, logo, accent color) with the global branding as fallback, shown in the console and on the tenant's devices.
- Shared library items and blueprints of the Default tenant, readable by every tenant.
- Enrollment tokens enroll into their tenant; API tokens, console users and notification channels belong to a tenant or are global.
- Several server instances behind a load balancer on one PostgreSQL database ([docs/high-availability.md](docs/high-availability.md)). Settings reload on every instance, remote shell sessions are relayed between instances, background jobs run once with leader handover.
- `/readyz` readiness check (database, schema, keys, notifications), graceful shutdown with `LIMDM_DRAIN_SECONDS`, and `LIMDM_TRUSTED_PROXIES` for load balancers whose `X-Forwarded-For` is trusted.
- An instance with a different CA directory, or one missing the audit switch point, refuses to start.
- Key rotation without enrolling devices again for the device CA, network CA, command signing key and session key (`limdm-server keys status|rotate|finish`, Settings, Security, Keys card with progress, audited, notification event `keys.rotate`).
- PKCS#11 HSM key provider (`LIMDM_KEY_PROVIDER=pkcs11`, `LIMDM_PKCS11_MODULE`, `LIMDM_PKCS11_TOKEN`, `LIMDM_PKCS11_PIN`) in a separate build with `-tags pkcs11`; `limdm-server sign -pkcs11 LABEL`.
- `LIMDM_SESSION_KEY` accepts several comma separated keys, the new one first; sealed values are sealed again with the new key in the background.
- The webhook signing secret is its own sealed value, unaffected by session key rotations and rotatable with `limdm-server keys rotate webhook` or the Keys card.
- docs/keys.md with key inventory, HSM setup, rotation runbooks and compromise procedure; docs/console.md with every console page and the role matrix; docs/README.md as index.
- Admin REST API under `/api/v1/` with API tokens (roles, read only, expiry, revocation, audited), OpenAPI 3.1 at `/api/v1/openapi.json`; the 202 approval answer (`approval_id`), token `scope_tags`, tenant handling and `tenant_id` of audit entries are documented there.
- Prometheus metrics at `/metrics`, protected by API tokens of the metrics, admin or auditor role.
- Device filter by installed package with version comparison (`pkg=openssl < 3.0.13`) and Packages CSV export.
- Four eyes approval for wipe, lost mode, scripts, console role changes and optionally recovery key views and remote shell sessions (Settings, Security; Approvals page).
- Device scopes for helpdesk and auditor accounts (tags, directory groups), enforced server side; console roles from directory groups or the OIDC groups claim.
- Optional MFA requirement for OIDC console sign in (`amr`, or configured `acr` values).
- Optional audit log retention with a signed checkpoint at the cut; deletion of retired devices with their personal data.
- Risk exceptions with reason, owner, approver and expiry; only active ones reach devices; shown on the compliance page and in the evidence export (`exceptions.csv`).
- Notification events for recovery key views, wipe and lost mode, scripts, role changes, approval requests and a broken audit chain.
- Version history for library items and blueprints with diff, rollback and restore of deleted objects; a review step shows the change and the affected devices before saving.
- Keyed (HMAC-SHA256) audit chain with recorded switch point; JSON Lines audit export and `limdm-server audit verify|key`; "Verify whole chain" action; audit paging and date filtered exports.
- Syslog (RFC 5424, UDP or TCP) forwarding of audit entries and device events via `LIMDM_SYSLOG`.
- Compliance history per device and check with a report at any date (console and CSV).
- Catalog version reported by the agent; CIS recommendation numbers with benchmark edition and BSI requirement IDs in check references.
- Custom compliance checks (`com.limdm.customchecks`): read only osquery queries or file, sysctl, package and service conditions, with severity, level and framework references; they count like built in checks.
- Remote support shell: audited interactive terminal from the console to a device over the existing mTLS channel. Off by default, needs `allow_remote_shell` at enrollment and the server setting. Transcripts for admins and auditors, `limdm support end` on the device.
- `limdm-agent enroll --allow-remote-shell`, `allow_remote_shell` in enroll.conf, `LIMDM_ALLOW_REMOTE_SHELL` for install.sh.
- Patch management in `com.limdm.updates`: weekdays, package holds, autoremove, snap refresh control.
- Restart announcement after updates; the user can postpone within the limits of the declaration.
- Owner and group in `com.limdm.files`.
- Firewall rules with source networks.
- Declarations `com.limdm.dconf` and `com.limdm.localusers` (with SSH keys).
- Script parameters, script timeout, structured script results on the device page, bulk scripts for admins.
- Diagnostics command "Collect logs" with a redacted, audited download.
- SUSE family support (openSUSE Leap, Tumbleweed, SLES, SLED) with zypper for packages, security patches and updates, zypper repositories, package source backup and osquery.
- Printers declaration `com.limdm.printers` (CUPS via lpadmin, driverless IPP Everywhere or PPD, default printer, duplex, paper size, managed `limdm-` queues).
- Inventory reports TPM presence, version and LUKS volumes bound to the TPM.
- `tpm2` option in `com.limdm.diskencryption` binds LUKS volumes to the TPM 2.0 with systemd-cryptenroll (configurable PCRs, optional PIN), plus the compliance check `disk.tpm`.
- `com.limdm.network` declaration: WLAN (WPA2/WPA3 personal and enterprise), wired 802.1X (EAP-TLS, PEAP, TTLS) with CA pinning and server domain match, WireGuard with device generated keys, OpenVPN import, applied as NetworkManager keyfiles.
- EAP-TLS device certificates from a separate network CA, issued from agent CSRs over mTLS, renewed automatically, revoked on retire and wipe.
- Network certificates page with network CA download, CRL download and a bearer token for RADIUS CRL fetches. Issued certificates and WireGuard public keys on the device page.
- Help page with glossary, device states, roles and device actions by impact; documentation links in page headers; status tooltips.
- The library item editor shows a type description, a field reference generated from the payload types, a live JSON check, a Format button and a documentation link.
- First steps checklist on the overview; empty states with an action.
- Copy buttons for tokens, install commands, enroll.conf, fingerprint and credentials; password repeat field and generator for local device accounts.
- Blueprint source on the device page and assignments in the blueprint list.
- Mobile menu button; keyboard navigation in action menus.
- Tests check every relative documentation link, every `LIMDM_` variable in docs/configuration.md and every declaration type in docs/declarations.md.

### Changed
- **Breaking:** `/healthz` no longer queries the database; use `/readyz` for load balancers.
- **Breaking:** the audit chain keeps one key segment per command key (`audit-keys`); `limdm-server audit key` prints one line per segment; an instance with an outdated audit key refuses to write entries.
- **Breaking:** geolocation (ipwho.is) and the DNS over HTTPS fallback are opt in through a server setting, default off.
- **Breaking:** without `allow_scripts`, `com.limdm.files` writes only to plain text allowlist locations.
- **Breaking:** undeclared files and firewall rules are removed from devices.
- **Breaking:** the helpdesk role gets exactly the device commands its description promises, from one server side list.
- Agents adopt a new command key only from a rollover record signed by the pinned key, accept new device CAs over the mTLS channel and renew certificates when the server asks.
- The device scope filter also filters by tenant; tenant accounts reach only tenant aware routes (deny by default), and every device route checks the device centrally.
- Audit entries record their tenant, hashed as a fifth field when set; audit CSV, JSON Lines and the API return `tenant_id`.
- Declaration resolution loads only library items of the device's tenant and of the Default tenant.
- Syslog forwarding continues from its stored position after a restart or leader change.
- Every instance downloads agent packages into its own release directory.
- Device list filters combine (AND); search, status counts and paging run in the database (200 devices per page).
- Finished commands are pruned after 180 days; `device_events` rows can only be deleted by the retention job.
- The desktop login client secret is stored encrypted on the server; existing items are migrated at startup.
- Evidence CSV includes agent version, catalog version, CIS benchmark and generation time; every export is audited with its SHA-256.
- Command audit entries link enqueue and result via command ID with the device as target.
- Check results carry an optional `severity`; osquery runs with `--disable_extensions`.
- Network secrets are masked in the library editor and the audit log; saving the mask keeps the stored value.
- The rpm package keeps only dependency names that Fedora and SUSE share; iproute, procps-ng and gnupg2 are weak dependencies.
- Repositories accept `family: suse` and key files under `/usr/lib/rpm/gnupg/keys`.
- Console errors render inside the layout, translated, with technical detail and a back link.
- Confirmation before irreversible or disruptive actions; security actions ordered by impact with explanations.
- Notification channels and the compliance webhook share one Settings tab.
- Check titles, check details and audit actions are shown translated and readable; German terms unified.
- Every document in docs/ was checked against the code and rewritten where it was wrong or incomplete.

### Fixed
- Four eyes approval covers every change to an administrator account (add, disable or enable, credential reset; new credentials go to the approver), refuses approvals by the creator of the requesting API token, and binds a remote shell approval to its local user; an approval is used only when the session really starts.
- A key rotation whose database transaction failed left `keys.json` on the new keys while the database named the old ones; `keys.json` is now replaced only after the commit.
- A session key rotation changed the webhook signature and broke every receiver.
- The proxy declaration reaches the agent; dnf4, pacman, apk and flatpak honor it.
- New firewall rules apply while the firewall is active.
- Self updates fail closed without a release key; a release fails without a signing key.
- Failed OIDC sign ins are written to the audit log.
- The agent no longer labels policy exclusions "documented exception (risk accepted)".
- Concurrent settings saves and SCIM updates on different instances no longer overwrite each other.
- Device assign, retire, delete and agent update requests check the device scope; ending a remote shell checks the device scope; revoking an unknown risk exception answers 404.
- Key status and rotation are limited to global administrators.
- docs/compliance.md no longer claims a CIS reference for every check.
- The stale "will be configured here" integrations text and hard coded English sentences in templates are gone.
- The compliance webhook card shows that the signature covers the timestamp and the body.

## 0.15.0 (2026-11-26)

### Added
- `limdm` command line for users on the device: `info` shows everything about the device and the agent; `software list|install|remove|request|search|request-new|requests`, `checks`, `profiles`, `certificates`, `log`, `sync`, `sso` and `recovery-key` do what the LiMDM app does. Packaged with the agent.

### Changed
- Agent events report changes only: the same event is sent at most once every 6 hours, tamper reports always.

### Fixed
- The software store lock rule was deleted and rewritten on every cycle, which sent "software stores read only" each time.

## 0.14.0 (2026-11-25)

### Added
- Settings, Security: a password policy (minimum length, character classes, no user name) for passwords set in the console, on devices and for local console accounts.

### Changed
- Hints sit below their fields and start with a capital letter; option labels too. The email kind reads "E-Mail (SMTP)" in German.

### Fixed
- Login items without `mode` from before 0.11 (they carry `local_password`) keep login mode instead of turning into sessions.
- Firewall rules with ports outside 1..65535 or reversed ranges are rejected; declaration tokens match for payloads with `&`, `<` or `>`.
- Agent: commands older than 8 days are refused, a reused command ID after a database restore runs, re-enrollment forgets the previous server's key and command IDs.
- Agent: maintenance windows, reboot checks and script intervals count suspended time; tamper reports are never dropped from a full queue, and text inside other events no longer counts as tamper.
- Agent: the desktop socket works without logind, package manager calls run one at a time, a broken renewed certificate keeps the current one, terminals are ended on Alpine without utmp, a stuck update on OpenRC is reported and offered again.
- Checks: dnf5 security advisories counted, deb822 comment stanzas left intact when a source is disabled, SDDM and LightDM drop-ins checked for autologin, sshd checks without host keys, Match Address blocks for local networks, installed NTP daemons kept, stricter `ptrace_scope` and `tcp_syncookies` kept.
- Console: blueprints from directory groups show in the device list, filter and counts; helpdesk sees no audit details; insecure remotes can be blocked; Enter in the bulk tag field adds the tag; Retire, Remove from catalog and Revoke ask first; "Approve for everyone" keeps a required app required.
- Docker: the state volume belongs to the nonroot user; fail2ban bans rejected enrollments on port 8444.
- Review of the 0.13 fixes: Google sync survives duplicate rows from older versions and address clashes; app request texts are sanitized (a NUL from the desktop socket blocked check ins); an address an active person holds is never treated as disabled; deleting a user whose current address is also a previous one works; a lock sent in lost mode stays after Found; IT locked accounts stay locked on unlock.
- Agent: the desktop socket without logind admits only users on a virtual console; device locks end SSH terminals but keep console started compositors; Arch PAM line goes before pam_systemd_home; re-enrollment is detected at start; users.json survives switching the login off; dnf totals and EPEL advisories are counted; SSH Match Address contexts are evaluated separately; unreadable dconf databases fail the check; NTP unit names per distribution; successful scripts with background children no longer fail; declaration tokens ignore HTML escapes.
- Server: OIDC outage at start keeps local login and settings usable; proxies without a port and proxy only DNS work for notifications; the agent TLS certificate copy is race free; the rate limiter stays bounded; SCIM PUT is serialized with PATCH; insecure remotes cannot be allowed; console items saved under 0.12 with a broken signature are marked in the library.
- Console: row menus open as a bottom sheet on phones; channel errors stay on the Integrations tab; more German texts; focus ring on the kind picker; helpdesk sees no dead links and no empty column.

## 0.13.0 (2026-11-25)

### Added
- Device events are paged, 50 per page.
- Integrations settings: kind picker, event grid, channel actions in a menu.

### Fixed
- Library items saved in the console verify after the JSONB round trip (signatures cover canonical JSON).
- Arch and Alpine: the PAM line gets its `auth sufficient` prefix; a broken line from 0.12.0 is replaced.
- Two repository items with `disable` on one device no longer fail every check in; a later Flatpak remote item wins.
- NUL bytes, invalid UTF-8 and `"checks": null` from devices no longer break check ins, the device page or the export.
- Background children of scripts no longer hang the agent; commands arrive in the order they were created.
- Lost mode survives the offline lock and an unlock; failed password releases are retried.
- Switching off the desktop login releases the SSO password locks; `user_lock` stays in force.
- The desktop socket no longer blocks the agent while the identity provider answers.
- dconf databases and new config directories are readable by sessions despite `UMask=0077`.
- pacman and apk run the post upgrade hook (agent updates on Arch and Alpine), and the removal hook checks the release.
- The device page no longer holds a transaction while taking more pool connections; exports stream without the 30 s limit and mark themselves incomplete on errors.
- Rate limits group IPv6 clients by /64 and drop idle keys; enrollment counts only failures.
- Status chips on the device list keep search and filters.
- "Device user disabled" is notified once per device; Flathub search without hits shows its message.
- The server starts when OIDC discovery fails and retries it in the background; the schema runs inside the migration lock.
- The legacy compliance webhook uses the SSRF protected client; proxies from the environment are checked against the target.
- Google sync: a renamed primary email updates the same user, archived users count as inactive, deleted groups are removed, SCIM users are not taken over, and a key saved during a sync is kept.
- Directory users keep their previous addresses, so a suspension also reaches device accounts listed under an old email.
- SCIM: concurrent PATCH requests are serialized, `name.*` changes update the display name, a new primary email wins, an email clash answers 409, `remove` of members with an empty list removes none.
- Agent TLS certificate renews itself before it expires; a database error during device authentication is no longer answered as "certificate revoked".
- Release signatures uploaded after a release was imported are added later; an older agent version picked for a device is dropped instead of being offered forever.
- Concurrent settings saves no longer overwrite each other; viewing a recovery key keeps a pending rotation.

## 0.12.0 (2026-11-25)

### Added
- Agent for CentOS Stream and other RHEL rebuilds, Arch (pacman) and Alpine (apk, OpenRC).
- Library items are signed with `command.key`; changed items are not delivered.
- RFC 9457 problem details for the agent API; `docs/api.md`.
- Notifications to email, Slack, Discord and webhooks with per channel events; a confirmation dialog for destructive actions.
- Catalog installs and removals show progress and an outcome banner.

### Changed
- Database sessions get statement, lock and idle transaction timeouts.
- Enrollment is rate limited per address; Flathub search and icons per device, cached for an hour.
- A second enrollment of the same machine ID is recorded in the audit log (`device.duplicate`).
- One check in per device at a time; background loops survive panics and run on one instance only.
- **Breaking:** the session cookie is `__Host-limdm_session`; everybody signs in once again after the update.

## 0.11.0 (2026-11-25)

### Added
- SSO session mode like Platform SSO and Passport: the first login binds the account with SSO, later logins use the local password until reconfirmation or the offline grace ends.
- Directory suspensions and deletions lock device accounts at the next poll.
- Signed commands (Ed25519, checked by the agent), fallback DNS over HTTPS, local users and admin rights from the console.
- SSH and disk encryption compliance checks.
- Device page header with key facts; protective actions (lock, lost mode, wipe, uninstall) stay visible as notices.
- greetd, swaylock, hyprlock, i3lock and other greeters and lockers run the desktop login.

### Changed
- **Breaking:** the default SSO mode is `session`; the strict behavior stays available as mode `login`, and SSO can be switched off per item.
- Faster frontend: charts load only on the overview, command output on demand, one delegated event listener.

## 0.10.2 (2026-11-25)

### Added
- Device tags as chips, tag filter, selection with bulk actions.
- Clickable device counts everywhere (catalog installs, Flatpaks, remotes, blueprints).
- Install and remove catalog apps remotely, per device and in bulk.
- Action menus with flyout submenus; native desktop dialogs.
- The tray menu shows who manages the device, its state and the agent version.

### Changed
- The blueprint editor offers only library items not assigned yet; catalog apps without icon or summary are completed from Flathub.

## 0.10.1 (2026-11-25)

### Added
- App requests for apps outside the catalog from the desktop app, with approval in the console.
- Flathub search in the console (Add app); vendor package repositories per catalog app (Debian and Fedora), seeded with Mullvad VPN, Tailscale, NetBird and 50 more Flathub apps.
- Managed Flatpak remotes (`catalog_remotes`, Flathub seeded) and the policy `only_managed_remotes`.
- Import of Flatpaks installed on devices into the catalog; `com.limdm.softwarestore` declaration for the store policy per blueprint.

### Fixed
- `/var/cache/limdm` was 0700, so catalog icons were unreadable for the desktop app.

## 0.10.0 (2026-11-25)

### Added
- Software catalog for self service installs without admin rights: catalog and requests in the console (Software page), detection across Flatpak and packages on the agent, Software page with search and categories in the desktop app.

## 0.9.2 (2026-11-25)

### Added
- `com.limdm.screenlock`: screen lock and login screen privacy on GNOME, Budgie, Cinnamon, MATE (dconf locks), KDE and wlroots desktops; login managers GDM, SDDM and LightDM (hide users, no autologin).

### Changed
- The item editor swaps the example settings when the type changes; a certificate upload replaces the example entry.

### Fixed
- Review fixes for the screen lock: login screen changes only with `hide_users` or `allow_autologin`, the idle locker follows remediate and exclude, desktops without a supported locker fail the check.

## 0.9.1 (2026-11-25)

### Added
- Desktop app: Profiles page (declarations with secrets masked), Certificates, full log, logo and dark mode.
- PEM and CRT upload (bundles) in the library editor for certificates.

### Changed
- The Agents page hides versions older than every agent in use.

## 0.9.0 (2026-11-25)

### Added
- GTK 4 and libadwaita desktop app (`/usr/lib/limdm/limdm-desktop-ui`); LiMDM logo for console, favicon and app icons.

### Fixed
- The desktop helper starts reliably through `systemd-run --user`; the agent installs the GTK typelibs on desktops.

## 0.8.5 (2026-11-25)

### Changed
- Due agent updates trigger an immediate check in (`/api/v1/poll`), except while an offered version installs.

## 0.8.4 (2026-11-25)

### Added
- Command `message` (console "Send message…"); a lock notifies the user first.
- Desktop helper autostart through a global systemd user unit and XDG autostart.

### Changed
- With `network_info: false` the server stores no public address and no location.
- The restart and shutdown delay counts from sending; users are notified.

## 0.8.3 (2026-11-25)

### Added
- Installation guide with host hardening, fail2ban filters and jails and CrowdSec (`deploy/fail2ban`, `deploy/crowdsec`).
- The server logs failed OIDC sign ins with reason and client address.

### Changed
- Settings tabs carry real labels in English and German; row actions are aligned and dialogs centered.

## 0.8.2 (2026-11-25)

### Added
- Update a single device to a chosen agent version.
- Settings in tabs (General, SSO, Monitoring, Branding, Integrations); grouped and filterable library table; recovery key in a dialog with copy.
- Tray icon for the desktop helper (StatusNotifierItem).

### Changed
- Packages depend on the tools the agent calls; desktop tools are installed only on desktops.

## 0.8.1 (2026-11-25)

### Added
- Flatpak applications and remotes (system and per user) in the inventory; `com.limdm.flatpak` remotes with `scope` and `disabled`.
- The agent installs zenity or kdialog on devices with a desktop; helper dialogs follow the GNOME HIG.
- The overview shows escrowed recovery keys.

### Fixed
- Signals reach only the agent's main process.

## 0.8.0 (2026-11-25)

### Added
- Agent self updates with automatic rollback: Agents page with versions from GitHub releases, rollout policy (automatic, pilot tag, delay), three failed devices block a version.
- The release workflow signs the checksums with `RELEASE_SIGNING_KEY`.
- Public address of every check in with location lookup.

## 0.7.0 (2026-11-25)

### Added
- Desktop login: local password after SSO.
- Lost mode and remote wipe; lost mode blocks logins and ends sessions.
- Tamper protection: the agent refuses manual stops, a watchdog restarts it and reports tampering.
- Device page Network tab (interfaces, VPN clients, DNS); profile with tabs and the version in the sidebar.

### Changed
- Routine agent events go to `device_events` instead of the audit log.
- SCIM follows RFC 7643 and 7644 (scimType, filters per resource, PATCH).

### Fixed
- SCIM DELETE did not reach devices; administrators removed from the environment kept access.
- A lost renewal response no longer locks a device out.

## 0.6.0 (2026-11-25)

First tagged release. It contains all work since the initial commit on 2026-11-24.

### Added
- Server and agent: declarative model with typed declarations, mTLS agent channel with a private device CA and CSR based enrollment, OIDC console login with PKCE, compliance checks for CIS Level 1 and 2 with safe remediation, desktop login through the OIDC device flow, append only hash chained audit log, signed agent self updates.
- Local admin fallback with TOTP (`LIMDM_LOCAL_LOGIN`, `limdm-server local-admin add|reset|disable|enable|list`), osquery inventory, sidebar console with light and dark theme.
- Library and blueprints as assignment maps with nested conditions and inheritance; declaration types for package sources, CA certificates, sysctl, kernel modules, sshd options, login banner, DNS, NTP, proxy, Flatpak and recurring scripts.
- Directory: SCIM 2.0 server and Google Workspace sync; console roles admin, helpdesk and auditor; all server settings in the console with sealed secrets; compliance policies with grace period, signed webhook and automatic lock; history charts; English and German console.
- Disk encryption recovery key escrow (`com.limdm.diskencryption`), polkit, sudo and boot loader password declarations.
- Desktop helper (`limdm-desktop`) with the agent socket, company name and logo branding, disabling package sources with backup, profile page with TOTP and recovery codes.
- Agent deployment from the console: `/install.sh`, `enroll.conf` for mass deployment, `LIMDM_RELEASE_REPO`.
- Container image (distroless, non root), Docker Compose with Caddy, `LIMDM_AGENT_HOSTS`.

### Changed
- **Breaking:** priority blueprints were migrated to the assignment map model.

### Fixed
- Every form post failed the CSRF check; device actions and inventory views.
