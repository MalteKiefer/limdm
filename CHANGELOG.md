# Changelog

All notable changes, newest first. Versions follow [Semantic Versioning](https://semver.org).

## 0.14.0

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

## 0.13.0

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

## 0.12.0

### Added
- Agent for CentOS Stream and other RHEL rebuilds, Arch (pacman) and Alpine (apk, OpenRC).
- Library items are signed with `command.key`; changed items are not delivered.
- RFC 9457 problem details for the agent API; `docs/api.md`.

### Changed
- Database sessions get statement, lock and idle transaction timeouts.
- Enrollment is rate limited per address; Flathub search and icons per device, cached for an hour.
- A second enrollment of the same machine ID is recorded in the audit log (`device.duplicate`).
- One check in per device at a time; background loops survive panics and run on one instance only.
- The session cookie is `__Host-limdm_session`; everybody signs in once again after the update.

## 0.11.0
- SSO session mode like Platform SSO and Passport; directory suspensions lock accounts at the next poll.
- Signed commands, fallback DNS over HTTPS, local users and admin rights from the console.
- Device page header like Iru, protective action notices, SSH and disk encryption checks.

## 0.10.2
- Device tags, bulk actions, clickable device counts, flyout menus, native desktop dialogs.

## 0.10.1
- App requests outside the catalog, Flathub search in the console, vendor package repositories.

## 0.10.0
- Software catalog for self service installs.
