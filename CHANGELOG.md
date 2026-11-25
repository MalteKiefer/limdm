# Changelog

All notable changes, newest first. Versions follow [Semantic Versioning](https://semver.org).

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
