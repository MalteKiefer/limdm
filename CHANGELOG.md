# Changelog

All notable changes, newest first. Versions follow [Semantic Versioning](https://semver.org).

## Unreleased

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
