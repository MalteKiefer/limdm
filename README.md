# LiMDM

[![CI](https://github.com/MalteKiefer/limdm/actions/workflows/ci.yml/badge.svg)](https://github.com/MalteKiefer/limdm/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MalteKiefer/limdm/actions/workflows/codeql.yml/badge.svg)](https://github.com/MalteKiefer/limdm/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MalteKiefer/limdm/badge)](https://scorecard.dev/viewer/?uri=github.com/MalteKiefer/limdm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Declarative device management for Linux clients (Debian, Ubuntu, Fedora, CentOS Stream and other RHEL rebuilds, openSUSE, SLES, Arch, Alpine), modelled on
Apple's Declarative Device Management. Administrators describe the desired state; the agent
on every device converges to it on its own, also while offline, and reports back.
Compliance checks map to BSI IT-Grundschutz, CIS Benchmarks (Level 1 and 2) and
ISO/IEC 27001:2022 Annex A.

> **Status:** early. Server and agent run on a Debian 13 test installation. Desktop
> features (login, disk recovery keys, desktop helper) are not yet verified on real
> Ubuntu and Fedora desktops. See [Limitations](#limitations).

## Features

* **Library items and blueprints.** Reusable, strictly validated configuration items
  (packages, updates, firewall, SSH, sudo, polkit, package sources, certificates, proxy,
  printers, WLAN and VPN profiles, dconf, local accounts, screen lock and more) are assigned
  through blueprints with nested conditions and inheritance. Every change is versioned with
  diff, review step, rollback and restore.
* **Compliance** with automatic remediation, grace periods, automatic lock, custom checks,
  risk exceptions, compliance history and CSV evidence for auditors.
* **Device commands** for lock and unlock, lost mode, wipe, restart, scripts, updates,
  software removal, local accounts (create, admin rights, password, lock), log collection and
  an audited remote support shell. Every command is signed with Ed25519 and checked by the
  agent before it runs. Wipe, lost mode, scripts and role changes can require four eyes
  approval.
* **Single sign on** for the console (OIDC, for example Google Workspace) and for the
  desktop login, either for every login or as a session model like Platform SSO, with
  configurable reconfirmation and offline grace.
* **Directory** sync via SCIM 2.0 or the Google Directory API; groups select blueprints,
  deactivated people lose their device accounts.
* **Software store** in the desktop app: a curated catalog from Flathub and vendor
  repositories (for example Tailscale, Mullvad, NetBird), requests for other apps and
  approval in the console.
* **Notifications** to email, Slack, Discord and signed webhooks for non compliant devices,
  tamper attempts, failed commands and more.
* **Disk encryption recovery keys** created on the device with the user's passphrase in a
  branded desktop dialog, escrowed and sealed on the server.
* **Inventory** via osquery: hardware, disks, volumes, packages, Flatpaks, snaps, accounts,
  network interfaces, package sources.
* **Governance:** roles (admin, helpdesk, auditor) with device scopes, multi tenancy for
  MSPs, a keyed and hash chained audit log with syslog forwarding, key rotation without
  enrolling devices again and an optional PKCS#11 HSM.
* **Integrations:** admin REST API with OpenAPI, Prometheus metrics, several server
  instances behind a load balancer.
* **Security by default:** mTLS only between agent and server (TLS 1.3, private device CA,
  pinned fingerprint), signed library items, IP allow and block lists for the console,
  append only audit log.
* **Agent self updates** with signed checksums and automatic rollback; packages for deb,
  rpm, Arch and Alpine, systemd and OpenRC. Console in English and German.

Upgrading from 0.15: stop every server instance first, see
[docs/operations.md](docs/operations.md#upgrading-from-015-to-016).

## Quick start

Server with Docker Compose, PostgreSQL and Caddy (automatic HTTPS):

```sh
git clone https://github.com/MalteKiefer/limdm && cd limdm/deploy/docker
cp .env.example .env    # set LIMDM_DOMAIN, LIMDM_SESSION_KEY, POSTGRES_PASSWORD
docker compose up -d
docker compose exec limdm limdm-server local-admin add admin
```

Open `https://<LIMDM_DOMAIN>`, sign in with the printed password and TOTP secret, create an
enrollment token and install the agent on a device:

```sh
curl -fsSL https://mdm.example.com/install.sh | sudo LIMDM_TOKEN=lmt_... sh
```

Host installation with deb, rpm, Arch or Alpine packages behind Caddy, OIDC and all options:
[docs/installation.md](docs/installation.md).

## Documentation

An index of all documents is in [docs/README.md](docs/README.md).

| Topic | Content |
|---|---|
| [Installation](docs/installation.md) | Supported systems, Docker Compose, deb/rpm with Caddy, PostgreSQL, ports, files, first sign in |
| [Configuration](docs/configuration.md) | Environment variables, Settings tabs, OIDC, roles, install script variables |
| [Console](docs/console.md) | Every console page, its actions, roles and permissions |
| [Concepts](docs/concepts.md) | Declarations, library, blueprints, conditions, inheritance, versions, device states |
| [Tenants](docs/tenants.md) | Multi tenancy for MSPs and groups of companies, super admins, shared objects |
| [Declarations](docs/declarations.md) | Reference of every library item type and field |
| [Agent](docs/agent.md) | Install script, `enroll.conf`, `limdm-agent`, `limdm` and `limdm-desktop`, files on the device, updates |
| [Desktop login](docs/desktop-login.md) | SSO login and session mode, reconfirmation, offline grace |
| [Disk encryption](docs/disk-encryption.md) | Recovery key escrow, rotation, TPM 2.0 binding |
| [Network profiles](docs/network.md) | WLAN, 802.1X, WireGuard and OpenVPN profiles, EAP-TLS device certificates, CRL |
| [Software catalog](docs/software.md) | Self service apps in the desktop app, requests, Flathub and vendor repositories |
| [Compliance](docs/compliance.md) | Checks with IDs, custom checks, frameworks, policies, exceptions, webhook, evidence |
| [Remote shell](docs/remote-shell.md) | Audited support terminal from the console to a device |
| [Notifications](docs/notifications.md) | Email, Slack, Discord and webhook channels, events |
| [Security](docs/security.md) | Architecture, mTLS, signed commands, sessions, four eyes, audit log, privacy |
| [Keys](docs/keys.md) | Key inventory, HSM, rotation runbooks, compromise |
| [High availability](docs/high-availability.md) | Several server instances on one database |
| [Agent API](docs/api.md) | Endpoints, problem details, integrity of commands and items |
| [Admin API](docs/admin-api.md) | REST API, API tokens, OpenAPI, Prometheus metrics |
| [Operations](docs/operations.md) | Upgrades, backup, health checks, releases, syslog, retention, troubleshooting |
| [Development](docs/development.md) | Building, tests, release process |
| [Brand guidelines](docs/brand-guidelines.md) | Console design and customer branding |

## Limitations

* Desktop login, the desktop helper and LUKS escrow still need testing on real GNOME and
  KDE desktops (GDM, SDDM, lock screen, SELinux context of `pam_exec` on Fedora).
* The BSI mapping is at module level; requirement IDs and the mapping to Grundschutz++
  (BSI Standard 300-1) need review by an information security officer.
* Official CIS Benchmarks exist for Ubuntu and Debian; Fedora uses the RHEL
  recommendations as reference.
* Server keys can live in a PKCS#11 HSM only with the separate `-tags pkcs11` build; agent
  keys are files (the TPM binds LUKS volumes, not the device key).
* The client secret of the desktop login declaration is sealed on the server but stored in
  plain text on the device (0600, root only).
* SUSE support, TPM binding and printers are not yet verified on real SUSE, TPM and CUPS
  systems.

## License

[MIT](LICENSE)
