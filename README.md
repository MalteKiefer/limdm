# LiMDM

[![CI](https://github.com/MalteKiefer/limdm/actions/workflows/ci.yml/badge.svg)](https://github.com/MalteKiefer/limdm/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MalteKiefer/limdm/actions/workflows/codeql.yml/badge.svg)](https://github.com/MalteKiefer/limdm/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MalteKiefer/limdm/badge)](https://scorecard.dev/viewer/?uri=github.com/MalteKiefer/limdm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Declarative device management for Linux clients (Debian, Ubuntu, Fedora, CentOS Stream and other RHEL rebuilds, Arch, Alpine), modelled on
Apple's Declarative Device Management. Administrators describe the desired state; the agent
on every device converges to it on its own, also while offline, and reports back.
Compliance checks map to BSI IT-Grundschutz, CIS Benchmarks (Level 1 and 2) and
ISO/IEC 27001:2022 Annex A.

> **Status:** early. Server and agent run on a Debian 13 test installation. Desktop
> features (login, disk recovery keys, desktop helper) are not yet verified on real
> Ubuntu and Fedora desktops. See [Limitations](#limitations).

## Features

* **Library items and blueprints.** Reusable, strictly validated configuration items
  (packages, firewall, SSH, sudo, polkit, package sources, certificates, proxy and more)
  are assigned through blueprints with nested conditions and inheritance.
* **Compliance** with automatic remediation, grace periods, signed webhooks, automatic
  lock and CSV evidence for auditors.
* **Single sign on** for the console (OIDC, for example Google Workspace) and for the
  desktop login, with a local password after SSO, mandatory reconfirmation and an
  offline lock.
* **Directory** sync via SCIM 2.0 or the Google Directory API; groups select blueprints,
  deactivated people lose their device accounts.
* **Disk encryption recovery keys** created on the device with the user's passphrase in a
  branded desktop dialog, escrowed and sealed on the server.
* **Inventory** via osquery: hardware, disks, volumes, packages, accounts, network
  interfaces, package sources.
* **mTLS only** between agent and server (TLS 1.3, private device CA, pinned fingerprint),
  append only and hash chained audit log, console in English and German.

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

Host installation with deb or rpm packages behind Caddy, OIDC and all options:
[docs/installation.md](docs/installation.md).

## Documentation

| Topic | Content |
|---|---|
| [Installation](docs/installation.md) | Docker Compose, deb/rpm with Caddy, PostgreSQL, first sign in, upgrades |
| [Configuration](docs/configuration.md) | Environment variables, console settings, OIDC, branding, roles |
| [Concepts](docs/concepts.md) | Declarations, library, blueprints, conditions, inheritance, directory |
| [Declarations](docs/declarations.md) | Reference of every library item type |
| [Agent deployment](docs/agent.md) | Install script, mass deployment with `enroll.conf`, desktop helper, updates |
| [Desktop login](docs/desktop-login.md) | SSO login, local password, reconfirmation, offline lock |
| [Disk encryption](docs/disk-encryption.md) | Recovery key escrow and rotation |
| [Compliance](docs/compliance.md) | Checks, frameworks, policies, webhooks, evidence |
| [Software catalog](docs/software.md) | Self service apps in the desktop app, requests, Flathub filter |
| [Security](docs/security.md) | Architecture, mTLS, sessions, audit log, privacy |
| [Operations](docs/operations.md) | Backup, restore, releases, troubleshooting |
| [Development](docs/development.md) | Building, tests, release process |

## Limitations

* Desktop login, the desktop helper and LUKS escrow still need testing on real GNOME and
  KDE desktops (GDM, SDDM, lock screen, SELinux context of `pam_exec` on Fedora).
* The BSI mapping is at module level; requirement IDs and the mapping to Grundschutz++
  (BSI Standard 300-1) need review by an information security officer.
* Official CIS Benchmarks exist for Ubuntu and Debian; Fedora uses the RHEL
  recommendations as reference.
* The device CA key is a 0600 file (no HSM or PKCS#11); agent keys are files (no TPM).
* The client secret of the desktop login declaration is stored unencrypted in the
  database and on the device (0600, root only).
* Console roles are assigned per user, not yet from directory groups.

## License

[MIT](LICENSE)
