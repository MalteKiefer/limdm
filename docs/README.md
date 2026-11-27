# LiMDM documentation

The documents for LiMDM 0.18 and the unreleased changes in the changelog. Start with [Installation](installation.md), then
[Concepts](concepts.md) and [Console](console.md). Changes per version are in the
[changelog](../CHANGELOG.md); the upgrade from 0.15 is in
[Operations](operations.md#upgrading-from-015-to-016).

## Set up and run

| Document | Content |
|---|---|
| [installation.md](installation.md) | Supported systems, Docker Compose, deb and rpm packages behind Caddy, PostgreSQL, ports, files, first sign in |
| [configuration.md](configuration.md) | Every environment variable, every Settings tab and field, roles, install script and Docker variables |
| [operations.md](operations.md) | Upgrades, backup and restore, health checks, releases and agent updates, monitoring, syslog, retention, command line, troubleshooting |
| [backup.md](backup.md) | Built in encrypted backups (local, S3, B2, SFTP, WebDAV), schedule, GFS expiry, restore, restore test |
| [retention.md](retention.md) | Retention period per data type with defaults and legal reasoning |
| [high-availability.md](high-availability.md) | Several server instances behind a load balancer on one PostgreSQL database |
| [keys.md](keys.md) | Key inventory, PKCS#11 HSM, rotation runbooks, compromise procedure |
| [tenants.md](tenants.md) | Multi tenancy, super admins, tenant branding, shared objects |

## Use the console

| Document | Content |
|---|---|
| [console.md](console.md) | Every console page and its actions, roles and permissions, device scopes |
| [i18n.md](i18n.md) | Languages of console and server, where texts live, glossary per language |
| [concepts.md](concepts.md) | Declarations, library, blueprints, conditions, merging, versions, commands, device states |
| [declarations.md](declarations.md) | Reference of every declaration type and field |
| [compliance.md](compliance.md) | Built in checks with IDs and references, custom checks, policies, risk exceptions, history, evidence |
| [notifications.md](notifications.md) | Channels and every notification event |
| [software.md](software.md) | Software catalog, requests, Flathub and vendor repositories |
| [patching.md](patching.md) | Update rules per source, update rings and waves, pending updates, CVEs, rollback |
| [logs.md](logs.md) | Log management: journal, container and file logs of the devices, search, alerts, encrypted archive in S3 or B2, restore |
| [vulnerabilities.md](vulnerabilities.md) | Fleet view of CVE findings: severity, CVSS, CISA KEV, remediation history, risk acceptance |
| [packages.md](packages.md) | Uploaded packages, scripts and files, delivery and verification |
| [network.md](network.md) | WLAN, 802.1X, WireGuard and OpenVPN profiles, EAP-TLS certificates, CRL |
| [disk-encryption.md](disk-encryption.md) | LUKS recovery keys, escrow, rotation, TPM 2.0, lost devices |
| [remote-shell.md](remote-shell.md) | Audited remote support shell |
| [workloads.md](workloads.md) | Containers and VMs per device (Docker, Podman, LXC, LXD, Incus, Proxmox, libvirt), start, shut down, restart |

## Devices

| Document | Content |
|---|---|
| [agent.md](agent.md) | Agent installation, `enroll.conf`, `limdm-agent`, `limdm` and `limdm-desktop` commands, files on the device, updates |
| [desktop-login.md](desktop-login.md) | SSO desktop login, session mode, offline grace |

## Security and integration

| Document | Content |
|---|---|
| [security.md](security.md) | Architecture, agent channel, sessions, four eyes approval, audit log, sealed values, privacy |
| [api.md](api.md) | Agent API over mTLS |
| [admin-api.md](admin-api.md) | Admin REST API, API tokens, OpenAPI, Prometheus metrics |

## Project

| Document | Content |
|---|---|
| [development.md](development.md) | Build, tests, lint, project layout, release process |
| [brand-guidelines.md](brand-guidelines.md) | Console design and customer branding |
| [../SECURITY.md](../SECURITY.md) | Reporting vulnerabilities, supported versions |
