# Installation

LiMDM consists of `limdm-server` (console and agent API, PostgreSQL) and `limdm-agent` on
every device. This page covers the server. Devices: [agent.md](agent.md).

```
 Browser ── HTTPS ──► Caddy :443 ──► limdm-server 127.0.0.1:8080 (console) ─┐
                                                                             ├─ PostgreSQL
 limdm-agent ── mTLS, TLS 1.3, pinned device CA ──► limdm-server :8444 ─────┘
```

Two ports are public:

* **443** for the console, served by Caddy with an automatic Let's Encrypt certificate.
* **8444** for agents. This port must reach `limdm-server` directly. Never put a TLS
  terminating proxy or load balancer in front of it: agents authenticate with client
  certificates and pin the server's device CA.

Port 80 is needed for the ACME HTTP challenge.

## Supported systems

| Component | Systems | Packages | Init |
|---|---|---|---|
| Server | Debian, Ubuntu | `limdm-server_<version>_linux_<arch>.deb` | systemd |
| Server | Fedora, CentOS Stream, RHEL and rebuilds (Rocky, Alma), openSUSE Leap, openSUSE Tumbleweed, SLES | `limdm-server_<version>_linux_<arch>.rpm` | systemd |
| Server | any Linux with Docker | container image `ghcr.io/maltekiefer/limdm-server` | Docker Compose |
| Server | other Linux (Arch, Alpine, ...) | `limdm-server_<version>_linux_<arch>.tar.gz` (binary, unit file, `server.env.example`), or the image | systemd unit included; write your own for other init systems |
| Agent | Debian 12+, Ubuntu 22.04+, Fedora, CentOS Stream 9+, RHEL rebuilds 9+, openSUSE Leap 16 and Tumbleweed, SLES and SLED 16, Arch, Alpine 3.17+ | deb, rpm, `.pkg.tar.zst`, `.apk` | systemd; OpenRC on Alpine |

Agents need OpenSSL 3 (the installer verifies the release signature with it): systems with
OpenSSL 1.1.1 as default, such as Ubuntu 20.04, Debian 11, RHEL 8 and its rebuilds,
openSUSE Leap 15 and SLES 15, are not supported. Details: [agent.md](agent.md#supported-distributions).

Architectures: amd64 and arm64. Feature differences per device family:
[agent.md](agent.md#supported-distributions).

## Ports

| Port | Listener | Reachable from |
|---|---|---|
| 443 | Caddy (or another reverse proxy), console | users, devices (`/install.sh`), identity provider (SCIM) |
| 80 | Caddy, ACME HTTP challenge and redirect | internet |
| 8444 | `limdm-server`, agent API (`LIMDM_AGENT_LISTEN`), mTLS | devices, directly or through TCP passthrough |
| 8080 | `limdm-server`, console without TLS (`LIMDM_LISTEN` default) | loopback only |
| 8443 | `limdm-server`, console with `LIMDM_TLS_CERT` (default then) | the load balancer or users |
| 5432 | PostgreSQL | the server only; prefer the unix socket |

Outbound: HTTPS to the OIDC provider, Google Directory API (if used), GitHub
(`LIMDM_RELEASE_REPO`, agent releases), the geolocation service (only if turned on),
notification targets, and the syslog target (`LIMDM_SYSLOG`).

## Files

Server (package):

| Path | Content |
|---|---|
| `/usr/bin/limdm-server` | binary |
| `/usr/lib/systemd/system/limdm-server.service` | unit, runs as `limdm`, sandboxed, sets `LIMDM_CA_DIR=/var/lib/limdm-server/ca` |
| `/usr/lib/sysusers.d/limdm-server.conf` | creates the system user `limdm` |
| `/etc/limdm-server/server.env` | environment (`root:limdm`, 0640, kept on upgrades) |
| `/var/lib/limdm-server/` | state directory (0700, `limdm`) |
| `/var/lib/limdm-server/ca/` | CA directory: CA certificates and keys, command key, `keys.json`, `audit-keys`, `audit-keyed-from` |
| `/var/lib/limdm-server/agent-releases/` | verified agent packages (`LIMDM_RELEASE_DIR`; the packaged `server.env` sets `/var/lib/limdm-server/releases`) |

The container keeps the same state under the volume `/var/lib/limdm-server` and runs as
user 65532.

Devices (agent package): binaries `limdm-agent`, `limdm` (command line for users) and
`limdm-desktop`; units `limdm-agent.service`, `limdm-watchdog.service` and
`limdm-watchdog.timer`, the user unit `limdm-desktop.service` and XDG autostart, or
`/etc/init.d/limdm-agent` with OpenRC; configuration in `/etc/limdm` (0700), state in
`/var/lib/limdm` (0700). Details: [agent.md](agent.md#files).

## Security model in short

| Asset | Protection | What you must do |
|---|---|---|
| Console | HTTPS (Caddy), OIDC or password with TOTP, CSRF and origin checks, strict CSP, HSTS, account lockout after 5 failures, per address rate limit | keep local login as break glass only, add fail2ban or CrowdSec |
| Agent API (8444) | mTLS with TLS 1.3, client certificates from the private device CA, server CA pinned by agents | never terminate TLS in front of it, firewall it like any public service |
| Device CA (`/var/lib/limdm-server/ca`) | 0600, owned by `limdm`, systemd sandbox | back it up encrypted and offline; whoever has the key can impersonate the server |
| `LIMDM_SESSION_KEY` | derives every key for stored secrets and sessions | 32 random bytes, root only file, backed up apart from the database |
| Database | unix socket and peer authentication, or `sslmode=verify-full` | no TCP listener on public interfaces |
| Audit log | append only, keyed hash chain (HMAC-SHA256), verified daily | ship it to your SIEM with `LIMDM_SYSLOG` ([operations.md](operations.md#syslog)) |

Default stance: deny everything, open 80, 443, 8444 and SSH (preferably only from your
admin network), run the server as an unprivileged sandboxed service, keep the host patched.

## Requirements

* Linux host with a public DNS name, for example `mdm.example.com`.
* PostgreSQL 15 or newer. Local via unix socket, or remote with `sslmode=verify-full`
  (the server refuses remote connections without certificate verification).
* Outbound HTTPS for the OIDC provider and, if used, the Google Directory API.

One instance is enough for most fleets. For several instances behind a load balancer see
[high-availability.md](high-availability.md).

## Option A: Docker Compose

[`deploy/docker/compose.yaml`](../deploy/docker/compose.yaml) runs PostgreSQL (unix socket
only, no TCP listener), the server image `ghcr.io/maltekiefer/limdm-server` (read only root
filesystem, no capabilities) and Caddy. All images are pinned by digest.

```sh
git clone https://github.com/MalteKiefer/limdm
cd limdm/deploy/docker
cp .env.example .env
```

Fill in `.env`:

| Variable | Value |
|---|---|
| `LIMDM_DOMAIN` | DNS name of the server, for example `mdm.example.com` |
| `LIMDM_VERSION` | image tag, for example `0.16.0` (default `latest`, the newest release) |
| `LIMDM_SESSION_KEY` | `openssl rand -hex 32`; also derives the keys for stored secrets, keep it safe |
| `POSTGRES_PASSWORD` | `openssl rand -hex 32` (hex only, it is part of the database URL) |
| `LIMDM_LOCAL_LOGIN` | `true` to allow local accounts (password and TOTP) |
| `LIMDM_OIDC_*`, `LIMDM_ADMINS`, `LIMDM_AUDITORS` | optional, OIDC can also be configured later in the console |

Start and create the first account:

```sh
docker compose up -d
docker compose logs -f limdm          # wait for "admin UI listening"
docker compose exec limdm limdm-server local-admin add admin
```

The last command prints the user name, a generated password and a TOTP secret
(`otpauth://` URI) for an authenticator app. It is shown once.

Verify the image provenance of a release:

```sh
gh attestation verify oci://ghcr.io/maltekiefer/limdm-server:0.16.0 --repo MalteKiefer/limdm
```

## Option B: deb or rpm package behind Caddy

Download `limdm-server_<version>_linux_<arch>.deb` or `.rpm` and `limdm_<version>_SHA256SUMS`
from the [releases](https://github.com/MalteKiefer/limdm/releases/latest) and verify:

```sh
sha256sum -c --ignore-missing limdm_0.16.0_SHA256SUMS
sudo apt install ./limdm-server_0.16.0_linux_amd64.deb      # Debian, Ubuntu
sudo dnf install ./limdm-server_0.16.0_linux_amd64.rpm      # Fedora, CentOS Stream, RHEL rebuilds
sudo zypper install --allow-unsigned-rpm ./limdm-server_0.16.0_linux_amd64.rpm   # openSUSE, SLES (verified by the checksum)
```

The package installs the binary, a systemd unit (`limdm-server.service`, runs as user
`limdm`), the sysusers entry and `/etc/limdm-server/server.env` ([files](#files)). An
upgrade restarts a running service.

### PostgreSQL

Local database with peer authentication over the unix socket:

```sh
sudo apt install postgresql
sudo -u postgres createuser limdm
sudo -u postgres createdb -O limdm limdm
```

```sh
LIMDM_DATABASE_URL=postgres:///limdm?host=/var/run/postgresql
```

Remote database: `postgres://limdm@db.example.com/limdm?sslmode=verify-full`.

### server.env

Edit `/etc/limdm-server/server.env` (owner `root:limdm`, mode `0640`). The packaged file is
an example for a console with its own certificate; remove `LIMDM_TLS_CERT` and
`LIMDM_TLS_KEY` when Caddy runs on the same host. Minimal setup behind Caddy:

```sh
LIMDM_DATABASE_URL=postgres:///limdm?host=/var/run/postgresql
LIMDM_LISTEN=127.0.0.1:8080
LIMDM_PUBLIC_URL=https://mdm.example.com
LIMDM_AGENT_URL=https://mdm.example.com:8444
LIMDM_AGENT_LISTEN=:8444
LIMDM_SESSION_KEY=<openssl rand -hex 32>
LIMDM_LOCAL_LOGIN=true
```

Without `LIMDM_TLS_CERT` the console only listens on loopback; Caddy provides HTTPS. A proxy
on another host needs `LIMDM_TRUSTED_PROXIES`. All variables:
[configuration.md](configuration.md#environment-variables).

### Caddy

```sh
sudo apt install caddy
```

`/etc/caddy/Caddyfile` ([`deploy/Caddyfile`](../deploy/Caddyfile)):

```
mdm.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:8080
}
```

```sh
sudo systemctl reload caddy
sudo systemctl enable --now limdm-server
```

### First account

```sh
sudo sh -c 'umask 077; sudo -u limdm limdm-server local-admin -env /etc/limdm-server/server.env add admin > /root/limdm-admin.txt'
```

The file contains the password and the TOTP secret (`-out FILE` writes a new 0600 file
instead). `reset`, `disable`, `enable` and `list` manage existing local accounts;
`-role helpdesk|auditor` sets another role ([configuration.md](configuration.md#local-admins)).

## Hardening the host

The steps below assume Debian or Ubuntu; Fedora equivalents are noted. Example files live
in [`deploy/`](../deploy).

### Base system

```sh
sudo apt install unattended-upgrades needrestart
sudo dpkg-reconfigure -plow unattended-upgrades     # Fedora: dnf install dnf-automatic, enable dnf-automatic-install.timer
```

* SSH with keys only: `PasswordAuthentication no`, `PermitRootLogin no` in
  `/etc/ssh/sshd_config.d/10-hardening.conf`, then `systemctl reload ssh`.
* Time sync must work (TOTP and certificate validity depend on it): `timedatectl` shows
  `System clock synchronized: yes`.
* The `limdm-server.service` unit already runs sandboxed (no capabilities, read only
  system, private tmp, syscall filter). Check with `systemd-analyze security limdm-server`;
  do not loosen it with drop-ins.
* File modes: `/etc/limdm-server/server.env` `root:limdm 0640`,
  `/var/lib/limdm-server/ca` `limdm:limdm 0700`, key file `0600`.

### Firewall with ufw

```sh
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit from 198.51.100.0/24 to any port 22 proto tcp   # SSH only from your admin network
sudo ufw allow 80/tcp                                           # ACME HTTP challenge, redirect to HTTPS
sudo ufw allow 443/tcp                                          # console (Caddy)
sudo ufw allow 8444/tcp                                         # agents, mTLS
sudo ufw enable
sudo ufw status verbose
```

PostgreSQL (5432) and the console listener (8080, loopback) must not be reachable from
outside; with the rules above they are not. If your devices only connect through a VPN,
restrict 8444 to the VPN range instead of opening it to everyone:

```sh
sudo ufw delete allow 8444/tcp
sudo ufw allow from 10.8.0.0/16 to any port 8444 proto tcp
```

Fedora, RHEL rebuilds and SUSE with firewalld:

```sh
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --permanent --add-port=8444/tcp
sudo firewall-cmd --reload
```

Plain nftables: `tcp dport { 80, 443, 8444 } accept` in the input chain with policy drop.

### Caddy

[`deploy/Caddyfile`](../deploy/Caddyfile) proxies the console, writes a JSON access log for
fail2ban and CrowdSec, limits request bodies and hides the server banner. The server itself
sets HSTS, CSP and the other security headers.

To allow the console only from your networks while devices can still fetch the install
script and your identity provider can reach SCIM, uncomment the `@outside` block in the
Caddyfile.

### fail2ban

LiMDM locks an account after 5 wrong passwords and rate limits sign ins per address.
fail2ban additionally blocks the source address at the firewall. The server logs every
failed sign in (local and OIDC) and every rejected enrollment with the client address, for
example:

```
{"level":"WARN","msg":"local login failed","user":"admin","remote":"203.0.113.7","err":"..."}
```

Install the filters and jails from [`deploy/fail2ban`](../deploy/fail2ban):

```sh
sudo apt install fail2ban
sudo cp deploy/fail2ban/filter.d/limdm*.conf /etc/fail2ban/filter.d/
sudo cp deploy/fail2ban/jail.d/limdm.local /etc/fail2ban/jail.d/
# put your office and VPN egress addresses into ignoreip in limdm.local
sudo fail2ban-regex systemd-journal /etc/fail2ban/filter.d/limdm.conf   # check the filter against your journal
sudo systemctl restart fail2ban
sudo fail2ban-client status limdm
```

* `limdm`: 5 failures in 10 minutes ban the address for an hour (longer for repeat
  offenders) on 80 and 443.
* `limdm-tls`: 30 failed TLS handshakes on 8444 in 10 minutes ban for 30 minutes.
  Agents whose certificate expired also fail the handshake; keep the threshold high and
  your NAT addresses in `ignoreip`.
* fail2ban uses ufw automatically when `banaction = ufw` is set in `jail.local`; the default
  nftables or iptables action works too.
* Add the stock `sshd` jail if SSH is reachable from the internet.

### CrowdSec

CrowdSec reads the same events and shares decisions with its community blocklist. Files:
[`deploy/crowdsec`](../deploy/crowdsec).

```sh
# add the CrowdSec package repository first (docs.crowdsec.net, "Linux" install guide)
sudo apt install crowdsec crowdsec-firewall-bouncer-nftables
sudo cscli collections install crowdsecurity/linux crowdsecurity/sshd crowdsecurity/caddy crowdsecurity/http-cve
sudo cp deploy/crowdsec/acquis.d/limdm.yaml /etc/crowdsec/acquis.d/
sudo cp deploy/crowdsec/parsers/s01-parse/limdm-logs.yaml /etc/crowdsec/parsers/s01-parse/
sudo cp deploy/crowdsec/scenarios/limdm-bf.yaml /etc/crowdsec/scenarios/
sudo systemctl reload crowdsec
sudo cscli explain --type syslog --log 'Nov 25 08:00:00 mdm limdm-server[1]: {"level":"WARN","msg":"local login failed","user":"x","remote":"203.0.113.7"}'
sudo cscli decisions list
```

* `limdm/limdm-bf`: more than 5 failed sign ins or enrollments within a few minutes.
* `limdm/limdm-tls-scan`: bursts of failed TLS handshakes on the agent port.
* For Caddy access logs add an acquisition for `/var/log/caddy/limdm-access.log` with
  `type: caddy`; `crowdsecurity/caddy` then detects scanners and known exploits.
* Whitelist your office and VPN egress addresses with a postoverflow whitelist
  (`crowdsecurity/whitelists`), so IT is never blocked.

Use either fail2ban or CrowdSec for the same service, not both, to keep bans traceable.

### PostgreSQL

* Listen on the unix socket only: `listen_addresses = ''` in `postgresql.conf` when the
  database is local.
* Peer authentication for `limdm`, no password: `local limdm limdm peer` in `pg_hba.conf`.
* Remote databases: TLS with a certificate the server verifies (`sslmode=verify-full`),
  a dedicated role that owns only the `limdm` database.

### Backups and keys

Back up the database, the device CA and `LIMDM_SESSION_KEY` ([operations.md](operations.md)).
Encrypt the CA and the session key and keep them apart from the database dump; test a
restore regularly.

### Checklist

- [ ] HTTPS certificate valid, port 80 only redirects
- [ ] only 22 (restricted), 80, 443 and 8444 open; 5432 and 8080 closed from outside
- [ ] `server.env` 0640 `root:limdm`, CA directory 0700 `limdm`
- [ ] OIDC configured, local login disabled or one break glass account
- [ ] fail2ban or CrowdSec active, `ignoreip` or whitelist set
- [ ] unattended security updates on the server
- [ ] backups of database, CA and session key, restore tested
      ([restore test](high-availability.md#restore-test))
- [ ] audit log exported or monitored, compliance webhook set

## After the first sign in

1. **Settings:** configure OIDC (for example Google Workspace) under SSO, branding (company
   name and logo), the stale threshold, notification channels and the compliance webhook,
   and under Security the password policy, four eyes approval and the privacy opt ins. See
   [configuration.md](configuration.md#console-settings).
2. **Users:** add console users with their role and scope, or map directory groups to
   roles ([configuration.md](configuration.md#console-users-and-roles)).
3. **Library and Blueprints:** the `default` blueprint already contains a CIS Level 1
   baseline. See [concepts.md](concepts.md).
4. **Enrollment:** create a token and roll out the agent ([agent.md](agent.md)).

Once an OIDC administrator exists you can disable local login in the settings; keep one
local account disabled but present as break glass access.

## Upgrades

* **Docker:** set `LIMDM_VERSION` to the new tag, `docker compose pull && docker compose up -d`.
* **Packages:** install the new package. The service restarts, database migrations run
  automatically at start (versioned, guarded by an advisory lock, so instances starting
  at once wait for each other).
* **Several instances:** one after the other, waiting for `/readyz` on each; some releases
  need a full stop ([high-availability.md](high-availability.md#upgrades)).
* **0.15 to 0.16:** stop every instance first, check health checks, proxies and the release
  key: [operations.md](operations.md#upgrading-from-015-to-016).

Back up the database before upgrading ([operations.md](operations.md)). Agents are updated from the console
([agent.md](agent.md#updates)).

## Moving to another DNS name

Agents keep the server URL they enrolled with and pin the device CA, not the host name.
When the server gets a new name, add every old name or IP to `LIMDM_AGENT_HOSTS`, so the
agent certificate of the server stays valid for them, and set `LIMDM_AGENT_URL` to the new
name for future enrollments. Keep the old DNS record pointing to the server.
