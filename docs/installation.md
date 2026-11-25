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

## Requirements

* Linux host with a public DNS name, for example `mdm.example.com`.
* PostgreSQL 15 or newer. Local via unix socket, or remote with `sslmode=verify-full`
  (the server refuses remote connections without certificate verification).
* Outbound HTTPS for the OIDC provider and, if used, the Google Directory API.

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
| `LIMDM_VERSION` | image tag, for example `0.6.0` (`latest` for the newest release) |
| `LIMDM_SESSION_KEY` | `openssl rand -hex 32`; also derives the keys for stored secrets, keep it safe |
| `POSTGRES_PASSWORD` | `openssl rand -hex 32` (hex only, it is part of the database URL) |
| `LIMDM_LOCAL_LOGIN` | `true` to allow local accounts (password and TOTP) |
| `LIMDM_OIDC_*`, `LIMDM_ADMINS` | optional, OIDC can also be configured later in the console |

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
gh attestation verify oci://ghcr.io/maltekiefer/limdm-server:0.6.0 --repo MalteKiefer/limdm
```

## Option B: deb or rpm package behind Caddy

Download `limdm-server_<version>_linux_<arch>.deb` or `.rpm` and `limdm_<version>_SHA256SUMS`
from the [releases](https://github.com/MalteKiefer/limdm/releases/latest) and verify:

```sh
sha256sum -c --ignore-missing limdm_0.6.0_SHA256SUMS
sudo apt install ./limdm-server_0.6.0_linux_amd64.deb      # Debian, Ubuntu
sudo dnf install ./limdm-server_0.6.0_linux_amd64.rpm      # Fedora
```

The package installs the binary, a systemd unit (`limdm-server.service`, runs as user
`limdm`) and `/etc/limdm-server/server.env`.

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

Edit `/etc/limdm-server/server.env` (owner `root:limdm`, mode `0640`). Minimal setup behind
Caddy:

```sh
LIMDM_DATABASE_URL=postgres:///limdm?host=/var/run/postgresql
LIMDM_LISTEN=127.0.0.1:8080
LIMDM_PUBLIC_URL=https://mdm.example.com
LIMDM_AGENT_URL=https://mdm.example.com:8444
LIMDM_AGENT_LISTEN=:8444
LIMDM_SESSION_KEY=<openssl rand -hex 32>
LIMDM_LOCAL_LOGIN=true
```

Without `LIMDM_TLS_CERT` the console only listens on loopback; Caddy provides HTTPS. All
variables: [configuration.md](configuration.md).

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

### Firewall

Allow 80/tcp and 443/tcp (Caddy) and 8444/tcp (agents). Example for nftables:

```
tcp dport { 80, 443, 8444 } accept
```

### First account

```sh
sudo sh -c 'umask 077; sudo -u limdm limdm-server local-admin -env /etc/limdm-server/server.env add admin > /root/limdm-admin.txt'
```

The file contains the password and the TOTP secret. `reset`, `disable`, `enable` and `list`
manage existing local accounts; `-role helpdesk|auditor` sets another role.

## After the first sign in

1. **Settings:** configure OIDC (for example Google Workspace), branding (company name and
   logo), the stale threshold and the compliance webhook. See
   [configuration.md](configuration.md).
2. **Users:** add console users with their role.
3. **Library and Blueprints:** the `default` blueprint already contains a CIS Level 1
   baseline. See [concepts.md](concepts.md).
4. **Enrollment:** create a token and roll out the agent ([agent.md](agent.md)).

Once an OIDC administrator exists you can disable local login in the settings; keep one
local account disabled but present as break glass access.

## Upgrades

* **Docker:** set `LIMDM_VERSION` to the new tag, `docker compose pull && docker compose up -d`.
* **Packages:** install the new package. The service restarts, database migrations run
  automatically at start (versioned, guarded by an advisory lock).

Back up the database before upgrading ([operations.md](operations.md)). Agents update
through their package manager or the signed self update ([agent.md](agent.md#updates)).

## Moving to another DNS name

Agents keep the server URL they enrolled with and pin the device CA, not the host name.
When the server gets a new name, add every old name or IP to `LIMDM_AGENT_HOSTS`, so the
agent certificate of the server stays valid for them, and set `LIMDM_AGENT_URL` to the new
name for future enrollments. Keep the old DNS record pointing to the server.
