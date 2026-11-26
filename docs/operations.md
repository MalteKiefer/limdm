# Operations

## Backup

Back up regularly and before every upgrade:

| What | Where | Why |
|---|---|---|
| PostgreSQL database | `pg_dump limdm` | devices, configuration, audit log, sealed secrets, webhook signing secret |
| CA directory | `LIMDM_CA_DIR` (default `/var/lib/limdm-server/ca`) | device and network CA, command key, `keys.json` (active and retiring key names), `audit-keys` (audit key segments of earlier command keys), `audit-keyed-from` (switch point of the keyed audit chain). Without it no device can check in and the audit log cannot be verified |
| `LIMDM_SESSION_KEY` | `server.env` or `.env` | without it sealed secrets and recovery keys are unreadable |

```sh
sudo -u postgres pg_dump -Fc limdm > limdm-$(date +%F).dump          # package install
docker compose exec db pg_dump -U limdm -Fc limdm > limdm-$(date +%F).dump   # Docker
```

Store the CA directory and the session key apart from the database dump, encrypted. Back
up the CA directory again after every key rotation step. With `LIMDM_KEY_PROVIDER=pkcs11`
the private keys are in the HSM: back up the token as its vendor describes, and the CA
directory for the certificates, `keys.json`, `audit-keys` and `audit-keyed-from`.
For point in time recovery, RPO and RTO guidance and a restore test procedure see
[high-availability.md](high-availability.md#backup).

## Key rotation

`limdm-server keys status|rotate KIND|finish KIND` and **Settings, Security, Keys** rotate the
device CA, the network CA, the command key, the session key and the webhook signing secret
without enrolling devices again. Each step takes effect after a restart of every instance.
Agents must run 0.16 or newer. Runbooks: [keys.md](keys.md).

## Restore

1. Install the same or a newer server version.
2. Restore the CA directory and `LIMDM_SESSION_KEY`.
3. `pg_restore -d limdm limdm-<date>.dump` into an empty database.
4. Start the server. Devices continue checking in without enrolling again.

## Upgrades

See [installation.md](installation.md#upgrades). Read the release notes; migrations run
automatically and are not reversible, so keep the backup until the new version runs.
With several instances upgrade one at a time, unless the release notes ask for a full stop
([high-availability.md](high-availability.md#upgrades)).

### Upgrading from 0.15 to 0.16

1. **Stop every instance before the first 0.16 instance starts.** At its first start 0.16
   switches the audit chain to keyed hashes (HMAC-SHA256 with a key derived from the
   command key) and records the switch point in `LIMDM_CA_DIR/audit-keyed-from` and the
   database. A 0.15 instance still running would append plain hashes behind the switch
   point and break the chain. Start one 0.16 instance, wait for `/readyz`, copy the CA
   directory (now with `audit-keyed-from`) to the other instances, then start them. An
   instance whose CA directory lacks the switch point, or differs from the one the others
   use, refuses to start; an instance with an outdated audit key refuses to write audit
   entries.
2. **Health checks.** `/healthz` no longer queries the database, it only shows that the
   process runs. Point load balancers and uptime monitoring that should notice a database
   outage at `/readyz` ([below](#health-checks)).
3. **Reverse proxy on another host.** The client address is taken from `X-Forwarded-For`
   only for proxies on loopback or listed in `LIMDM_TRUSTED_PROXIES`. Set it when Caddy,
   nginx or a load balancer runs on another host or container network, otherwise rate
   limits, console network lists and the audit log see the proxy's address.
4. **Release builds.** The release workflow needs the secret `RELEASE_SIGNING_KEY` and the
   variable `UPDATE_PUBKEY` and fails without them ([release key](#release-key)). Agents
   built without a release key refuse every self update.
5. **New environment variables**, all optional: `LIMDM_TRUSTED_PROXIES`,
   `LIMDM_DRAIN_SECONDS`, `LIMDM_SYSLOG`, `LIMDM_MULTI_TENANT`, `LIMDM_KEY_PROVIDER` and
   `LIMDM_PKCS11_*`; `LIMDM_SESSION_KEY` accepts a comma separated list during a rotation
   ([configuration.md](configuration.md#environment-variables)).
6. **Webhook signing secret.** It is now its own sealed value. Installations with settings
   or notification channels keep the value derived from the session key, migrated at the
   first start, so receivers need no change. Rotate it with
   `limdm-server keys rotate webhook` or **Settings, Security, Keys**.
7. **Privacy opt ins.** Geolocation of device public addresses and the DNS over HTTPS
   fallback of agents are now off by default. Turn them on in **Settings, Security,
   Privacy** if you used them.
8. **Agent behavior.** Files of `com.limdm.files` and firewall rules that are no longer
   declared are removed from devices. On devices enrolled without `allow_scripts`,
   `com.limdm.files` writes only to the allowlisted plain text locations
   ([declarations.md](declarations.md#comlimdmfiles-list)).
9. **Agents.** Key rotations need agents 0.16 or newer: update the fleet before rotating
   ([keys.md](keys.md#rotation)).

## Health checks

| Path | Meaning | Answer |
|---|---|---|
| `/healthz` | liveness: the process serves requests. No database check, so a database outage does not restart every instance | `200 ok` |
| `/readyz` | readiness: database reachable, it holds the schema of this version, keys loaded, audit key current (not outdated by a command key rotation), notifications from other instances arrive, not shutting down | `200 ready`, or `503` with the reasons |

Both answer on the console listener without sign in and regardless of the console network
lists. On SIGTERM an instance fails `/readyz` for `LIMDM_DRAIN_SECONDS`, ends its remote
shells and hands its background jobs to the other instances.

## Several instances

Run several server instances behind a load balancer for availability:
[high-availability.md](high-availability.md).

## Releases and agent updates

Tagged releases (`vX.Y.Z`, signed tags) build for amd64 and arm64:

* `limdm-agent` packages as deb, rpm, Arch (`.pkg.tar.zst`) and Alpine (`.apk`), and a
  tar.gz with `limdm-agent`, `limdm-desktop` and `limdm`,
* `limdm-server` packages as deb and rpm, and a tar.gz,
* the container image `ghcr.io/maltekiefer/limdm-server`,
* `limdm_<version>_SHA256SUMS` with its signature `limdm_<version>_SHA256SUMS.sig`, SBOMs and provenance
  attestations.

The release job waits for approval of the `release` environment.

Rollout of agent versions to devices: [agent.md](agent.md#updates).

### Release key

Self updates fail closed. An agent installs an update only when the release `SHA256SUMS`
carry a valid signature of the release key whose public half is compiled into it. An agent
built without a public key (`make build` without `UPDATE_PUBKEY`) refuses every self update
and reports the event "agent update to X failed: ... built without a release signing key";
update such devices with the package manager.

```sh
limdm-server keygen -out release.key          # once; prints the public key
```

* Secret `RELEASE_SIGNING_KEY` of the protected `release` environment: content of
  `release.key`. The release workflow signs `SHA256SUMS` and uploads `SHA256SUMS.sig`.
* Repository variable `UPDATE_PUBKEY`: the printed public key. Release builds embed it.
* The workflow fails when either is missing; it never publishes unsigned checksums.

The private key is a CI secret, not an offline key. It is protected by the environment's
required reviewers and the tag ruleset, so anyone who can approve a release run can sign.
Keep a copy of `release.key` outside GitHub to rotate or recover it.

Manual signing: `limdm-server sign -key release.key limdm_<version>_SHA256SUMS`
(`-key-env VAR` reads the hex key from a variable), or with a key in an HSM:
`limdm-server sign -pkcs11 LABEL limdm_<version>_SHA256SUMS` (server built with
`-tags pkcs11`, [keys.md](keys.md#release-key)). The signature goes to stdout.

## Monitoring

* `journalctl -u limdm-server` / `docker compose logs limdm`: JSON logs.
* `GET /readyz` for load balancers and uptime checks ([health checks](#health-checks)).
* Prometheus metrics at `<LIMDM_PUBLIC_URL>/metrics` (see below).
* Syslog forwarding of the audit log and device events to a SIEM ([below](#syslog)).
* The overview shows stale devices (no check in within the stale threshold).
* Notification channels and the compliance webhook report events and non compliant devices
  ([notifications.md](notifications.md)).

### Prometheus metrics

`GET /metrics` on the console listener answers in the Prometheus text format. It needs an API
token (Administration, **API tokens**) of the role `metrics`, `admin` or `auditor`; create a
`metrics` token for the scraper, it can read nothing else. Tokens with scope tags and
tokens of a tenant get no metrics. The console's network allow and block lists apply, as
for every console path.

```yaml
scrape_configs:
  - job_name: limdm
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/limdm.token
    static_configs:
      - targets: ["mdm.example.com"]
```

| Metric | Labels | Meaning |
|---|---|---|
| `limdm_devices` | `status` | Devices by status (compliant, in grace, non compliant, stale, pending, retired) |
| `limdm_devices_last_checkin` | `age` | Active devices by time since the last check in: `lt_1h`, `lt_24h`, `lt_7d`, `lt_30d`, `ge_30d`, `never` |
| `limdm_compliance_failing_devices` | `check` | Active devices failing a compliance check |
| `limdm_commands_open` | `status` | Commands waiting for the device (`pending`) or sent but not answered (`sent`) |
| `limdm_agent_versions` | `version` | Active devices by agent version |
| `limdm_notifications_24h` | `result` | Notification deliveries in the last 24 hours, `ok` or `failed` |
| `limdm_audit_chain_intact` | | 1 while the audit hash chain verifies, 0 after an entry was changed |
| `limdm_audit_verified_timestamp_seconds` | | Last audit chain verification |
| `limdm_http_requests_total` | `listener`, `method`, `code` | Requests since the process started, console and agent listener; per instance, scrape every instance |

Useful alerts: `limdm_audit_chain_intact == 0`, `increase(limdm_notifications_24h{result="failed"}[1h]) > 0`,
`limdm_devices{status="stale"} > 0`. Each scrape verifies the audit entries written since the
last verification.

### Syslog

With `LIMDM_SYSLOG=udp://host:514` or `tcp://host:514` the server forwards every audit entry
and device event as an RFC 5424 message (facility 13, log audit; TCP with octet counting
framing, RFC 6587). Audit entries have the message ID `audit` and the structured data
`limdm@32473` with `id`, `actor`, `action`, `target` and `hash`; device events have the
message ID `event` with `id` and `device`. A copy outside the database anchors the audit
chain externally. Forwarding runs on one instance, retries unsent entries and continues
from its stored position after a restart or leader change
([high-availability.md](high-availability.md#background-jobs)). Both streams are written one
transaction at a time up to the commit, so ids become visible in order and the position
(last sent id) cannot skip an entry that committed late.

`LIMDM_SYSLOG=tcp+tls://host:6514` sends over TLS (RFC 5425, octet counting, TLS 1.2 or
newer); the collector's certificate is verified against the system roots, or against the CA
file in `LIMDM_SYSLOG_CA` for a private CA.

## Retention

An hourly job (one instance) deletes:

| Data | Kept |
|---|---|
| Finished commands (`ok`, `failed`, `expired`) | 180 days; lock, unlock, lost mode, end of lost mode and wipe stay |
| Device events | 365 days (`device_events` refuses deletes outside this job) |
| Compliance changes | 365 days; the latest change per device and check stays |
| Device metrics (memory, disk, load) | 30 days |
| Fleet history (overview chart) | 400 days |
| Notification delivery log | 30 days |
| Approval requests | expire after 24 hours |
| Audit log | forever, or **Settings, Security, Audit log retention** (365 to 36500 days) |

Audit retention runs once a day and only behind a fully verified chain. The last deleted
entry's id and hash become a checkpoint signed with the audit key, from which verification
starts afterwards; the deletion itself is an audit entry ([security.md](security.md#audit-log)).

## Command line

`limdm-server` without arguments runs `serve`.

| Command | Purpose |
|---|---|
| `serve` | run the server with the [environment variables](configuration.md#environment-variables) |
| `local-admin [-env FILE] [-role admin\|helpdesk\|auditor] [-out FILE] add\|reset\|disable\|enable\|list [NAME]` | local console accounts ([configuration.md](configuration.md#local-admins)) |
| `keys [-env FILE] status` | active and retiring keys, rotation progress |
| `keys [-env FILE] rotate ca\|network-ca\|command\|session\|webhook [-name NAME]` | start a rotation (`-name` is required with an HSM) |
| `keys [-env FILE] finish KIND [-force]` | finish a rotation ([keys.md](keys.md#rotation)) |
| `audit [-ca DIR] verify FILE.jsonl` | verify a JSON Lines audit export (**Audit**, export) outside the server; prints the range and "chain intact" or the first broken entry |
| `audit [-ca DIR] key` | print the audit key segments (`key=<hex> keyed_from=<id>`, one line per command key) for an auditor who verifies on another machine |
| `audit -key HEX -keyed-from ID verify FILE.jsonl` | verify with a printed key instead of the CA directory (one segment) |
| `keygen [-out FILE]` | create a release signing key (default `release.key`), print the public key |
| `sign -key FILE\|-key-env VAR\|-pkcs11 LABEL SHA256SUMS` | sign release checksums ([release key](#release-key)) |

`audit` reads `LIMDM_CA_DIR` (default `/var/lib/limdm-server/ca`) and, with an HSM, the
`LIMDM_KEY_PROVIDER` and `LIMDM_PKCS11_*` variables. Run the commands as the `limdm` user so
key files stay readable only by it.

## Troubleshooting

| Symptom | Check |
|---|---|
| Agent cannot check in | `journalctl -u limdm-agent`; port 8444 reachable without proxy; certificate expired more than 180 days ago means enrolling again |
| `TLS handshake error ... bad certificate` in the server log | an agent with a revoked or foreign certificate, or a scanner |
| Enrollment fails with fingerprint mismatch | fingerprint copied from another server, or a proxy on 8444 |
| Devices stay `pending` | no status yet; first check in takes up to one interval |
| `/install.sh` reports "no release found" | no release in `LIMDM_RELEASE_REPO` yet, or GitHub not reachable |
| Agent update fails with "built without a release signing key" | the agent was built without `UPDATE_PUBKEY`; update with the package manager ([release key](#release-key)) |
| Desktop helper does not ask | `limdm-desktop --now` in the session; zenity or kdialog installed; `/run/limdm/agent.sock` exists. Compositors without XDG autostart (sway, Hyprland) get the dialog from the agent together with the daily notification |
| Device locked unexpectedly | `/etc/nologin` text: manual lock, compliance lock or offline lock; check in from the device unlocks the offline lock |
| Console sign in loops | clock skew (TOTP), cookies blocked, `LIMDM_PUBLIC_URL` differs from the URL in the browser; with several instances: different `LIMDM_SESSION_KEY` |
| Every request comes from the proxy address (lockouts, network lists, audit) | the proxy is not on loopback: set `LIMDM_TRUSTED_PROXIES` |
| Instance does not start: "differs from the one the other server instances use" | its `LIMDM_CA_DIR` is not the one of the other instances ([high-availability.md](high-availability.md#requirements)) |
| `/readyz` answers 503 | the reasons are in the body: database unreachable, schema of another version, keys not loaded, audit key outdated after a key rotation (restart the instance), notifications interrupted (reconnects within seconds), shutting down |

Root can always log in at the console of a locked device.
