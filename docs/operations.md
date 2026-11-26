# Operations

## Backup

Back up regularly and before every upgrade:

| What | Where | Why |
|---|---|---|
| PostgreSQL database | `pg_dump limdm` | devices, configuration, audit log, sealed secrets |
| Device CA | `LIMDM_CA_DIR` (default `/var/lib/limdm-server/ca`) | without it no device can check in |
| `LIMDM_SESSION_KEY` | `server.env` or `.env` | without it sealed secrets and recovery keys are unreadable |

```sh
sudo -u postgres pg_dump -Fc limdm > limdm-$(date +%F).dump          # package install
docker compose exec db pg_dump -U limdm -Fc limdm > limdm-$(date +%F).dump   # Docker
```

Store the CA key and the session key apart from the database dump, encrypted.

## Restore

1. Install the same or a newer server version.
2. Restore the CA directory and `LIMDM_SESSION_KEY`.
3. `pg_restore -d limdm limdm-<date>.dump` into an empty database.
4. Start the server. Devices continue checking in without re enrollment.

## Upgrades

See [installation.md](installation.md#upgrades). Read the release notes; migrations run
automatically and are not reversible, so keep the backup until the new version runs.

## Releases and agent updates

Tagged releases (`vX.Y.Z`, signed tags) build deb, rpm and tar.gz for amd64 and arm64, SBOMs,
checksums, provenance attestations and the container image. The release job waits for
approval of the `release` environment.

Rollout of agent versions to devices: [agent.md](agent.md#updates).

### Release key

Self updates fail closed. An agent installs an update only when the release `SHA256SUMS`
carry a valid signature of the release key whose public half is compiled into it. An agent
built without a public key (`make build` without `UPDATE_PUBKEY`) refuses every self update
and reports the event "agent update to X failed: ... built without a release signing key";
update such devices with the package manager.

```sh
limdm-server keygen -out release.key          # once
```

* Secret `RELEASE_SIGNING_KEY` of the protected `release` environment: content of
  `release.key`. The release workflow signs `SHA256SUMS` and uploads `SHA256SUMS.sig`.
* Variable `UPDATE_PUBKEY`: the printed public key. Release builds embed it.
* The workflow fails when either is missing; it never publishes unsigned checksums.

The private key is a CI secret, not an offline key. It is protected by the environment's
required reviewers and the tag ruleset, so anyone who can approve a release run can sign.
Keep a copy of `release.key` outside GitHub to rotate or recover it.

Manual signing: `limdm-server sign -key release.key limdm_<version>_SHA256SUMS`.

## Monitoring

* `journalctl -u limdm-server` / `docker compose logs limdm`: JSON logs.
* Prometheus metrics at `<LIMDM_PUBLIC_URL>/metrics` (see below).
* The overview shows stale devices (no check in within the stale threshold).
* The compliance webhook reports non-compliant devices to your ticket or chat system.

### Prometheus metrics

`GET /metrics` on the console listener answers in the Prometheus text format. It needs an API
token (Administration, **API tokens**) of the role `metrics`, `admin` or `auditor`; create a
`metrics` token for the scraper, it can read nothing else. The console's network allow and
block lists apply, as for every console path.

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
| `limdm_devices` | `status` | Devices by status (compliant, in grace, non-compliant, stale, pending, retired) |
| `limdm_devices_last_checkin` | `age` | Active devices by time since the last check in: `lt_1h`, `lt_24h`, `lt_7d`, `lt_30d`, `ge_30d`, `never` |
| `limdm_compliance_failing_devices` | `check` | Active devices failing a compliance check |
| `limdm_commands_open` | `status` | Commands waiting for the device (`pending`) or sent but not answered (`sent`) |
| `limdm_agent_versions` | `version` | Active devices by agent version |
| `limdm_notifications_24h` | `result` | Notification deliveries in the last 24 hours, `ok` or `failed` |
| `limdm_audit_chain_intact` | | 1 while the audit hash chain verifies, 0 after an entry was changed |
| `limdm_audit_verified_timestamp_seconds` | | Last audit chain verification |
| `limdm_http_requests_total` | `listener`, `method`, `code` | Requests since the process started, console and agent listener |

Useful alerts: `limdm_audit_chain_intact == 0`, `increase(limdm_notifications_24h{result="failed"}[1h]) > 0`,
`limdm_devices{status="stale"} > 0`. Each scrape verifies the audit entries written since the
last verification.

## Troubleshooting

| Symptom | Check |
|---|---|
| Agent cannot check in | `journalctl -u limdm-agent`; port 8444 reachable without proxy; certificate expired more than 180 days ago means re enrollment |
| `TLS handshake error ... bad certificate` in the server log | an agent with a revoked or foreign certificate, or a scanner |
| Enrollment fails with fingerprint mismatch | fingerprint copied from another server, or a proxy on 8444 |
| Devices stay `pending` | no status yet; first check in takes up to one interval |
| `/install.sh` reports "no release found" | no release in `LIMDM_RELEASE_REPO` yet, or GitHub not reachable |
| Desktop helper does not ask | `limdm-desktop --now` in the session; zenity or kdialog installed; `/run/limdm/agent.sock` exists. Compositors without XDG autostart (sway, Hyprland) get the dialog from the agent together with the daily notification |
| Device locked unexpectedly | `/etc/nologin` text: manual lock, compliance lock or offline lock; check in from the device unlocks the offline lock |
| Console sign in loops | clock skew (TOTP), cookies blocked, `LIMDM_PUBLIC_URL` differs from the URL in the browser |

Root can always log in at the console of a locked device.
