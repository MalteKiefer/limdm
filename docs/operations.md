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

## Releases and agent self update

Tagged releases (`vX.Y.Z`, signed tags) build deb, rpm and tar.gz for amd64 and arm64, SBOMs,
checksums, provenance attestations and the container image. The release job waits for
approval of the `release` environment.

The agent can update itself from the server, independent of package managers:

```sh
limdm-server keygen -out release.key          # once; keep the private key offline
```

Store the printed public key as the repository variable `UPDATE_PUBKEY`; release builds
embed it into the agent. To publish an update to devices:

```sh
limdm-server release -key release.key -version 0.6.1 -dir /var/lib/limdm-server/releases \
  amd64=limdm-agent-linux-amd64 arm64=limdm-agent-linux-arm64
```

with `LIMDM_RELEASE_DIR` pointing to that directory. Agents fetch the signed manifest at
check in, verify the signature and install only newer versions.

## Monitoring

* `journalctl -u limdm-server` / `docker compose logs limdm`: JSON logs.
* The overview shows stale devices (no check in within the stale threshold).
* The compliance webhook reports non-compliant devices to your ticket or chat system.

## Troubleshooting

| Symptom | Check |
|---|---|
| Agent cannot check in | `journalctl -u limdm-agent`; port 8444 reachable without proxy; certificate expired more than 180 days ago means re enrollment |
| `TLS handshake error ... bad certificate` in the server log | an agent with a revoked or foreign certificate, or a scanner |
| Enrollment fails with fingerprint mismatch | fingerprint copied from another server, or a proxy on 8444 |
| Devices stay `pending` | no status yet; first check in takes up to one interval |
| `/install.sh` reports "no release found" | no release in `LIMDM_RELEASE_REPO` yet, or GitHub not reachable |
| Desktop helper does not ask | `limdm-desktop --now` in the session; zenity or kdialog installed; `/run/limdm/agent.sock` exists |
| Device locked unexpectedly | `/etc/nologin` text: manual lock, compliance lock or offline lock; check in from the device unlocks the offline lock |
| Console sign in loops | clock skew (TOTP), cookies blocked, `LIMDM_PUBLIC_URL` differs from the URL in the browser |

Root can always log in at the console of a locked device.
