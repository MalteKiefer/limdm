# Backup and restore

LiMDM backs itself up: a scheduled job writes an encrypted, signed archive to one or more
storage targets, keeps a GFS series of archives, verifies them and reports failures. Restores
run on the command line. Point in time recovery of PostgreSQL stays a database task
([high-availability.md](high-availability.md#backup)); the archive is the complete, portable
copy of one moment.

Set it up under **Settings, Backup** (global admins only).

## What an archive holds

One archive per run, `limdm-<public host>-<UTC time>.lbk`:

| Entry | Content |
|---|---|
| `db/<table>.tsv` | every table as a PostgreSQL `COPY` text export, all from one read only snapshot (repeatable read), in restore order |
| `ca/` | the CA directory: device and network CA, command key, `keys.json`, `audit-keys`, `audit-keyed-from`, without the release cache. With an HSM only the certificates and these files |
| `artifacts/` | uploaded packages when they are stored locally ([packages.md](packages.md)) |
| `manifest.json` | server version, schema hash, table columns, sequences, the SHA-256 of every entry, `keys.json` (the active and retiring key generation of every kind), the device CA fingerprint, the audit head (last id and hash), the identifier of the session key |
| `manifest.sig` | Ed25519 signature of the manifest with the command key |

The tar is compressed with gzip and encrypted with [age](https://age-encryption.org) to the
X25519 recipients set in the console. The format is open: `age -d -i key.txt FILE.lbk | tar
-tz` lists an archive without LiMDM.

**Not in the archive:** `LIMDM_SESSION_KEY`. Sealed values in the database (recovery keys,
client secrets, target secrets) need it, so it is kept apart, for example in a password safe
with the age private key held by another person. The manifest names it only by an identifier
derived with HKDF, which lets a restore check that the right key is set. Encrypting the
archive with the session key itself would make it unreadable exactly when the server is lost.

Why `COPY` and not `pg_dump`: the server image is static and contains no PostgreSQL client,
and `pg_dump` must match the server's major version. The `COPY` export runs over the
server's own connection, needs no extra binary and is restored by the same code that knows
the schema. For PITR or a dump of the whole cluster, use `pg_dump` or pgBackRest next to it.

## Setup

1. Create an age key pair **offline**: `age-keygen -o limdm-backup.agekey`. Keep the file in
   a safe or on a hardware key; enter its public key (`age1...`) as recipient. Two
   recipients let two people restore independently.
2. Add targets (local, S3, Backblaze B2, SFTP, WebDAV):

   | Kind | Use | Notes |
   |---|---|---|
   | local | a directory, also an NFS or SMB mount | written as `<dir>/<archive>` with mode 0600 |
   | S3 | AWS S3, MinIO, Ceph, Hetzner Object Storage, Wasabi, Backblaze B2 (S3 API), GCS with HMAC keys | Signature V4; path style URLs for most non AWS services. **Object Lock**: archives are written with `GOVERNANCE` or `COMPLIANCE` retention for the set days; the bucket must have been created with Object Lock |
   | SFTP | any SSH server | the host key is pinned (`ssh-keyscan HOST` line or `SHA256:` fingerprint); password or OpenSSH private key |
   | Backblaze B2 | B2 buckets | its own target kind: region (from the bucket endpoint, for example `eu-central-003`), bucket, application key id and application key. Uses B2's S3 compatible API (see below); **file lock** works like Object Lock when the bucket has it enabled |
   | WebDAV | Nextcloud, ownCloud, Hetzner Storage Box, Apache `mod_dav` | https only; the folder URL (Nextcloud: `https://HOST/remote.php/dav/files/USER/limdm`, Storage Box: `https://uXXXXX.your-storagebox.de/limdm`); with a user name the secret is the password (use an app password), without one a bearer token. Folders are created with `MKCOL`, archives streamed with `PUT`, listed with `PROPFIND` (depth 1), expired with `DELETE` |

   Large archives go to S3 and B2 as multipart uploads in parts of 256 MiB (a single PUT
   takes at most 5 GiB); every part carries its Content-MD5, the lock retention is set when
   the upload starts, and a failed upload is aborted so no parts stay behind.

   **Why B2 runs over its S3 API:** Backblaze supports the S3 API for every bucket created
   since 2020, including multipart uploads for large files and Object Lock (B2 file lock)
   with the same headers. One tested client covers both, instead of a second implementation
   of the native B2 API (authorize, upload URLs, `b2_start_large_file`). Admins still enter
   B2 credentials directly; the endpoint `https://s3.<region>.backblazeb2.com` is derived
   from the region. Buckets from before 2020 without S3 support need a new bucket.

   Other services (Azure Blob, Google Drive, Dropbox): mount them with rclone (`rclone mount
   remote: /srv/backup`) or point an rclone `serve sftp` / `serve s3` / `serve webdav` at them
   and use the matching target. **Test** writes, reads and deletes a probe object and shows
   whether Object Lock is on.
3. Set the hour and the GFS counts (default 7 daily, 4 weekly, 12 monthly per target) and
   switch on the schedule.

The **3-2-1 rule** indicator turns green with two or more targets, one of them not local and
one with Object Lock: a compromised server or admin account can then not delete the last
copies.

## Schedule

The backup job runs on one instance (the leader, like retention and syslog):

| When | Reason in the history |
|---|---|
| daily at the set hour; a failed run is retried every hour until one succeeds | `schedule` |
| after every key rotation step (`keys.json` or the audit key files changed) | `key rotation` |
| **Back up now** in the console or `limdm-server backup create` | `manual` |
| before an upgrade (see below) | `upgrade` |

After every successful run, archives the GFS rule no longer keeps are deleted on each target
(also their personal data: retention in backups ends with the archive, GDPR Art. 17). An
archive still under Object Lock is kept and deleted at a later run.

Once a week the newest archive is downloaded from every target and compared with the
recorded SHA-256 (**Checksum verified**); **Verify** does it at once. This needs no private
key. Decryption and a full restore are checked by `restore-test` (below).

Every run, verification, deletion, restore test and restore is an audit entry (`backup.*`).
A failed run or a damaged archive sends the notification **Backup failed or stored backup
damaged** (`backup.failed`) to the subscribed channels. Metrics:
`limdm_backup_last_success_timestamp_seconds`, `limdm_backup_last_size_bytes`,
`limdm_backup_last_run_failed`, `limdm_backup_failures_total`
([operations.md](operations.md#prometheus-metrics)). Alert when the last success is older
than 26 hours.

### Before upgrades

Migrations cannot be undone. Back up with the old version before installing the new one:

```sh
sudo -u limdm limdm-server backup -env /etc/limdm-server/server.env create -reason upgrade
docker compose exec limdm limdm-server backup create -reason upgrade        # Docker
```

The deb and rpm packages do this themselves: their pre install script runs
`limdm-server backup create -reason upgrade -if-configured` with the installed version as
the `limdm` user when backups are configured, and stops the upgrade when it fails. Set
`LIMDM_SKIP_UPGRADE_BACKUP=1` in the environment of the package manager to skip it once.
With Docker, run the command above before pulling the new image.

## Command line

```
limdm-server backup [-env FILE] create [-reason TEXT] [-if-configured]
limdm-server backup [-env FILE] list [-from TARGET]
limdm-server backup [-env FILE] verify  -identity KEY [-from TARGET] [-command-key HEX] FILE
limdm-server backup [-env FILE] restore -identity KEY [-from TARGET] [-db URL] [-ca DIR] [-window 168h] [-replay FILE] [-force] FILE
limdm-server backup [-env FILE] restore-test -identity KEY [-from TARGET] [-db SCRATCH_URL] FILE
```

`FILE` is a local archive, or with `-from` the archive name on a configured target.

`verify` decrypts the archive, checks every entry against the manifest and the manifest
signature, and prints the signing command key. Pass the expected key with `-command-key`
(or run it on the server, which compares with its active key): age alone does not prove who
wrote an archive, the signature does.

## Restore

A restore runs on the command line, into an **empty** database and an empty CA directory
(`-force` overrides both checks). It refuses archives from a newer server version and, unless
forced, a `LIMDM_SESSION_KEY` other than the one the archive was made with.

1. Install the same or a newer server version. Keep the agent port closed (firewall) until
   step 6.
2. Set `LIMDM_SESSION_KEY` from the separate safe, `LIMDM_DATABASE_URL` to a new database.
3. `limdm-server backup verify -identity limdm-backup.agekey -command-key HEX FILE`
4. Export the audit entries written after the backup, if any copy survived: the syslog
   collector (`LIMDM_SYSLOG`) or a JSON Lines export.
5. `limdm-server backup restore -identity limdm-backup.agekey -replay audit-after.log FILE`
   loads the database in one transaction, writes the CA directory, opens the restored keys,
   records `backup.restore` and applies the revocations from the replay file (below).
   Uploaded packages land in `artifacts.restore` next to the CA directory; move them into
   `LIMDM_ARTIFACT_DIR`.
6. Start one instance, check `/readyz` and **Audit, Verify chain**, then open the agent
   port. Watch the 403 rate of the agent API (`limdm_http_requests_total{listener="agent"}`).
7. Note RTO and RPO for the restore record.

With PITR, restore PostgreSQL first with its own tools, then restore only the CA directory
from the archive matching that point (`tar` from `age -d`), or run `restore` into a scratch
database and copy `ca/` from there.

### What happens automatically, what by hand

| After the backup | After the restore |
|---|---|
| a device renewed its certificate | **automatic**: during the restore window (default 7 days, `-window`) a certificate the device CA issued after the backup is accepted once and pinned as the device's certificate (`device.cert_repin` audit entry). Retired and unknown devices stay out. After the window such devices must enroll again |
| a device enrolled | **by hand**: it is unknown to the restored database; enroll it again |
| a device was retired or deleted | **automatic with `-replay`**: retired again |
| an enrollment token or API token was revoked | **automatic with `-replay`**: revoked again |
| console users disabled or changed, roles, settings, key rotations, library and blueprint changes, approvals | **by hand**: `restore` prints every later audit entry it did not apply; review them in order |
| a key rotation step | restore the archive made **after** the rotation (a rotation triggers a backup); an older CA directory does not match newer device certificates |

`-replay` reads JSON Lines exports (**Audit**, export) and the RFC 5424 messages the server
sends to syslog. Only entries with an id above the archive's audit head are used. Without a
surviving copy nothing is replayed: retire devices that were lost in between by hand.

The restore window only widens which certificate of an **existing, active** device is
accepted; the chain to the device CA is checked as always, and a certificate issued before
the backup is never accepted this way.

## Restore test

```sh
sudo -u limdm limdm-server backup -env /etc/limdm-server/server.env restore-test -identity limdm-backup.agekey -from offsite ARCHIVE
```

restores the archive into a scratch database (`<database>_restore_test`, created and dropped
again; needs `CREATEDB`, or pass `-db` with an empty scratch database) and a temporary CA
directory, opens the restored keys, verifies the whole audit chain and opens a sealed value.
The result is an audit entry and appears as **Restore tested** in the history: the evidence for
ISO 27001 A.8.13 and BSI CON.3. Run it monthly (cron or a systemd timer on a host that holds
the age key only for that run), and a full restore on a separate host twice a year
([high-availability.md](high-availability.md#restore-test)).

## Docker

The compose example keeps the CA directory and local uploads in the `state` volume; both
are inside every archive. The image is read only, so archives are staged in `TMPDIR`, which
the compose file points at the state volume. A local target must be a mounted volume:

```yaml
  limdm:
    environment:
      TMPDIR: /var/lib/limdm-server
    volumes:
      - state:/var/lib/limdm-server
      - ./backups:/backups          # local target directory /backups
```

Create the host directory for the nonroot container user first: `mkdir backups && sudo
chown 65532 backups`. Copy it off the host, or prefer an S3, B2, SFTP or WebDAV target.

The image contains everything a backup needs (no `pg_dump`). Restore with
`docker compose run --rm limdm backup restore ...` against the new, empty database.
