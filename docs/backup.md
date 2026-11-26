# Backup and restore

LiMDM backs itself up: a scheduled job writes an encrypted, signed archive to one or more
storage targets on freely configurable schedules, keeps archives by a retention rule per
schedule, verifies them and reports failures. Restores
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

   S3, B2 and WebDAV requests follow no redirects. Through an outbound proxy from the
   environment (`HTTPS_PROXY`, `http` or `https` proxies) the server resolves the target
   itself and tunnels to that address; private networks are fine, loopback and link local
   addresses (cloud metadata) are refused.

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
3. Add one or more schedules (below), each with its targets and retention. Without a
   schedule, backups run only by hand, after key rotations and before upgrades.

The **3-2-1 rule** indicator turns green with two or more targets, one of them not local and
one with Object Lock: a compromised server or admin account can then not delete the last
copies.

## Schedules

**Settings, Backup, Schedules** creates, edits, pauses, resumes, runs and deletes schedules
(every change is a `backup.settings` audit entry). Each schedule has a name, its own targets
and its own retention, and one of four kinds:

| Kind | Settings | Example |
|---|---|---|
| Every N hours | 1 to 168 hours, offset in minutes after midnight | every 6 hours at 00:30, 06:30, 12:30, 18:30 |
| Weekdays at times | weekdays and one or more times of day (HH:MM) | Monday to Friday at 02:00 and 14:00 |
| Monthly on a day | day 1 to 31 (the last day in shorter months) and times | the 31st at 03:00 runs on 28 or 29 February |
| Cron expression | five fields: minute, hour, day of month, month, day of week | `30 1 * * 1-5` |

The cron syntax is strict: numbers with `*`, lists (`0,30`), ranges (`1-5`) and steps (`*/15`,
`8-18/2`); day of week 0 to 7 (0 and 7 are Sunday). Names, `@daily` style shortcuts and
second fields are refused instead of guessed. With both day fields restricted, a day matches
when either does (as in cron). The console lists the next five runs of every schedule.

**Time zone.** All schedules use one time zone, an IANA name such as `Europe/Berlin` (default:
the server's). The image carries its own time zone data. Schedules are computed per local
date: every date and time of day maps to exactly one instant, so the change to and from
daylight saving time never runs a slot twice and never skips a day. A time in the spring
forward gap (02:30 on the last Sunday of March in Europe) runs once, an hour later; a time in
the repeated hour in autumn runs once. Intervals that divide a day (1, 2, 3, 4, 6, 8, 12, 24
hours) run at the same local times every day; other intervals (5, 7, 36, 168 hours ...) count
absolute hours from midnight UTC plus the offset, so their local times drift by an hour at
DST changes.

**Missed runs and retries.** A run that was due while the server was down runs once when the
job starts again, not once per missed slot. A failed run is retried after an hour until one
succeeds or the next slot comes. Paused schedules do not catch up when resumed.

Besides the schedules:

| When | Targets | Reason in the history |
|---|---|---|
| a schedule's slot | the schedule's targets | `schedule NAME` |
| **Run now** of a schedule | the schedule's targets | `manual, schedule NAME` |
| after every key rotation step (`keys.json` or the audit key files changed) | all targets | `key rotation` |
| **Back up now** or `limdm-server backup create` | all targets | `manual` |
| before an upgrade (see below) | all targets | `upgrade` |

Archives carry the schedule in their name (`limdm-HOST-20261126T020000Z-nightly.lbk`);
runs outside a schedule have none.

## Retention of archives

After every successful run each target is pruned: archives of a schedule by that schedule's
rule, archives outside a schedule (and of a deleted schedule) by the general rule set next to
the recipients. Only this server's archives (named after `LIMDM_PUBLIC_URL`) are pruned;
archives of another server sharing the target are left to that server. A rule combines:

| Part | Keeps |
|---|---|
| Keep last | the newest N archives |
| Keep for days | every archive younger than D days |
| Daily, Weekly, Monthly, Yearly | the newest archive of each of the last N days, ISO weeks, months, years that have one (GFS) |

An archive stays when **any** part keeps it, so whichever part keeps more wins; the newest
archive always stays. Days, weeks, months and years are counted in the schedule time zone.
The default for archives outside a schedule is keep last 3, 7 daily, 4 weekly, 12 monthly. The
schedule list shows a preview: how many archives of a simulated year of runs the rule keeps,
and which ones. Deleting expired archives also deletes their personal data (retention in
backups ends with the archive, GDPR Art. 17). An archive still under Object Lock is kept and
deleted at a later run.

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

## What is set where

Everything about backups, data retention and the package repository is managed in the
console (**Settings, Backup**, **Settings, Data retention**, **Software, Packages**), except:

| Setting | Where | Why not in the console |
|---|---|---|
| `LIMDM_SESSION_KEY` | environment | bootstrap secret; it opens the sealed values the console itself needs |
| age private key | offline, `-identity` of the CLI | must never reach the server |
| restore, restore test, verify with decryption | `limdm-server backup` CLI | need the age private key; a restore runs while no console exists |
| restore window | `restore -window` | belongs to the restore, which runs on the command line |
| `-replay` file | `restore -replay` | the audit copy is read on the restore host |
| scheduling `restore-test` | cron or a systemd timer on a host with the age key | the server never holds the key |
| `LIMDM_ARTIFACT_DIR` | environment | a server file system path; letting the console choose paths for server writes would let an admin account write anywhere the service user may |
| `TMPDIR` | environment | where the process stages files; a property of the host or container |
| `LIMDM_SKIP_UPGRADE_BACKUP` | environment of apt or dnf | read by the package script, before the new server exists |

## Command line

```
limdm-server backup [-env FILE] create [-reason TEXT] [-if-configured]
limdm-server backup [-env FILE] list [-from TARGET]
limdm-server backup [-env FILE] verify  -identity KEY [-from TARGET] [-command-key HEX] FILE
limdm-server backup [-env FILE] restore -identity KEY [-from TARGET] [-command-key HEX] [-db URL] [-ca DIR] [-window 168h] [-replay FILE] [-force] FILE
limdm-server backup [-env FILE] restore-test -identity KEY [-from TARGET] [-command-key HEX] [-db SCRATCH_URL] FILE
```

`FILE` is a local archive, or with `-from` the archive name on a configured target.

`verify` decrypts the archive, checks every entry against the manifest and the manifest
signature, and prints the signing command key. Pass the expected key with `-command-key`
(or run it on the server, which compares with its active key): age alone does not prove who
wrote an archive, the signature does. `restore` and `restore-test` refuse an archive whose
signer is neither `-command-key` nor the active command key of the server they run on.

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
5. `limdm-server backup restore -identity limdm-backup.agekey -command-key HEX -replay audit-after.log FILE`
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
| a device renewed its certificate | **automatic**: during the restore window (default 7 days, `-window`) a certificate the device CA issued after the backup that is valid longer than the pinned one is accepted and pinned as the device's certificate (an older certificate of the device cannot take the pin back) (`device.cert_repin` audit entry). Retired and unknown devices stay out. After the window such devices must enroll again |
| a device enrolled | **by hand**: it is unknown to the restored database; enroll it again |
| a device was retired or deleted | **automatic with `-replay`**: retired again |
| an enrollment token or API token was revoked | **automatic with `-replay`**: revoked again |
| console users disabled or changed, roles, settings, key rotations, library and blueprint changes, approvals | **by hand**: `restore` prints every later audit entry it did not apply; review them in order |
| a key rotation step | restore the archive made **after** the rotation (a rotation triggers a backup); an older CA directory does not match newer device certificates |

`-replay` reads JSON Lines exports (**Audit**, export) and the RFC 5424 messages the server
sends to syslog. Only entries with an id above the archive's audit head are used. Syslog
messages carry no signature: replay only a copy you trust (a collector that accepts the
server alone), since a forged line can retire devices. Without a
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
