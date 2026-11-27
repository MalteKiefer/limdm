# Log management

LiMDM collects the logs of managed devices without extra software on them: the agent
reads the systemd journal, Docker and Podman container logs and plain log files, and
ships them over its mTLS connection. The server keeps a searchable window (7 days by
default) in PostgreSQL and can archive every day, encrypted, to an S3 compatible bucket
or Backblaze B2. The console has a **Logs** page for the whole fleet and a **Logs** tab
on every device page.

Collection is off until a [`com.limdm.logging`](declarations.md#comlimdmlogging) item
enables it for a blueprint.

## Data flow

```
journald ─┐
docker ───┼─ agent: filter, mask, rate limit ─ spool on disk ─ POST /api/v1/logs (mTLS, gzip)
files ────┘                                                      │
                                       server: quotas, dedup ─ device_logs (one partition per day)
                                                                 │
                          console search, histogram, export, alerts      daily archive ─ S3 / B2
```

1. Every 30 seconds the agent reads what is new in each enabled source, drops what the
   filters exclude, masks secrets, applies the rate limit and appends the lines to a
   spool under `/var/lib/limdm/logs` (mode 0700).
2. The spool is shipped segment by segment (at most 1000 lines or 256 KiB each). A segment
   is removed once the server answered; a batch lost on the way is sent again.
3. The server stores each line once: the key is device, source and the cursor the agent
   sends (journal cursor, container and time, file inode and offset). A batch sent twice
   is stored once (at least once delivery, no duplicates).

## Collection on the device

| Source | How | Cursor |
|---|---|---|
| journal | `journalctl -o json --after-cursor=...` with the units and minimum priority of the item | journal cursor |
| containers | `docker` or `podman` `ps` and `container inspect` to pick the containers, then `logs --timestamps --since` per container | time of the last line per container |
| files | read from the stored offset; complete lines only | inode and offset |

* Collection starts at the end of each source when it is first seen: the agent does not
  ship history from before the item was assigned (nor of a new container or file).
* File rotation: when the inode changes, the rest of the old file is read from
  `<path>.1` when it was renamed there, then the new file from its start. A file that
  got shorter (`copytruncate`) is read from the start again.
* Priorities: journal lines keep theirs. Container standard output is `info`, standard
  error `notice`; container and file lines that name `panic`, `fatal`, `crit`, `error`
  or `warn` early in the text get the matching higher priority.
* LiMDM's own lines (`limdm-*` units, `/var/log/limdm*`) are never shipped, so shipping
  cannot feed itself. Shipping errors are logged once after three failures in a row.
* The agent never restarts or reconfigures journald, Docker or Podman. Each read is
  bounded in time (30 s) and output, so a busy production host (Docker, Postfix) only sees
  a few short tool calls every 30 seconds.

### File sources

The agent reads files as root, so a file source is held to these rules (on the server when
the item is saved, and on the device before every read):

* Only below `/var/log/`, `/srv/<name>/log/` or a custom root of the item (`roots`), clean
  absolute paths without wildcards. Secret locations are refused anywhere (`/etc/shadow`,
  `/etc/gshadow`, `/etc/ssh/`, `/root/`, `/home/*/.ssh`, `/etc/ssl/private/`,
  `/var/lib/limdm/`, `/etc/limdm/`, `/proc`, `/sys`, `/dev`, `/run`, `/boot`).
* Custom roots (`roots`) are for applications that log elsewhere, for example
  `/opt/app/logs`. A root must be a clean absolute directory at least two levels deep: `/`
  and bare top level directories (`/etc`, `/home`, `/usr`, `/var`, `/opt` ...) are refused,
  so are roots in a secret location. A root must contain a path component `log` or `logs` (or one ending in `-log`, `_log`, `-logs`, `_logs`), for example `/opt/app/logs` or `/data/nginx-log`; wide roots such as `/var/lib` or `/var/backups` never pass. Name only directories that hold nothing but logs: the
  agent reads every declared file below them as root and ships it. Because a root widens
  what the agent reads, saving an item with `roots` needs four eyes approval when it is on,
  and the audit entry lists the roots. The server checks the rules when the item is saved,
  the agent again before every read.
* Symbolic links of the directories are resolved and the real path must still be in an
  allowed root; the file itself is opened with `O_NOFOLLOW` (a link as the file is refused,
  also one pointing inside the root), and the opened file must be the file the real path
  names (same device and inode), so it cannot be swapped between the checks and the read.
* Neither the file nor its directory may be writable by group or others unless root owns
  it (`/var/log` owned by root with group write, as on Ubuntu, is fine). A log directory of
  a service user that others can write to is refused: make it `0755` or move the log.
* A refused file is skipped silently on the device (no lines, no error loop); check the
  path and the modes when a file source stays empty.

### Filters, masking and limits

* `include` and `exclude` are regular expressions on the message.
* Masking runs on the device before a line is stored in the spool. The built in rules
  replace passwords, tokens and keys in `key=value` and `key: value` form, the value of
  `Authorization` headers, PEM private keys, JWTs, AWS access key IDs and credentials in
  URLs with `***`; `mask` adds own expressions. Masking cannot know every format: check a
  sample of the shipped lines before rolling a source out widely.
* `lines_per_second` (default 20, bursts of ten seconds) and `mb_per_day` (default 100)
  bound what one device sends; lines over the limits are dropped and counted.
* `buffer_mb` (default 32) bounds the spool while the server is not reachable. When it is
  full the oldest segment is removed and its lines are counted as dropped. Dropped lines
  are reported with the next batch and shown per day in **Settings, Logs**.

### Personal devices

A device is personal when it has the tag `personal` or the custom attribute
`ownership=personal`. On personal devices the server switches every logging item off
unless the item sets `allow_personal`. Use that only with the consent the applicable law
and works agreements require.

## Transport

`POST /api/v1/logs` on the agent listener, authenticated with the device certificate like
every agent request. The body is `{"lines": [...], "dropped": n}`, gzip encoded, at most
4 MiB decompressed and 2000 lines; a message is cut at 8 KiB.

Backpressure: the server answers `429` with `Retry-After` when a device sends more than 30
batches a minute or a device or tenant reached its daily quota (until midnight UTC), and
`503` while the disk guard refuses new lines. The agent waits as told and keeps its spool.

## Storage on the server

`device_logs` holds time, device, tenant, source (`journald`, `container`, `file`), unit
(unit, container name or file path), priority 0 to 7, host, message and the extra fields
as JSONB. It is partitioned by day (`device_logs_YYYYMMDD`, UTC). Indexes: tenant and time,
device and time, tenant, unit and time, and a trigram index on the message (`pg_trgm`)
for text and regular expression search. Without the `pg_trgm` extension (it is a trusted
extension, the database owner can create it) the schema leaves the trigram index out and
text search scans the time range.

The logs job runs on one server instance:

* creates the partitions of the retention window and two days ahead,
* archives finished days when archiving is on ([Archive](#archive)),
* drops the partitions older than the retention (dropping a partition is cheap and leaves
  no bloat). With archiving on, a day is only dropped when every tenant of that day has
  a verified archive with the same number of lines; otherwise it stays and a notification
  (`logs.guard`) says why,
* evaluates the alert rules every minute.

### Retention, quotas and disk guard (Settings, Logs)

| Setting | Default | |
|---|---|---|
| Days on the server | 7 | 1 to 90 |
| Maximum store size | none | GB of all log partitions with indexes; above it new lines are refused |
| Minimum free disk | none | percent free on the database disk; checked where the server can read the database's data directory (same host and a role allowed to read `data_directory`) |
| MB per device and day | 200 | server side quota on top of the agent's own limit |
| MB per tenant and day | none | with overrides per tenant |
| Helpdesk reads device logs | off | see [Access](#access) |

When the disk guard trips the server answers `503` to new batches, the devices keep their
lines in their spool, and a `logs.guard` notification goes out.

## Search

**Logs** searches every device of the caller's tenant and scope; the device page's **Logs**
tab searches one device. Filters: time range (quick ranges or absolute), source, minimum
priority, device, and the query language:

```
device:mail unit:postfix* prio<=err "connection refused" -healthcheck /timeout after \d+/
```

| Term | Matches |
|---|---|
| `word`, `"a phrase"` | the message contains it (case insensitive) |
| `/regex/` | the message matches the regular expression (case insensitive, at most 200 characters) |
| `device:NAME` | device ID, host name, or the short name of an FQDN; `*` as wildcard |
| `tag:`, `blueprint:`, `os:` | devices with that tag, blueprint or OS ID (`debian`, `fedora` ...) |
| `source:` | `journald`, `container` (also `docker`, `podman`) or `file` |
| `unit:`, `container:`, `file:` | unit, container name or file path, `*` as wildcard |
| `host:` | the host name the journal recorded |
| `prio:err`, `prio<=warning`, `prio>3` | priority by name or number (0 emerg to 7 debug); `prio<=err` is err and more severe |
| `field.NAME:value` | an extra field, e.g. `field._PID:1234` or `field.compose_project:paperless` |
| `-term` | negation |

Search times measured with 5,000,000 lines of 2000 devices over seven days (PostgreSQL 19 on
a laptop, through the API): newest 200 lines 45 ms, a phrase over 24 hours 76 ms and over 7 days
236 ms, a rare word over 7 days 32 ms, unit and priority 46 ms, a regular expression over 24
hours 150 ms, one device over 7 days 2 ms, histogram of 24 hours 118 ms, histogram of a phrase
over 7 days 404 ms. Reproduce with `LIMDM_TEST_LOG_LINES=1 go test -run TestLogSearchVolume -v
./internal/server` on a test database.

Every search runs read only under a statement timeout of 20 seconds; a search that takes
longer asks for a narrower range or filter. The page shows a histogram of lines per time
bucket and priority (click a bar to zoom), the result list with virtual scrolling, the
lines before and after a line on the same device (context), a live tail that polls with
backoff and can be paused, saved views, a link to the current filter, and an export.

Export: the current filter as NDJSON or CSV, at most 100,000 lines, newest first. Every
export is audited (`logs.export`) with the filter.

### Alert rules

An alert rule is a query, a threshold and a window: when at least *threshold* lines
matched in the last *window* minutes, a `logs.alert` notification goes to the channels
that subscribed to it (Settings, Notifications), at most once per window. **Test** counts
now and sends a test notification. Rules belong to the tenant that created them and count
only the devices of the account that saved it (its tenant and device scope, stored with the
rule); only a rule saved by an unscoped global administrator counts the whole installation.
**Test** counts with the scope of whoever clicks it. Notifications name the rule, the query
and the count, never the text of the lines.

### Access

| Role | Reads |
|---|---|
| admin, auditor | every device of their tenant and scope, and the settings and archive state |
| helpdesk | one device at a time (the device tab), only when **Helpdesk reads device logs** is on, only devices of its scope |

API tokens follow the same rules by role and scope. Only global administrators change the
settings, rotate the keys and start archive runs or restores; all of it is audited.

## Archive

With **Archive** on, each finished day (older than yesterday, so late lines of devices that
were offline are included) is exported to a storage target of **Settings, Backup** (S3
compatible including AWS, Hetzner and MinIO, Backblaze B2, also WebDAV, SFTP or a local
directory). Credentials are the target's, sealed like the backup target secrets; S3 and
B2 are always reached over TLS.

Layout under the target's prefix:

```
logs/t<tenant>/<device>/<YYYY-MM-DD>.ndjson.gz.enc
logs/t<tenant>/manifests/<YYYY-MM-DD>.json
```

* Objects: one per tenant, device and day, gzip compressed NDJSON (one line per log line
  with time, device, source, unit, priority, host, message, fields and the dedup key),
  encrypted before upload.
* Manifest per tenant and day: the key ID, and every object with its line count, size and
  SHA-256. The manifest's own SHA-256 is kept in the database.
* Verify: every object and the manifest is read back after the upload and its SHA-256
  compared. Only then the day counts as archived; a partition is never dropped before.
* A day that received lines after it was archived (a device came back online) is archived
  again before its partition is dropped.
* Archive retention: archived days older than **Keep archives (days)** are deleted from
  the target (0 keeps them). With S3 Object Lock or a B2 file lock on the target the
  provider refuses early deletes; such days stay listed until the lock ends.

### Encryption

* Format `LIMDMLG2`: a header with the key ID, a random 32 byte salt and the object name
  (`logs/t<tenant>/<device>/<day>...`), then chunks of 64 KiB sealed with AES-256-GCM.
  Every object has its own key, HKDF-SHA256 of the tenant's data key and the salt, so the
  chunk number is a unique nonce under that key and no nonce repeats across objects. The
  additional data binds the header (tenant, device and day) and marks the last chunk, so
  changed, reordered, removed or appended chunks and objects moved to another name fail to
  open. Objects of the first format `LIMDMLG1` (0.21.0: one random 4 byte nonce prefix per
  object under the data key) stay readable; new archives are always written as version 2.
* Each tenant has its own random 256 bit data key, stored in the database with its ID
  (`lk-<tenant>-<random>`), wrapped (AES-256-GCM) with a key encryption key of the server
  key management: the key kind `logs` ([keys.md](keys.md#log-archive-key)), an Ed25519 key
  in the CA directory or in the HSM (PKCS#11), the same root as the CA and command keys.
  It is independent of `LIMDM_SESSION_KEY`: a session key rotation or a leaked session key
  does not touch the archive. The key encryption key ID is stored with every data key.
* Data keys are not in the bucket: whoever holds the bucket alone cannot read the logs.
* Rotation of data keys: **Rotate keys** (Settings, Logs) gives every tenant a new active
  data key; older archives keep naming their key and stay readable.
* Rotation of the key encryption key: **Settings, Keys**, `logs` (or `limdm-server keys
  rotate logs`). After the restart every data key is wrapped again with the new key; then
  `finish` removes the old one. Archived days stay readable throughout.
* Decrypting an archive needs the database (or its backup, for the data keys) and the CA
  directory or HSM (for the key encryption key).

### Restore

Console: **Settings, Logs, Archive**, **Restore** on a day. The objects are downloaded,
checked against the manifest, decrypted and loaded into the day's partition. The day is
searchable on the Logs page for **Keep restored days (hours)** (default 24), then dropped
again. Every restore is audited (`logs.restore`).

Command line, for example when the console is not available:

```sh
limdm-server logs -env /etc/limdm-server/server.env status                    # archived days
limdm-server logs -env /etc/limdm-server/server.env archive                   # archive finished days now
limdm-server logs -env /etc/limdm-server/server.env restore -day 2026-11-20   # all tenants of a day
limdm-server logs -env /etc/limdm-server/server.env restore -day 2026-11-20 -tenant 2
```

## Privacy

Logs contain personal data (user names, addresses, mail addresses in Postfix lines).

* Off by default; enable it per blueprint and only for the sources you need.
* Masking and filters run on the device, before anything leaves it.
* Personal devices are refused unless the item allows them.
* Short retention on the server (7 days by default); archives are encrypted per tenant and
  deleted after their retention.
* Access is limited to admins and auditors, the helpdesk only per device when allowed;
  exports and restores are audited.
