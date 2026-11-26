# High availability

LiMDM runs as several identical server instances behind a load balancer, all connected to
one PostgreSQL database. Any instance answers any request; no sticky sessions are needed.
PostgreSQL itself is made highly available with the usual tools (see
[PostgreSQL](#postgresql)).

```
                 console (HTTPS, L7)            agents (TCP 8444, passthrough)
                         │                                  │
                ┌────────┴──────── load balancer ───────────┴────────┐
                │                                                    │
        ┌───────┴───────┐        ┌───────────────┐         ┌─────────┴─────┐
        │ limdm-server 1│        │ limdm-server 2│   ...   │ limdm-server n│
        └───────┬───────┘        └───────┬───────┘         └───────┬───────┘
                └──────────── PostgreSQL primary (+ standby) ──────┘
                       shared CA directory (read mostly)
```

## Requirements

* Every instance runs the same version (except during a [rolling upgrade](#upgrades)) with
  the same environment: `LIMDM_DATABASE_URL`, `LIMDM_SESSION_KEY`, `LIMDM_PUBLIC_URL`,
  `LIMDM_AGENT_URL`, OIDC and syslog settings. Different session keys make sessions and
  sealed secrets unreadable on the other instances.
* **The same CA directory** (`LIMDM_CA_DIR`) on every instance. It holds the device CA, the
  network CA, the command key (command and item signatures, audit chain key), `keys.json`
  (active and retiring key names), `audit-keys` (audit key segments of earlier command
  keys) and the `audit-keyed-from` switch point. Two ways, both supported:
  * a shared volume (NFS, CephFS, a cluster file system), mounted on every instance with
    mode 0700 for the `limdm` user; the files are written at the first start and by key
    rotations, and only read otherwise, or
  * start the first instance once, then copy the directory (`rsync -a`, encrypted channel)
    to the others before starting them.

  The first instance records the fingerprints of both CAs and the command key in the
  database. An instance with different key material refuses to start ("differs from the
  one the other server instances use"), and so does an instance whose directory lacks
  `audit-keyed-from` after the audit chain switched to keyed hashes. Concurrent first
  starts are serialized by an advisory lock, so only one instance creates keys.
  A key rotation ([keys.md](keys.md)) updates the recorded fingerprints at `rotate` and
  `finish`: during the overlap an instance with the old or the new directory starts; after
  `finish` only the updated directory does, so copy it to every instance before restarting.
* `LIMDM_RELEASE_DIR` stays local: every instance downloads and verifies the agent packages
  of the five newest releases itself and serves them from its own directory. For older
  versions still pinned to devices, copy the directory from an existing instance.
* The console port of each instance has TLS (`LIMDM_TLS_CERT`) or a local reverse proxy;
  without a certificate the console listens on loopback only.

## What the instances share

| State | How |
|---|---|
| Devices, configuration, audit log, approvals, exceptions, sessions of local accounts, lockout counters | PostgreSQL |
| Console sessions, OIDC state, nonce and PKCE verifier | sealed cookies (`LIMDM_SESSION_KEY`), valid on every instance |
| Desktop login (device code flow) | runs between the device and the identity provider; the server only hands out the configuration |
| Console settings | stored in PostgreSQL; a trigger sends `NOTIFY limdm_settings`, every instance reloads within milliseconds. Saves are serialized across instances (advisory lock) and load a newer change first, so two admins saving on different instances do not undo each other |
| Audit chain | appends take the advisory lock 7363, so ids and hashes stay in order with any number of instances. A check in appends its entries (command results, tamper events, escrow, compliance actions) at its commit, so the lock is held for the append only and check ins of different devices run in parallel; no transaction takes a second pool connection while it holds the lock |
| Result of the last full audit verification | PostgreSQL (`settings` key `audit_verification`), shown on the audit page and in `/metrics` of every instance |
| SCIM read, modify and write | advisory lock across instances |
| Remote shell | relayed between instances, see [below](#remote-shell) |
| Background jobs | leader election per job, see [below](#background-jobs) |
| Rate limits (sign in, enrollment, API tokens, SCIM, CRL, device endpoints), the cap on audited OIDC failures | **per instance**, in memory. With n instances an address gets up to n times the budget. Accepted: the lockout of local accounts (5 failures, 15 minutes) is stored in the database and counts across instances, API and SCIM tokens are 256 bit random values. Counters expire an hour after their last hit; beyond 200,000 throughput keys (devices, tokens) the least recently used are dropped, failure counters (sign in, enrollment, token, SCIM, CRL) never before their window ends |
| Fleet overview cache, Flathub search cache, agent rollout (policy and approved releases for polls) | per instance, one minute, one hour and 30 seconds |
| `/metrics` request counters | per instance; scrape every instance (`limdm_http_requests_total`), the fleet gauges are the same on all |

## Load balancer

* **Console (HTTPS):** layer 7 is fine. It must pass WebSocket upgrades (`/shell/*/ws`) and
  set `X-Forwarded-For`. List the load balancer addresses in `LIMDM_TRUSTED_PROXIES`
  (comma separated addresses or networks); only then does the server take the client
  address from the header (rate limits, console network lists, audit). Without it every
  request seems to come from the load balancer. A proxy on loopback is always trusted.
* **Agent API (8444):** TCP passthrough only. Mutual TLS ends at the instance, which needs
  the device certificate; a load balancer that terminates TLS breaks every device. The
  agent certificate of the server is issued by the device CA for the host of
  `LIMDM_AGENT_URL` and `LIMDM_AGENT_HOSTS`, the same on every instance.
* **Health checks:** `GET /readyz` on the console port. Route traffic for both ports by the
  console port's readiness (HAProxy `check port`, a shared health check in cloud load
  balancers).
* **Client addresses on 8444:** with plain TCP passthrough the instance sees the load
  balancer's address: the device's public address and location and the enrollment failure
  limit then see the balancer. Enable PROXY protocol version 2 on the balancer (HAProxy
  `send-proxy-v2`, AWS NLB proxy protocol v2, nginx stream `proxy_protocol on`) and list its
  addresses under **Settings, Operations, PROXY protocol sources** (`LIMDM_AGENT_PROXY_PROTOCOL`
  is the initial value): connections from those addresses must start
  with the header, connections from anywhere else must not and keep their own address.
  Alternatively use a balancer that keeps the client address (HAProxy `usesrc clientip`,
  LVS direct routing). Enrollment failures are limited per address and token (20 tries of
  one wrong token in five minutes) and per address (200 failures), per instance, so a few
  wrong tokens behind one balancer do not block other enrollments.

### Health endpoints

| Path | Meaning | Answer |
|---|---|---|
| `/healthz` | liveness: the process serves requests; no database check, so a database outage does not restart every instance | `200 ok` |
| `/readyz` | readiness: database reachable, it holds the schema of this version, keys loaded, the audit key is current (not outdated by a command key rotation), notifications from other instances arrive, not shutting down | `200 ready` or `503` with the reasons |

Both are reachable without sign in and regardless of the console network lists.

### Caddy

Caddy as layer 7 load balancer for the console and layer 4 for the agent port (the
`layer4` app needs a Caddy build with [caddy-l4](https://github.com/mholt/caddy-l4)).
Its TCP proxy cannot check `/readyz` on the console port, so a draining instance still
gets new device connections; HAProxy handles 8444 better.

```
{
	layer4 {
		:8444 {
			route {
				proxy 10.0.1.11:8444 10.0.1.12:8444
			}
		}
	}
}

mdm.example.com {
	reverse_proxy https://10.0.1.11:8443 https://10.0.1.12:8443 {
		lb_policy least_conn
		health_uri /readyz
		health_interval 5s
		transport http {
			tls_server_name mdm.example.com
		}
	}
}
```

Instances: `LIMDM_LISTEN=:8443`, `LIMDM_TLS_CERT`/`LIMDM_TLS_KEY` (a certificate for
`mdm.example.com`, or an internal one with `tls_trust_pool`), `LIMDM_TRUSTED_PROXIES=<Caddy
address>`. Caddy forwards WebSockets and sets `X-Forwarded-For` by default.

### nginx

```nginx
stream {
    upstream limdm_agent {
        server 10.0.1.11:8444 max_fails=2 fail_timeout=10s;
        server 10.0.1.12:8444 max_fails=2 fail_timeout=10s;
    }
    server {
        listen 8444;
        proxy_pass limdm_agent;       # TCP passthrough, no ssl here
        proxy_timeout 1h;             # remote shell streams
    }
}

http {
    upstream limdm_console {
        least_conn;
        server 10.0.1.11:8443 max_fails=2 fail_timeout=10s;
        server 10.0.1.12:8443 max_fails=2 fail_timeout=10s;
    }
    map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    server {
        listen 443 ssl;
        server_name mdm.example.com;
        ssl_certificate     /etc/ssl/mdm.example.com.pem;
        ssl_certificate_key /etc/ssl/mdm.example.com.key;
        client_max_body_size 2m;
        location / {
            proxy_pass https://limdm_console;
            proxy_ssl_server_name on;
            proxy_ssl_name mdm.example.com;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 1h;
        }
    }
}
```

Open source nginx has no active health checks; it takes an instance out after failed
requests (`max_fails`). Instances drain for `LIMDM_DRAIN_SECONDS` before closing, so set it
higher than `fail_timeout`, or use nginx Plus `health_check uri=/readyz`.

### HAProxy

```
frontend console
    mode http
    bind :443 ssl crt /etc/haproxy/mdm.example.com.pem
    option forwardfor
    timeout client 1h                 # WebSockets of the remote shell
    default_backend limdm_console

backend limdm_console
    mode http
    balance leastconn
    timeout server 1h
    option httpchk GET /readyz
    http-check expect status 200
    server s1 10.0.1.11:8443 ssl verify required ca-file /etc/haproxy/ca.pem sni str(mdm.example.com) check inter 3s
    server s2 10.0.1.12:8443 ssl verify required ca-file /etc/haproxy/ca.pem sni str(mdm.example.com) check inter 3s

frontend agent
    mode tcp
    bind :8444
    timeout client 1h
    default_backend limdm_agent

backend limdm_agent
    mode tcp                          # TLS passthrough: mTLS ends at the instance
    balance leastconn
    timeout server 1h
    option httpchk GET /readyz        # health of the instance, via the console port
    http-check expect status 200
    server s1 10.0.1.11:8444 check port 8443 check-ssl verify none inter 3s
    server s2 10.0.1.12:8444 check port 8443 check-ssl verify none inter 3s
```

`verify none` on the health check only: the check reaches the console port by address. Add
`source 0.0.0.0 usesrc clientip` (transparent proxy, needs routing back through HAProxy) to
keep device addresses on 8444.

## Background jobs

Each periodic job runs on exactly one instance, the holder of its PostgreSQL advisory lock:
directory sync, history (fleet snapshot, full audit verification, audit and data retention,
expiry of approvals), catalog icons, syslog forwarding and sealing values again after a
session key rotation. The other instances try to take
over every 15 seconds. The leader checks its lock connection every 15 seconds; if it breaks
(database failover, network), the job stops before another instance can start it.
Notifications from these jobs (`audit.broken`) are therefore sent once. Notifications caused
by a request or a device check in are sent by the instance that handled it, also once.

Syslog forwarding stores its position in the table `syslog_cursor`. A new leader continues
after the last entry the previous one sent: no gaps, at most the last batch twice after a
crash. Device events that commit out of id order can still be skipped, as before.

Agent package downloads run on every instance (see `LIMDM_RELEASE_DIR` above), and so does
the retry of an OIDC discovery that failed at startup. Which instance leads which job is
logged ("leading background loop").

## Remote shell

A session lives on the instance where the console user started it: watcher, timeouts and
transcript. The device (`POST /api/v1/shell/<id>`) and the console WebSocket may reach any
instance. An instance that does not hold the session finds its home instance in the table
`shell_sessions` (column `instance`, liveness in `server_instances`) and relays the stream
over PostgreSQL `NOTIFY limdm_shell`: output and input in chunks of 4 KiB, each direction
sent in order. No connection between the instances is needed, so there are no further
ports, certificates or trust relationships; the database connection (TLS,
`sslmode=verify-full` for remote hosts) carries the relay.

* Keystrokes and output pass through PostgreSQL's notification queue (memory, spilled to
  `pg_notify` files under load), not tables or the WAL. Transcripts are stored as before.
* A relay that falls behind by more than 1024 messages (4 MiB) ends the session with "the
  relay between server instances fell behind".
* When the home instance stops, relayed legs notice within 15 seconds. A clean stop ends
  the session and stores the transcript; after a crash the session shows as
  `interrupted`.

## Shutdown and leader handover

On SIGTERM an instance:

1. stops its background jobs at once and releases their locks; another instance takes
   over within 15 seconds,
2. answers `/readyz` with 503 for `LIMDM_DRAIN_SECONDS` (default 5), so the load balancer
   stops sending new requests,
3. ends the remote shells it holds or relays and stores them,
4. closes the listeners and waits up to 15 seconds for running requests,
5. removes itself from `server_instances`.

Set `LIMDM_DRAIN_SECONDS` to at least the load balancer's health check interval times its
fall count, and systemd `TimeoutStopSec` (default 90 s) above `LIMDM_DRAIN_SECONDS` plus 30.

## Upgrades

Schema changes apply at start inside one transaction under an advisory lock: instances that
start at the same time wait for each other, the first applies the schema, the others find
it current. The schema is applied only when it changed: each applied version is recorded by
its hash (`schema_applied`), and an instance whose schema is recorded already starts without
taking the advisory lock or any table lock. A rolling restart of the same version therefore
never queues ACCESS EXCLUSIVE lock requests in front of the running instances; only the first
instance of a new version takes them (bounded by a 30 s lock wait). Startup work on key material (signing existing items, sealing secrets) is
serialized the same way.

**Rolling upgrade** (default for releases whose notes do not say otherwise):

1. Back up the database ([operations.md](operations.md#backup)).
2. Stop one instance (SIGTERM, it drains), upgrade the package or image, start it.
3. Wait for `/readyz` 200 on it, then continue with the next instance.

The schema is additive within a release line, so older instances keep working while newer
ones run. `server_instances.version` shows which version each instance runs:
`SELECT id, version, seen_at FROM server_instances`.

**Full stop** is required when the release notes say so, at least for:

* **0.15 to 0.16:** the audit chain switches to keyed hashes (HMAC) at the first start of
  0.16. A 0.15 instance still running afterwards would append plain hashes behind the
  switch point and break the chain. Stop all instances, start one 0.16 instance, wait for
  `/readyz`, then distribute the CA directory (it now contains `audit-keyed-from`) and
  start the others. The other changes of this upgrade:
  [operations.md](operations.md#upgrading-from-015-to-016).
* **0.16 to 0.17:** 0.16 instances write device packages into `devices.packages`, which
  0.17 moved into `device_packages` (devices whose package list does not change are not
  sent again), and save device users and enroll devices without the user list signature
  (agents then get no user list until it is saved again). The first 0.17 start also
  partitions `device_metrics` and moves the package lists while it holds the schema
  locks. Stop all instances, start one 0.17 instance, wait for `/readyz`, then start the
  others.
* changes of `LIMDM_SESSION_KEY` (sealed secrets would be unreadable on the other
  instances) and key rotations of the CA directory.

## PostgreSQL

All instances connect to the primary. Requirements of LiMDM:

* `LISTEN/NOTIFY` and session advisory locks: connect directly or through a pooler in
  **session** mode. PgBouncer transaction or statement pooling breaks both (the
  notification listener, leader election of background jobs, session settings of the
  index build), so it is not supported.
* Connections: each instance opens up to `LIMDM_DB_MAX_CONNS` (default 32) plus one for
  notifications and, at a schema change, one for the migration. Keep the sum over all
  instances below `max_connections` (default 100) minus what backups and monitoring use,
  for example 3 instances with 24 each for 100. Transactions never wait for a second
  connection of the same pool, so a small pool slows requests down but cannot lock up.
  For many instances put PgBouncer in **session** mode in front and size
  `default_pool_size` like the sum above.
* Writes only: standbys cannot serve LiMDM (no read routing).
* After a failover, connections break: instances reconnect (pool, notification listener),
  background jobs restart under new locks, running remote shells end.

Options:

| Option | Failover | Notes |
|---|---|---|
| Managed service with HA (Amazon RDS/Aurora Multi AZ, Google Cloud SQL HA, Azure Database for PostgreSQL flexible server with zone redundant HA) | automatic, 30 to 120 s, DNS name stays | simplest; use `sslmode=verify-full` with the provider's CA |
| Patroni with etcd/Consul, access through a virtual IP (vip-manager, keepalived) or HAProxy on the Patroni REST API | automatic, about 30 s | proven self hosted setup; synchronous mode for zero data loss |
| Streaming replication with manual promotion (`pg_ctl promote`, repmgr) | manual | small setups; document and practice the switch |
| libpq multi host URL | client side | `postgres://limdm@db1,db2/limdm?sslmode=verify-full&target_session_attrs=read-write`: instances find the primary themselves |

Use synchronous replication (`synchronous_commit = on` with `synchronous_standby_names`)
when the audit log must not lose committed entries on failover (RPO 0); asynchronous
replication can lose the last seconds.

## Backup

| What | How | Notes |
|---|---|---|
| Database | continuous archiving with point in time recovery (pgBackRest, WAL-G, Barman, or the managed service's backups), plus the built in daily backup ([backup.md](backup.md)) | PITR gives an RPO of seconds to minutes |
| CA directory | in every built in backup; it runs again after every key rotation step | identical on all instances |
| `LIMDM_SESSION_KEY` | with the CA directory, apart from the database backups | |
| `LIMDM_RELEASE_DIR` | not needed | downloaded again |

## RTO and RPO

| Failure | Effect | Recovery time | Data loss |
|---|---|---|---|
| One server instance | load balancer removes it after the health checks; its remote shells end; its background jobs move within 15 s | seconds | none |
| PostgreSQL primary, HA failover | requests fail during the failover, then continue | failover time (30 to 120 s) | none with synchronous replication, otherwise the last seconds |
| Whole database lost, restore from PITR | all instances unready until restored | restore time: plan about 1 hour per 100 GB plus WAL replay; measure it | up to the last archived WAL segment (`archive_timeout`, for example 60 s) |
| Restore from the nightly dump only | as above | dump size dependent | up to 24 hours |
| CA directory lost without backup | devices cannot be verified: every device must enroll again | days | device identities |

Devices tolerate outages: they keep their declarations, check in again when the server is
back. Only devices with `offline_lock_hours` in `com.limdm.agent` lock themselves after
that time without server contact, so keep it well above your RTO.

## Restore test

`limdm-server backup restore-test` restores an archive into a scratch database, verifies the
audit chain and the sealed values and records the result; run it monthly
([backup.md](backup.md#restore-test)). In addition, practice a full restore at least twice a
year and after major changes, on a separate host:

1. Restore the CA directory and `LIMDM_SESSION_KEY` to a test host; set a different
   `LIMDM_PUBLIC_URL`, keep `LIMDM_AGENT_URL` unreachable for devices.
2. Restore the database (PITR to a recent time, or `limdm-server backup restore` into an
   empty database).
3. Start one instance and check `/readyz`.
4. Sign in, open **Audit**, run **Verify whole chain**: it must report the chain intact.
5. Open a device and an item; open a recovery key of a test device (sealed secrets
   readable).
6. Note the time taken (RTO) and the newest audit entry against the time of the failure
   simulation (RPO), and record the test in the audit log or your ISMS.
7. Destroy the test host and its copies of the keys.
