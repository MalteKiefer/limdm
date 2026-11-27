-- Idempotent schema applied at startup under an advisory lock; data conversions run in Go at startup (library.go migrate).

-- Reusable configuration building blocks (one declaration type each).
CREATE TABLE IF NOT EXISTS library_items (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Assignment maps: a tree of assign / if nodes, optionally inheriting from a parent.
CREATE TABLE IF NOT EXISTS blueprints (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS parent_id BIGINT REFERENCES blueprints(id) ON DELETE SET NULL;
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS tree JSONB NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS devices (
    id             TEXT PRIMARY KEY,
    cert_serial    TEXT NOT NULL,           -- only this client certificate is accepted
    cert_not_after TIMESTAMPTZ NOT NULL,
    hostname       TEXT NOT NULL DEFAULT '',
    machine_id     TEXT NOT NULL DEFAULT '',
    users          JSONB NOT NULL DEFAULT '[]',
    agent_version  TEXT NOT NULL DEFAULT '',
    inventory      JSONB NOT NULL DEFAULT '{}',
    checks         JSONB NOT NULL DEFAULT '[]',
    decl_status    JSONB NOT NULL DEFAULT '[]',
    status_hash    TEXT NOT NULL DEFAULT '',
    packages       JSONB NOT NULL DEFAULT '[]',
    packages_hash  TEXT NOT NULL DEFAULT '',
    failing        INT NOT NULL DEFAULT 0,
    enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ,
    retired        BOOLEAN NOT NULL DEFAULT false
);

-- One blueprint per device; NULL means the blueprint named 'default'.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS blueprint_id BIGINT REFERENCES blueprints(id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

-- Directory: people and groups from SCIM or Google Workspace.
CREATE TABLE IF NOT EXISTS dir_users (
    id           BIGSERIAL PRIMARY KEY,
    external_id  TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL, -- scim | google
    user_name    TEXT NOT NULL,
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    department   TEXT NOT NULL DEFAULT '',
    title        TEXT NOT NULL DEFAULT '',
    active       BOOLEAN NOT NULL DEFAULT true,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS dir_groups (
    id          BIGSERIAL PRIMARY KEY,
    external_id TEXT NOT NULL,
    source      TEXT NOT NULL,
    name        TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, external_id)
);
CREATE TABLE IF NOT EXISTS dir_members (
    group_id BIGINT NOT NULL REFERENCES dir_groups(id) ON DELETE CASCADE,
    user_id  BIGINT NOT NULL REFERENCES dir_users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
-- A device without an explicit blueprint gets the one of its primary user's group.
CREATE TABLE IF NOT EXISTS blueprint_group_assignments (
    group_id     BIGINT PRIMARY KEY REFERENCES dir_groups(id) ON DELETE CASCADE,
    blueprint_id BIGINT NOT NULL REFERENCES blueprints(id) ON DELETE CASCADE,
    priority     INT NOT NULL DEFAULT 100
);
-- Compliance policy state: since when failing, end of grace, last webhook, policy lock.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS noncompliant_since TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS grace_until TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS auto_locked BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_user_id BIGINT REFERENCES dir_users(id) ON DELETE SET NULL;

-- History for charts: per device at most every 15 minutes, fleet once a day; 30 days kept.
CREATE TABLE IF NOT EXISTS device_metrics (
    device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    at            TIMESTAMPTZ NOT NULL,
    mem_used_mb   BIGINT NOT NULL,
    mem_total_mb  BIGINT NOT NULL,
    root_used_pct REAL NOT NULL,
    load1         REAL NOT NULL,
    PRIMARY KEY (device_id, at)
);
CREATE TABLE IF NOT EXISTS fleet_history (
    day           DATE PRIMARY KEY,
    compliant     INT NOT NULL,
    noncompliant  INT NOT NULL,
    in_grace      INT NOT NULL,
    stale         INT NOT NULL,
    pending       INT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash   BYTEA PRIMARY KEY,
    note         TEXT NOT NULL DEFAULT '',
    blueprint_id BIGINT REFERENCES blueprints(id) ON DELETE CASCADE,
    uses_left    INT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_by   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commands (
    id         BIGSERIAL PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    payload    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'pending', -- pending | sent | ok | failed | expired
    output     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commands_device_status ON commands(device_id, status);

-- Fallback admin accounts when no OIDC provider is available. Password (argon2id)
-- and TOTP are both required; credentials are generated by `limdm-server local-admin`.
CREATE TABLE IF NOT EXISTS local_admins (
    name           TEXT PRIMARY KEY,
    role           TEXT NOT NULL CHECK (role IN ('admin', 'helpdesk', 'auditor')),
    password_hash  TEXT NOT NULL,
    totp_secret    TEXT NOT NULL,
    totp_last_step BIGINT NOT NULL DEFAULT 0,
    failures       INT NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    disabled       BOOLEAN NOT NULL DEFAULT false,
    last_login     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- OIDC console users; the environment lists only seed this table.
CREATE TABLE IF NOT EXISTS console_users (
    email      TEXT PRIMARY KEY,
    role       TEXT NOT NULL CHECK (role IN ('admin', 'helpdesk', 'auditor')),
    disabled   BOOLEAN NOT NULL DEFAULT false,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Settings edited in the UI (secrets sealed with a key derived from LIMDM_SESSION_KEY).
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append only, hash chained audit trail (ISO 27001 A.8.15, BSI OPS.1.1.5).
CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT NOT NULL DEFAULT '',
    detail  TEXT NOT NULL DEFAULT '',
    prev    BYTEA NOT NULL,
    hash    BYTEA NOT NULL
);

-- UPDATE and TRUNCATE are refused always; DELETE only inside a transaction
-- that set limdm.retention (the audit retention job, retention.go), which
-- records a signed cut so the remaining chain stays verifiable.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('limdm.retention', true) = 'on' THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'audit_log is append only';
END $$;

DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

CREATE TABLE IF NOT EXISTS recovery_keys (
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    uuid        TEXT NOT NULL,
    device_path TEXT NOT NULL,
    sealed      BYTEA NOT NULL,
    escrowed_at TIMESTAMPTZ NOT NULL,
    viewed_at   TIMESTAMPTZ,
    viewed_by   TEXT,
    rotate      BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, uuid)
);

ALTER TABLE local_admins ADD COLUMN IF NOT EXISTS totp_pending TEXT;

CREATE TABLE IF NOT EXISTS local_recovery_codes (
    name    TEXT NOT NULL REFERENCES local_admins(name) ON DELETE CASCADE,
    hash    TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    PRIMARY KEY (name, hash)
);

-- Indexes for check in and console paths (lookups by member, inactive directory
-- users, blueprint and primary user, metric retention).
CREATE INDEX IF NOT EXISTS dir_members_user ON dir_members(user_id, group_id);
CREATE INDEX IF NOT EXISTS dir_users_inactive ON dir_users(email) WHERE NOT active;
CREATE INDEX IF NOT EXISTS dir_users_scim_username ON dir_users(lower(user_name)) WHERE source = 'scim';
CREATE INDEX IF NOT EXISTS dir_users_source_ext ON dir_users(source, external_id);
CREATE INDEX IF NOT EXISTS devices_blueprint ON devices(blueprint_id);
CREATE INDEX IF NOT EXISTS devices_primary_user ON devices(primary_user_id);
CREATE INDEX IF NOT EXISTS device_metrics_at ON device_metrics USING brin(at);
-- last_seen and status updates change no indexed column: leave room for HOT updates
ALTER TABLE devices SET (fillfactor = 70);

-- Certificate renewal: the new serial is pending until the device first uses
-- it, so a lost renewal response cannot lock the device out.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS pending_serial TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS pending_not_after TIMESTAMPTZ;

-- People deleted from the directory (SCIM DELETE) must lose their device
-- accounts like deactivated ones: a tombstone remembers the email until the
-- person is provisioned again. Triggers cover every write path.
CREATE TABLE IF NOT EXISTS dir_tombstones (
    email      TEXT PRIMARY KEY,
    removed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Console users seeded from LIMDM_ADMINS / LIMDM_AUDITORS are disabled at start
-- once they are no longer listed; users edited in the console are not.
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS from_env BOOLEAN NOT NULL DEFAULT false;

-- Session generation: bumped on sign out, credential changes, reset, role
-- change and disable; sessions issued under an older generation end.
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS session_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE local_admins ADD COLUMN IF NOT EXISTS session_gen BIGINT NOT NULL DEFAULT 0;

-- Last tamper event reported by the agent or its watchdog.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tampered_at TIMESTAMPTZ;

-- Routine agent events (changes made, desktop logins) are high volume; they
-- live here instead of the hash chained audit log, append only, one multi row
-- insert per check in and no global lock. Security events (tamper, escrow,
-- command results, enrollment) stay in audit_log. Kept 365 days.
CREATE TABLE IF NOT EXISTS device_events (
    id        BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    at        TIMESTAMPTZ NOT NULL,
    detail    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS device_events_device ON device_events(device_id, id DESC);
CREATE INDEX IF NOT EXISTS device_events_at ON device_events USING brin(at);
CREATE OR REPLACE FUNCTION device_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'device_events is append only'; END $$;
DROP TRIGGER IF EXISTS device_events_append_only ON device_events;
CREATE TRIGGER device_events_append_only BEFORE UPDATE ON device_events
    FOR EACH ROW EXECUTE FUNCTION device_events_append_only();

-- Columns for list views, computed once on write instead of detoasting the
-- inventory and check JSON of every device on every page view.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_name TEXT GENERATED ALWAYS AS (coalesce(inventory->>'os_name', '')) STORED;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS desktop TEXT GENERATED ALWAYS AS (coalesce(inventory->>'desktop', '')) STORED;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS memory_mb BIGINT GENERATED ALWAYS AS (coalesce((inventory->>'memory_mb')::bigint, 0)) STORED;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS checks_count INT GENERATED ALWAYS AS (CASE WHEN jsonb_typeof(checks) = 'array' THEN jsonb_array_length(checks) ELSE 0 END) STORED;

-- Last verified position of the audit hash chain (incremental verification).
CREATE TABLE IF NOT EXISTS audit_checkpoint (
    one         BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
    last_id     BIGINT NOT NULL,
    last_hash   BYTEA NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL
);

-- Agent releases fetched from GitHub; devices get approved, unblocked ones.
CREATE TABLE IF NOT EXISTS agent_releases (
    version        TEXT PRIMARY KEY,
    published_at   TIMESTAMPTZ NOT NULL,
    fetched_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    sums           TEXT NOT NULL,
    sums_sig       TEXT NOT NULL DEFAULT '',
    approved_at    TIMESTAMPTZ,
    approved_by    TEXT,
    blocked        BOOLEAN NOT NULL DEFAULT false,
    blocked_reason TEXT NOT NULL DEFAULT ''
);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS update_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS update_state TEXT NOT NULL DEFAULT '';   -- offered, ok, failed, rolled_back
ALTER TABLE devices ADD COLUMN IF NOT EXISTS update_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS update_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS update_target TEXT NOT NULL DEFAULT '';  -- version an admin picked for this device
ALTER TABLE devices ADD COLUMN IF NOT EXISTS external_ip TEXT NOT NULL DEFAULT '';   -- peer address of the last check in
ALTER TABLE devices ADD COLUMN IF NOT EXISTS geo JSONB;                              -- location of external_ip (geo.go)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS geo_at TIMESTAMPTZ;

-- Software catalog (self service, catalog.go). sources and detect hold the
-- api.AppSource list and extra package names; scope lists blueprint IDs
-- (empty: every device).
CREATE TABLE IF NOT EXISTS catalog_apps (
    slug        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'available',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    sources     JSONB NOT NULL,
    detect      TEXT[] NOT NULL DEFAULT '{}',
    scope       BIGINT[] NOT NULL DEFAULT '{}',
    icon        BYTEA,
    icon_tried  TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS catalog_requests (
    id          BIGSERIAL PRIMARY KEY,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    app         TEXT NOT NULL REFERENCES catalog_apps(slug) ON DELETE CASCADE,
    username    TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied
    decided_by  TEXT,
    decided_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS catalog_requests_device ON catalog_requests(device_id, app, created_at DESC);

-- Flatpak remotes IT manages (software catalog): allowed ones are added on
-- devices, blocked ones disabled; catalog_only remotes get the catalog filter.
CREATE TABLE IF NOT EXISTS catalog_remotes (
    name         TEXT PRIMARY KEY,
    url          TEXT NOT NULL,
    title        TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL DEFAULT 'allowed',
    catalog_only BOOLEAN NOT NULL DEFAULT true,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- requests for Flatpaks outside the catalog: app is set when approved
ALTER TABLE catalog_requests ALTER COLUMN app DROP NOT NULL;
ALTER TABLE catalog_requests ADD COLUMN IF NOT EXISTS flatpak TEXT NOT NULL DEFAULT '';
ALTER TABLE catalog_requests ADD COLUMN IF NOT EXISTS remote TEXT NOT NULL DEFAULT '';
ALTER TABLE catalog_requests ADD COLUMN IF NOT EXISTS app_name TEXT NOT NULL DEFAULT '';

-- icon hash computed once per write, not per catalog query and check in
ALTER TABLE catalog_apps ADD COLUMN IF NOT EXISTS icon_hash TEXT GENERATED ALWAYS AS (coalesce(encode(sha256(icon), 'hex'), '')) STORED;

-- Ed25519 signature of each command (command.key), checked by the agent
ALTER TABLE commands ADD COLUMN IF NOT EXISTS signature TEXT NOT NULL DEFAULT '';

-- Ed25519 signature of each library item (command.key), checked before delivery
ALTER TABLE library_items ADD COLUMN IF NOT EXISTS signature TEXT NOT NULL DEFAULT '';

-- Notification channels (email, Slack, Discord, webhook); secret is sealed
CREATE TABLE IF NOT EXISTS notification_channels (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('email', 'slack', 'discord', 'webhook')),
    config     JSONB NOT NULL DEFAULT '{}',
    secret     TEXT NOT NULL DEFAULT '',
    events     TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notification_log (
    id         BIGSERIAL PRIMARY KEY,
    channel_id BIGINT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event      TEXT NOT NULL,
    ok         BOOLEAN NOT NULL,
    error      TEXT NOT NULL DEFAULT '',
    at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notification_log_channel ON notification_log(channel_id, id DESC);
-- the one off repair of checks and decl_status is migration 9 (library.go)
-- users of a device already reported as disabled (notified once)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS users_disabled TEXT[] NOT NULL DEFAULT '{}';
-- addresses a directory user had before (renames, domain moves): device user
-- lists still name the old one, and a later suspension must reach it
ALTER TABLE dir_users ADD COLUMN IF NOT EXISTS previous_emails TEXT[] NOT NULL DEFAULT '{}';
CREATE OR REPLACE FUNCTION dir_users_previous_email() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF lower(OLD.email) <> lower(NEW.email) AND NOT lower(OLD.email) = ANY(NEW.previous_emails) THEN
        NEW.previous_emails := array_append(NEW.previous_emails, lower(OLD.email));
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS dir_users_previous_email ON dir_users;
CREATE TRIGGER dir_users_previous_email BEFORE UPDATE OF email ON dir_users
    FOR EACH ROW EXECUTE FUNCTION dir_users_previous_email();
CREATE OR REPLACE FUNCTION dir_users_tombstone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO dir_tombstones(email) SELECT DISTINCT e FROM unnest(array_append(OLD.previous_emails, lower(OLD.email))) e
            ON CONFLICT (email) DO UPDATE SET removed_at = now();
        RETURN OLD;
    END IF;
    DELETE FROM dir_tombstones WHERE email = lower(NEW.email);
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS dir_users_tombstone ON dir_users;
CREATE TRIGGER dir_users_tombstone AFTER INSERT OR UPDATE OF email OR DELETE ON dir_users
    FOR EACH ROW EXECUTE FUNCTION dir_users_tombstone();

-- W3
CREATE OR REPLACE FUNCTION rows_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION '% is append only', TG_TABLE_NAME; END $$;
-- Catalog version of the device's last check report (evidence export).
ALTER TABLE devices ADD COLUMN IF NOT EXISTS catalog_version TEXT NOT NULL DEFAULT '';

-- Compliance history: one row per change of a check result (devices report
-- only changes). Pruned after 365 days like device_events, keeping the last
-- row before the cutoff so the state at any date stays known.
CREATE TABLE IF NOT EXISTS compliance_changes (
    id              BIGSERIAL PRIMARY KEY,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    at              TIMESTAMPTZ NOT NULL,
    check_id        TEXT NOT NULL,
    status          TEXT NOT NULL, -- pass | fail | na | excepted | advisory | removed
    detail          TEXT NOT NULL DEFAULT '',
    catalog_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS compliance_changes_device ON compliance_changes(device_id, check_id, id);
CREATE INDEX IF NOT EXISTS compliance_changes_at ON compliance_changes USING brin(at);
DROP TRIGGER IF EXISTS compliance_changes_append_only ON compliance_changes;
CREATE TRIGGER compliance_changes_append_only BEFORE UPDATE ON compliance_changes
    FOR EACH ROW EXECUTE FUNCTION rows_append_only();
-- the baseline for devices that reported before the history existed is
-- migration 9 (library.go)

-- Versions of library items and blueprints: every save, rollback and delete
-- (the deleted payload stays). No foreign key, versions outlive the object.
CREATE TABLE IF NOT EXISTS library_item_versions (
    id          BIGSERIAL PRIMARY KEY,
    item_id     BIGINT NOT NULL,
    version     INT NOT NULL,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    payload     JSONB NOT NULL,
    signature   TEXT NOT NULL DEFAULT '',
    deleted     BOOLEAN NOT NULL DEFAULT false,
    note        TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (item_id, version)
);
CREATE TABLE IF NOT EXISTS blueprint_versions (
    id           BIGSERIAL PRIMARY KEY,
    blueprint_id BIGINT NOT NULL,
    version      INT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    parent_id    BIGINT,
    tree         JSONB NOT NULL,
    deleted      BOOLEAN NOT NULL DEFAULT false,
    note         TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (blueprint_id, version)
);
DROP TRIGGER IF EXISTS library_item_versions_append_only ON library_item_versions;
CREATE TRIGGER library_item_versions_append_only BEFORE UPDATE OR DELETE ON library_item_versions
    FOR EACH ROW EXECUTE FUNCTION rows_append_only();
DROP TRIGGER IF EXISTS blueprint_versions_append_only ON blueprint_versions;
CREATE TRIGGER blueprint_versions_append_only BEFORE UPDATE OR DELETE ON blueprint_versions
    FOR EACH ROW EXECUTE FUNCTION rows_append_only();
-- the baseline version of blueprints saved before versioning existed is
-- migration 10 (library.go); library items get theirs at startup in server.go
-- W2
-- Four eyes approvals: a second admin approves wipe, lost mode, scripts, role
-- changes and (optionally) recovery key views before they run.
CREATE TABLE IF NOT EXISTS approvals (
    id           BIGSERIAL PRIMARY KEY,
    action       TEXT NOT NULL,             -- command | user.update | recovery.view
    target       TEXT NOT NULL,             -- device id or console login
    payload      JSONB NOT NULL DEFAULT '{}',
    reason       TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected | expired | used
    decided_by   TEXT,
    decided_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status, expires_at);
-- Role scopes: helpdesk and auditor accounts limited to device tags or
-- directory group names; empty means every device. Roles taken from
-- directory groups (from_group) are derived again on every request.
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS scope_tags TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS scope_groups TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS from_group BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS oidc_groups TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE local_admins ADD COLUMN IF NOT EXISTS scope_tags TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE local_admins ADD COLUMN IF NOT EXISTS scope_groups TEXT[] NOT NULL DEFAULT '{}';
-- Risk acceptance: exceptions with reason, owner, approver and expiry; only
-- active ones reach the agents (merged into the compliance declaration).
CREATE TABLE IF NOT EXISTS risk_exceptions (
    id         BIGSERIAL PRIMARY KEY,
    check_id   TEXT NOT NULL,
    mode       TEXT NOT NULL CHECK (mode IN ('exclude', 'advisory')),
    tag        TEXT NOT NULL DEFAULT '',   -- '' = every device
    reason     TEXT NOT NULL,
    owner      TEXT NOT NULL,
    approver   TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
-- Retention: rows of audit_log and device_events are deleted only by the
-- retention job and the device deletion, which set limdm.retention for their
-- transaction (audit_log_immutable above). audit_cut records where the chain
-- starts after a prune, with an HMAC under the audit chain key, so the
-- remaining chain stays verifiable.
CREATE OR REPLACE FUNCTION device_events_retention_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('limdm.retention', true) = 'on' THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'device_events rows are deleted by the retention job only';
END $$;
DROP TRIGGER IF EXISTS device_events_retention_only ON device_events;
CREATE TRIGGER device_events_retention_only BEFORE DELETE OR TRUNCATE ON device_events
    FOR EACH STATEMENT EXECUTE FUNCTION device_events_retention_only();
CREATE TABLE IF NOT EXISTS audit_cut (
    one       BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
    last_id   BIGINT NOT NULL,
    last_hash BYTEA NOT NULL,
    mac       BYTEA NOT NULL,
    cut_at    TIMESTAMPTZ NOT NULL
);
-- W4
-- limdm_version_key turns a package version into numbers for comparing:
-- the epoch is dropped and every run of digits is one element, so
-- '1:3.0.13-1~deb12u1' becomes {3,0,13,1,12,1}
CREATE OR REPLACE FUNCTION limdm_version_key(v text) RETURNS numeric[] LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(array_agg(m.x[1]::numeric ORDER BY m.n), '{}')
    FROM regexp_matches(regexp_replace(coalesce(v, ''), '^[0-9]+:', ''), '[0-9]+', 'g') WITH ORDINALITY AS m(x, n)
$$;
-- tokens for the admin REST API and the metrics endpoint; only the hash is stored
CREATE TABLE IF NOT EXISTS api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    token_hash   BYTEA NOT NULL UNIQUE,
    role         TEXT NOT NULL CHECK (role IN ('admin', 'helpdesk', 'auditor', 'metrics')),
    read_only    BOOLEAN NOT NULL DEFAULT false,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
-- E1
-- EAP-TLS device certificates issued by the network CA. No foreign key: a
-- revoked certificate stays on the CRL until it expires, also when the
-- device record is gone.
CREATE TABLE IF NOT EXISTS network_certs (
    serial        TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL,
    subject       TEXT NOT NULL,
    sans          TEXT NOT NULL DEFAULT '',
    not_before    TIMESTAMPTZ NOT NULL,
    not_after     TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoke_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS network_certs_device ON network_certs(device_id);
-- integration v0.16.0
-- device scope of helpdesk and auditor API tokens (tags, as for console users)
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS scope_tags TEXT[] NOT NULL DEFAULT '{}';
-- W1
-- Structured results of script commands and recurring scripts (newest 200 per device).
CREATE TABLE IF NOT EXISTS script_results (
    id          BIGSERIAL PRIMARY KEY,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id  BIGINT,
    name        TEXT NOT NULL DEFAULT '',
    exit_code   INTEGER NOT NULL,
    stdout      TEXT NOT NULL DEFAULT '',
    stderr      TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS script_results_device ON script_results(device_id, id);
-- Log bundles of the diagnostics command (newest 10 per device), downloaded by admins and helpdesk.
CREATE TABLE IF NOT EXISTS diagnostics (
    command_id BIGINT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS diagnostics_device ON diagnostics(device_id, command_id);
-- E3
-- remote shell sessions: who opened which shell on which device, and its output
CREATE TABLE IF NOT EXISTS shell_sessions (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id   BIGINT,
    requested_by TEXT NOT NULL,
    local_user   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    connected_at TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ,
    end_reason   TEXT NOT NULL DEFAULT '',
    transcript   BYTEA NOT NULL DEFAULT '',
    truncated    BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS shell_sessions_device ON shell_sessions(device_id, created_at DESC);
-- E4c
-- running server instances (high availability): heartbeat every 10 s; a
-- remote shell runs on the instance that started it
CREATE TABLE IF NOT EXISTS server_instances (
    id         TEXT PRIMARY KEY,
    hostname   TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE shell_sessions ADD COLUMN IF NOT EXISTS instance TEXT NOT NULL DEFAULT '';
-- every instance reloads the console settings when one of them saves them
CREATE OR REPLACE FUNCTION settings_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('limdm_settings', NEW.key);
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS settings_notify ON settings;
CREATE TRIGGER settings_notify AFTER INSERT OR UPDATE ON settings FOR EACH ROW EXECUTE FUNCTION settings_notify();
-- syslog forwarding position, so a new leader continues where the last one stopped
CREATE TABLE IF NOT EXISTS syslog_cursor (
    stream  TEXT PRIMARY KEY,
    last_id BIGINT NOT NULL
);
-- schema versions applied to this database, checked by /readyz
CREATE TABLE IF NOT EXISTS schema_applied (
    hash       TEXT PRIMARY KEY,
    version    TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- E4a
-- Multi tenancy: every company of an MSP or a group is a tenant. Tenant 1
-- ("Default") owns all data from before tenants existed and the global
-- objects; installs with one company never see more. Console users, API
-- tokens and notification channels with a NULL tenant are global (super
-- admins, all tenants). Audit entries with a NULL tenant are global entries.
CREATE TABLE IF NOT EXISTS tenants (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    disabled     BOOLEAN NOT NULL DEFAULT false,
    company_name TEXT NOT NULL DEFAULT '',
    logo         BYTEA NOT NULL DEFAULT '',
    color        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO tenants(id, name) VALUES (1, 'Default') ON CONFLICT DO NOTHING;
SELECT setval(pg_get_serial_sequence('tenants', 'id'), (SELECT max(id) FROM tenants));
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE enroll_tokens ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE library_items ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE library_items ADD COLUMN IF NOT EXISTS shared BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS shared BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE risk_exceptions ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE network_certs ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE device_events ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE compliance_changes ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE console_users ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);
ALTER TABLE local_admins ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id BIGINT;
-- the default blueprint applies to every device without one, in every tenant
UPDATE blueprints SET shared = true WHERE name = 'default' AND tenant_id = 1 AND NOT shared;
CREATE INDEX IF NOT EXISTS devices_tenant ON devices(tenant_id);
CREATE INDEX IF NOT EXISTS audit_log_tenant ON audit_log(tenant_id, id) WHERE tenant_id IS NOT NULL;
-- rows written per device take the tenant of their device, so no write path
-- can file them under another tenant
CREATE OR REPLACE FUNCTION limdm_device_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.tenant_id := coalesce((SELECT tenant_id FROM devices WHERE id = NEW.device_id), NEW.tenant_id);
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS device_events_tenant ON device_events;
CREATE TRIGGER device_events_tenant BEFORE INSERT ON device_events FOR EACH ROW EXECUTE FUNCTION limdm_device_tenant();
DROP TRIGGER IF EXISTS compliance_changes_tenant ON compliance_changes;
CREATE TRIGGER compliance_changes_tenant BEFORE INSERT ON compliance_changes FOR EACH ROW EXECUTE FUNCTION limdm_device_tenant();
DROP TRIGGER IF EXISTS network_certs_tenant ON network_certs;
CREATE TRIGGER network_certs_tenant BEFORE INSERT ON network_certs FOR EACH ROW EXECUTE FUNCTION limdm_device_tenant();
-- E4b
-- key rotation (keys.go): how far each device has moved to the active device
-- CA (set when its certificate is from that CA and it trusts the CA bundle)
-- and which command key it has pinned; the CA that issued a network certificate
ALTER TABLE devices ADD COLUMN IF NOT EXISTS cert_ca TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS command_key TEXT;
ALTER TABLE network_certs ADD COLUMN IF NOT EXISTS ca TEXT NOT NULL DEFAULT '';
-- the current audit key (its id): an instance with another key cannot write entries
CREATE TABLE IF NOT EXISTS audit_key (
    one    BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
    key_id TEXT NOT NULL
);
-- the version history stays append only, except that a session key rotation
-- may seal a login client secret again (payload only, flag set per transaction)
CREATE OR REPLACE FUNCTION rows_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'library_item_versions' AND current_setting('limdm.reseal', true) = 'on' THEN
        IF to_jsonb(NEW) - 'payload' = to_jsonb(OLD) - 'payload' THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION '% is append only', TG_TABLE_NAME;
END $$;
-- L
-- Allowed states and references, checked for new and changed rows. NOT VALID:
-- adding them does not scan the tables, and existing rows are not checked.
DO $$
BEGIN
    ALTER TABLE commands ADD CONSTRAINT commands_status_check
        CHECK (status IN ('pending', 'sent', 'ok', 'failed', 'expired')) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE approvals ADD CONSTRAINT approvals_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'used')) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE catalog_requests ADD CONSTRAINT catalog_requests_status_check
        CHECK (status IN ('pending', 'approved', 'denied')) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE devices ADD CONSTRAINT devices_update_state_check
        CHECK (update_state IN ('', 'offered', 'ok', 'failed', 'rolled_back')) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
-- results and sessions outlive the retention of their command
DO $$
BEGIN
    ALTER TABLE script_results ADD CONSTRAINT script_results_command_fk
        FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE SET NULL NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE shell_sessions ADD CONSTRAINT shell_sessions_command_fk
        FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE SET NULL NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT '{}'; -- tokenScopes (adminapi.go), empty: all of the role
-- Idempotency-Key of admin API requests (adminapi_admin.go): the first
-- answer per token and key, replayed for 24 hours
CREATE TABLE IF NOT EXISTS api_idempotency (
    token_id     BIGINT NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    key          TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status       INT NOT NULL DEFAULT 0,
    location     TEXT NOT NULL DEFAULT '',
    body         BYTEA NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (token_id, key)
);
CREATE INDEX IF NOT EXISTS api_idempotency_created ON api_idempotency(created_at);

-- S1
-- signatures of what devices act on as root besides library items (datasig.go)
ALTER TABLE catalog_apps ADD COLUMN IF NOT EXISTS signature TEXT NOT NULL DEFAULT '';
ALTER TABLE catalog_remotes ADD COLUMN IF NOT EXISTS signature TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS users_sig TEXT NOT NULL DEFAULT '';
-- library item and blueprint names are unique per tenant, not globally
ALTER TABLE library_items DROP CONSTRAINT IF EXISTS library_items_name_key;
ALTER TABLE blueprints DROP CONSTRAINT IF EXISTS blueprints_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS library_items_tenant_name ON library_items(tenant_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS blueprints_tenant_name ON blueprints(tenant_id, name);
-- failed local sign ins per account and client network: a lockout from one
-- source does not lock the account for everyone else (local.go)
CREATE TABLE IF NOT EXISTS local_login_failures (
    name         TEXT NOT NULL REFERENCES local_admins(name) ON DELETE CASCADE,
    source       TEXT NOT NULL,
    failures     INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (name, source)
);
-- B
-- backup runs (backup.go): one row per run, with the targets that hold the
-- archive, the result of the checksum verification and of the last restore test
CREATE TABLE IF NOT EXISTS backups (
    id                 BIGSERIAL PRIMARY KEY,
    name               TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    actor              TEXT NOT NULL DEFAULT '',
    started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    size               BIGINT NOT NULL DEFAULT 0,
    sha256             TEXT NOT NULL DEFAULT '',
    targets            TEXT[] NOT NULL DEFAULT '{}',
    status             TEXT NOT NULL,
    error              TEXT NOT NULL DEFAULT '',
    keys_hash          TEXT NOT NULL DEFAULT '',
    server_version     TEXT NOT NULL DEFAULT '',
    verified_at        TIMESTAMPTZ,
    verify_error       TEXT NOT NULL DEFAULT '',
    restore_tested_at  TIMESTAMPTZ,
    restore_test_error TEXT NOT NULL DEFAULT '',
    deleted_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS backups_started ON backups(started_at DESC);
ALTER TABLE backups ADD COLUMN IF NOT EXISTS schedule TEXT NOT NULL DEFAULT '';
-- the last restore: while window_until lies ahead, a device certificate of
-- our CA issued after backup_at is pinned again (restoreRepin)
CREATE TABLE IF NOT EXISTS restore_state (
    one          BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
    backup_name  TEXT NOT NULL,
    backup_at    TIMESTAMPTZ NOT NULL,
    restored_at  TIMESTAMPTZ NOT NULL,
    window_until TIMESTAMPTZ NOT NULL
);
-- uploaded packages (packages.go): content addressed per tenant; approved_by
-- stays NULL while a four eyes approval is pending
CREATE TABLE IF NOT EXISTS artifacts (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id),
    sha256      TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    filename    TEXT NOT NULL,
    size        BIGINT NOT NULL,
    store       TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    approved_by TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sha256)
);

-- integration v0.17.0
-- installed packages per device, written by diff at check in (server.go
-- savePackages) instead of the whole list as JSONB; devices.packages is no
-- longer read or written (migration 12 moves its content here)
CREATE TABLE IF NOT EXISTS device_packages (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    version   TEXT NOT NULL,
    arch      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, name, arch, version)
);
CREATE INDEX IF NOT EXISTS device_packages_name ON device_packages(name, device_id);

-- review: sequence numbers of signed data (api.SignedSeq)
ALTER TABLE catalog_apps ADD COLUMN IF NOT EXISTS seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE catalog_remotes ADD COLUMN IF NOT EXISTS seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS users_seq BIGINT NOT NULL DEFAULT 0;

-- UI-F
-- saved views of the console app (views.go): personal, or shared by an
-- admin with the tenant (tenant_id NULL: the global view)
CREATE TABLE IF NOT EXISTS saved_views (
    id         BIGSERIAL PRIMARY KEY,
    owner      TEXT NOT NULL,
    tenant_id  BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    list       TEXT NOT NULL,
    name       TEXT NOT NULL,
    query      TEXT NOT NULL DEFAULT '',
    sort       TEXT NOT NULL DEFAULT '',
    columns    TEXT[] NOT NULL DEFAULT '{}',
    shared     BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saved_views_owner ON saved_views(owner, list);
CREATE INDEX IF NOT EXISTS saved_views_shared ON saved_views(tenant_id, list) WHERE shared;
-- the console app counts failed commands of the last day (appstats.go)
CREATE INDEX IF NOT EXISTS commands_updated ON commands(updated_at);

-- UI-D
-- why an approval was approved or rejected (app inbox, approvals.go)
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decision_reason TEXT NOT NULL DEFAULT '';
-- daily security update and agent version counts (app_home_updates.go); NULL before recorded
ALTER TABLE fleet_history ADD COLUMN IF NOT EXISTS security_devices INT;
ALTER TABLE fleet_history ADD COLUMN IF NOT EXISTS security_old INT;
ALTER TABLE fleet_history ADD COLUMN IF NOT EXISTS agent_current INT;
ALTER TABLE fleet_history ADD COLUMN IF NOT EXISTS agent_total INT;
-- scheduled reports (app_reports_schedule.go): a saved report preset run
-- as its owner in the tenant view it was scheduled in, sent as a link
CREATE TABLE IF NOT EXISTS report_schedules (
    id         BIGSERIAL PRIMARY KEY,
    view_id    BIGINT NOT NULL REFERENCES saved_views(id) ON DELETE CASCADE,
    owner      TEXT NOT NULL,
    tenant_id  BIGINT REFERENCES tenants(id) ON DELETE CASCADE, -- NULL: the all tenants view
    cadence    TEXT NOT NULL CHECK (cadence IN ('daily', 'weekly', 'monthly')),
    channels   BIGINT[] NOT NULL DEFAULT '{}',
    emails     TEXT[] NOT NULL DEFAULT '{}',
    next_run   TIMESTAMPTZ NOT NULL,
    last_run   TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (view_id, owner)
);
CREATE INDEX IF NOT EXISTS report_schedules_due ON report_schedules(next_run);
CREATE TABLE IF NOT EXISTS report_runs (
    id          BIGSERIAL PRIMARY KEY,
    schedule_id BIGINT NOT NULL REFERENCES report_schedules(id) ON DELETE CASCADE,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind        TEXT NOT NULL,
    rows        INT NOT NULL DEFAULT 0,
    sha256      TEXT NOT NULL DEFAULT '',
    content     BYTEA NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS report_runs_schedule ON report_runs(schedule_id, id DESC);

-- ws/ui-config
-- pilot rollout of a blueprint change (app_config_pilot.go): the devices
-- moved to the pilot copy and the blueprint they had set before
CREATE TABLE IF NOT EXISTS blueprint_pilots (
    pilot_id          BIGINT NOT NULL REFERENCES blueprints(id) ON DELETE CASCADE,
    blueprint_id      BIGINT NOT NULL REFERENCES blueprints(id) ON DELETE CASCADE,
    device_id         TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    prev_blueprint_id BIGINT,
    created_by        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pilot_id, device_id)
);
CREATE INDEX IF NOT EXISTS blueprint_pilots_blueprint ON blueprint_pilots(blueprint_id);

-- R3-S
-- enrollment tokens: at most 500 uses and 30 days (enrollsettings.go); older
-- tokens are cut down to these limits once
UPDATE enroll_tokens SET uses_left = LEAST(uses_left, 500), expires_at = LEAST(expires_at, now() + interval '30 days')
    WHERE uses_left > 500 OR expires_at > now() + interval '30 days';
-- TPM bound device keys (tpmattest.go): the attestation key pinned at
-- enrollment and the SHA-256 of the endorsement key's public area
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tpm_bound BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tpm_ak BYTEA;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tpm_ek_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS require_tpm BOOLEAN NOT NULL DEFAULT false;
-- R3-P
-- update rings (app_patch.go): ordered per tenant; a wave starts at the
-- first ring and reaches ring N once it is deferral_days old, the ring
-- before has it and nothing is paused (or approved, with require_approval)
CREATE TABLE IF NOT EXISTS update_rings (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    position         INT NOT NULL,
    deferral_days    INT NOT NULL DEFAULT 0,
    wave_days        INT NOT NULL DEFAULT 0,
    paused           BOOLEAN NOT NULL DEFAULT false,
    require_approval BOOLEAN NOT NULL DEFAULT false,
    approved_wave    INT NOT NULL DEFAULT 0,
    all_devices      BOOLEAN NOT NULL DEFAULT false,
    tags             TEXT[] NOT NULL DEFAULT '{}',
    groups           TEXT[] NOT NULL DEFAULT '{}',
    blueprints       BIGINT[] NOT NULL DEFAULT '{}',
    wave             INT NOT NULL DEFAULT 0,
    wave_at          TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);
CREATE TABLE IF NOT EXISTS update_waves (
    tenant_id  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wave       INT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id, wave)
);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS update_ring_id BIGINT REFERENCES update_rings(id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS updates JSONB;
-- Debian and Ubuntu security data (app_patch_cve.go): fixed versions per
-- distribution, release, source package and CVE, the state of each feed,
-- and the CVEs matched against the installed packages of each device
ALTER TABLE device_packages ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS cve_fixes (
    distro   TEXT NOT NULL,
    release  TEXT NOT NULL,
    package  TEXT NOT NULL,
    cve      TEXT NOT NULL,
    fixed    TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (distro, release, package, cve)
);
CREATE TABLE IF NOT EXISTS cve_feeds (
    distro     TEXT PRIMARY KEY,
    url        TEXT NOT NULL DEFAULT '',
    fetched_at TIMESTAMPTZ,
    rows       INT NOT NULL DEFAULT 0,
    bytes      BIGINT NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    error_at   TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS device_cves (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cve       TEXT NOT NULL,
    package   TEXT NOT NULL,
    installed TEXT NOT NULL,
    fixed     TEXT NOT NULL,
    severity  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, cve, package)
);
CREATE INDEX IF NOT EXISTS device_cves_cve ON device_cves(cve);
-- R3-E
-- custom device attributes for file and firewall templates ({{.Attributes.name}})
ALTER TABLE devices ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{}';
-- R3-D
-- the device timeline reads the audit entries of one device
CREATE INDEX IF NOT EXISTS audit_log_target ON audit_log(target, id);
-- R3-W
-- the latest container and VM inventory of each device (app_workloads.go)
CREATE TABLE IF NOT EXISTS device_workloads (
    device_id  TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    inventory  JSONB NOT NULL,
    hash       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
