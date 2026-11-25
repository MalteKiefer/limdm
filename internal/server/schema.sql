-- Idempotent base schema applied at startup; data conversions live in migrations.go.

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

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
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
-- agents without a compliance item reported "checks": null, which the
-- jsonb_array_* functions of the device page and the export reject
UPDATE devices SET checks = '[]' WHERE jsonb_typeof(checks) <> 'array';
UPDATE devices SET decl_status = '[]' WHERE jsonb_typeof(decl_status) <> 'array';
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
