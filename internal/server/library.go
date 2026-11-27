package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// ---- schema and migrations ----

// migrate applies schema.sql and the migrations when they changed since the
// last start. An unchanged schema takes no lock at all: a rolling restart
// must not queue ACCESS EXCLUSIVE requests in front of the running instances.
func migrate(ctx context.Context, db *pgxpool.Pool) error {
	if ok, err := schemaCurrent(ctx, db); err != nil || ok {
		return err
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// one migrator at a time, for the schema transaction and the index builds
	// after it. A try lock in a loop: a statement waiting for the lock would
	// hold a snapshot, and the concurrent index build of the instance that
	// migrates waits for every older snapshot to end
	for start := time.Now(); ; {
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7364)`).Scan(&got); err != nil {
			return err
		}
		if got {
			break
		}
		if time.Since(start) > 15*time.Minute {
			return errors.New("another instance has been migrating the schema for 15 minutes")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	defer func() {
		// the session keeps the lock and settings otherwise; at worst the
		// connection is closed with them
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7364); RESET statement_timeout`); err != nil {
			conn.Conn().Close(context.WithoutCancel(ctx)) //nolint:errcheck // already failing
		}
	}()
	if ok, err := schemaCurrent(ctx, conn); err != nil || ok { // another instance was faster
		return err
	}
	// the schema inside one transaction: SET LOCAL keeps the disabled
	// timeouts to it
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// no statement limit, but a bounded lock wait: the schema takes table
	// locks until the commit, and a running instance must not stall behind them
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = 0; SET LOCAL lock_timeout = '30s'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	for _, m := range migrations {
		var done bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, m.version).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		if err := m.run(ctx, tx); err != nil {
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, m.version); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := buildIndexes(ctx, conn); err != nil {
		return fmt.Errorf("build indexes: %w", err)
	}
	// recorded last: a start that failed to build an index tries again
	_, err = conn.Exec(ctx, `INSERT INTO schema_applied(hash, version) VALUES ($1, $2) ON CONFLICT (hash) DO NOTHING`, schemaHash(), Version)
	return err
}

// concurrentIndexes are indexes on tables that grow with the fleet. They are
// built with CREATE INDEX CONCURRENTLY outside the schema transaction, so a
// first build on a big installation does not block writes to the table.
// Each entry is "name ON table ...".
var concurrentIndexes = []string{
	// poll and check in: device users disabled, renamed or deleted in the directory
	`dir_users_lower_email ON dir_users (lower(email))`,
	`dir_users_previous_emails ON dir_users USING gin (previous_emails) WHERE NOT active`,
	// enrollment: earlier records of the same machine
	`devices_machine_id ON devices (machine_id) WHERE NOT retired`,
	// device list and API pages: sorted by host name
	`devices_hostname ON devices (hostname, id)`,
	`devices_retired_hostname ON devices (retired, hostname, id)`,
	// device filters (deviceFilters, pkgCond)
	`devices_tags ON devices USING gin (tags)`,
	`devices_apps ON devices USING gin ((inventory->'apps') jsonb_path_ops)`,
	`devices_flatpaks ON devices USING gin ((inventory->'flatpaks') jsonb_path_ops)`,
	`devices_flatpak_remotes ON devices USING gin ((inventory->'flatpak_remotes') jsonb_path_ops)`,
	`devices_checks ON devices USING gin (checks jsonb_path_ops)`,
	// retention of finished commands
	`commands_finished ON commands (updated_at) WHERE status IN ('ok', 'failed', 'expired')`,
}

// buildIndexes creates the concurrentIndexes that are missing, on conn
// which holds the migration lock. An invalid index left by an interrupted
// build is built again.
func buildIndexes(ctx context.Context, conn *pgxpool.Conn) error {
	if _, err := conn.Exec(ctx, `SET statement_timeout = 0`); err != nil { // reset by migrate
		return err
	}
	for _, ix := range concurrentIndexes {
		name, _, _ := strings.Cut(ix, " ")
		var invalid bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
			WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace AND NOT i.indisvalid)`, name).Scan(&invalid); err != nil {
			return err
		}
		if invalid {
			if _, err := conn.Exec(ctx, `DROP INDEX CONCURRENTLY IF EXISTS `+name); err != nil {
				return err
			}
		}
		if _, err := conn.Exec(ctx, `CREATE INDEX CONCURRENTLY IF NOT EXISTS `+ix); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// schemaCurrent tells whether this exact schema and set of migrations was
// applied already (schema_applied, keyed by schemaHash).
func schemaCurrent(ctx context.Context, q rowQuerier) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT to_regclass('schema_applied') IS NOT NULL`).Scan(&ok)
	if err != nil || !ok {
		return false, err
	}
	err = q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_applied WHERE hash=$1)`, schemaHash()).Scan(&ok)
	return ok, err
}

var migrations = []struct {
	version int
	run     func(context.Context, pgx.Tx) error
}{
	{2, migratePriorityBlueprints},
	{3, seedDefaultBlueprint},
	{4, func(ctx context.Context, tx pgx.Tx) error { // helpdesk role for local accounts
		_, err := tx.Exec(ctx, `ALTER TABLE local_admins DROP CONSTRAINT IF EXISTS local_admins_role_check;
			ALTER TABLE local_admins ADD CONSTRAINT local_admins_role_check CHECK (role IN ('admin', 'helpdesk', 'auditor'))`)
		return err
	}},
	{5, seedCatalog},
	{6, func(ctx context.Context, tx pgx.Tx) error { // Flathub as the first managed remote
		_, err := tx.Exec(ctx, `INSERT INTO catalog_remotes(name, url, title) VALUES ('flathub', 'https://dl.flathub.org/repo/flathub.flatpakrepo', 'Flathub')
			ON CONFLICT (name) DO NOTHING`)
		return err
	}},
	{7, func(ctx context.Context, tx pgx.Tx) error { return seedApps(ctx, tx, moreCatalog) }},
	{8, seedVendorIcons},
	// one off data repairs and baselines, formerly run with schema.sql at every start
	{9, func(ctx context.Context, tx pgx.Tx) error {
		// agents without a compliance item reported "checks": null, which the
		// jsonb_array_* functions of the device page and the export reject;
		// then the history baseline for devices that reported before it existed
		_, err := tx.Exec(ctx, `UPDATE devices SET checks = '[]' WHERE jsonb_typeof(checks) <> 'array';
			UPDATE devices SET decl_status = '[]' WHERE jsonb_typeof(decl_status) <> 'array';
			INSERT INTO compliance_changes(device_id, at, check_id, status, detail, catalog_version)
			SELECT d.id, coalesce(d.last_seen, now()), c->>'id', coalesce(c->>'status', ''), coalesce(c->>'detail', ''), d.catalog_version
			FROM devices d, jsonb_array_elements(d.checks) c
			WHERE c->>'id' IS NOT NULL AND NOT EXISTS (SELECT 1 FROM compliance_changes x WHERE x.device_id = d.id)`)
		return err
	}},
	{10, func(ctx context.Context, tx pgx.Tx) error { // baseline version of blueprints saved before versioning existed
		_, err := tx.Exec(ctx, `INSERT INTO blueprint_versions(blueprint_id, version, name, description, parent_id, tree, note, created_by, created_at)
			SELECT b.id, 1, b.name, b.description, b.parent_id, b.tree, 'baseline', 'system', b.updated_at FROM blueprints b
			WHERE NOT EXISTS (SELECT 1 FROM blueprint_versions v WHERE v.blueprint_id = b.id)`)
		return err
	}},
	{11, partitionMetrics}, // device_metrics by day (partitions.go)
	{12, func(ctx context.Context, tx pgx.Tx) error { // packages from devices.packages to device_packages
		_, err := tx.Exec(ctx, `INSERT INTO device_packages(device_id, name, version, arch)
			SELECT d.id, left(p->>'n', 200), left(coalesce(p->>'v', ''), 200), left(coalesce(p->>'a', ''), 50)
			FROM devices d, jsonb_array_elements(CASE WHEN jsonb_typeof(d.packages) = 'array' THEN d.packages ELSE '[]'::jsonb END) p
			WHERE coalesce(p->>'n', '') <> ''
			ON CONFLICT DO NOTHING;
			DROP INDEX IF EXISTS devices_packages;
			UPDATE devices SET packages = '[]' WHERE packages <> '[]'`)
		return err
	}},
}

func columnExists(ctx context.Context, tx pgx.Tx, table, column string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name=$2)`, table, column).Scan(&ok)
	return ok, err
}

// migratePriorityBlueprints converts the first model (blueprints as flat lists
// of declarations combined by priority) into library items and assignment maps.
// Non-default blueprints inherit from default, which keeps the old behaviour.
func migratePriorityBlueprints(ctx context.Context, tx pgx.Tx) error {
	legacy, err := columnExists(ctx, tx, "blueprints", "declarations")
	if err != nil || !legacy {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id, name, declarations FROM blueprints ORDER BY priority DESC, id`)
	if err != nil {
		return err
	}
	type old struct {
		id    int64
		name  string
		decls []api.Declaration
	}
	olds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (old, error) {
		var o old
		var raw []byte
		if err := row.Scan(&o.id, &o.name, &raw); err != nil {
			return o, err
		}
		return o, json.Unmarshal(raw, &o.decls)
	})
	if err != nil {
		return err
	}
	var defaultID int64
	for _, o := range olds {
		if o.name == "default" {
			defaultID = o.id
		}
	}
	for _, o := range olds {
		var ids []int64
		for _, d := range o.decls {
			var id int64
			if err := tx.QueryRow(ctx, `INSERT INTO library_items(name, type, payload) VALUES ($1,$2,$3) RETURNING id`,
				o.name+": "+d.Identifier, d.Type, string(d.Payload)).Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		tree, _ := json.Marshal([]api.Node{{Kind: "assign", Items: ids}})
		var parent *int64
		if o.id != defaultID && defaultID != 0 {
			parent = &defaultID
		}
		if _, err := tx.Exec(ctx, `UPDATE blueprints SET tree=$2, parent_id=$3 WHERE id=$1`, o.id, string(tree), parent); err != nil {
			return err
		}
	}
	var hasAssign bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('device_blueprints') IS NOT NULL`).Scan(&hasAssign); err != nil {
		return err
	}
	if hasAssign {
		// a device keeps the assigned blueprint that used to win (lowest priority number)
		if _, err := tx.Exec(ctx, `UPDATE devices d SET blueprint_id = (
			SELECT db.blueprint_id FROM device_blueprints db JOIN blueprints b ON b.id=db.blueprint_id
			WHERE db.device_id=d.id ORDER BY b.priority, b.id LIMIT 1)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DROP TABLE device_blueprints`); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `ALTER TABLE blueprints DROP COLUMN declarations, DROP COLUMN priority`)
	return err
}

// seedDefaultBlueprint gives a new installation the CIS Level 1 baseline.
func seedDefaultBlueprint(ctx context.Context, tx pgx.Tx) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM blueprints WHERE name='default' AND tenant_id=1)`).Scan(&exists); err != nil || exists {
		return err
	}
	var ids []int64
	for _, li := range api.DefaultLibrary() {
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO library_items(name, type, payload) VALUES ($1,$2,$3)
			ON CONFLICT (tenant_id, name) DO UPDATE SET name=EXCLUDED.name RETURNING id`, li.Name, li.Type, string(li.Payload)).Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	tree, _ := json.Marshal([]api.Node{{Kind: "assign", Items: ids}})
	_, err := tx.Exec(ctx, `INSERT INTO blueprints(name, description, tree, shared) VALUES ('default', 'Baseline for every device', $1, true)`, string(tree))
	return err
}

// ---- resolution ----

type blueprintRec struct {
	ID       int64
	Name     string
	Parent   *int64
	Tree     []api.Node
	Desc     string
	Updated  time.Time
	Devices  int
	Assigned bool // explicitly assigned to the device
	Applies  bool // the device's effective blueprint (explicit, group or default)
}

func scanBlueprint(row pgx.Row) (blueprintRec, error) {
	var b blueprintRec
	var raw []byte
	if err := row.Scan(&b.ID, &b.Name, &b.Parent, &raw, &b.Desc, &b.Updated); err != nil {
		return b, err
	}
	return b, json.Unmarshal(raw, &b.Tree)
}

const blueprintCols = `id, name, parent_id, tree, description, updated_at`

// blueprintChain returns the blueprint and its ancestors, root first.
func blueprintChain(ctx context.Context, q pgx.Tx, id int64) ([]blueprintRec, error) {
	var chain []blueprintRec
	seen := map[int64]bool{}
	for cur := &id; cur != nil; {
		if seen[*cur] || len(chain) > 10 {
			return nil, errors.New("blueprint inheritance cycle")
		}
		seen[*cur] = true
		b, err := scanBlueprint(q.QueryRow(ctx, `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, *cur))
		if err != nil {
			return nil, err
		}
		chain = append(chain, b)
		cur = b.Parent
	}
	slices.Reverse(chain)
	return chain, nil
}

// deviceFacts reads the attributes blueprint rules test.
func deviceFacts(ctx context.Context, q pgx.Tx, deviceID string) (api.Facts, *int64, error) {
	var inv []byte
	var tags []string
	var bp *int64
	err := q.QueryRow(ctx, `SELECT inventory, tags, blueprint_id FROM devices WHERE id=$1`, deviceID).Scan(&inv, &tags, &bp)
	if err != nil {
		return api.Facts{}, nil, err
	}
	var i api.Inventory
	if err := json.Unmarshal(inv, &i); err != nil {
		return api.Facts{}, nil, err
	}
	groups, dept, err := directoryFacts(ctx, q, deviceID)
	if err != nil {
		return api.Facts{}, nil, err
	}
	return api.Facts{OSID: i.OSID, OSVersion: i.OSVersion, Arch: i.Arch, Desktop: i.Desktop, Vendor: i.Vendor,
		Model: i.Model, Hostname: i.Hostname, Tags: tags, Groups: groups, Department: dept}, bp, nil
}

type resolved struct {
	Chain []blueprintRec
	Items []api.LibraryItem
	Decls []api.Declaration
	// TemplateErrors are the items whose templates did not render for the
	// device (templates.go); their payload goes out still marked.
	TemplateErrors []string
}

// resolveDevice evaluates the device's blueprint chain against its facts.
func resolveDevice(ctx context.Context, q pgx.Tx, deviceID string) (resolved, error) {
	var res resolved
	facts, bp, err := deviceFacts(ctx, q, deviceID)
	if err != nil {
		return res, err
	}
	if bp == nil { // explicit assignment first, then the primary user's group, then default
		if bp, err = groupBlueprint(ctx, q, deviceID); err != nil {
			return res, err
		}
	}
	if bp == nil {
		var def int64
		if err := q.QueryRow(ctx, `SELECT id FROM blueprints WHERE name='default' AND tenant_id=1`).Scan(&def); err != nil {
			return res, err
		}
		bp = &def
	}
	if res.Chain, err = blueprintChain(ctx, q, *bp); err != nil {
		return res, err
	}
	maps := make([][]api.Node, len(res.Chain))
	for i, b := range res.Chain {
		maps[i] = b.Tree
	}
	ids := api.Resolve(maps, facts)
	if res.Items, err = libraryItems(ctx, q, deviceID, ids); err != nil {
		return res, err
	}
	rendered, err := renderItems(ctx, q, deviceID, res.Items, &res.TemplateErrors)
	if err != nil {
		return res, err
	}
	if res.Decls, err = api.Merge(rendered); err != nil {
		return res, err
	}
	return res, applyExceptions(ctx, q, deviceID, res.Decls) // risk exceptions (exceptions.go)
}

// libraryItems loads the items of a device and returns them in the order
// of ids. Only items of the device's tenant and of the default tenant
// (kept by global admins) resolve, so a reference across tenants that got
// past validation never delivers another tenant's item.
func libraryItems(ctx context.Context, q pgx.Tx, deviceID string, ids []int64) ([]api.LibraryItem, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `SELECT id, name, type, description, payload, signature FROM library_items
		WHERE id = ANY($1) AND tenant_id IN (1, (SELECT tenant_id FROM devices WHERE id=$2))`, ids, deviceID)
	if err != nil {
		return nil, err
	}
	byID := map[int64]api.LibraryItem{}
	for rows.Next() {
		var it api.LibraryItem
		var raw []byte
		var sig string
		if err := rows.Scan(&it.ID, &it.Name, &it.Type, &it.Description, &raw, &sig); err != nil {
			rows.Close()
			return nil, err
		}
		it.Payload = raw
		if !itemSignatureOK(it.Name, it.Type, raw, sig) {
			// changed outside the console (database write, restore of a foreign
			// backup): never delivered, and loud in the log
			slog.Error("library item signature invalid, item not delivered", "item", it.ID, "name", it.Name)
			continue
		}
		var err error
		if it.Payload, err = openItemSecrets(it.Type, raw); err != nil { // sealed client secret (loginsecret.go)
			slog.Error("library item secret cannot be opened, item not delivered", "item", it.ID, "name", it.Name, "err", err)
			continue
		}
		byID[it.ID] = it
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]api.LibraryItem, 0, len(ids))
	for _, id := range ids {
		if it, ok := byID[id]; ok {
			out = append(out, it)
		}
	}
	return out, nil
}

func scanItem(row pgx.CollectableRow) (api.LibraryItem, error) {
	var it api.LibraryItem
	var raw []byte
	err := row.Scan(&it.ID, &it.Name, &it.Type, &it.Description, &raw)
	it.Payload = raw
	return it, err
}

// effectiveDeclarations is what a device receives at check in.
func effectiveDeclarations(ctx context.Context, q pgx.Tx, deviceID string) ([]api.Declaration, error) {
	r, err := resolveDevice(ctx, q, deviceID)
	return r.Decls, err
}

// ---- web: library ----

func (s *Server) allItems(ctx context.Context) ([]api.LibraryItem, error) {
	cond, args := visibleCond(ctx, "i", 0)
	rows, err := s.db.Query(ctx, `SELECT id, name, type, description, payload FROM library_items i WHERE `+cond+` ORDER BY type, name`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanItem)
}

// itemUsage counts how many blueprints reference each library item.
func (s *Server) itemUsage(ctx context.Context) (map[int64][]string, error) {
	bps, err := s.allBlueprints(ctx, "")
	if err != nil {
		return nil, err
	}
	use := map[int64][]string{}
	var walk func(name string, nodes []api.Node)
	walk = func(name string, nodes []api.Node) {
		for _, n := range nodes {
			for _, id := range n.Items {
				if !slices.Contains(use[id], name) {
					use[id] = append(use[id], name)
				}
			}
			for _, b := range n.Branches {
				walk(name, b.Nodes)
			}
			walk(name, n.Else)
		}
	}
	for _, b := range bps {
		walk(b.Name, b.Tree)
	}
	return use, nil
}

// restoreNetworkSecrets puts the stored secrets of a network item back where
// the edited payload (console editor, admin API, a masked version) still
// holds the mask; masks with nothing stored stay and fail validation.
func (s *Server) restoreNetworkSecrets(ctx context.Context, it *api.LibraryItem) error {
	if it.Type != api.TypeNetwork {
		return nil
	}
	var stored []byte
	if it.ID > 0 {
		if err := tenantGuard(ctx, s.db, "library_items", it.ID); err != nil {
			return err
		}
		if err := s.db.QueryRow(ctx, `SELECT payload FROM library_items WHERE id=$1 AND type=$2`, it.ID, it.Type).Scan(&stored); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	p, err := api.RestoreNetworkSecrets(it.Payload, stored)
	if err != nil {
		return invalid("payload", err)
	}
	it.Payload = p
	return nil
}

// saveLibraryItem prepares, validates, signs and stores a library item with
// its new version and audit entry; ID 0 creates one and sets it.ID. The
// console and the admin API both save through here.
func (s *Server) saveLibraryItem(ctx context.Context, actor string, it *api.LibraryItem) error {
	if it.Type == api.TypeBootloader { // hash a plain password before it is validated and stored
		p, err := api.PrepareBootloader(it.Payload)
		if err != nil {
			return invalid("payload", err)
		}
		it.Payload = p
	}
	if err := s.checkArtifactRefs(ctx, it); err != nil { // packages.go
		return invalid("payload", err)
	}
	return s.storeItem(ctx, actor, "library.save", "save", it, false)
}

// itemField names the request field a validation error of it is about.
func itemField(it api.LibraryItem, err error) string {
	switch {
	case strings.TrimSpace(it.Name) == "" || len(it.Name) > 100:
		return "name"
	case strings.HasPrefix(err.Error(), "unknown declaration type"):
		return "type"
	}
	return "payload"
}

// storeItem validates, signs and saves an item with its new version and
// audit entry in one transaction and sets it.ID. restore lets a rollback
// recreate a deleted item under its old ID.
func (s *Server) storeItem(ctx context.Context, actor, action, note string, it *api.LibraryItem, restore bool) error {
	if it.ID > 0 && !restore { // ownership before anything else, so validation reveals nothing
		if err := tenantGuard(ctx, s.db, "library_items", it.ID); err != nil {
			return err
		}
	}
	if err := s.restoreNetworkSecrets(ctx, it); err != nil {
		return err
	}
	if err := it.Validate(); err != nil {
		return invalid(itemField(*it, err), err)
	}
	sealed, _, err := sealItemSecrets(it.Type, it.Payload) // never stored, signed, versioned or audited in clear
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, sealed); err != nil {
		return invalid("payload", err)
	}
	it.Payload = compact.Bytes()
	if s.itemNeedsApproval(*it) { // four eyes: stored as a request, signed when approved
		return s.requestItemApproval(ctx, actor, action, note, *it, restore)
	}
	return s.auditAction(ctx, actor, action, it.Name, itemDetail(*it, note), func(tx pgx.Tx) error {
		return writeItem(ctx, tx, actor, note, it, restore)
	})
}

// itemDetail is the audit text of an item save.
func itemDetail(it api.LibraryItem, note string) string {
	detail := it.Type + " " + string(it.Payload)
	if it.Type == api.TypeNetwork {
		detail = it.Type + " " + string(api.MaskNetworkSecrets(it.Payload)) // no secrets in the audit log
	}
	var l api.Logging
	if it.Type == api.TypeLogging && json.Unmarshal(it.Payload, &l) == nil && len(l.Roots) > 0 {
		detail = "custom log roots " + strings.Join(l.Roots, ", ") + "; " + detail
	}
	if note != "save" {
		detail = note + ": " + detail
	}
	return detail
}

// writeItem signs and writes a validated, compact item with its version in
// tx and sets it.ID.
func writeItem(ctx context.Context, tx pgx.Tx, actor, note string, it *api.LibraryItem, restore bool) error {
	sig := signItem(it.Name, it.Type, it.Payload)
	id := it.ID
	if id > 0 {
		if err := tenantGuard(ctx, tx, "library_items", id); err != nil {
			return err
		}
		if err := checkIfMatch(ctx, tx, "library_items", id); err != nil {
			return err
		}
		if err := ensureItemBaseline(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE library_items SET name=$2, type=$3, description=$4, payload=$5, signature=$6, updated_at=now() WHERE id=$1`,
			id, it.Name, it.Type, it.Description, string(it.Payload), sig)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			if !restore {
				return &userError{http.StatusNotFound, "library item not found"}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO library_items(id, name, type, description, payload, signature, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				id, it.Name, it.Type, it.Description, string(it.Payload), sig, ownerTenant(ctx)); err != nil {
				return err
			}
		}
	} else if err := tx.QueryRow(ctx, `INSERT INTO library_items(name, type, description, payload, signature, tenant_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		it.Name, it.Type, it.Description, string(it.Payload), sig, ownerTenant(ctx)).Scan(&id); err != nil {
		return err
	}
	it.ID = id
	return recordItemVersion(ctx, tx, id, actor, note, false)
}

// deleteLibraryItem removes an item no blueprint uses, with its audit entry
// and a deleted version that keeps the last payload.
func (s *Server) deleteLibraryItem(ctx context.Context, actor string, id int64) error {
	if err := tenantGuard(ctx, s.db, "library_items", id); err != nil {
		return err
	}
	use, err := s.itemUsage(ctx)
	if err != nil {
		return err
	}
	if len(use[id]) > 0 {
		return &userError{http.StatusConflict, "item is used by blueprints: " + strings.Join(use[id], ", ")}
	}
	return s.auditAction(ctx, actor, "library.delete", strconv.FormatInt(id, 10), "", func(tx pgx.Tx) error {
		// the last payload stays in the version history
		if err := ensureItemBaseline(ctx, tx, id); err != nil {
			return err
		}
		if err := recordItemVersion(ctx, tx, id, actor, "delete", true); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM library_items WHERE id=$1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			err = &userError{http.StatusNotFound, "library item not found"}
		}
		return err
	})
}

// ---- web: blueprints ----

// effectiveBlueprintSQL is the blueprint of device d as resolveDevice picks
// it: the explicit one, else the primary user's group, else default.
const effectiveBlueprintSQL = `coalesce(d.blueprint_id,
	(SELECT a.blueprint_id FROM dir_users u JOIN dir_members m ON m.user_id=u.id JOIN blueprint_group_assignments a ON a.group_id=m.group_id
	 JOIN blueprints gb ON gb.id=a.blueprint_id AND (gb.tenant_id=d.tenant_id OR gb.tenant_id=1 AND gb.shared)
	 WHERE u.id=d.primary_user_id AND u.active ORDER BY a.priority, a.group_id LIMIT 1),
	(SELECT id FROM blueprints WHERE name='default' AND tenant_id=1))`

func (s *Server) allBlueprints(ctx context.Context, deviceID string) ([]blueprintRec, error) {
	cond, args := visibleCond(ctx, "b", 1)
	dcond, dargs := tenantDevices(ctx, 1+len(args))
	rows, err := s.db.Query(ctx, `SELECT b.id, b.name, b.parent_id, b.tree, b.description, b.updated_at,
		(SELECT count(*) FROM devices d WHERE NOT d.retired AND `+dcond+` AND `+effectiveBlueprintSQL+` = b.id),
		EXISTS(SELECT 1 FROM devices d WHERE d.id=$1 AND (d.blueprint_id=b.id OR (d.blueprint_id IS NULL AND b.name='default' AND b.tenant_id=1))),
		EXISTS(SELECT 1 FROM devices d WHERE d.id=$1 AND `+effectiveBlueprintSQL+` = b.id)
		FROM blueprints b WHERE `+cond+` ORDER BY b.name='default' DESC, b.name`, append(append([]any{deviceID}, args...), dargs...)...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (blueprintRec, error) {
		var b blueprintRec
		var raw []byte
		if err := row.Scan(&b.ID, &b.Name, &b.Parent, &raw, &b.Desc, &b.Updated, &b.Devices, &b.Assigned, &b.Applies); err != nil {
			return b, err
		}
		return b, json.Unmarshal(raw, &b.Tree)
	})
}

// saveBlueprint validates and stores a blueprint with its new version and
// audit entry; ID 0 creates one and sets bp.ID. The console and the admin
// API both save through here.
func (s *Server) saveBlueprint(ctx context.Context, actor string, bp *blueprintRec) error {
	if bp.Tree == nil {
		bp.Tree = []api.Node{}
	}
	if err := s.validateBlueprint(ctx, *bp); err != nil {
		return err
	}
	return s.storeBlueprint(ctx, actor, "blueprint.save", "save", bp, false)
}

// validateBlueprint checks name, items and inheritance before a save.
func (s *Server) validateBlueprint(ctx context.Context, bp blueprintRec) error {
	if !identOK(bp.Name) {
		return invalid("name", errors.New("name must be 1..64 characters: letters, digits, dot, dash, underscore"))
	}
	if bp.Name == "default" && ownerTenant(ctx) != defaultTenant { // names are unique per tenant; default applies by name
		return &userError{http.StatusConflict, "the name is already in use"}
	}
	items, err := s.allItems(ctx)
	if err != nil {
		return err
	}
	ids := map[int64]bool{}
	for _, it := range items {
		ids[it.ID] = true
	}
	if err := api.ValidateTree(bp.Tree, func(i int64) bool { return ids[i] }); err != nil {
		return invalid("tree", err)
	}
	if bp.Parent == nil {
		return nil
	}
	var ok bool
	pcond, pargs := visibleCond(ctx, "b", 1)
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM blueprints b WHERE b.id=$1 AND `+pcond+`)`, append([]any{*bp.Parent}, pargs...)...).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return invalid("parent_id", errors.New("the parent blueprint does not exist"))
	}
	if bp.ID > 0 {
		if err := s.checkNoCycle(ctx, bp.ID, *bp.Parent); err != nil {
			return invalid("parent_id", err)
		}
	}
	return nil
}

// storeBlueprint saves a validated blueprint with its new version and audit
// entry in one transaction and sets bp.ID; restore lets a rollback recreate
// a deleted one.
func (s *Server) storeBlueprint(ctx context.Context, actor, action, note string, bp *blueprintRec, restore bool) error {
	tree, _ := json.Marshal(bp.Tree)
	detail := string(tree)
	if note != "save" {
		detail = note + ": " + detail
	}
	return s.auditAction(ctx, actor, action, bp.Name, detail, func(tx pgx.Tx) error {
		id := bp.ID
		var exists bool
		if id > 0 {
			if err := tenantGuard(ctx, tx, "blueprints", id); err != nil {
				return err
			}
			if err := checkIfMatch(ctx, tx, "blueprints", id); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM blueprints WHERE id=$1)`, id).Scan(&exists); err != nil {
				return err
			}
		}
		switch {
		case exists:
			if err := ensureBlueprintBaseline(ctx, tx, id); err != nil {
				return err
			}
			// the default blueprint applies by name and cannot inherit
			tag, err := tx.Exec(ctx, `UPDATE blueprints SET name=$2, description=$3, parent_id=CASE WHEN name='default' THEN NULL ELSE $4::bigint END, tree=$5, updated_at=now()
				WHERE id=$1 AND (name <> 'default' OR $2 = 'default')`, id, bp.Name, bp.Desc, bp.Parent, string(tree))
			if err == nil && tag.RowsAffected() == 0 {
				err = &userError{http.StatusNotFound, "blueprint not found, or default cannot be renamed"}
			}
			if err != nil {
				return err
			}
		case id > 0 && restore:
			if _, err := tx.Exec(ctx, `INSERT INTO blueprints(id, name, description, parent_id, tree, tenant_id) VALUES ($1,$2,$3,$4,$5,$6)`,
				id, bp.Name, bp.Desc, bp.Parent, string(tree), ownerTenant(ctx)); err != nil {
				return err
			}
		case id > 0:
			return &userError{http.StatusNotFound, "blueprint not found, or default cannot be renamed"}
		default:
			if err := tx.QueryRow(ctx, `INSERT INTO blueprints(name, description, parent_id, tree, tenant_id) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
				bp.Name, bp.Desc, bp.Parent, string(tree), ownerTenant(ctx)).Scan(&id); err != nil {
				return err
			}
		}
		bp.ID = id
		return recordBlueprintVersion(ctx, tx, id, actor, note, false)
	})
}

func identOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// checkNoCycle refuses a parent that already inherits from the blueprint.
func (s *Server) checkNoCycle(ctx context.Context, id, parent int64) error {
	for cur, n := &parent, 0; cur != nil; n++ {
		if *cur == id || n > 10 {
			return errors.New("parent would create an inheritance cycle")
		}
		var next *int64
		if err := s.db.QueryRow(ctx, `SELECT parent_id FROM blueprints WHERE id=$1`, *cur).Scan(&next); err != nil {
			return err
		}
		cur = next
	}
	return nil
}

// deleteBlueprint removes a blueprint other than default, with its audit
// entry; its devices fall back to default.
func (s *Server) deleteBlueprint(ctx context.Context, actor string, id int64) error {
	if err := tenantGuard(ctx, s.db, "blueprints", id); err != nil {
		return err
	}
	return s.auditAction(ctx, actor, "blueprint.delete", strconv.FormatInt(id, 10), "devices fall back to default", func(tx pgx.Tx) error {
		// the last version stays in the history (rolled back for default below)
		if err := ensureBlueprintBaseline(ctx, tx, id); err != nil {
			return err
		}
		if err := recordBlueprintVersion(ctx, tx, id, actor, "delete", true); err != nil {
			return err
		}
		var name string
		err := tx.QueryRow(ctx, `DELETE FROM blueprints WHERE id=$1 RETURNING name`, id).Scan(&name)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return &userError{http.StatusNotFound, "blueprint not found"}
		case err == nil && name == "default":
			return &userError{http.StatusConflict, "the default blueprint cannot be deleted"} // rolls the delete back
		}
		return err
	})
}

// itemKey signs library items; it is the command key, set when the server
// starts. itemPrevKey is the previous command key while a rotation runs:
// items signed with it stay valid until they are signed again (keys_reseal.go).
var (
	itemKey     crypto.Signer
	itemPrevKey ed25519.PublicKey
)

func signItem(name, typ string, payload []byte) string {
	if itemKey == nil {
		return ""
	}
	sig, err := signEd25519(itemKey, api.ItemSigned(name, typ, canonicalJSON(payload)))
	if err != nil {
		slog.Error("signing library item", "item", logSafe(name), "err", err) // unsigned: withheld from devices
		return ""
	}
	return hex.EncodeToString(sig)
}

// canonicalJSON is the form a signature covers: decoded and encoded again, so
// object keys are sorted and numbers and escapes are normalized. PostgreSQL
// stores payloads as JSONB, which reorders keys; the text read back must give
// the same bytes as the text the console signed.
func canonicalJSON(payload []byte) []byte {
	var v any
	if json.Unmarshal(payload, &v) == nil {
		if b, err := json.Marshal(v); err == nil {
			return b
		}
	}
	return payload
}

func itemSignatureOK(name, typ string, payload []byte, sig string) bool {
	if itemKey == nil {
		return true // no key (tools without the CA directory)
	}
	return itemSigValid(itemKey.Public().(ed25519.PublicKey), name, typ, payload, sig) ||
		(itemPrevKey != nil && itemSigValid(itemPrevKey, name, typ, payload, sig))
}

func itemSigValid(pub ed25519.PublicKey, name, typ string, payload []byte, sig string) bool {
	b, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	if ed25519.Verify(pub, api.ItemSigned(name, typ, canonicalJSON(payload)), b) {
		return true
	}
	// signatures made before canonicalJSON cover the compacted database text
	var c bytes.Buffer
	if json.Compact(&c, payload) != nil {
		return false
	}
	return ed25519.Verify(pub, api.ItemSigned(name, typ, c.Bytes()), b)
}

// signExistingItems signs every unsigned library item once: on the upgrade
// that introduced signatures and on a fresh installation (items seeded by
// migrations). A marker file next to the key, not a database row, records
// it, so whoever can only write to the database cannot have items signed.
func signExistingItems(ctx context.Context, db *pgxpool.Pool, caDir string) error {
	marker := filepath.Join(caDir, "items-signed-v1")
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	rows, err := db.Query(ctx, `SELECT id, name, type, payload FROM library_items WHERE signature = ''`)
	if err != nil {
		return err
	}
	type item struct {
		id        int64
		name, typ string
		payload   []byte
	}
	var todo []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.name, &it.typ, &it.payload); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, it)
	}
	rows.Close()
	for _, it := range todo {
		if _, err := db.Exec(ctx, `UPDATE library_items SET signature=$2 WHERE id=$1`, it.id, signItem(it.name, it.typ, it.payload)); err != nil {
			return err
		}
	}
	return os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}
