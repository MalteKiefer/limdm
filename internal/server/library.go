package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// ---- schema and migrations ----

func migrate(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7364)`); err != nil { // one migrator at a time
		return err
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
	return tx.Commit(ctx)
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
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM blueprints WHERE name='default')`).Scan(&exists); err != nil || exists {
		return err
	}
	var ids []int64
	for _, li := range api.DefaultLibrary() {
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO library_items(name, type, payload) VALUES ($1,$2,$3)
			ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id`, li.Name, li.Type, string(li.Payload)).Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	tree, _ := json.Marshal([]api.Node{{Kind: "assign", Items: ids}})
	_, err := tx.Exec(ctx, `INSERT INTO blueprints(name, description, tree) VALUES ('default', 'Baseline for every device', $1)`, string(tree))
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
	Assigned bool
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
		if err := q.QueryRow(ctx, `SELECT id FROM blueprints WHERE name='default'`).Scan(&def); err != nil {
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
	if res.Items, err = libraryItems(ctx, q, ids); err != nil {
		return res, err
	}
	res.Decls, err = api.Merge(res.Items)
	return res, err
}

// libraryItems loads items and returns them in the order of ids.
func libraryItems(ctx context.Context, q pgx.Tx, ids []int64) ([]api.LibraryItem, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `SELECT id, name, type, description, payload FROM library_items WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, scanItem)
	if err != nil {
		return nil, err
	}
	byID := map[int64]api.LibraryItem{}
	for _, it := range all {
		byID[it.ID] = it
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
	rows, err := s.db.Query(ctx, `SELECT id, name, type, description, payload FROM library_items ORDER BY type, name`)
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

func (s *Server) library(w http.ResponseWriter, r *http.Request, sess session) {
	items, err := s.allItems(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	use, err := s.itemUsage(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	type row struct {
		api.LibraryItem
		UsedBy []string
	}
	groups := map[string][]row{}
	var types []string
	for _, it := range items {
		if _, ok := groups[it.Type]; !ok {
			types = append(types, it.Type)
		}
		groups[it.Type] = append(groups[it.Type], row{it, use[it.ID]})
	}
	label := func(t string) string {
		if l, ok := typeLabels[t]; ok {
			return strings.ToLower(l)
		}
		return t
	}
	sort.Slice(types, func(i, j int) bool { return label(types[i]) < label(types[j]) })
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool { return strings.ToLower(g[i].Name) < strings.ToLower(g[j].Name) })
	}
	s.render(w, r, sess, "library", map[string]any{"Groups": groups, "Types": types, "AllTypes": sortedTypes()})
}

func sortedTypes() []string {
	t := make([]string, 0, len(api.Types))
	for k := range api.Types {
		t = append(t, k)
	}
	sort.Strings(t)
	return t
}

func (s *Server) libraryEdit(w http.ResponseWriter, r *http.Request, sess session) {
	it := api.LibraryItem{Type: r.URL.Query().Get("type")}
	if v := r.PathValue("id"); v != "new" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			rows, qerr := s.db.Query(r.Context(), `SELECT id, name, type, description, payload FROM library_items WHERE id=$1`, id)
			if qerr == nil {
				it, err = pgx.CollectExactlyOneRow(rows, scanItem)
			} else {
				err = qerr
			}
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
	} else if q := r.URL.Query(); q.Get("from") != "" && q.Get("remote") != "" {
		var err error
		if it, err = s.flatpakTemplate(r.Context(), q.Get("from"), q.Get("remote"), q.Get("inst"), q.Get("mode")); err != nil {
			http.NotFound(w, r)
			return
		}
	} else if q.Get("from") != "" {
		var err error
		if it, err = s.sourceTemplate(r.Context(), q.Get("from"), q.Get("file"), q.Get("mode")); err != nil {
			http.NotFound(w, r)
			return
		}
	} else if ex, ok := api.Types[it.Type]; ok {
		it.Payload = json.RawMessage(ex)
	} else {
		it.Type, it.Payload = api.TypePackages, json.RawMessage(api.Types[api.TypePackages])
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, it.Payload, "", "  "); err != nil {
		pretty.WriteString(string(it.Payload))
	}
	use, err := s.itemUsage(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "item", map[string]any{"It": it, "Payload": pretty.String(), "AllTypes": sortedTypes(),
		"Example": prettyJSON(api.Types[it.Type]), "Examples": itemExamples(), "UsedBy": use[it.ID]})
}

func (s *Server) librarySave(w http.ResponseWriter, r *http.Request, sess session) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	it := api.LibraryItem{ID: id, Name: strings.TrimSpace(r.FormValue("name")), Type: r.FormValue("type"),
		Description: strings.TrimSpace(r.FormValue("description")), Payload: json.RawMessage(r.FormValue("payload"))}
	fail := func(err error) {
		s.render(w, r, sess, "item", map[string]any{"It": it, "Payload": r.FormValue("payload"), "AllTypes": sortedTypes(),
			"Example": prettyJSON(api.Types[it.Type]), "Examples": itemExamples(), "Error": err.Error()})
	}
	if it.Type == api.TypeCertificates {
		p, err := addUploadedCerts(r, it.Payload)
		if err != nil {
			fail(err)
			return
		}
		it.Payload = p
	}
	if it.Type == api.TypeBootloader { // hash a plain password before it is validated and stored
		p, err := api.PrepareBootloader(it.Payload)
		if err != nil {
			fail(err)
			return
		}
		it.Payload = p
	}
	if err := it.Validate(); err != nil {
		fail(err)
		return
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, it.Payload); err != nil {
		fail(err)
		return
	}
	err := s.auditAction(r.Context(), sess.Email, "library.save", it.Name, it.Type+" "+compact.String(), func(tx pgx.Tx) error {
		if id > 0 {
			tag, err := tx.Exec(r.Context(), `UPDATE library_items SET name=$2, type=$3, description=$4, payload=$5, updated_at=now() WHERE id=$1`,
				id, it.Name, it.Type, it.Description, compact.String())
			if err == nil && tag.RowsAffected() == 0 {
				err = errors.New("library item not found")
			}
			return err
		}
		_, err := tx.Exec(r.Context(), `INSERT INTO library_items(name, type, description, payload) VALUES ($1,$2,$3,$4)`,
			it.Name, it.Type, it.Description, compact.String())
		return err
	})
	if err != nil {
		fail(err)
		return
	}
	http.Redirect(w, r, "/library", http.StatusSeeOther)
}

func (s *Server) libraryDelete(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	use, err := s.itemUsage(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(use[id]) > 0 {
		http.Error(w, "item is used by blueprints: "+strings.Join(use[id], ", "), http.StatusConflict)
		return
	}
	err = s.auditAction(r.Context(), sess.Email, "library.delete", strconv.FormatInt(id, 10), "", func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `DELETE FROM library_items WHERE id=$1`, id)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/library", http.StatusSeeOther)
}

// ---- web: blueprints ----

func (s *Server) allBlueprints(ctx context.Context, deviceID string) ([]blueprintRec, error) {
	rows, err := s.db.Query(ctx, `SELECT b.id, b.name, b.parent_id, b.tree, b.description, b.updated_at,
		(SELECT count(*) FROM devices d WHERE NOT d.retired AND (d.blueprint_id=b.id OR (d.blueprint_id IS NULL AND b.name='default'))),
		EXISTS(SELECT 1 FROM devices d WHERE d.id=$1 AND (d.blueprint_id=b.id OR (d.blueprint_id IS NULL AND b.name='default')))
		FROM blueprints b ORDER BY b.name='default' DESC, b.name`, deviceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (blueprintRec, error) {
		var b blueprintRec
		var raw []byte
		if err := row.Scan(&b.ID, &b.Name, &b.Parent, &raw, &b.Desc, &b.Updated, &b.Devices, &b.Assigned); err != nil {
			return b, err
		}
		return b, json.Unmarshal(raw, &b.Tree)
	})
}

func (s *Server) blueprints(w http.ResponseWriter, r *http.Request, sess session) {
	bps, err := s.allBlueprints(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	names := map[int64]string{}
	for _, b := range bps {
		names[b.ID] = b.Name
	}
	s.render(w, r, sess, "blueprints", map[string]any{"Blueprints": bps, "Names": names})
}

func (s *Server) blueprintEdit(w http.ResponseWriter, r *http.Request, sess session) {
	bp := blueprintRec{Tree: []api.Node{}}
	if v := r.PathValue("id"); v != "new" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			bp, err = scanBlueprint(s.db.QueryRow(r.Context(), `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, id))
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
	} else {
		var def int64
		if err := s.db.QueryRow(r.Context(), `SELECT id FROM blueprints WHERE name='default'`).Scan(&def); err == nil {
			bp.Parent = &def
		}
	}
	tree, _ := json.MarshalIndent(bp.Tree, "", "  ")
	s.renderBlueprint(w, r, sess, bp, string(tree), "")
}

func (s *Server) renderBlueprint(w http.ResponseWriter, r *http.Request, sess session, bp blueprintRec, tree, errMsg string) {
	items, err := s.allItems(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	bps, err := s.allBlueprints(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	var parent int64
	if bp.Parent != nil {
		parent = *bp.Parent
	}
	s.render(w, r, sess, "blueprint", map[string]any{"BP": bp, "Tree": tree, "Error": errMsg, "Items": items, "Blueprints": bps,
		"ParentID": parent, "ItemsJSON": items, "FieldsJSON": api.RuleFields})
}

func (s *Server) blueprintSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	bp := blueprintRec{ID: id, Name: strings.TrimSpace(r.FormValue("name")), Desc: strings.TrimSpace(r.FormValue("description"))}
	if p, err := strconv.ParseInt(r.FormValue("parent_id"), 10, 64); err == nil && p > 0 {
		bp.Parent = &p
	}
	err := json.Unmarshal([]byte(r.FormValue("tree")), &bp.Tree)
	if err == nil && !identOK(bp.Name) {
		err = errors.New("name must be 1..64 characters: letters, digits, dot, dash, underscore")
	}
	if err == nil {
		items, ierr := s.allItems(ctx)
		if ierr != nil {
			s.fail(w, ierr)
			return
		}
		ids := map[int64]bool{}
		for _, it := range items {
			ids[it.ID] = true
		}
		err = api.ValidateTree(bp.Tree, func(i int64) bool { return ids[i] })
	}
	if err == nil && bp.Parent != nil && id > 0 {
		err = s.checkNoCycle(ctx, id, *bp.Parent)
	}
	if err != nil {
		s.renderBlueprint(w, r, sess, bp, r.FormValue("tree"), err.Error())
		return
	}
	tree, _ := json.Marshal(bp.Tree)
	err = s.auditAction(ctx, sess.Email, "blueprint.save", bp.Name, string(tree), func(tx pgx.Tx) error {
		if id > 0 {
			// the default blueprint applies by name and cannot inherit
			tag, err := tx.Exec(ctx, `UPDATE blueprints SET name=$2, description=$3, parent_id=CASE WHEN name='default' THEN NULL ELSE $4::bigint END, tree=$5, updated_at=now()
				WHERE id=$1 AND (name <> 'default' OR $2 = 'default')`, id, bp.Name, bp.Desc, bp.Parent, string(tree))
			if err == nil && tag.RowsAffected() == 0 {
				err = errors.New("blueprint not found, or default cannot be renamed")
			}
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO blueprints(name, description, parent_id, tree) VALUES ($1,$2,$3,$4)`, bp.Name, bp.Desc, bp.Parent, string(tree))
		return err
	})
	if err != nil {
		s.renderBlueprint(w, r, sess, bp, r.FormValue("tree"), err.Error())
		return
	}
	http.Redirect(w, r, "/blueprints", http.StatusSeeOther)
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

func (s *Server) blueprintDelete(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.auditAction(r.Context(), sess.Email, "blueprint.delete", strconv.FormatInt(id, 10), "devices fall back to default", func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM blueprints WHERE id=$1 AND name <> 'default'`, id)
		if err == nil && tag.RowsAffected() == 0 {
			err = errors.New("blueprint not found or is the default")
		}
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/blueprints", http.StatusSeeOther)
}

// prettyJSON indents an example payload for display.
func prettyJSON(s string) string {
	var b bytes.Buffer
	if json.Indent(&b, []byte(s), "", "  ") != nil {
		return s
	}
	return b.String()
}

// addUploadedCerts appends the certificates of an uploaded PEM file (one or
// a bundle) to a certificates payload, named after the file.
func addUploadedCerts(r *http.Request, payload json.RawMessage) (json.RawMessage, error) {
	f, hdr, err := r.FormFile("pem_file")
	if err != nil {
		return payload, nil // no upload
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 512<<10))
	if err != nil {
		return nil, err
	}
	var v struct {
		Certificates []api.Certificate `json:"certificates"`
	}
	if len(bytes.TrimSpace(payload)) > 0 {
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
	}
	// the editor's example entry is no certificate: an upload replaces it
	v.Certificates = slices.DeleteFunc(v.Certificates, func(c api.Certificate) bool { return strings.HasSuffix(strings.TrimSpace(c.PEM), "-----...") })
	base := strings.ToLower(nonName.ReplaceAllString(strings.TrimSuffix(filepath.Base(hdr.Filename), filepath.Ext(hdr.Filename)), "-"))
	base = strings.Trim(base, "-._")
	if base == "" {
		base = "certificate"
	}
	n := 0
	for rest := raw; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		name := base
		if n > 0 {
			name = fmt.Sprintf("%s-%d", base, n+1)
		}
		v.Certificates = append(v.Certificates, api.Certificate{Name: name, PEM: string(pem.EncodeToMemory(b))})
		n++
	}
	if n == 0 {
		return nil, errors.New("the uploaded file contains no PEM certificate")
	}
	return json.Marshal(v)
}

// itemExamples are the example settings per type, for the item editor to
// swap when the type changes.
func itemExamples() map[string]string {
	m := make(map[string]string, len(api.Types))
	for t, ex := range api.Types {
		m[t] = prettyJSON(ex)
	}
	return m
}
