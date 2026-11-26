package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Library items and blueprints keep every saved version (who, when, payload,
// signature), also the last one of a deleted object. The history page shows
// a line diff between two versions; a rollback saves an old version again as
// a new version, audited like any save.

// ---- storing versions ----

// ensureItemBaseline keeps the current row as version 1 when the item has no
// version yet (created by a migration since the last start).
func ensureItemBaseline(ctx context.Context, tx pgx.Tx, id int64) error {
	payload, err := versionPayload(ctx, tx, id)
	if payload == nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO library_item_versions(item_id, version, name, type, description, payload, signature, note, created_by, created_at)
		SELECT i.id, 1, i.name, i.type, i.description, $2, i.signature, 'baseline', 'system', i.updated_at FROM library_items i
		WHERE i.id = $1 AND NOT EXISTS (SELECT 1 FROM library_item_versions v WHERE v.item_id = i.id)`, id, payload)
	return err
}

// recordItemVersion stores the item row as it is now as its next version.
func recordItemVersion(ctx context.Context, tx pgx.Tx, id int64, by, note string, deleted bool) error {
	payload, err := versionPayload(ctx, tx, id)
	if payload == nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO library_item_versions(item_id, version, name, type, description, payload, signature, deleted, note, created_by)
		SELECT i.id, coalesce((SELECT max(version) FROM library_item_versions WHERE item_id = i.id), 0) + 1,
			i.name, i.type, i.description, $5, i.signature, $3, $4, $2
		FROM library_items i WHERE i.id = $1`, id, by, deleted, note, payload)
	return err
}

// versionPayload is the payload a version of the item keeps: network
// secrets masked, so they live in library_items only and never in the
// append only history (a rollback takes them from the current item).
// nil when the item does not exist.
func versionPayload(ctx context.Context, tx pgx.Tx, id int64) (any, error) {
	var typ string
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT type, payload FROM library_items WHERE id=$1`, id).Scan(&typ, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if typ == api.TypeNetwork {
		payload = api.MaskNetworkSecrets(payload)
	}
	return string(payload), nil
}

func ensureBlueprintBaseline(ctx context.Context, tx pgx.Tx, id int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO blueprint_versions(blueprint_id, version, name, description, parent_id, tree, note, created_by, created_at)
		SELECT b.id, 1, b.name, b.description, b.parent_id, b.tree, 'baseline', 'system', b.updated_at FROM blueprints b
		WHERE b.id = $1 AND NOT EXISTS (SELECT 1 FROM blueprint_versions v WHERE v.blueprint_id = b.id)`, id)
	return err
}

func recordBlueprintVersion(ctx context.Context, tx pgx.Tx, id int64, by, note string, deleted bool) error {
	_, err := tx.Exec(ctx, `INSERT INTO blueprint_versions(blueprint_id, version, name, description, parent_id, tree, deleted, note, created_by)
		SELECT b.id, coalesce((SELECT max(version) FROM blueprint_versions WHERE blueprint_id = b.id), 0) + 1,
			b.name, b.description, b.parent_id, b.tree, $3, $4, $2
		FROM blueprints b WHERE b.id = $1`, id, by, deleted, note)
	return err
}

// ---- reading versions ----

type version struct {
	Version int
	At      time.Time
	By      string
	Note    string
	Deleted bool
	Doc     string // the text the diff compares
	Item    api.LibraryItem
	BP      blueprintRec
}

func (s *Server) itemVersions(ctx context.Context, id int64) ([]version, error) {
	rows, err := s.db.Query(ctx, `SELECT version, created_at, created_by, note, deleted, name, type, description, payload
		FROM library_item_versions WHERE item_id = $1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (version, error) {
		var v version
		var raw []byte
		err := row.Scan(&v.Version, &v.At, &v.By, &v.Note, &v.Deleted, &v.Item.Name, &v.Item.Type, &v.Item.Description, &raw)
		v.Item.ID, v.Item.Payload = id, raw
		v.Doc = itemDoc(v.Item)
		return v, err
	})
}

func (s *Server) blueprintVersions(ctx context.Context, id int64) ([]version, error) {
	names := map[int64]string{}
	if rows, err := s.db.Query(ctx, `SELECT id, name FROM blueprints`); err == nil {
		for rows.Next() {
			var i int64
			var n string
			if rows.Scan(&i, &n) == nil {
				names[i] = n
			}
		}
		rows.Close()
	}
	rows, err := s.db.Query(ctx, `SELECT version, created_at, created_by, note, deleted, name, description, parent_id, tree
		FROM blueprint_versions WHERE blueprint_id = $1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (version, error) {
		var v version
		var raw []byte
		if err := row.Scan(&v.Version, &v.At, &v.By, &v.Note, &v.Deleted, &v.BP.Name, &v.BP.Desc, &v.BP.Parent, &raw); err != nil {
			return v, err
		}
		v.BP.ID = id
		if err := json.Unmarshal(raw, &v.BP.Tree); err != nil {
			return v, err
		}
		v.Doc = blueprintDoc(v.BP, names)
		return v, nil
	})
}

// itemDoc is the readable text of an item version: header fields, then the
// settings as indented JSON.
func itemDoc(it api.LibraryItem) string {
	payload := it.Payload
	if it.Type == api.TypeNetwork { // diffs never show network secrets
		payload = api.MaskNetworkSecrets(payload)
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, canonicalJSON(payload), "", "  ") != nil { // JSONB reorders keys
		pretty.Write(payload)
	}
	return fmt.Sprintf("name: %s\ntype: %s\ndescription: %s\n\n%s\n", it.Name, it.Type, it.Description, pretty.String())
}

func blueprintDoc(b blueprintRec, names map[int64]string) string {
	parent := "none"
	if b.Parent != nil {
		parent = firstNonEmpty(names[*b.Parent], "#"+strconv.FormatInt(*b.Parent, 10))
	}
	tree, _ := json.MarshalIndent(b.Tree, "", "  ")
	return fmt.Sprintf("name: %s\ndescription: %s\ninherits from: %s\n\n%s\n", b.Name, b.Desc, parent, tree)
}

// ---- diff ----

type diffLine struct {
	Op   string // "same", "add", "del"
	Text string
}

// lineDiff compares two texts line by line (longest common subsequence).
// ponytail: O(n*m) table, falls back to "all removed, all added" above 4M cells.
func lineDiff(a, b string) []diffLine {
	x, y := strings.Split(strings.TrimRight(a, "\n"), "\n"), strings.Split(strings.TrimRight(b, "\n"), "\n")
	if len(x)*len(y) > 4_000_000 {
		var out []diffLine
		for _, l := range x {
			out = append(out, diffLine{"del", l})
		}
		for _, l := range y {
			out = append(out, diffLine{"add", l})
		}
		return out
	}
	n, m := len(x), len(y)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []diffLine
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			out = append(out, diffLine{"same", x[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, diffLine{"del", x[i]})
			i++
		default:
			out = append(out, diffLine{"add", y[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, diffLine{"del", x[i]})
	}
	for ; j < m; j++ {
		out = append(out, diffLine{"add", y[j]})
	}
	return out
}

// ---- affected devices (preview before saving) ----

// affectedDevices lists the active devices whose effective blueprint is one
// of roots or inherits from one.
func (s *Server) affectedDevices(ctx context.Context, roots []int64) ([]deviceRow, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id, parent_id FROM blueprints`)
	if err != nil {
		return nil, err
	}
	children := map[int64][]int64{}
	for rows.Next() {
		var id int64
		var parent *int64
		if err := rows.Scan(&id, &parent); err != nil {
			rows.Close()
			return nil, err
		}
		if parent != nil {
			children[*parent] = append(children[*parent], id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := slices.Clone(roots)
	for i := 0; i < len(ids) && i < 10000; i++ {
		for _, c := range children[ids[i]] {
			if !slices.Contains(ids, c) {
				ids = append(ids, c)
			}
		}
	}
	cond, args := tenantDevices(ctx, 1)
	return s.listDevicesWhere(ctx, `NOT d.retired AND `+cond+` AND `+effectiveBlueprintSQL+` = ANY($1)`, append([]any{ids}, args...)...)
}

// treeUses reports whether an assignment map references the item anywhere.
func treeUses(nodes []api.Node, id int64) bool {
	for _, n := range nodes {
		if slices.Contains(n.Items, id) || treeUses(n.Else, id) {
			return true
		}
		for _, b := range n.Branches {
			if treeUses(b.Nodes, id) {
				return true
			}
		}
	}
	return false
}

// preview is what the editor shows before a save: the change against the
// stored version and the devices it reaches.
type preview struct {
	Diff       []diffLine
	Devices    []deviceRow
	Blueprints []string
}

func (s *Server) itemPreview(ctx context.Context, it api.LibraryItem) (*preview, error) {
	p := &preview{}
	old := ""
	if it.ID > 0 {
		vs, err := s.itemVersions(ctx, it.ID)
		if err != nil {
			return nil, err
		}
		if len(vs) > 0 {
			old = vs[0].Doc
		}
		bps, err := s.allBlueprints(ctx, "")
		if err != nil {
			return nil, err
		}
		var roots []int64
		for _, b := range bps {
			if treeUses(b.Tree, it.ID) {
				roots = append(roots, b.ID)
				p.Blueprints = append(p.Blueprints, b.Name)
			}
		}
		if p.Devices, err = s.affectedDevices(ctx, roots); err != nil {
			return nil, err
		}
	}
	p.Diff = lineDiff(old, itemDoc(it))
	return p, nil
}

func (s *Server) blueprintPreview(ctx context.Context, bp blueprintRec) (*preview, error) {
	p := &preview{}
	old := ""
	bps, err := s.allBlueprints(ctx, "")
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	for _, b := range bps {
		names[b.ID] = b.Name
	}
	if bp.ID > 0 {
		vs, err := s.blueprintVersions(ctx, bp.ID)
		if err != nil {
			return nil, err
		}
		if len(vs) > 0 {
			old = vs[0].Doc
		}
		if p.Devices, err = s.affectedDevices(ctx, []int64{bp.ID}); err != nil {
			return nil, err
		}
		p.Blueprints = []string{names[bp.ID]}
	}
	p.Diff = lineDiff(old, blueprintDoc(bp, names))
	return p, nil
}

// ---- web: history and rollback ----

func versionID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// pickVersions chooses the two versions to compare: ?a=old&b=new, by
// default the latest and the one before.
func pickVersions(r *http.Request, vs []version) (a, b *version) {
	find := func(key string) *version {
		n, err := strconv.Atoi(r.URL.Query().Get(key))
		if err != nil {
			return nil
		}
		for i := range vs {
			if vs[i].Version == n {
				return &vs[i]
			}
		}
		return nil
	}
	if b = find("b"); b == nil && len(vs) > 0 {
		b = &vs[0]
	}
	if a = find("a"); a == nil && b != nil {
		for i := range vs {
			if vs[i].Version < b.Version {
				a = &vs[i]
				break
			}
		}
	}
	return a, b
}

func (s *Server) renderVersions(w http.ResponseWriter, r *http.Request, sess session, kind string, id int64, vs []version, exists bool) {
	if len(vs) == 0 {
		http.NotFound(w, r)
		return
	}
	a, b := pickVersions(r, vs)
	old := ""
	if a != nil {
		old = a.Doc
	}
	name := firstNonEmpty(vs[0].Item.Name, vs[0].BP.Name)
	s.render(w, r, sess, "versions", map[string]any{"Kind": kind, "ID": id, "Name": name, "Versions": vs, "A": a, "B": b,
		"Diff": lineDiff(old, b.Doc), "Exists": exists})
}

func (s *Server) libraryHistory(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := versionID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.tenantOwns(r.Context(), sess, "library_items", id, true) {
		s.notFound(w, r, sess)
		return
	}
	vs, err := s.itemVersions(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	var exists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM library_items WHERE id=$1)`, id).Scan(&exists)
	s.renderVersions(w, r, sess, "library", id, vs, exists)
}

func (s *Server) blueprintHistory(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := versionID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.tenantOwns(r.Context(), sess, "blueprints", id, true) {
		s.notFound(w, r, sess)
		return
	}
	vs, err := s.blueprintVersions(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	var exists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM blueprints WHERE id=$1)`, id).Scan(&exists)
	s.renderVersions(w, r, sess, "blueprints", id, vs, exists)
}

// versionByNumber returns version n from a list.
func versionByNumber(vs []version, n int) (version, error) {
	for _, v := range vs {
		if v.Version == n && !v.Deleted {
			return v, nil
		}
	}
	return version{}, errors.New("version not found")
}

func (s *Server) libraryRollback(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, ok := versionID(r)
	n, err := strconv.Atoi(r.FormValue("version"))
	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}
	if !s.tenantOwns(ctx, sess, "library_items", id, false) {
		s.notFound(w, r, sess)
		return
	}
	vs, err := s.itemVersions(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	v, err := versionByNumber(vs, n)
	if err == nil {
		err = s.storeItem(ctx, sess.Email, "library.rollback", fmt.Sprintf("rollback to version %d", n), &v.Item, true)
	}
	if err != nil {
		s.errorPage(w, r, sess, http.StatusConflict, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/library/%d/history", id), http.StatusSeeOther)
}

func (s *Server) blueprintRollback(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, ok := versionID(r)
	n, err := strconv.Atoi(r.FormValue("version"))
	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}
	if !s.tenantOwns(ctx, sess, "blueprints", id, false) {
		s.notFound(w, r, sess)
		return
	}
	vs, err := s.blueprintVersions(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	v, err := versionByNumber(vs, n)
	if err == nil {
		err = s.validateBlueprint(ctx, v.BP)
	}
	if err == nil {
		err = s.storeBlueprint(ctx, sess.Email, "blueprint.rollback", fmt.Sprintf("rollback to version %d", n), &v.BP, true)
	}
	if err != nil {
		s.errorPage(w, r, sess, http.StatusConflict, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/blueprints/%d/history", id), http.StatusSeeOther)
}

type deletedObject struct {
	ID   int64
	Name string
	At   time.Time
	By   string
}

// deletedObjects lists objects whose latest version is a deletion.
func (s *Server) deletedObjects(ctx context.Context, table, idCol string) ([]deletedObject, error) {
	if ctxTenant(ctx) != 0 { // versions carry no tenant: restoring deleted objects is global
		return nil, nil
	}
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (`+idCol+`) `+idCol+`, name, created_at, created_by, deleted FROM `+table+`
		ORDER BY `+idCol+`, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []deletedObject
	for rows.Next() {
		var d deletedObject
		var deleted bool
		if err := rows.Scan(&d.ID, &d.Name, &d.At, &d.By, &deleted); err != nil {
			return nil, err
		}
		if deleted {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}
