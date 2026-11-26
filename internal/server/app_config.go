package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// API of the configuration area of the console app (/app/config): the
// blueprint and library overviews with usage and assignment sources, the
// review of a change before it is saved, versions with rollback and the
// restore of deleted objects. Saves and deletes stay on the admin API
// (/api/v1/library-items, /api/v1/blueprints), which share the console's
// functions; everything here calls the same functions as the console pages.

func (s *Server) appConfigRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/config/blueprints", s.need("read", s.apiConfigBlueprints))
	m.HandleFunc("POST /api/v1/config/blueprints/preview", s.need("admin", unscopedAPI(s.apiConfigBlueprintPreview)))
	m.HandleFunc("GET /api/v1/config/library", s.need("read", s.apiConfigLibrary))
	m.HandleFunc("POST /api/v1/config/library/preview", s.need("admin", unscopedAPI(s.apiConfigItemPreview)))
	m.HandleFunc("GET /api/v1/config/{kind}/{id}/versions", s.need("read", unscopedAPI(s.apiConfigVersions)))
	m.HandleFunc("POST /api/v1/config/{kind}/{id}/rollback", s.need("admin", unscopedAPI(s.apiConfigRollback)))
	m.HandleFunc("POST /api/v1/config/blueprints/{id}/pilot", s.need("admin", unscopedAPI(s.apiConfigPilotStart)))
	m.HandleFunc("POST /api/v1/config/blueprints/{id}/pilot/{op}", s.need("admin", unscopedAPI(s.apiConfigPilotEnd)))
	s.appConfigSoftwareRoutes(m)
}

// configKinds maps the {kind} of a versions route to its table.
var configKinds = map[string]string{"blueprints": "blueprints", "library": "library_items"}

type apiBlueprintSource struct {
	Kind     string `json:"kind"` // device, group or default
	Group    string `json:"group,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Devices  int    `json:"devices,omitempty"` // kind device: devices with it set directly
}

type apiBlueprintRow struct {
	apiBlueprint
	Parent    string               `json:"parent"`
	Devices   int                  `json:"devices"`
	Status    map[string]int       `json:"status"` // devices by compliance status
	Items     int                  `json:"items"`  // distinct library items in the map
	Sources   []apiBlueprintSource `json:"sources"`
	ReadOnly  bool                 `json:"read_only"` // a shared blueprint of the default tenant seen by a tenant
	Deletable bool                 `json:"deletable"`
	Inherited []int64              `json:"inherited"`          // ancestors, root first
	Pilot     *apiPilot            `json:"pilot,omitempty"`    // a running pilot of a change
	PilotOf   int64                `json:"pilot_of,omitempty"` // this is the pilot copy of that blueprint
}

type apiDeleted struct {
	ID   int64     `json:"id"`
	Name string    `json:"name"`
	At   time.Time `json:"at"`
	By   string    `json:"by"`
}

func toAPIDeleted(ds []deletedObject) []apiDeleted {
	out := []apiDeleted{}
	for _, d := range ds {
		out = append(out, apiDeleted(d))
	}
	return out
}

// treeItems lists the distinct library items an assignment map references.
func treeItems(nodes []api.Node, out []int64) []int64 {
	for _, n := range nodes {
		for _, id := range n.Items {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
		for _, b := range n.Branches {
			out = treeItems(b.Nodes, out)
		}
		out = treeItems(n.Else, out)
	}
	return out
}

// owned reports which of ids (rows of table) the tenant a request acts for
// may change: global requests every row, tenants only their own.
func (s *Server) owned(ctx context.Context, table string) (func(int64) bool, error) {
	t := ctxTenant(ctx)
	if t == 0 {
		return func(int64) bool { return true }, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id FROM `+table+` WHERE tenant_id=$1`, t)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	return func(id int64) bool { return slices.Contains(ids, id) }, nil
}

func (s *Server) apiConfigBlueprints(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	bps, err := s.allBlueprints(ctx, "")
	if err != nil {
		s.apiFail(w, err)
		return
	}
	assign, err := s.blueprintAssignments(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	own, err := s.owned(ctx, "blueprints")
	if err != nil {
		s.apiFail(w, err)
		return
	}
	// compliance of each blueprint: its devices by status
	dcond, dargs := tenantDevices(ctx, 0)
	devs, err := s.listDevicesWhere(ctx, `NOT d.retired AND `+dcond, dargs...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	status := map[string]map[string]int{}
	for _, d := range devs {
		if status[d.Blueprints] == nil {
			status[d.Blueprints] = map[string]int{}
		}
		status[d.Blueprints][d.Status]++
	}
	pilots, err := s.pilots(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	pilotOf := map[int64]int64{}
	for bp, p := range pilots {
		pilotOf[p.ID] = bp
	}
	names, parents := map[int64]string{}, map[int64]*int64{}
	for _, b := range bps {
		names[b.ID], parents[b.ID] = b.Name, b.Parent
	}
	out := []apiBlueprintRow{}
	for _, b := range bps {
		row := apiBlueprintRow{apiBlueprint: toAPIBlueprint(b), Devices: b.Devices, Status: status[b.Name], Items: len(treeItems(b.Tree, nil)),
			Sources: []apiBlueprintSource{}, ReadOnly: !own(b.ID), Inherited: []int64{}}
		if row.Status == nil {
			row.Status = map[string]int{}
		}
		row.Deletable = !row.ReadOnly && b.Name != "default"
		if p, ok := pilots[b.ID]; ok {
			row.Pilot = &p
		}
		row.PilotOf = pilotOf[b.ID]
		row.Deletable = row.Deletable && row.Pilot == nil && row.PilotOf == 0
		if b.Parent != nil {
			row.Parent = names[*b.Parent]
		}
		for p, n := b.Parent, 0; p != nil && n < 10; p, n = parents[*p], n+1 {
			row.Inherited = append([]int64{*p}, row.Inherited...)
		}
		if a := assign[b.ID]; a != nil {
			if a.Direct > 0 {
				row.Sources = append(row.Sources, apiBlueprintSource{Kind: "device", Devices: a.Direct})
			}
			for _, g := range a.Groups {
				row.Sources = append(row.Sources, apiBlueprintSource{Kind: "group", Group: g.Group, Priority: g.Priority})
			}
		}
		if b.Name == "default" {
			row.Sources = append(row.Sources, apiBlueprintSource{Kind: "default"})
		}
		out = append(out, row)
	}
	deleted, err := s.deletedObjects(ctx, "blueprint_versions", "blueprint_id")
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"items": out, "deleted": toAPIDeleted(deleted), "rule_fields": api.RuleFields})
}

type apiLibraryRow struct {
	api.LibraryItem
	UpdatedAt time.Time `json:"updated_at"`
	UsedBy    []string  `json:"used_by"`
	Invalid   bool      `json:"invalid"`   // signature fails: not delivered until saved again
	ReadOnly  bool      `json:"read_only"` // shared item of the default tenant seen by a tenant
}

func (s *Server) apiConfigLibrary(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	cond, args := visibleCond(ctx, "i", 0)
	rows, err := s.db.Query(ctx, `SELECT id, name, type, description, payload, signature, updated_at FROM library_items i WHERE `+cond+` ORDER BY type, lower(name)`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	use, err := s.itemUsage(ctx)
	if err != nil {
		rows.Close()
		s.apiFail(w, err)
		return
	}
	own, err := s.owned(ctx, "library_items")
	if err != nil {
		rows.Close()
		s.apiFail(w, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (apiLibraryRow, error) {
		var it apiLibraryRow
		var raw []byte
		var sig string
		if err := row.Scan(&it.ID, &it.Name, &it.Type, &it.Description, &raw, &sig, &it.UpdatedAt); err != nil {
			return it, err
		}
		it.Payload, it.Invalid = raw, !itemSignatureOK(it.Name, it.Type, raw, sig)
		maskItem(&it.LibraryItem)
		it.UsedBy = nonNil(use[it.ID])
		it.ReadOnly = !own(it.ID)
		return it, nil
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if out == nil {
		out = []apiLibraryRow{}
	}
	deleted, err := s.deletedObjects(ctx, "library_item_versions", "item_id")
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"items": out, "deleted": toAPIDeleted(deleted)})
}

// ---- review before saving ----

type apiPreviewDevice struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Status   string `json:"status"`
}

// apiPreview is what the editor shows before a save: the change against the
// stored version, the devices it reaches and the expected effect.
type apiPreview struct {
	Diff          []apiDiffLine      `json:"diff"`
	Blueprints    []string           `json:"blueprints"`
	Devices       int                `json:"devices"`
	Online        int                `json:"online"` // checked in within the stale threshold
	Offline       int                `json:"offline"`
	Status        map[string]int     `json:"status"`
	Sample        []apiPreviewDevice `json:"sample"` // up to 30 devices
	NeedsApproval bool               `json:"needs_approval"`
	Impact        []apiImpact        `json:"impact"`
}

type apiDiffLine struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// apiImpact is one expected effect of a change, a code with values the
// console words: compliance level, checks excluded or advisory, items
// added to or removed from a blueprint.
type apiImpact struct {
	Code   string   `json:"code"`
	Values []string `json:"values"`
}

func (s *Server) toAPIPreview(p *preview) apiPreview {
	out := apiPreview{Diff: []apiDiffLine{}, Blueprints: nonNil(p.Blueprints), Devices: len(p.Devices), Status: map[string]int{},
		Sample: []apiPreviewDevice{}, Impact: []apiImpact{}}
	for _, d := range p.Diff {
		out.Diff = append(out.Diff, apiDiffLine(d))
	}
	for _, d := range p.Devices {
		out.Status[d.Status]++
		if d.Status == "stale" || d.Status == "pending" {
			out.Offline++
		} else {
			out.Online++
		}
		if len(out.Sample) < 30 {
			out.Sample = append(out.Sample, apiPreviewDevice{d.ID, d.Hostname, d.Status})
		}
	}
	return out
}

func (s *Server) apiConfigItemPreview(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	var it api.LibraryItem
	if !decodeJSON(w, r, &it) {
		return
	}
	it.Name, it.Description = strings.TrimSpace(it.Name), strings.TrimSpace(it.Description)
	if it.ID > 0 && !s.tenantOwns(ctx, c.sess(), "library_items", it.ID, false) {
		problem(w, http.StatusNotFound, "library item not found")
		return
	}
	var stored []byte
	if it.ID > 0 {
		_ = s.db.QueryRow(ctx, `SELECT payload FROM library_items WHERE id=$1`, it.ID).Scan(&stored)
	}
	if it.Type == api.TypeBootloader { // as the console: hash a plain password before validation
		p, err := api.PrepareBootloader(it.Payload)
		if err != nil {
			s.apiFail(w, invalid("payload", err))
			return
		}
		it.Payload = p
	}
	if err := s.restoreNetworkSecrets(ctx, &it); err != nil {
		s.apiFail(w, err)
		return
	}
	if err := it.Validate(); err != nil {
		s.apiFail(w, invalid(itemField(it, err), err))
		return
	}
	if err := s.checkArtifactRefs(ctx, &it); err != nil {
		s.apiFail(w, invalid("payload", err))
		return
	}
	p, err := s.itemPreview(ctx, it)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := s.toAPIPreview(p)
	out.NeedsApproval = s.itemNeedsApproval(it)
	if it.Type == api.TypeCompliance {
		out.Impact = complianceImpact(stored, it.Payload)
	}
	writeJSON(w, out)
}

// complianceImpact names what a changed compliance item changes for the
// checks: the level, newly excluded or no longer excluded checks, checks
// that become advisory or count again.
func complianceImpact(old, cur []byte) []apiImpact {
	var a, b api.Compliance
	_ = json.Unmarshal(old, &a)
	_ = json.Unmarshal(cur, &b)
	out := []apiImpact{}
	if len(old) > 0 && a.Level != b.Level {
		out = append(out, apiImpact{"level", []string{strconv.Itoa(a.Level), strconv.Itoa(b.Level)}})
	}
	add := func(code string, from, to []string) {
		var vs []string
		for _, v := range to {
			if !slices.Contains(from, v) {
				vs = append(vs, v)
			}
		}
		if len(vs) > 0 {
			out = append(out, apiImpact{code, vs})
		}
	}
	add("excluded_added", a.Exclude, b.Exclude)
	add("excluded_removed", b.Exclude, a.Exclude)
	add("advisory_added", a.Advisory, b.Advisory)
	add("advisory_removed", b.Advisory, a.Advisory)
	return out
}

type apiBlueprintInput struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ParentID    *int64     `json:"parent_id"`
	Tree        []api.Node `json:"tree"`
}

func (s *Server) apiConfigBlueprintPreview(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	var in apiBlueprintInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.ParentID != nil && *in.ParentID <= 0 {
		in.ParentID = nil
	}
	if in.Tree == nil {
		in.Tree = []api.Node{}
	}
	if in.ID > 0 && !s.tenantOwns(ctx, c.sess(), "blueprints", in.ID, false) {
		problem(w, http.StatusNotFound, "blueprint not found")
		return
	}
	bp := blueprintRec{ID: in.ID, Name: strings.TrimSpace(in.Name), Desc: strings.TrimSpace(in.Description), Parent: in.ParentID, Tree: in.Tree}
	if err := s.validateBlueprint(ctx, bp); err != nil {
		s.apiFail(w, err)
		return
	}
	p, err := s.blueprintPreview(ctx, bp)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := s.toAPIPreview(p)
	var old []api.Node
	if in.ID > 0 {
		if cur, err := scanBlueprint(s.db.QueryRow(ctx, `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, in.ID)); err == nil {
			old = cur.Tree
		}
	}
	items, err := s.allItems(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	names := map[int64]string{}
	for _, it := range items {
		names[it.ID] = it.Name
	}
	before, after := treeItems(old, nil), treeItems(bp.Tree, nil)
	diff := func(code string, from, to []int64) {
		var vs []string
		for _, id := range to {
			if !slices.Contains(from, id) {
				vs = append(vs, firstNonEmpty(names[id], "#"+strconv.FormatInt(id, 10)))
			}
		}
		if len(vs) > 0 {
			out.Impact = append(out.Impact, apiImpact{code, vs})
		}
	}
	diff("items_added", before, after)
	diff("items_removed", after, before)
	writeJSON(w, out)
}

// ---- versions and rollback ----

type apiVersion struct {
	Version int       `json:"version"`
	At      time.Time `json:"at"`
	By      string    `json:"by"`
	Note    string    `json:"note"`
	Deleted bool      `json:"deleted"`
	Doc     string    `json:"doc"` // the readable text diffs compare
}

// configVersions loads the versions of a blueprint or library item after
// the console's checks: no device scoped accounts, tenant ownership.
func (s *Server) configVersions(w http.ResponseWriter, r *http.Request, c apiCaller, shared bool) (string, int64, []version, bool) {
	table, ok := configKinds[r.PathValue("kind")]
	if !ok {
		problem(w, http.StatusNotFound, "unknown kind")
		return "", 0, nil, false
	}
	id, ok := pathID(w, r)
	if !ok {
		return "", 0, nil, false
	}
	if !s.tenantOwns(r.Context(), c.sess(), table, id, shared) {
		problem(w, http.StatusNotFound, "not found")
		return "", 0, nil, false
	}
	var vs []version
	var err error
	if table == "blueprints" {
		vs, err = s.blueprintVersions(r.Context(), id)
	} else {
		vs, err = s.itemVersions(r.Context(), id)
	}
	if err != nil {
		s.apiFail(w, err)
		return "", 0, nil, false
	}
	if len(vs) == 0 {
		problem(w, http.StatusNotFound, "no versions")
		return "", 0, nil, false
	}
	return table, id, vs, true
}

func (s *Server) apiConfigVersions(w http.ResponseWriter, r *http.Request, c apiCaller) {
	table, id, vs, ok := s.configVersions(w, r, c, true)
	if !ok {
		return
	}
	var exists bool
	if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, id).Scan(&exists); err != nil {
		s.apiFail(w, err)
		return
	}
	out := make([]apiVersion, len(vs))
	for i, v := range vs {
		out[i] = apiVersion{v.Version, v.At, v.By, v.Note, v.Deleted, v.Doc}
	}
	writeJSON(w, map[string]any{"id": id, "name": firstNonEmpty(vs[0].Item.Name, vs[0].BP.Name), "exists": exists, "items": out})
}

// apiConfigRollback saves an old version again as the newest one, or
// restores a deleted object, as the console's rollback does (four eyes for
// root effective library items).
func (s *Server) apiConfigRollback(w http.ResponseWriter, r *http.Request, c apiCaller) {
	table, id, vs, ok := s.configVersions(w, r, c, false)
	if !ok {
		return
	}
	var body struct {
		Version int `json:"version"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	v, err := versionByNumber(vs, body.Version)
	if err != nil {
		problem(w, http.StatusNotFound, err.Error())
		return
	}
	ctx, note := r.Context(), fmt.Sprintf("rollback to version %d", body.Version)
	if table == "blueprints" {
		err = s.validateBlueprint(ctx, v.BP)
		if err == nil {
			err = s.storeBlueprint(ctx, c.actor(), "blueprint.rollback", note, &v.BP, true)
		}
	} else {
		err = s.storeItem(ctx, c.actor(), "library.rollback", note, &v.Item, true)
	}
	if aid, ok := pendingApproval(err); ok {
		w.Header().Set("Location", "/api/v1/approvals/"+strconv.FormatInt(aid, 10))
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": aid, "status": "pending"})
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "status": "saved"})
}
