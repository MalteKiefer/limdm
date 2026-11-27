package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// The firewall inventory of a device (R3-F): the agent reports the rules
// its host firewall holds; the console shows them grouped managed,
// foreign and system and offers per foreign rule adopt (into a firewall
// library item), keep (an exception in the item) and discard (the signed
// command firewall_remove_rule, admins, four eyes).

func init() {
	auditActions["firewall.adopt"] = "Firewall rule adopted"
	auditActions["firewall.keep"] = "Firewall rule kept as exception"
}

func (s *Server) appFirewallRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/devices/{id}/firewall", s.need("read", s.apiDeviceFirewall))
	m.HandleFunc("GET /api/v1/devices/{id}/firewall/targets", s.need("admin", s.apiFirewallTargets))
	m.HandleFunc("POST /api/v1/devices/{id}/firewall/rules/{rid}/{action}", s.need("admin", s.apiFirewallRuleAction))
}

// storeFirewall keeps the latest inventory of a device and reports whether
// the agent should send it again (the stored hash differs).
func storeFirewall(ctx context.Context, tx pgx.Tx, id string, req api.CheckinRequest) (bool, error) {
	if inv := req.Firewall; inv != nil {
		sanitizeFirewall(inv)
		_, err := tx.Exec(ctx, `INSERT INTO device_firewall(device_id, inventory, hash, updated_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (device_id) DO UPDATE SET inventory=EXCLUDED.inventory, hash=EXCLUDED.hash, updated_at=now()`, id, jsonb(inv), truncate(req.FirewallHash, 128))
		return false, err
	}
	if req.FirewallHash == "" { // agent before the inventory
		return false, nil
	}
	var hash string
	err := tx.QueryRow(ctx, `SELECT hash FROM device_firewall WHERE device_id=$1`, id).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	return err == nil && hash != req.FirewallHash, err
}

// sanitizeFirewall bounds what a device reports and classifies every rule
// again: the server never trusts the agent's word that a rule is foreign.
func sanitizeFirewall(inv *api.FirewallInventory) {
	if len(inv.Rules) > api.MaxFirewallRules {
		inv.Rules, inv.Truncated = inv.Rules[:api.MaxFirewallRules], true
	}
	if len(inv.Errors) > 20 {
		inv.Errors = inv.Errors[:20]
	}
	for i := range inv.Errors {
		inv.Errors[i] = truncate(inv.Errors[i], 300)
	}
	inv.Backend, inv.DefaultZone = truncate(inv.Backend, 20), truncate(inv.DefaultZone, 64)
	for i := range inv.Rules {
		r := &inv.Rules[i]
		for _, f := range []*string{&r.Source, &r.Origin, &r.Table, &r.Chain, &r.Zone, &r.Direction, &r.Action, &r.Proto, &r.Port, &r.Service,
			&r.From, &r.To, &r.Iface, &r.Handle, &r.Risk} {
			*f = truncate(*f, 200)
		}
		r.Comment, r.Raw = truncate(r.Comment, 300), truncate(r.Raw, 1000)
		origin := r.Origin
		r.Finish() // ID, match and system class from the reported fields
		if origin == api.OriginManaged && r.Origin != api.OriginSystem {
			r.Origin = api.OriginManaged
		}
	}
	if inv.Rules == nil {
		inv.Rules = []api.FirewallInvRule{}
	}
}

// loadFirewall reads the stored inventory; ok is false when the device has
// not reported one.
func loadFirewall(ctx context.Context, q rowQuerier, id string) (api.FirewallInventory, time.Time, bool, error) {
	var inv api.FirewallInventory
	var raw []byte
	var at time.Time
	err := q.QueryRow(ctx, `SELECT inventory, updated_at FROM device_firewall WHERE device_id=$1`, id).Scan(&raw, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return inv, at, false, nil
	}
	if err != nil {
		return inv, at, false, err
	}
	return inv, at, true, json.Unmarshal(raw, &inv)
}

type apiFirewallRule struct {
	api.FirewallInvRule
	Kept       bool   `json:"kept"`                  // listed in keep of the device's firewall declaration
	AdoptError string `json:"adopt_error,omitempty"` // why it cannot be adopted
}

type apiDeviceFirewallDoc struct {
	Reports   bool                  `json:"reports"`
	UpdatedAt *time.Time            `json:"updated_at"`
	Inventory api.FirewallInventory `json:"inventory"`
	Rules     []apiFirewallRule     `json:"rules"`
	Managed   bool                  `json:"managed"` // a firewall declaration applies to the device
}

// apiDeviceFirewall returns the firewall inventory of a device with the
// exceptions of its declaration.
func (s *Server) apiDeviceFirewall(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	ctx := r.Context()
	doc := apiDeviceFirewallDoc{Rules: []apiFirewallRule{}}
	var keep []string
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		inv, at, ok, err := loadFirewall(ctx, tx, id)
		if err != nil {
			return err
		}
		doc.Inventory, doc.Reports = inv, ok
		if ok {
			doc.UpdatedAt = &at
		}
		decls, err := effectiveDeclarations(ctx, tx, id)
		if err != nil {
			return err
		}
		for _, d := range decls {
			if d.Type == api.TypeFirewall {
				var f api.Firewall
				if err := json.Unmarshal(d.Payload, &f); err != nil {
					return err
				}
				doc.Managed, keep = true, f.Keep
			}
		}
		return nil
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if doc.Inventory.Rules == nil {
		doc.Inventory.Rules = []api.FirewallInvRule{}
	}
	for _, fr := range doc.Inventory.Rules {
		ar := apiFirewallRule{FirewallInvRule: fr}
		if fr.Origin == api.OriginForeign {
			ar.Kept = slices.Contains(keep, fr.Match)
			if _, err := api.AdoptFragment(fr, doc.Inventory); err != nil {
				ar.AdoptError = err.Error()
			}
		}
		doc.Rules = append(doc.Rules, ar)
	}
	doc.Inventory.Rules = nil // once, in rules
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, doc)
}

// foreignRule finds a rule of the stored inventory that is foreign; the
// server classifies again (RemovableRule checks SystemRule itself).
func foreignRule(ctx context.Context, q rowQuerier, deviceID, ruleID string) (api.FirewallInvRule, api.FirewallInventory, error) {
	inv, _, ok, err := loadFirewall(ctx, q, deviceID)
	if err != nil {
		return api.FirewallInvRule{}, inv, err
	}
	fr, found := inv.FindRule(ruleID)
	if !ok || !found {
		return fr, inv, invalid("rule_id", errors.New("the rule is not in the device's firewall inventory (it changed meanwhile)"))
	}
	if err := api.RemovableRule(fr, true); err != nil {
		return fr, inv, invalid("rule_id", err)
	}
	return fr, inv, nil
}

// firewallRemovePayload builds the payload of firewall_remove_rule from the
// command parameters rule_id and confirm_risk.
func (s *Server) firewallRemovePayload(r *http.Request, deviceID string) ([]byte, error) {
	fr, _, err := foreignRule(r.Context(), s.db, deviceID, strings.TrimSpace(r.FormValue("rule_id")))
	if err != nil {
		var fe *fieldError
		if errors.As(err, &fe) {
			return nil, errors.New(fe.Msg)
		}
		return nil, err
	}
	p := api.FirewallRemoveRule{ID: fr.ID, Raw: fr.Raw, ConfirmRisk: r.FormValue("confirm_risk") == "on" || r.FormValue("confirm_risk") == "1"}
	if err := api.RemovableRule(fr, p.ConfirmRisk); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// apiFirewallRuleAction adopts a foreign rule into a firewall library item
// or keeps it as an exception there. item_id 0 creates the item (name) and
// assigns it in the blueprint blueprint_id the caller picked (firewallTargets):
// item and assignment are written in one transaction, so a failure leaves
// no item behind. A blueprint that is the global default or reaches more
// devices than this one needs confirm. An existing item goes through the
// normal library save: validation, signature, audit and four eyes.
func (s *Server) apiFirewallRuleAction(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if action != "adopt" && action != "keep" {
		problem(w, http.StatusNotFound, "unknown action")
		return
	}
	retired, ok := s.deviceFound(w, r, c, id)
	if !ok {
		return
	}
	if retired {
		problem(w, http.StatusConflict, "the device is retired")
		return
	}
	var body struct {
		ItemID      int64  `json:"item_id"`
		Name        string `json:"name"`
		BlueprintID int64  `json:"blueprint_id"`
		Confirm     bool   `json:"confirm"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ctx := r.Context()
	fr, inv, err := foreignRule(ctx, s.db, id, r.PathValue("rid"))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	it := api.LibraryItem{Type: api.TypeFirewall, Name: strings.TrimSpace(body.Name)}
	var f api.Firewall
	if body.ItemID > 0 {
		if err := tenantGuard(ctx, s.db, "library_items", body.ItemID); err != nil {
			s.apiFail(w, err)
			return
		}
		var raw []byte
		if err := s.db.QueryRow(ctx, `SELECT id, name, type, description, payload FROM library_items WHERE id=$1`, body.ItemID).
			Scan(&it.ID, &it.Name, &it.Type, &it.Description, &raw); err != nil {
			s.apiActionFail(w, err)
			return
		}
		if it.Type != api.TypeFirewall {
			problemField(w, http.StatusUnprocessableEntity, "item_id", "not a firewall library item")
			return
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			s.apiFail(w, err)
			return
		}
	} else {
		if it.Name == "" {
			problemField(w, http.StatusUnprocessableEntity, "name", "name of the new firewall item")
			return
		}
		// enforce stays off: a new item never switches a firewall on
		it.Description = "Rules adopted from device firewalls."
	}
	if action == "adopt" {
		f, err = api.AdoptInto(f, fr, inv)
	} else {
		f, err = api.KeepInto(f, fr)
	}
	if err != nil {
		problemField(w, http.StatusUnprocessableEntity, "rule_id", err.Error())
		return
	}
	if it.Payload, err = json.Marshal(f); err != nil {
		s.apiFail(w, err)
		return
	}
	created := it.ID == 0
	if created {
		if err := s.adoptIntoNewItem(ctx, c.actor(), id, &it, body.BlueprintID, body.Confirm); err != nil {
			s.apiFail(w, err)
			return
		}
	} else if err := s.saveLibraryItem(ctx, c.actor(), &it); err != nil {
		if aid, ok := pendingApproval(err); ok { // four eyes: another admin decides
			writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": aid, "status": "pending"})
			return
		}
		s.apiFail(w, err)
		return
	}
	if err := s.auditAction(ctx, c.actor(), "firewall."+action, id, fmt.Sprintf("item %d %s: %s", it.ID, it.Name, fr.Match), nil); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"item_id": it.ID, "item_name": it.Name, "created": created})
}

// firewallTarget is a blueprint a new firewall item can be assigned in.
type firewallTarget struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Devices       int    `json:"devices"`        // active devices the blueprint reaches, its children included
	GlobalDefault bool   `json:"global_default"` // the default blueprint of the whole installation
	Device        bool   `json:"device"`         // the device's own effective blueprint
}

// firewallTargets are the blueprints the caller may assign a new firewall
// item in for the device: for a tenant account only blueprints of its own
// tenant (never the global default), for the whole installation those of
// the device's tenant and of the default tenant.
func firewallTargets(ctx context.Context, q pgx.Tx, deviceID string) ([]firewallTarget, error) {
	var devTenant, eff int64
	if err := q.QueryRow(ctx, `SELECT d.tenant_id, `+effectiveBlueprintSQL+` FROM devices d WHERE d.id=$1`, deviceID).Scan(&devTenant, &eff); err != nil {
		return nil, err
	}
	reach := map[int64]int{}
	rows, err := q.Query(ctx, `SELECT `+effectiveBlueprintSQL+`, count(*)::int FROM devices d WHERE NOT d.retired GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b *int64
		var n int
		if err := rows.Scan(&b, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if b != nil {
			reach[*b] = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	type bp struct {
		firewallTarget
		parent *int64
		tenant int64
	}
	var all []bp
	rows, err = q.Query(ctx, `SELECT id, name, parent_id, tenant_id FROM blueprints ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b bp
		if err := rows.Scan(&b.ID, &b.Name, &b.parent, &b.tenant); err != nil {
			rows.Close()
			return nil, err
		}
		b.GlobalDefault = b.Name == "default" && b.tenant == defaultTenant
		b.Device = b.ID == eff
		all = append(all, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// a blueprint reaches its own devices and those of every descendant
	var count func(id int64, depth int) int
	count = func(id int64, depth int) int {
		n := reach[id]
		for _, c := range all {
			if c.parent != nil && *c.parent == id && depth < 10 {
				n += count(c.ID, depth+1)
			}
		}
		return n
	}
	t := ctxTenant(ctx)
	out := []firewallTarget{}
	for _, b := range all {
		if t != 0 && (b.tenant != t || b.GlobalDefault) || t == 0 && b.tenant != devTenant && b.tenant != defaultTenant {
			continue
		}
		b.Devices = count(b.ID, 0)
		out = append(out, b.firewallTarget)
	}
	return out, nil
}

func (s *Server) apiFirewallTargets(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	var list []firewallTarget
	err := pgx.BeginFunc(r.Context(), s.db, func(tx pgx.Tx) error {
		var err error
		list, err = firewallTargets(r.Context(), tx, id)
		return err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"items": list})
}

// adoptIntoNewItem writes the new firewall item and its assignment in the
// picked blueprint in one transaction with both audit entries and versions.
// It checks the blueprint against firewallTargets before anything is
// written. Firewall items never wait for four eyes (not a root type); if
// that changes, the request is refused instead of leaving a lone item.
func (s *Server) adoptIntoNewItem(ctx context.Context, actor, deviceID string, it *api.LibraryItem, blueprintID int64, confirm bool) error {
	if err := it.Validate(); err != nil {
		return invalid(itemField(*it, err), err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, it.Payload); err != nil {
		return invalid("payload", err)
	}
	it.Payload = compact.Bytes()
	if s.itemNeedsApproval(*it) {
		return &userError{http.StatusConflict, "this item needs four eyes approval: adopt the rule into an existing firewall item"}
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		targets, err := firewallTargets(ctx, tx, deviceID)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(targets, func(t firewallTarget) bool { return t.ID == blueprintID })
		if i < 0 {
			return invalid("blueprint_id", errors.New("pick a blueprint of your tenant that this device can use"))
		}
		target := targets[i]
		if (target.GlobalDefault || target.Devices > 1) && !confirm {
			what := ""
			if target.GlobalDefault {
				what = " (the default blueprint of the whole installation)"
			}
			return invalid("confirm", fmt.Errorf("blueprint %s reaches %d devices%s: confirm to assign the new item there", target.Name, target.Devices, what))
		}
		if err := writeItem(ctx, tx, actor, "save", it, false); err != nil {
			return err
		}
		if err := audit(ctx, tx, actor, "library.save", it.Name, itemDetail(*it, "save")); err != nil {
			return err
		}
		var name string
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT name, tree FROM blueprints WHERE id=$1 FOR UPDATE`, blueprintID).Scan(&name, &raw); err != nil {
			return err
		}
		var tree []api.Node
		if err := json.Unmarshal(raw, &tree); err != nil {
			return err
		}
		tree = append(tree, api.Node{Kind: "assign", Items: []int64{it.ID}})
		if err := api.ValidateTree(tree, func(int64) bool { return true }); err != nil { // the other items were valid before
			return invalid("tree", err)
		}
		if err := ensureBlueprintBaseline(ctx, tx, blueprintID); err != nil {
			return err
		}
		b, _ := json.Marshal(tree)
		if _, err := tx.Exec(ctx, `UPDATE blueprints SET tree=$2, updated_at=now() WHERE id=$1`, blueprintID, string(b)); err != nil {
			return err
		}
		if err := recordBlueprintVersion(ctx, tx, blueprintID, actor, "save", false); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "blueprint.save", name, string(b))
	})
}
