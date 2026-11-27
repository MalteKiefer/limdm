package server

import (
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
// assigns it in the device's blueprint. Both go through the normal library
// save: validation, signature, audit and four eyes.
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
		ItemID int64  `json:"item_id"`
		Name   string `json:"name"`
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
	if err := s.saveLibraryItem(ctx, c.actor(), &it); err != nil {
		if aid, ok := pendingApproval(err); ok { // four eyes: another admin decides
			writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": aid, "status": "pending"})
			return
		}
		s.apiFail(w, err)
		return
	}
	if created {
		if err := s.assignToDeviceBlueprint(ctx, c.actor(), id, it.ID); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	if err := s.auditAction(ctx, c.actor(), "firewall."+action, id, fmt.Sprintf("item %d %s: %s", it.ID, it.Name, fr.Match), nil); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"item_id": it.ID, "item_name": it.Name, "created": created})
}

// assignToDeviceBlueprint adds an item to the blueprint the device resolves
// to (the last of its chain), through the normal blueprint save.
func (s *Server) assignToDeviceBlueprint(ctx context.Context, actor, deviceID string, itemID int64) error {
	var bp blueprintRec
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		res, err := resolveDevice(ctx, tx, deviceID)
		if err != nil {
			return err
		}
		if len(res.Chain) == 0 {
			return errors.New("the device has no blueprint")
		}
		bp = res.Chain[len(res.Chain)-1]
		return nil
	})
	if err != nil {
		return err
	}
	bp.Tree = append(bp.Tree, api.Node{Kind: "assign", Items: []int64{itemID}})
	return s.saveBlueprint(ctx, actor, &bp)
}
