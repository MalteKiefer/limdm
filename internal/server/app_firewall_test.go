package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestAppFirewall(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	inv := &api.FirewallInventory{Backend: "ufw", Active: true, Policy: api.FirewallPolicies{In: "deny", Out: "allow"}, Rules: []api.FirewallInvRule{
		{Source: "ufw", Origin: "foreign", Direction: "in", Action: "allow", Port: "8080", Proto: "tcp", Raw: "ufw allow 8080/tcp"},
		{Source: "ufw", Origin: "foreign", Direction: "in", Action: "allow", Port: "22", Proto: "tcp", Raw: "ufw allow 22", Risk: "ssh"},
		// the agent claims foreign; the server classifies it as Docker's
		{Source: "iptables", Origin: "foreign", Table: "filter", Chain: "FORWARD", Direction: "forward", Action: "accept", Raw: "-A FORWARD -o docker0 -j ACCEPT"},
	}}
	store := func(req api.CheckinRequest) bool {
		t.Helper()
		var need bool
		if err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) (err error) { need, err = storeFirewall(ctx, tx, "d1", req); return err }); err != nil {
			t.Fatal(err)
		}
		return need
	}
	if !store(api.CheckinRequest{FirewallHash: "h1"}) {
		t.Fatal("no inventory stored, but not asked for")
	}
	if store(api.CheckinRequest{Firewall: inv, FirewallHash: "h1"}) || store(api.CheckinRequest{FirewallHash: "h1"}) || !store(api.CheckinRequest{FirewallHash: "h2"}) {
		t.Fatal("need firewall")
	}
	if store(api.CheckinRequest{}) {
		t.Fatal("old agent asked for an inventory")
	}
	code, body := call(dashAuditor, "GET", "/api/v1/devices/d1/firewall", ``)
	var doc struct {
		Reports bool
		Rules   []apiFirewallRule
	}
	if json.Unmarshal([]byte(body), &doc); code != 200 || !doc.Reports || len(doc.Rules) != 3 {
		t.Fatalf("get: %d %s", code, body)
	}
	web, ssh, docker := doc.Rules[0], doc.Rules[1], doc.Rules[2]
	if docker.Origin != api.OriginSystem || web.Origin != api.OriginForeign || web.AdoptError != "" || docker.ID == "" {
		t.Fatalf("classes: %+v", doc.Rules)
	}
	cmd := func(sess session, rule string, confirm bool) (int, string) {
		b, _ := json.Marshal(map[string]any{"type": "firewall_remove_rule", "params": map[string]any{"rule_id": rule, "confirm_risk": confirm}})
		return call(sess, "POST", "/api/v1/devices/d1/commands", string(b))
	}
	if code, _ := cmd(dashHelpdesk, web.ID, false); code != 403 {
		t.Fatalf("helpdesk discard: %d", code)
	}
	if code, body := cmd(dashAdmin, docker.ID, true); code != 422 || !strings.Contains(body, "never removed") {
		t.Fatalf("system discard: %d %s", code, body)
	}
	if code, body := cmd(dashAdmin, ssh.ID, false); code != 422 || !strings.Contains(body, "confirm the risk") {
		t.Fatalf("ssh discard: %d %s", code, body)
	}
	if code, body := cmd(dashAdmin, ssh.ID, true); code != 202 || !strings.Contains(body, "approval_id") {
		t.Fatalf("discard with four eyes: %d %s", code, body)
	}
	var payload string
	if err := db.QueryRow(ctx, `SELECT payload->>'payload' FROM approvals WHERE target='d1' ORDER BY id DESC LIMIT 1`).Scan(&payload); err != nil ||
		!strings.Contains(payload, `"raw":"ufw allow 22"`) || !strings.Contains(payload, `"confirm_risk":true`) {
		t.Fatalf("approval payload %q %v", payload, err)
	}
	// adopt into a new item: created, not enforcing, assigned in the device's blueprint
	if code, _ := call(dashHelpdesk, "POST", "/api/v1/devices/d1/firewall/rules/"+web.ID+"/adopt", `{"name":"adopted"}`); code != 403 {
		t.Fatalf("helpdesk adopt: %d", code)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/devices/d1/firewall/rules/"+docker.ID+"/adopt", `{"name":"adopted"}`); code != 422 {
		t.Fatalf("system adopt: %d %s", code, body)
	}
	code, body = call(dashAdmin, "POST", "/api/v1/devices/d1/firewall/rules/"+web.ID+"/adopt", `{"name":"adopted"}`)
	var res struct {
		ItemID  int64 `json:"item_id"`
		Created bool
	}
	if json.Unmarshal([]byte(body), &res); code != 200 || !res.Created || res.ItemID == 0 {
		t.Fatalf("adopt: %d %s", code, body)
	}
	var raw string
	var assigned bool
	if err := db.QueryRow(ctx, `SELECT payload::text, EXISTS(SELECT 1 FROM blueprints WHERE name='default' AND tree::text LIKE '%'||$2||'%') FROM library_items WHERE id=$1`,
		res.ItemID, itoa(res.ItemID)).Scan(&raw, &assigned); err != nil || !strings.Contains(raw, `"8080/tcp"`) || !strings.Contains(raw, `"enforce": false`) || !assigned {
		t.Fatalf("item %s assigned=%v %v", raw, assigned, err)
	}
	// keep into the same item; the page lists it as accepted
	if code, body := call(dashAdmin, "POST", "/api/v1/devices/d1/firewall/rules/"+ssh.ID+"/keep", `{"item_id":`+itoa(res.ItemID)+`}`); code != 200 {
		t.Fatalf("keep: %d %s", code, body)
	}
	_, body = call(dashAuditor, "GET", "/api/v1/devices/d1/firewall", ``)
	if json.Unmarshal([]byte(body), &doc); !doc.Rules[1].Kept || doc.Rules[0].Kept {
		t.Fatalf("kept: %s", body)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action IN ('firewall.adopt', 'firewall.keep') AND target='d1'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit %d %v", n, err)
	}
	if code, _ := call(dashAuditor, "GET", "/api/v1/devices/nope/firewall", ``); code != 404 {
		t.Fatalf("unknown device: %d", code)
	}
	_ = s
}
