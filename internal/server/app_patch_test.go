package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestAdvanceRings(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	waves := []updateWave{{Wave: 1, StartedAt: now.Add(-10 * day)}, {Wave: 2, StartedAt: now.Add(-3 * day)}, {Wave: 3, StartedAt: now.Add(-time.Hour)}}
	rings := []updateRing{{Name: "pilot"}, {Name: "early", DeferralDays: 2}, {Name: "broad", DeferralDays: 7}}
	if ch := advanceRings(rings, waves, now); len(ch) != 3 || rings[0].Wave != 3 || rings[1].Wave != 2 || rings[2].Wave != 1 {
		t.Fatalf("%v %+v", ch, rings)
	}
	if ch := advanceRings(rings, waves, now); len(ch) != 0 {
		t.Fatalf("second pass changed %v", ch)
	}
	// a paused ring stops the rollout behind it
	rings = []updateRing{{Name: "pilot", Wave: 3, Paused: true}, {Name: "early", Wave: 1}}
	if advanceRings(rings, waves, now); rings[1].Wave != 1 {
		t.Fatalf("passed a paused ring: %+v", rings)
	}
	// approval caps the wave
	rings = []updateRing{{Name: "pilot", Wave: 3}, {Name: "early", RequireApproval: true, ApprovedWave: 1}}
	if advanceRings(rings, waves, now); rings[1].Wave != 1 {
		t.Fatalf("approval ignored: %+v", rings)
	}
	// the schedule of the first ring
	first := updateRing{WaveDays: 7}
	if !waveDue(first, waves[:1], now) || waveDue(first, waves, now) || waveDue(updateRing{}, nil, now) || !waveDue(first, nil, now) {
		t.Fatal("waveDue")
	}
	// membership: first ring by position, all devices as catch all
	rs := []updateRing{{ID: 1, Tags: []string{"pilot"}}, {ID: 2, Groups: []string{"IT"}}, {ID: 3, Blueprints: []int64{7}}, {ID: 4, AllDevices: true}}
	for want, dev := range map[int64]struct {
		tags, groups []string
		bps          []int64
	}{1: {[]string{"pilot"}, []string{"IT"}, nil}, 2: {nil, []string{"IT"}, []int64{7}}, 3: {nil, nil, []int64{1, 7}}, 4: {[]string{"x"}, nil, nil}} {
		if r := ringOf(rs, dev.tags, dev.groups, dev.bps); r == nil || r.ID != want {
			t.Errorf("want ring %d, got %+v", want, r)
		}
	}
	if ringOf(rs[:3], nil, nil, nil) != nil {
		t.Error("device without match is in a ring")
	}
}

func TestAppPatch(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	if code, _ := call(dashHelpdesk, "POST", "/api/v1/update-rings", `{"name":"pilot","position":1}`); code != 403 {
		t.Fatalf("helpdesk created a ring: %d", code)
	}
	// the CVE import is installation wide: not for tenant admins
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'other') ON CONFLICT DO NOTHING;
		INSERT INTO console_users(email, role, tenant_id) VALUES ('t@firma.de', 'admin', 2)`); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(session{Email: "t@firma.de", Role: "admin", Tenant: 2}, "POST", "/api/v1/updates/cve-feeds/refresh", ``); code != 403 {
		t.Fatalf("tenant admin started the CVE import: %d", code)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/update-rings", `{"name":"","position":1}`); code != 422 || !strings.Contains(body, "name") {
		t.Fatalf("empty name: %d %s", code, body)
	}
	code, body := call(dashAdmin, "POST", "/api/v1/update-rings", `{"name":"pilot","position":1,"tags":["Prod"]}`)
	var pilot updateRing
	if json.Unmarshal([]byte(body), &pilot); code != 200 || pilot.ID == 0 || pilot.Tags[0] != "prod" {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := call(dashAdmin, "POST", "/api/v1/update-rings", `{"name":"pilot","position":2}`); code != 422 {
		t.Fatalf("duplicate name: %d", code)
	}
	code, body = call(dashAdmin, "POST", "/api/v1/update-rings", `{"name":"broad","position":2,"deferral_days":0,"all_devices":true,"require_approval":true}`)
	var broad updateRing
	if json.Unmarshal([]byte(body), &broad); code != 200 {
		t.Fatalf("broad: %d %s", code, body)
	}
	// a wave reaches pilot at once, broad only after approval
	if code, body := call(dashAdmin, "POST", "/api/v1/update-waves", ``); code != 201 {
		t.Fatalf("wave: %d %s", code, body)
	}
	gate := func(dev string) *api.UpdateGate {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		g, err := updateGate(ctx, tx, dev, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return g
	}
	if g := gate("d1"); g == nil || g.Ring != "pilot" || g.Wave != 1 || !g.Open {
		t.Fatalf("pilot gate %+v", g)
	}
	if g := gate("d3"); g == nil || g.Ring != "broad" || g.Wave != 0 {
		t.Fatalf("broad gate %+v", g)
	}
	if code, _ := call(dashAdmin, "POST", "/api/v1/update-rings/"+itoa(broad.ID)+"/approve", ``); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if g := gate("d3"); g.Wave != 1 {
		t.Fatalf("approved gate %+v", g)
	}
	if code, _ := call(dashAdmin, "POST", "/api/v1/update-rings/"+itoa(pilot.ID)+"/pause", ``); code != 200 {
		t.Fatalf("pause: %d", code)
	}
	if g := gate("d1"); g.Open {
		t.Fatalf("paused gate %+v", g)
	}
	code, body = call(dashAuditor, "GET", "/api/v1/update-rings", ``)
	if code != 200 || !strings.Contains(body, `"unassigned":1`) || !strings.Contains(body, `"paused":true`) || !strings.Contains(body, `"wave":1`) {
		t.Fatalf("list: %d %s", code, body)
	}
	// the device's update status and the fleet view
	st := api.UpdateStatus{Pending: []api.PendingUpdate{
		{Name: "openssl", Current: "3.0.1", Candidate: "3.0.2", Source: api.SourceOSAll, Security: true, Severity: "Important", CVEs: []string{"CVE-2024-1234", "bogus"}},
		{Name: "vim", Current: "9.0", Candidate: "9.1", Source: api.SourceOSAll},
	}, Runs: []api.UpdateRun{{Source: api.SourceOSSecurity, At: time.Now(), Result: "no_updates"}}}
	tx, _ := db.Begin(ctx)
	if err := storeUpdateStatus(ctx, tx, "d1", &st); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	code, body = call(dashHelpdesk, "GET", "/api/v1/devices/d1/updates", ``)
	if code != 200 || !strings.Contains(body, `"candidate":"3.0.2"`) || strings.Contains(body, "bogus") || !strings.Contains(body, `"name":"pilot"`) {
		t.Fatalf("device updates: %d %s", code, body)
	}
	code, body = call(dashAuditor, "GET", "/api/v1/updates/fleet", ``)
	if code != 200 || !strings.Contains(body, `"id":"CVE-2024-1234"`) || !strings.Contains(body, `"security_devices":1`) || !strings.Contains(body, `"severity":"Important"`) {
		t.Fatalf("fleet: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/updates/fleet?cve=CVE-2024-1234", ``); code != 200 || !strings.Contains(body, `"hostname":"alpha"`) {
		t.Fatalf("cve devices: %d %s", code, body)
	}
	if _, err := db.Exec(ctx, `INSERT INTO device_packages(device_id, name, version, arch) VALUES ('d1','openssl','3.0.1','amd64'), ('d2','openssl','3.0.1','amd64')`); err != nil {
		t.Fatal(err)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/updates/package-versions?name=openssl", ``); code != 200 || !strings.Contains(body, `"devices":2`) {
		t.Fatalf("versions: %d %s", code, body)
	}
	// downgrade needs four eyes, hold not
	if code, body := call(dashAdmin, "POST", "/api/v1/devices/d1/commands", `{"type":"package_downgrade","params":{"name":"openssl"}}`); code != 202 || !strings.Contains(body, "approval_id") {
		t.Fatalf("downgrade: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/devices/d1/commands", `{"type":"package_hold","params":{"name":"-x"}}`); code != 422 {
		t.Fatalf("bad hold: %d %s", code, body)
	}
	if code, _ := call(dashHelpdesk, "POST", "/api/v1/devices/d1/commands", `{"type":"package_hold","params":{"name":"openssl"}}`); code != 403 {
		t.Fatalf("helpdesk hold: %d", code)
	}
	if code, body := call(dashAdmin, "DELETE", "/api/v1/update-rings/"+itoa(pilot.ID), ``); code != 204 {
		t.Fatalf("delete: %d %s", code, body)
	}
	_ = s
}
