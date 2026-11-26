package server

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestActivityCategory(t *testing.T) {
	for action, want := range map[string]string{"command.wipe": "commands", "approval.reject": "approvals", "login": "access",
		"api.read": "audit", "library.save": "changes", "device.enroll": "devices", "export.done": "audit"} {
		if got := activityCategory(action); got != want {
			t.Errorf("%s: %s, want %s", action, got, want)
		}
	}
	if a, e, ok := parseActivityCursor("12:7"); !ok || a != 12 || e != 7 {
		t.Fatal("cursor")
	}
	if _, _, ok := parseActivityCursor("12"); ok {
		t.Fatal("bad cursor passed")
	}
}

func TestAppActivity(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	for _, a := range []string{"login", "library.save", "command.sync"} {
		if err := s.auditAction(ctx, "admin@firma.de", a, "d1", "x", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO device_events(device_id, at, detail) VALUES ('d1', now(), 'sudo: alice'), ('d2', now() - interval '1 minute', 'boot')`); err != nil {
		t.Fatal(err)
	}
	type page struct {
		Items []activityItem `json:"items"`
		Next  string         `json:"next_cursor"`
	}
	var p page
	code, body := call(dashAuditor, "GET", "/api/v1/activity?limit=2", "")
	if json.Unmarshal([]byte(body), &p); code != 200 || len(p.Items) != 2 || p.Next == "" {
		t.Fatalf("first page: %d %s", code, body)
	}
	seen := map[string]bool{}
	for p.Next != "" {
		for _, it := range p.Items {
			if seen[it.ID] {
				t.Fatalf("%s twice", it.ID)
			}
			seen[it.ID] = true
		}
		code, body = call(dashAuditor, "GET", "/api/v1/activity?limit=2&cursor="+p.Next, "")
		p = page{}
		if json.Unmarshal([]byte(body), &p); code != 200 {
			t.Fatalf("next page: %d %s", code, body)
		}
	}
	for _, it := range p.Items {
		seen[it.ID] = true
	}
	if len(seen) != 5 { // three audit entries, two device events
		t.Fatalf("merged stream: %v", seen)
	}
	// the helpdesk sees device events, never the audit log
	if code, body := call(dashHelpdesk, "GET", "/api/v1/activity", ""); code != 200 || strings.Contains(body, `"kind":"audit"`) || !strings.Contains(body, "sudo: alice") {
		t.Fatalf("helpdesk: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/activity?category=commands", ""); code != 200 || strings.Count(body, `"id"`) != 1 || !strings.Contains(body, "command.sync") {
		t.Fatalf("category: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/activity?target=d2", ""); code != 200 || !strings.Contains(body, "boot") || strings.Contains(body, "library.save") {
		t.Fatalf("target: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/activity/histogram?q="+url.QueryEscape("sudo"), ""); code != 200 || !strings.Contains(body, `"events":1`) || strings.Count(body, `"day"`) != 30 {
		t.Fatalf("histogram: %d %s", code, body)
	}
	if code, _ := call(dashHelpdesk, "GET", "/api/v1/audit/status", ""); code != 403 {
		t.Fatalf("helpdesk audit status: %d", code)
	}
	if code, body := call(dashAuditor, "POST", "/api/v1/audit/verify", ""); code != 200 || !strings.Contains(body, `"broken_at":0`) || !strings.Contains(body, `"verified_at":"`) || !strings.Contains(body, "library.save") {
		t.Fatalf("verify: %d %s", code, body)
	}
}
