package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAppReports(t *testing.T) {
	_, db, call := dashServer(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO compliance_changes(device_id, at, check_id, status, detail, catalog_version) VALUES
		('d1', now() - interval '3 days', 'c1', 'pass', '', '1'), ('d2', now() - interval '3 days', 'c1', 'fail', 'root login', '1')`); err != nil {
		t.Fatal(err)
	}
	if code, body := call(dashHelpdesk, "GET", "/api/v1/compliance/history", ""); code != 200 || !strings.Contains(body, `"hostname":"beta","pass":0,"fail":1`) {
		t.Fatalf("history: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "GET", "/api/v1/compliance/history?device=d2", ""); code != 200 || !strings.Contains(body, `"detail":"root login"`) || !strings.Contains(body, `"changes":[{`) {
		t.Fatalf("device history: %d %s", code, body)
	}
	old := time.Now().AddDate(0, 0, -10).Format("2006-01-02")
	if code, body := call(dashAdmin, "GET", "/api/v1/compliance/history?at="+old, ""); code != 200 || !strings.Contains(body, `"devices":[]`) {
		t.Fatalf("history before: %d %s", code, body)
	}
	if code, _ := call(dashAdmin, "GET", "/api/v1/compliance/history?at=yesterday", ""); code != 400 {
		t.Fatalf("bad date: %d", code)
	}
	// exports: admins and auditors, audited with the file hash
	if code, body := call(dashAuditor, "GET", "/api/v1/exports/inventory.csv", ""); code != 200 || !strings.HasPrefix(body, "device_id,hostname") || !strings.Contains(body, "gamma") {
		t.Fatalf("inventory: %d %s", code, body)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='export.done' AND target='inventory.csv' AND actor='audit@firma.de' AND detail LIKE 'rows=3 sha256=%'`).Scan(&n)
	if n != 1 {
		t.Fatal("export not audited")
	}
	if code, _ := call(dashHelpdesk, "GET", "/api/v1/exports/inventory.csv", ""); code != 403 {
		t.Fatalf("helpdesk export: %d", code)
	}
	if code, _ := call(dashAdmin, "GET", "/api/v1/exports/secrets.csv", ""); code != 404 {
		t.Fatalf("unknown export: %d", code)
	}
	if code, body := call(dashAdmin, "GET", "/api/v1/exports/audit.jsonl", ""); code != 200 || !strings.Contains(body, `"action":"export"`) {
		t.Fatalf("audit jsonl: %d %s", code, body)
	}
}
