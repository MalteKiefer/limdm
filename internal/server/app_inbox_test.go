package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppInbox(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO commands(device_id, type, status, created_by) VALUES ('d1', 'sync', 'failed', 'x'), ('d2', 'reboot', 'ok', 'x'), ('d2', 'lock', 'failed', 'x');
		UPDATE devices SET tags='{}' WHERE id='d2';
		INSERT INTO approvals(action, target, reason, requested_by, expires_at, tenant_id) VALUES
			('recovery.view', 'd1', 'locked out', 'boss@firma.de', now() + interval '1 day', 1),
			('recovery.view', 'd1', 'again', 'admin@firma.de', now() + interval '1 day', 1)`); err != nil {
		t.Fatal(err)
	}
	if code, body := call(dashAdmin, "GET", "/api/v1/commands?status=failed", ""); code != 200 || strings.Count(body, `"status":"failed"`) != 2 || !strings.Contains(body, `"hostname":"beta"`) {
		t.Fatalf("failed commands: %d %s", code, body)
	}
	rec := httptest.NewRecorder()
	s.apiCommands(rec, httptest.NewRequest("GET", "/api/v1/commands", nil), apiCaller{Role: "helpdesk", Tags: []string{"prod"}})
	if body := rec.Body.String(); rec.Code != 200 || strings.Contains(body, "beta") || !strings.Contains(body, "alpha") {
		t.Fatalf("scoped commands: %d %s", rec.Code, body)
	}
	if code, _ := call(dashAdmin, "GET", "/api/v1/commands?status=broken", ""); code != 400 {
		t.Fatalf("bad status: %d", code)
	}
	// the app must give a reason to reject; it is stored and audited
	if code, body := call(dashAdmin, "POST", "/api/v1/approvals/1/reject", ""); code != 422 || !strings.Contains(body, `"field":"reason"`) {
		t.Fatalf("reject without reason: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/approvals/1/reject", `{"reason":"not needed"}`); code != 200 || !strings.Contains(body, `"decision_reason":"not needed"`) || !strings.Contains(body, `"status":"rejected"`) {
		t.Fatalf("reject: %d %s", code, body)
	}
	var detail string
	db.QueryRow(ctx, `SELECT detail FROM audit_log WHERE action='approval.reject'`).Scan(&detail)
	if !strings.Contains(detail, `reason="not needed"`) {
		t.Fatalf("audit detail: %q", detail)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/approvals/2/approve", ""); code != 409 || !strings.Contains(body, "own request") {
		t.Fatalf("own request: %d %s", code, body)
	}
}
