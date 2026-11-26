package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNextReportRun(t *testing.T) {
	loc := time.UTC
	wed := time.Date(2026, 11, 25, 10, 0, 0, 0, loc) // a Wednesday
	for _, tc := range []struct {
		cadence string
		from    time.Time
		want    time.Time
	}{
		{"daily", wed, time.Date(2026, 11, 26, 6, 0, 0, 0, loc)},
		{"daily", time.Date(2026, 11, 25, 5, 0, 0, 0, loc), time.Date(2026, 11, 25, 6, 0, 0, 0, loc)},
		{"weekly", wed, time.Date(2026, 11, 30, 6, 0, 0, 0, loc)},
		{"weekly", time.Date(2026, 11, 30, 6, 0, 0, 0, loc), time.Date(2026, 12, 7, 6, 0, 0, 0, loc)},
		{"monthly", wed, time.Date(2026, 12, 1, 6, 0, 0, 0, loc)},
		{"monthly", time.Date(2026, 12, 31, 23, 0, 0, 0, loc), time.Date(2027, 1, 1, 6, 0, 0, 0, loc)},
	} {
		if got := nextReportRun(tc.cadence, tc.from); !got.Equal(tc.want) {
			t.Errorf("%s from %s: %s, want %s", tc.cadence, tc.from, got, tc.want)
		}
	}
}

func TestPresetExport(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	kind, q, err := presetExport("kind=audit.jsonl&days=7&actor=anna&at=2026-01-01", now)
	if err != nil || kind != "audit.jsonl" || q.Encode() != "actor=anna&from=2026-01-03" {
		t.Fatalf("%s %s %v", kind, q.Encode(), err)
	}
	if _, _, err := presetExport("kind=secrets.csv", now); err == nil {
		t.Fatal("unknown kind passed")
	}
	if _, _, err := presetExport("kind=audit.csv&days=-1", now); err == nil {
		t.Fatal("negative days passed")
	}
}

func TestAppReportSchedules(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO notification_channels(name, kind, config, secret, events, enabled) VALUES ('ops', 'webhook', '{}', '', '{}', true)`); err != nil {
		t.Fatal(err)
	}
	var chanID int64
	db.QueryRow(ctx, `SELECT id FROM notification_channels`).Scan(&chanID)
	code, body := call(dashAuditor, "POST", "/api/v1/views", `{"list":"reports","name":"Inventory weekly","query":"kind=inventory.csv"}`)
	var v savedView
	if json.Unmarshal([]byte(body), &v); code != 201 {
		t.Fatalf("view: %d %s", code, body)
	}
	in := `{"view_id":` + itoa(v.ID) + `,"cadence":"weekly","channels":[` + itoa(chanID) + `],"emails":[]}`
	if code, body := call(dashHelpdesk, "POST", "/api/v1/report-schedules", in); code != 403 {
		t.Fatalf("helpdesk schedules: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "POST", "/api/v1/report-schedules", strings.Replace(in, "weekly", "hourly", 1)); code != 422 || !strings.Contains(body, "cadence") {
		t.Fatalf("bad cadence: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "POST", "/api/v1/report-schedules", strings.Replace(in, `"emails":[]`, `"emails":["a@b.de"]`, 1)); code != 422 || !strings.Contains(body, "e-mail channel") {
		t.Fatalf("emails without a mail channel: %d %s", code, body)
	}
	var sch reportSchedule
	code, body = call(dashAuditor, "POST", "/api/v1/report-schedules", in)
	if json.Unmarshal([]byte(body), &sch); code != 200 || sch.Cadence != "weekly" || sch.NextRun.Weekday() != time.Monday {
		t.Fatalf("schedule: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/report-schedules", ""); code != 200 || !strings.Contains(body, `"name":"ops"`) || !strings.Contains(body, "Inventory weekly") {
		t.Fatalf("list: %d %s", code, body)
	}

	// the leader runs it when due, as the owner; the file stays on the server
	db.Exec(ctx, `UPDATE report_schedules SET next_run = now() - interval '1 minute'`)
	if err := s.runDueReports(ctx); err != nil {
		t.Fatal(err)
	}
	var run reportRun
	if err := db.QueryRow(ctx, `SELECT id, rows, sha256, error FROM report_runs`).Scan(&run.ID, &run.Rows, &run.SHA256, &run.Error); err != nil || run.Rows != 3 || run.Error != "" {
		t.Fatalf("run: %+v %v", run, err)
	}
	var next time.Time
	db.QueryRow(ctx, `SELECT next_run FROM report_schedules`).Scan(&next)
	if !next.After(time.Now()) {
		t.Fatal("next run not moved on")
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='report.run' AND actor='system' AND detail LIKE '%as audit@firma.de: inventory.csv rows=3%'`).Scan(&n)
	if n != 1 {
		t.Fatal("run not audited")
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/report-runs/"+itoa(run.ID), ""); code != 200 || !strings.Contains(body, "gamma") {
		t.Fatalf("download: %d %s", code, body)
	}
	db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'Zweig')`)
	if code, _ := call(session{Email: "admin@firma.de", Role: "admin", Tenant: 2}, "GET","/api/v1/report-runs/"+itoa(run.ID), ""); code == 200 {
		t.Fatal("another tenant's view downloads the report")
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/report-schedules/"+itoa(sch.ID)+"/runs", ""); code != 200 || !strings.Contains(body, `"rows":3`) {
		t.Fatalf("runs: %d %s", code, body)
	}
	// a run as an owner who lost the right is recorded as failed
	db.Exec(ctx, `UPDATE console_users SET role='helpdesk' WHERE email='audit@firma.de'`)
	if code, body := call(dashAdmin, "POST", "/api/v1/report-schedules/"+itoa(sch.ID)+"/run", ""); code != 200 || !strings.Contains(body, "no longer an admin or auditor") {
		t.Fatalf("run without rights: %d %s", code, body)
	}
	if code, _ := call(dashAdmin, "DELETE", "/api/v1/report-schedules/"+itoa(sch.ID), ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}
}

func TestAppHomeUpdates(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `UPDATE devices SET checks = checks || '[{"id":"updates.security","status":"fail","detail":"4 security updates, 9 updates in total pending"}]'::jsonb WHERE id='d1';
		UPDATE devices SET checks = checks || '[{"id":"updates.security","status":"pass","detail":"0 security updates, 2 updates in total pending"}]'::jsonb WHERE id='d2';
		INSERT INTO compliance_changes(device_id, at, check_id, status) VALUES ('d1', now() - interval '20 days', 'updates.security', 'fail');
		UPDATE devices SET agent_version = CASE id WHEN 'd1' THEN '0.17.1' WHEN 'd2' THEN '0.17.0' ELSE '0.16.0' END;
		INSERT INTO agent_releases(version, published_at, sums, approved_at) VALUES ('0.17.0', now(), '', now()), ('0.18.0', now(), '', NULL);
		INSERT INTO fleet_history(day, compliant, noncompliant, in_grace, stale, pending) VALUES (current_date, 1, 1, 0, 1, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := s.snapshotUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	var st statsUpdates
	code, body := call(dashAdmin, "GET", "/api/v1/stats/updates", "")
	if json.Unmarshal([]byte(body), &st); code != 200 || st.SecurityDevices != 1 || st.SecurityUpdates != 4 || st.SecurityOld != 1 ||
		st.AgentNewest != "0.17.0" || !st.AgentApproved || st.AgentCurrent != 2 || st.AgentTotal != 3 || len(st.History) != 1 || *st.History[0].SecurityDevices != 1 {
		t.Fatalf("updates: %d %s", code, body)
	}
	for _, a := range []string{"keys.rotate", "blueprint.save", "blueprint.save", "login"} {
		if err := s.auditAction(ctx, "admin@firma.de", a, "x", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/stats/annotations", ""); code != 200 || !strings.Contains(body, `"action":"blueprint.save","label":"Blueprint saved","target":"x","count":2`) || strings.Contains(body, `"login"`) {
		t.Fatalf("annotations: %d %s", code, body)
	}
	if code, _ := call(dashHelpdesk, "GET", "/api/v1/stats/annotations", ""); code != 403 {
		t.Fatalf("helpdesk annotations: %d", code)
	}
}
