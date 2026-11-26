package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The compliance endpoints of the console app: page data, one check, the
// heatmap, the history, the policies and the evidence export with its audit
// entry, and the role limits of the export.
func TestAppComplianceAPI(t *testing.T) {
	db := loadTestDB(t, 4)
	s := loadTestServer(db)
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24}, auth: &oidcAuth{}})
	ctx := context.Background()
	checks := func(st string) string {
		return `[{"id":"ssh.baseline","title":"SSH server is hardened","level":1,"status":"` + st + `","detail":"PermitRootLogin yes","refs":{"bsi":["SYS.2.3"],"iso":["A.8.5"]}},
			{"id":"custom.no_telnet","title":"Telnet","level":1,"severity":"high","status":"pass"}]`
	}
	for _, d := range [][3]string{{"d1", "pc1", "fail"}, {"d2", "pc2", "pass"}} {
		if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, checks, last_seen, failing) VALUES ($1,'s',now(),$2,$3,now(),$4)`,
			d[0], d[1], checks(d[2]), map[string]int{"fail": 1}[d[2]]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO compliance_changes(device_id, at, check_id, status, detail, catalog_version) VALUES ('d1', now() - interval '2 days', 'ssh.baseline', 'fail', '', '2026.11.1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO library_items(name, type, payload) VALUES ('base','com.limdm.compliance','{"level":2,"grace_hours":72,"lock_after_hours":24}'),
		('own','com.limdm.customchecks','{"checks":[{"id":"custom.no_telnet","title":"Telnet","severity":"high","level":1,"package":{"name":"telnet","state":"absent"}}]}')`); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	tok := func(name, role string) string {
		tx, _ := db.Begin(ctx)
		defer tx.Rollback(ctx)
		k, _, _, err := insertToken(ctx, tx, tokenApproval{Name: name, Role: role, Days: 30}, name+"@firma.de")
		if err != nil || tx.Commit(ctx) != nil {
			t.Fatal(err)
		}
		return k
	}
	admin, helpdesk := tok("alice", "admin"), tok("hd", "helpdesk")
	get := func(tk, path string, v any) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tk)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if v != nil && resp.StatusCode == 200 {
			if err := json.Unmarshal(b, v); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return resp.StatusCode, string(b)
	}

	var page appCompliance
	if code, body := get(admin, "/api/v1/compliance", &page); code != 200 || page.Total != 2 || page.Compliant != 1 || page.NonCompliant != 1 || len(page.Checks) != 2 {
		t.Fatalf("page %d %s", code, body)
	}
	if len(page.Controls) != 2 || page.Controls[0].Framework != "bsi" {
		t.Fatalf("controls %+v", page.Controls)
	}
	var ch appCheckDetail
	if code, body := get(admin, "/api/v1/compliance/checks/ssh.baseline", &ch); code != 200 || ch.Fail != 1 || ch.Pass != 1 || len(ch.Devices) != 2 ||
		ch.Devices[0].Hostname != "pc1" || ch.Devices[0].Blueprint == "" || ch.Devices[0].Detail != "PermitRootLogin yes" {
		t.Fatalf("check %d %s", code, body)
	}
	if code, _ := get(admin, "/api/v1/compliance/checks/nope.x", nil); code != 404 {
		t.Fatalf("unknown check %d", code)
	}
	var heat struct{ Cells []appHeatCell }
	if code, body := get(admin, "/api/v1/compliance/heatmap", &heat); code != 200 || len(heat.Cells) != 2 {
		t.Fatalf("heatmap %d %s", code, body)
	}
	if code, _ := get(admin, "/api/v1/compliance/heatmap?group=tenant", nil); code != 400 {
		t.Fatalf("tenant group without tenants %d", code)
	}
	var hist struct {
		Devices []appHistoryDevice
		State   []appHistoryRow
	}
	day := time.Now().AddDate(0, 0, -1).Format(time.DateOnly)
	if code, body := get(helpdesk, "/api/v1/compliance/history?at="+day+"&device=d1", &hist); code != 200 || len(hist.Devices) != 1 || hist.Devices[0].Fail != 1 || len(hist.State) != 1 {
		t.Fatalf("history %d %s", code, body)
	}
	if code, _ := get(admin, "/api/v1/compliance/history?at=yesterday", nil); code != 400 {
		t.Fatalf("bad date %d", code)
	}
	var pol struct {
		Policies     []appPolicy
		CustomChecks []appCustomCheck `json:"custom_checks"`
	}
	if code, body := get(admin, "/api/v1/compliance/policies", &pol); code != 200 || len(pol.Policies) != 2 || pol.Policies[1].GraceHours != 72 || pol.Policies[0].Blueprints[0] != "default" ||
		len(pol.CustomChecks) != 1 || pol.CustomChecks[0].Test != "package" {
		t.Fatalf("policies %d %s", code, body)
	}

	code, body := get(admin, "/api/v1/exports/compliance.csv", nil)
	if code != 200 || !strings.Contains(body, "ssh.baseline") || !strings.HasPrefix(body, "device_id,") {
		t.Fatalf("export %d %s", code, body)
	}
	var detail string
	if err := db.QueryRow(ctx, `SELECT detail FROM audit_log WHERE action='export.done' AND target='compliance.csv'`).Scan(&detail); err != nil || !strings.Contains(detail, "sha256=") || strings.Contains(detail, "incomplete") {
		t.Fatalf("export audit %q %v", detail, err)
	}
	if code, _ := get(helpdesk, "/api/v1/exports/compliance.csv", nil); code != 403 {
		t.Fatalf("helpdesk export %d", code)
	}
	if code, _ := get(admin, "/api/v1/exports/secrets.csv", nil); code != 404 {
		t.Fatalf("unknown export %d", code)
	}

	// signed evidence and the PDF report, audited like the CSV exports
	code, body = get(admin, "/api/v1/exports/evidence.json?days=30", nil)
	if code != 200 {
		t.Fatalf("evidence %d %s", code, body)
	}
	if info, err := VerifyEvidence([]byte(body), []ed25519.PublicKey{testCmdKey.Public().(ed25519.PublicKey)}); err != nil || info.Devices != 2 || info.Changes != 1 {
		t.Fatalf("evidence verify %+v %v", info, err)
	}
	if code, body = get(admin, "/api/v1/exports/evidence.pdf", nil); code != 200 || !strings.HasPrefix(body, "%PDF-") {
		t.Fatalf("evidence pdf %d", code)
	}
	var signs, done int
	db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='evidence.sign'), count(*) FILTER (WHERE action='export.done' AND target LIKE 'evidence.%' AND detail LIKE '%sha256=%')
		FROM audit_log`).Scan(&signs, &done)
	if signs != 2 || done != 2 {
		t.Fatalf("evidence audit: %d sign, %d done", signs, done)
	}
	if code, _ := get(admin, "/api/v1/exports/evidence.json?days=999", nil); code != 400 {
		t.Fatalf("evidence days %d", code)
	}

	// the helpdesk asks for an exception; another admin approves it and is
	// recorded as approver
	post := func(tk, path, body string) (int, http.Header) {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tk)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	day = time.Now().AddDate(0, 2, 0).Format(time.DateOnly)
	code, hdr := post(helpdesk, "/api/v1/exception-requests", `{"check_id":"ssh.baseline","mode":"advisory","tag":"lab","reason":"legacy jump host","owner":"cto","expires":"`+day+`"}`)
	if code != http.StatusAccepted {
		t.Fatalf("exception request %d", code)
	}
	appr := hdr.Get("Location")
	if code, _ := post(helpdesk, appr+"/approve", ""); code != http.StatusForbidden {
		t.Fatalf("helpdesk decided %d", code)
	}
	if code, _ := post(admin, appr+"/approve", ""); code != 200 {
		t.Fatalf("approve %d", code)
	}
	var approver, by string
	if err := db.QueryRow(ctx, `SELECT approver, created_by FROM risk_exceptions WHERE check_id='ssh.baseline' AND tag='lab'`).Scan(&approver, &by); err != nil ||
		!strings.HasPrefix(approver, "api:alice#") || !strings.HasPrefix(by, "api:hd#") {
		t.Fatalf("approved exception: %q %q %v", approver, by, err)
	}
	if code, _ := post(helpdesk, "/api/v1/exception-requests", `{"check_id":"x","mode":"exclude","reason":"","owner":"o","expires":"`+day+`"}`); code != 400 {
		t.Fatalf("invalid request %d", code)
	}
}
