package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAdminAPI covers the API tokens, the admin REST API, the device search
// and the metrics endpoint against a real PostgreSQL (see TestIntegration).
func TestAdminAPI(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{3}, 32), Admins: []string{"admin@firma.de"},
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// devices in every state; pc1 and pc2 carry the finance tag and openssl
	ok, fail := `[{"id":"c1","status":"pass"}]`, `[{"id":"c1","status":"fail"}]`
	_, err = db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags, packages, last_seen, checks, failing, grace_until, retired, agent_version) VALUES
		('d1', 's', now(), 'pc1', '{finance}', '[{"n":"openssl","v":"3.0.2-0ubuntu1.15"}]', now(), $1, 0, NULL, false, '0.15.0'),
		('d2', 's', now(), 'pc2', '{finance}', '[{"n":"openssl","v":"1:3.0.13-1~deb12u1"}]', now(), $2, 1, NULL, false, '0.15.0'),
		('d3', 's', now(), 'pc3', '{}', '[]', now() - interval '3 days', $1, 0, NULL, false, '0.14.0'),
		('d4', 's', now(), 'pc4', '{}', '[]', now(), $2, 1, now() + interval '1 hour', false, '0.15.0'),
		('d5', 's', now(), 'pc5', '{}', '[]', NULL, '[]', 0, NULL, false, ''),
		('d6', 's', now(), 'pc6', '{}', '[]', now(), $1, 0, NULL, true, '0.15.0')`, ok, fail)
	if err != nil {
		t.Fatal(err)
	}
	// the SQL status matches the status computed in Go
	for _, st := range deviceStatuses {
		dq, _ := parseDeviceQuery(url.Values{"status": {st}}, s.staleAfter())
		w := dq.where()
		list, err := s.listDevicesQuery(ctx, w.sql(), "", w.args...)
		if err != nil || len(list) != 1 || list[0].Status != st {
			t.Fatalf("status %s: %v %+v", st, err, list)
		}
	}

	adminSess := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	console := func(method, path string, form url.Values) (int, string) {
		t.Helper()
		if form != nil {
			form.Set("csrf", s.csrfToken(adminSess))
		}
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(adminSess)})
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	newToken := func(name, role string) string {
		t.Helper()
		code, body := console("POST", "/settings/api", url.Values{"name": {name}, "role": {role}, "days": {"30"}})
		tok := regexp.MustCompile(`lma_[A-Za-z0-9_-]+`).FindString(body)
		if code != 200 || tok == "" {
			t.Fatalf("create %s token: %d", role, code)
		}
		return tok
	}
	adminTok, auditorTok, helpdeskTok := newToken("ci", "admin"), newToken("report", "auditor"), newToken("desk", "helpdesk")
	var stored int
	db.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE token_hash = sha256($1::bytea)`, adminTok).Scan(&stored)
	if stored != 1 {
		t.Fatal("token not stored as its SHA-256")
	}

	type apiResp struct {
		StatusCode int
		Header     http.Header
	}
	call := func(tok, method, path, body string) (apiResp, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return apiResp{resp.StatusCode, resp.Header}, string(b)
	}
	auditCount := func(action string) (n int) {
		db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1`, action).Scan(&n)
		return n
	}

	// authentication
	if resp, _ := call("", "GET", "/api/v1/devices", ""); resp.StatusCode != 401 || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("no token: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp, _ := call("lma_wrong", "GET", "/api/v1/devices", ""); resp.StatusCode != 401 || auditCount("api.auth_failed") != 1 {
		t.Fatalf("wrong token: %d", resp.StatusCode)
	}

	// search: filters combine, versions compare by their numbers, pages follow the cursor
	var page struct {
		Items []struct {
			Hostname string   `json:"hostname"`
			Tags     []string `json:"tags"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	resp, body := call(adminTok, "GET", "/api/v1/devices?tag=finance&pkg="+url.QueryEscape("openssl < 3.0.13"), "")
	if json.Unmarshal([]byte(body), &page); resp.StatusCode != 200 || len(page.Items) != 1 || page.Items[0].Hostname != "pc1" {
		t.Fatalf("filtered list: %d %s", resp.StatusCode, body)
	}
	_, body = call(adminTok, "GET", "/api/v1/devices?tag=finance&limit=1", "")
	page.Next = ""
	if json.Unmarshal([]byte(body), &page); len(page.Items) != 1 || page.Next == "" {
		t.Fatalf("first page: %s", body)
	}
	_, body = call(adminTok, "GET", "/api/v1/devices?tag=finance&limit=1&cursor="+page.Next, "")
	page.Next = ""
	if json.Unmarshal([]byte(body), &page); len(page.Items) != 1 || page.Items[0].Hostname != "pc2" || page.Next != "" {
		t.Fatalf("second page: %s", body)
	}
	if code, html := console("GET", "/devices?tag=finance&pkg="+url.QueryEscape("openssl>=3.0.13"), nil); code != 200 || !strings.Contains(html, "pc2") || strings.Contains(html, ">pc1<") {
		t.Fatalf("console search: %d", code)
	}
	if code, csv := console("GET", "/export/packages.csv", nil); code != 200 || !strings.Contains(csv, "d2,pc2,openssl,1:3.0.13-1~deb12u1") {
		t.Fatalf("packages export: %d %s", code, csv)
	}

	// role denial is refused and audited
	item := `{"name":"editors","type":"com.limdm.packages","payload":{"install":["vim"],"remove":[]}}`
	if resp, _ := call(auditorTok, "POST", "/api/v1/library-items", item); resp.StatusCode != 403 || auditCount("api.denied") != 1 {
		t.Fatalf("auditor write: %d", resp.StatusCode)
	}
	if resp, _ := call(helpdeskTok, "GET", "/api/v1/audit", ""); resp.StatusCode != 403 {
		t.Fatalf("helpdesk audit read: %d", resp.StatusCode)
	}

	// write path through the console's save, audited under the token's name
	resp, body = call(adminTok, "POST", "/api/v1/library-items", item)
	if resp.StatusCode != 201 || !strings.HasPrefix(resp.Header.Get("Location"), "/api/v1/library-items/") {
		t.Fatalf("create item: %d %s", resp.StatusCode, body)
	}
	var actor string
	db.QueryRow(ctx, `SELECT actor FROM audit_log WHERE action='library.save' ORDER BY id DESC LIMIT 1`).Scan(&actor)
	if !strings.HasPrefix(actor, "api:ci#") {
		t.Fatalf("audit actor %q", actor)
	}
	if resp, body := call(adminTok, "POST", "/api/v1/library-items", item); resp.StatusCode != 409 {
		t.Fatalf("duplicate name: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(adminTok, "POST", "/api/v1/library-items", `{"name":"x","type":"com.limdm.packages","payload":{"install":["bad name"]}}`); resp.StatusCode != 422 {
		t.Fatalf("invalid payload: %d", resp.StatusCode)
	}
	if resp, _ := call(adminTok, "DELETE", resp.Header.Get("Location"), ""); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, body := call(adminTok, "POST", "/api/v1/blueprints", `{"name":"finance","tree":[]}`); resp.StatusCode != 201 {
		t.Fatalf("create blueprint: %d %s", resp.StatusCode, body)
	}

	// commands follow the console's role rules
	resp, body = call(helpdeskTok, "POST", "/api/v1/devices/d1/commands", `{"type":"reboot","params":{"minutes":5}}`)
	if resp.StatusCode != 202 {
		t.Fatalf("reboot: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(helpdeskTok, "GET", resp.Header.Get("Location"), ""); resp.StatusCode != 200 || !strings.Contains(body, `"status":"pending"`) || !strings.Contains(body, `"created_by":"api:desk#`) {
		t.Fatalf("command status: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(helpdeskTok, "POST", "/api/v1/devices/d1/commands", `{"type":"wipe","params":{"confirm":"pc1"}}`); resp.StatusCode != 403 {
		t.Fatalf("helpdesk wipe: %d", resp.StatusCode)
	}
	if resp, _ := call(helpdeskTok, "PATCH", "/api/v1/devices/d1", `{"tags":["x"]}`); resp.StatusCode != 403 {
		t.Fatalf("helpdesk patch: %d", resp.StatusCode)
	}

	// four eyes: an API wipe becomes an approval request (202 with its ID)
	set := s.settings()
	set.FourEyes = true
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	resp, body = call(adminTok, "POST", "/api/v1/devices/d1/commands", `{"type":"wipe","params":{"confirm":"pc1","reason":"stolen"}}`)
	var pending, wipes int
	db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE action='command' AND target='d1' AND status='pending'`).Scan(&pending)
	db.QueryRow(ctx, `SELECT count(*) FROM commands WHERE type='wipe'`).Scan(&wipes)
	if resp.StatusCode != 202 || !strings.Contains(body, `"approval_id"`) || pending != 1 || wipes != 0 {
		t.Fatalf("wipe under four eyes: %d %s pending=%d wipes=%d", resp.StatusCode, body, pending, wipes)
	}
	set.FourEyes = false
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})

	// scoped tokens see and act on their devices only and get no metrics
	if code, _ := console("POST", "/settings/api", url.Values{"name": {"x"}, "role": {"admin"}, "days": {"30"}, "scope_tags": {"finance"}}); code != 400 {
		t.Fatalf("scoped admin token: %d", code)
	}
	_, tbody := console("POST", "/settings/api", url.Values{"name": {"fin"}, "role": {"helpdesk"}, "days": {"30"}, "scope_tags": {"finance"}})
	finTok := regexp.MustCompile(`lma_[A-Za-z0-9_-]+`).FindString(tbody)
	if resp, body := call(finTok, "GET", "/api/v1/devices", ""); resp.StatusCode != 200 || !strings.Contains(body, "pc1") || strings.Contains(body, "pc3") {
		t.Fatalf("scoped list: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(finTok, "GET", "/api/v1/devices/d3", ""); resp.StatusCode != 404 {
		t.Fatalf("scoped get: %d", resp.StatusCode)
	}
	if resp, _ := call(finTok, "POST", "/api/v1/devices/d3/commands", `{"type":"reboot","params":{"minutes":5}}`); resp.StatusCode != 404 {
		t.Fatalf("scoped command: %d", resp.StatusCode)
	}
	if resp, _ := call(finTok, "GET", "/metrics", ""); resp.StatusCode != 403 {
		t.Fatalf("scoped metrics: %d", resp.StatusCode)
	}
	if resp, body := call(adminTok, "PATCH", "/api/v1/devices/d1", `{"tags":["Finance","laptop"],"blueprint_id":null}`); resp.StatusCode != 200 || !strings.Contains(body, `"tags":["finance","laptop"]`) {
		t.Fatalf("patch: %d %s", resp.StatusCode, body)
	}

	// every error is a problem document, wrong methods are 405
	if resp, _ := call(adminTok, "GET", "/api/v1/nothing", ""); resp.StatusCode != 404 || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unknown path: %d", resp.StatusCode)
	}
	if resp, _ := call(adminTok, "DELETE", "/api/v1/tags", ""); resp.StatusCode != 405 || resp.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("wrong method: %d", resp.StatusCode)
	}
	if resp, body := call("", "GET", "/api/v1/openapi.json", ""); resp.StatusCode != 200 || !json.Valid([]byte(body)) || !strings.Contains(body, `"openapi": "3.1`) {
		t.Fatalf("openapi: %d", resp.StatusCode)
	}

	// metrics
	resp, body = call(auditorTok, "GET", "/metrics", "")
	for _, want := range []string{`limdm_devices{status="stale"} 1`, `limdm_agent_versions{version="0.15.0"} 3`, `limdm_audit_chain_intact 1`,
		`limdm_compliance_failing_devices{check="c1"} 2`, `limdm_commands_open{status="pending"} 1`, `limdm_http_requests_total{listener="console",method="GET",code="200"}`} {
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Fatalf("metrics lack %q: %d\n%s", want, resp.StatusCode, body)
		}
	}
	if resp, _ := call(helpdeskTok, "GET", "/metrics", ""); resp.StatusCode != 403 {
		t.Fatalf("helpdesk metrics: %d", resp.StatusCode)
	}

	// revoked tokens stop working
	var id string
	db.QueryRow(ctx, `SELECT id::text FROM api_tokens WHERE name='ci'`).Scan(&id)
	if code, _ := console("POST", "/settings/api/"+id+"/revoke", url.Values{}); code != http.StatusSeeOther || auditCount("api_token.revoke") != 1 {
		t.Fatalf("revoke: %d", code)
	}
	if resp, body := call(adminTok, "GET", "/api/v1/tags", ""); resp.StatusCode != 401 || !strings.Contains(body, "revoked") {
		t.Fatalf("revoked token: %d %s", resp.StatusCode, body)
	}
	if auditCount("api_token.create") != 4 {
		t.Fatal("token creation not audited")
	}
}

func TestProblemWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	http.NotFound(&problemWriter{ResponseWriter: rec}, httptest.NewRequest("GET", "/api/v1/x", nil))
	if rec.Code != 404 || rec.Header().Get("Content-Type") != "application/problem+json" || !strings.Contains(rec.Body.String(), `"status":404`) {
		t.Fatalf("%d %s %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
}
