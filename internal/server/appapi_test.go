package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestParseDeviceFilter(t *testing.T) {
	for _, tc := range []struct {
		in    string
		conds int
		err   bool
	}{
		{"", 0, false},
		{`web status:non-compliant os:"Ubuntu 24" tag:prod`, 4, false},
		{"status:in-grace seen:>7d check:ssh.root", 3, false},
		{"pkg:openssl<3.0.13", 1, false},
		{"status:broken", 0, true},
		{"color:red", 0, true},
		{"seen:7d", 0, true},
		{strings.Repeat("a ", 21), 0, true},
	} {
		w, err := parseDeviceFilter(tc.in, time.Hour)
		if (err != nil) != tc.err || len(w.conds) != tc.conds {
			t.Errorf("%q: %d conds, err %v", tc.in, len(w.conds), err)
		}
	}
	toks, _ := parseFilterTokens(`os:"Ubuntu 24.04" free`)
	if len(toks) != 2 || toks[0] != (filterToken{"os", "Ubuntu 24.04"}) || toks[1] != (filterToken{"", "free"}) {
		t.Fatalf("tokens: %+v", toks)
	}
}

func TestDeviceOrder(t *testing.T) {
	var w sqlWhere
	order, so, err := deviceOrder("-last_seen", "", &w)
	if err != nil || !strings.Contains(order, "DESC") || len(w.conds) != 0 {
		t.Fatalf("%s %v", order, err)
	}
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw, _ := base64.RawURLEncoding.DecodeString(deviceCursor(so, deviceRow{ID: "d1", LastSeen: &seen}))
	if _, _, err := deviceOrder("-last_seen", string(raw), &w); err != nil || len(w.conds) != 1 || !strings.Contains(w.conds[0], "<") {
		t.Fatalf("keyset: %v %v", w.conds, err)
	}
	if _, _, err := deviceOrder("failing", `["x","d1"]`, &sqlWhere{}); err == nil {
		t.Fatal("a text cursor value for a number column passed")
	}
	if _, _, err := deviceOrder("color", "", &sqlWhere{}); err == nil {
		t.Fatal("unknown sort passed")
	}
}

// TestSchemasCoverTypes: every declaration type the console knows has a
// payload schema the app can render.
func TestSchemasCoverTypes(t *testing.T) {
	for typ := range typeLabels {
		if _, ok := api.PayloadSchema(typ); !ok {
			t.Errorf("%s has no schema", typ)
		}
	}
}

func TestWebappAssets(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.webappRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/app/assets/missing-abc123.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/app", nil))
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/app/" {
		t.Fatalf("/app: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// TestAppAPI covers the console app endpoints with a console session
// against a real PostgreSQL (see TestIntegration).
func TestAppAPI(t *testing.T) {
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
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{3}, 32),
		Admins: []string{"admin@firma.de"}, Auditors: []string{"audit@firma.de"},
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	ok, fail := `[{"id":"c1","status":"pass","refs":{"cis":["5.2.10"]}}]`, `[{"id":"c1","title":"SSH root","status":"fail","refs":{"cis":["5.2.10"]}}]`
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version) VALUES
		('d1', 's', now(), 'alpha', '{"os_name":"Ubuntu 24.04"}', '{prod}', now(), $1, 0, '0.17.0'),
		('d2', 's', now(), 'beta', '{"os_name":"Debian 12"}', '{prod}', now() - interval '1 hour', $2, 1, '0.17.0'),
		('d3', 's', now(), 'gamma', '{"os_name":"Ubuntu 24.04"}', '{}', now() - interval '3 days', $1, 0, '0.16.0')`, ok, fail); err != nil {
		t.Fatal(err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	admin := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	auditor := session{Email: "audit@firma.de", Role: "auditor", IAT: time.Now(), Last: time.Now()}
	call := func(sess session, method, path, body string, hdr map[string]string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	csrf := map[string]string{csrfHeader: s.csrfToken(admin), "Origin": "https://mdm.test", "Sec-Fetch-Site": "same-origin"}

	// the app needs a session; without one the login page
	req, _ := http.NewRequest("GET", srv.URL+"/app/devices", nil)
	resp0, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp0.Body.Close()
	if resp0.StatusCode != http.StatusFound || resp0.Header.Get("Location") != "/login?next=%2Fapp%2Fdevices" {
		t.Fatalf("app without session: %d %s", resp0.StatusCode, resp0.Header.Get("Location"))
	}
	if code, body := call(admin, "GET", "/app/devices", "", nil); code != 200 || !strings.Contains(body, "<html") && !strings.Contains(body, "<!doctype") {
		t.Fatalf("app: %d", code)
	}

	// me: role, permissions and the CSRF token of the session
	var me apiMeInfo
	code, body := call(admin, "GET", "/api/v1/me", "", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if json.Unmarshal([]byte(body), &me); code != 200 || me.Login != "admin@firma.de" || me.CSRFToken != s.csrfToken(admin) || !strings.Contains(strings.Join(me.Permissions, ","), "admin") {
		t.Fatalf("me: %d %s", code, body)
	}
	if code, body := call(auditor, "GET", "/api/v1/me", "", nil); code != 200 || strings.Contains(body, `"admin"`) || !strings.Contains(body, `"audit"`) {
		t.Fatalf("auditor me: %d %s", code, body)
	}

	// cross site requests and state changes without the CSRF header are refused
	if code, _ := call(admin, "GET", "/api/v1/me", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatalf("cross site: %d", code)
	}
	view := `{"list":"devices","name":"Prod","query":"tag:prod","columns":["hostname"],"shared":true}`
	if code, _ := call(admin, "POST", "/api/v1/views", view, map[string]string{"Origin": "https://mdm.test"}); code != 403 {
		t.Fatalf("no csrf: %d", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/views", view, map[string]string{csrfHeader: s.csrfToken(admin), "Origin": "https://evil.test"}); code != 403 {
		t.Fatalf("foreign origin: %d", code)
	}

	// saved views: shared ones are audited and visible to others, only admins share
	var v savedView
	code, body = call(admin, "POST", "/api/v1/views", view, csrf)
	if json.Unmarshal([]byte(body), &v); code != 201 || v.ID == 0 || !v.Mine || !v.Shared {
		t.Fatalf("create view: %d %s", code, body)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='view.save' AND actor='admin@firma.de'`).Scan(&n)
	if n != 1 {
		t.Fatal("shared view not audited")
	}
	acsrf := map[string]string{csrfHeader: s.csrfToken(auditor)}
	if code, _ := call(auditor, "POST", "/api/v1/views", view, acsrf); code != 403 {
		t.Fatalf("auditor shares: %d", code)
	}
	if code, body := call(auditor, "POST", "/api/v1/views", strings.Replace(view, `"shared":true`, `"shared":false`, 1), acsrf); code != 201 {
		t.Fatalf("auditor personal view: %d %s", code, body)
	}
	if code, body := call(auditor, "GET", "/api/v1/views?list=devices", "", nil); code != 200 || strings.Count(body, `"name":"Prod"`) != 2 {
		t.Fatalf("auditor views: %d %s", code, body)
	}
	if code, _ := call(auditor, "DELETE", "/api/v1/views/"+itoa(v.ID), "", acsrf); code != 404 {
		t.Fatalf("auditor deletes a shared view: %d", code)
	}
	if code, _ := call(admin, "PUT", "/api/v1/views/"+itoa(v.ID), strings.Replace(view, "Prod", "Production", 1), csrf); code != 200 {
		t.Fatalf("update view: %d", code)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/views/"+itoa(v.ID), "", csrf); code != 204 {
		t.Fatalf("delete view: %d", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/views", `{"list":"Devices!","name":"x"}`, csrf); code != 422 {
		t.Fatalf("invalid view: %d", code)
	}

	// device list conventions: filter, sort, cursor, facets
	var page struct {
		Items []apiDevice `json:"items"`
		Next  string      `json:"next_cursor"`
	}
	code, body = call(admin, "GET", "/api/v1/devices?sort=-hostname&limit=2&filter="+url.QueryEscape("tag:prod"), "", nil)
	if json.Unmarshal([]byte(body), &page); code != 200 || len(page.Items) != 2 || page.Items[0].Hostname != "beta" {
		t.Fatalf("sorted list: %d %s", code, body)
	}
	code, body = call(admin, "GET", "/api/v1/devices?sort=last_seen&limit=1", "", nil)
	if json.Unmarshal([]byte(body), &page); code != 200 || page.Items[0].Hostname != "gamma" || page.Next == "" {
		t.Fatalf("by last seen: %d %s", code, body)
	}
	code, body = call(admin, "GET", "/api/v1/devices?sort=last_seen&limit=5&cursor="+page.Next, "", nil)
	page.Next = ""
	if json.Unmarshal([]byte(body), &page); code != 200 || len(page.Items) != 2 || page.Items[0].Hostname != "beta" || page.Next != "" {
		t.Fatalf("next page: %d %s", code, body)
	}
	if code, body := call(admin, "GET", "/api/v1/devices?filter="+url.QueryEscape(`status:non-compliant os:"debian"`), "", nil); code != 200 || !strings.Contains(body, "beta") || strings.Contains(body, "alpha") {
		t.Fatalf("filter: %d %s", code, body)
	}
	if code, _ := call(admin, "GET", "/api/v1/devices?filter=color:red", "", nil); code != 400 {
		t.Fatalf("unknown key: %d", code)
	}
	var facets struct {
		Total  int                     `json:"total"`
		Facets map[string][]facetCount `json:"facets"`
	}
	code, body = call(admin, "GET", "/api/v1/devices/facets?filter=tag:prod", "", nil)
	if json.Unmarshal([]byte(body), &facets); code != 200 || facets.Total != 2 || len(facets.Facets["os"]) != 2 || facets.Facets["tag"][0] != (facetCount{"prod", 2}) {
		t.Fatalf("facets: %d %s", code, body)
	}

	// home aggregates
	var fleet statsFleet
	code, body = call(admin, "GET", "/api/v1/stats/fleet", "", nil)
	if json.Unmarshal([]byte(body), &fleet); code != 200 || fleet.Total != 3 || fleet.Online != 2 || fleet.Cells[0].Status != "non-compliant" {
		t.Fatalf("fleet: %d %s", code, body)
	}
	var comp statsCompliance
	code, body = call(admin, "GET", "/api/v1/stats/compliance", "", nil)
	if json.Unmarshal([]byte(body), &comp); code != 200 || comp.Score != 50 || comp.TopFailing[0].ID != "c1" || comp.Frameworks[1].Rate != 66.7 {
		t.Fatalf("compliance: %d %s", code, body)
	}
	var att statsAttention
	code, body = call(admin, "GET", "/api/v1/stats/attention", "", nil)
	if json.Unmarshal([]byte(body), &att); code != 200 || att.NonCompliant != 1 || att.Stale != 1 {
		t.Fatalf("attention: %d %s", code, body)
	}

	// schemas
	if code, body := call(admin, "GET", "/api/v1/schemas/"+api.TypeFirewall, "", nil); code != 200 || !strings.Contains(body, `"properties"`) {
		t.Fatalf("schema: %d %s", code, body)
	}
	if code, _ := call(admin, "GET", "/api/v1/schemas/com.example.x", "", nil); code != 404 {
		t.Fatalf("unknown schema: %d", code)
	}

	// events and attention honor role, token scope, tenant and device scope
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'other')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags, last_seen, checks, failing, tenant_id) VALUES
		('t2', 's', now(), 'foreign', '{}', now(), '[]', 0, 2)`); err != nil {
		t.Fatal(err)
	}
	if err := s.auditAction(withTenant(ctx, 2), "x@other", "secret.change", "t2", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.auditAction(withTenant(ctx, 1), "x@one", "device.change", "d1", "", nil); err != nil {
		t.Fatal(err)
	}
	poll := func(c apiCaller) string {
		t.Helper()
		rec := httptest.NewRecorder()
		st := eventState{since: time.Now().Add(-time.Hour), pending: -1}
		if err := s.pollEvents(ctx, rec, c, c.sess(), &st); err != nil {
			t.Fatal(err)
		}
		return rec.Body.String()
	}
	tenantAuditor := session{Email: "audit@firma.de", Role: "auditor", Tenant: 1}
	if out := poll(apiCaller{Role: "auditor", Tenant: 1, Sess: &tenantAuditor}); !strings.Contains(out, "device.change") || strings.Contains(out, "secret.change") || strings.Contains(out, "foreign") || !strings.Contains(out, "alpha") {
		t.Fatalf("tenant 1 auditor: %s", out)
	}
	if out := poll(apiCaller{Role: "auditor", Name: "r", ID: 9, ReadOnly: true, Scopes: []string{"read"}}); strings.Contains(out, "event: activity") || !strings.Contains(out, "foreign") {
		t.Fatalf("read scoped token: %s", out)
	}
	helpdesk := session{Email: "desk@firma.de", Role: "helpdesk"}
	if out := poll(apiCaller{Role: "helpdesk", Sess: &helpdesk}); strings.Contains(out, "event: activity") {
		t.Fatalf("helpdesk: %s", out)
	}
	if out := poll(apiCaller{Role: "auditor", Name: "a", ID: 8, ReadOnly: true, Scopes: []string{"audit"}}); !strings.Contains(out, "secret.change") {
		t.Fatalf("audit scoped token: %s", out)
	}
	// an open software request reaches the inbox of global readers only
	if _, err := db.Exec(ctx, `INSERT INTO catalog_requests(device_id, flatpak, remote, app_name, username, note) VALUES ('d1', 'org.example.App', 'flathub', 'App', 'ann', '')`); err != nil {
		t.Fatal(err)
	}
	globalAuditor := session{Email: "g@firma.de", Role: "auditor"}
	if out := poll(apiCaller{Role: "auditor", Sess: &globalAuditor}); !strings.Contains(out, `"requests":1`) {
		t.Fatalf("global auditor misses the request: %s", out)
	}
	if out := poll(apiCaller{Role: "auditor", Tenant: 1, Sess: &tenantAuditor}); !strings.Contains(out, `"requests":0`) {
		t.Fatalf("tenant auditor sees fleet requests: %s", out)
	}
	scopedTok := apiCaller{Role: "auditor", ReadOnly: true, Scopes: []string{"read"}}
	if scopedTok.can("audit") || !(apiCaller{Role: "auditor"}).can("audit") || (apiCaller{Role: "admin", Scopes: []string{"read"}}).can("admin") {
		t.Fatal("can ignores role or scopes")
	}
	if strings.Contains(strings.Join(scopedTok.permissions(false), ","), "audit") {
		t.Fatal("permissions ignore token scopes")
	}
	if _, err := db.Exec(ctx, `INSERT INTO backups(name, status) VALUES ('b1', 'ok')`); err != nil {
		t.Fatal(err)
	}
	attention := func(c apiCaller) string {
		rec := httptest.NewRecorder()
		s.apiStatsAttention(rec, httptest.NewRequest("GET", "/api/v1/stats/attention", nil), c)
		return rec.Body.String()
	}
	if out := attention(scopedTok); !strings.Contains(out, `"last_backup":null`) {
		t.Fatalf("read scoped token sees the backup: %s", out)
	}
	if out := attention(apiCaller{Role: "auditor"}); !strings.Contains(out, `"status":"ok"`) {
		t.Fatalf("auditor misses the backup: %s", out)
	}

	// live events: a check in shows up as a device event
	sreq, _ := http.NewRequest("GET", srv.URL+"/api/v1/events/stream", nil)
	sreq.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(admin)})
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(sreq.WithContext(sctx))
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %v %v", err, resp)
	}
	defer resp.Body.Close()
	if _, err := db.Exec(ctx, `UPDATE devices SET last_seen = now() + interval '1 second' WHERE id='d3'`); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	var got []string
	for sc.Scan() && (!strings.Contains(sc.Text(), `"gamma"`) || !strings.Contains(strings.Join(got, "\n"), "event: device")) {
		got = append(got, sc.Text())
	}
	if !strings.Contains(strings.Join(got, "\n"), "event: inbox") {
		t.Fatalf("stream events: %q", got)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
