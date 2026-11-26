package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// resetDB empties the test database and applies the schema.
func resetDB(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTenantRouteGate(t *testing.T) {
	tenantAdmin := session{Role: "admin", Tenant: 2}
	if tenantAllowed(tenantAdmin, "GET /settings/api") != true || tenantAllowed(tenantAdmin, "GET /agents") {
		t.Fatal("tenant accounts reach listed routes only")
	}
	if !tenantAllowed(session{Role: "admin", Super: true, Tenant: 2}, "GET /agents") || !tenantAllowed(session{Role: "admin", Super: true}, "GET /agents") {
		t.Fatal("super admins reach every route")
	}
	cond, args := scopeCond(session{Role: "admin", Tenant: 2}, 3)
	if cond != "d.tenant_id = $4" || len(args) != 1 {
		t.Fatalf("tenant filter missing from the device filter: %q", cond)
	}
	cond, args = scopeCond(session{Role: "auditor", Tenant: 2, Tags: []string{"x"}}, 0)
	if !strings.HasPrefix(cond, "d.tenant_id = $1 AND (d.tags && $2") || len(args) != 3 {
		t.Fatalf("tenant and scope: %q", cond)
	}
	if cond, _ := scopeCond(session{Role: "admin", Super: true}, 0); cond != "TRUE" {
		t.Fatal("the global view filters nothing")
	}
	one := int64(1)
	if !slices.Equal(auditFields("a", "b", "c", "d", nil), []string{"a", "b", "c", "d"}) || len(auditFields("a", "b", "c", "d", &one)) != 5 {
		t.Fatal("audit fields")
	}
}

// TestTenantIsolation walks every console route as an admin of tenant A
// against the data of tenant B and expects 403 or 404 for B's objects, no
// trace of B in any answer and B's rows unchanged afterwards. Routes are
// read from the source, so a new route is covered without editing this test.
func TestTenantIsolation(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db := resetDB(t, dsn)
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	netCA, err := loadOrCreateNetworkCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, cmdKey: testCmdKey, ca: ca, netCA: netCA, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", AgentURL: "https://127.0.0.1:8444", StaleAfter: 24 * time.Hour, MultiTenant: true,
		SessionKey: bytes.Repeat([]byte{7}, 32), LocalLogin: true, CADir: t.TempDir(),
	}}
	s.rt.Store(&runtimeState{set: Settings{LocalLogin: true, StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	scalar := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := db.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return v
	}
	// tenant A (2) and B (3); everything of B is named with a marker
	exec(`INSERT INTO tenants(id, name) VALUES (2, 'tenant-a'), (3, 'tenant-b-secret')`)
	exec(`INSERT INTO console_users(email, role, tenant_id) VALUES ('a@a.test', 'admin', 2), ('b@b.test', 'admin', 3), ('root@msp.test', 'admin', NULL)`)
	exec(`INSERT INTO local_admins(name, role, password_hash, totp_secret, tenant_id) VALUES ('userb', 'helpdesk', 'x', 'x', 3)`)
	exec(`INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tenant_id, tags) VALUES
		('deva', 'a1', now() + interval '1 year', 'host-a', 2, '{a}'), ('devb', 'b1', now() + interval '1 year', 'host-b-secret', 3, '{b}')`)
	itemB := scalar(`INSERT INTO library_items(name, type, payload, tenant_id) VALUES ('item-b-secret', 'com.limdm.banner', '{"text":"x"}', 3) RETURNING id::text`)
	bpB := scalar(`INSERT INTO blueprints(name, tenant_id) VALUES ('bp-b-secret', 3) RETURNING id::text`)
	tokB := sha("lmt_btoken")
	exec(`INSERT INTO enroll_tokens(token_hash, note, uses_left, expires_at, created_by, tenant_id) VALUES ($1, 'token-b-secret', 5, now() + interval '1 day', 'b@b.test', 3)`, tokB)
	excB := scalar(`INSERT INTO risk_exceptions(check_id, mode, reason, owner, approver, expires_at, created_by, tenant_id)
		VALUES ('ssh.root', 'exclude', 'exc-b-secret', 'o', 'p', now() + interval '1 day', 'b@b.test', 3) RETURNING id::text`)
	apprB := scalar(`INSERT INTO approvals(action, target, requested_by, reason, expires_at, tenant_id) VALUES ('command', 'devb', 'b@b.test', 'appr-b-secret', now() + interval '1 day', 3) RETURNING id::text`)
	chanB := scalar(`INSERT INTO notification_channels(name, kind, tenant_id) VALUES ('chan-b-secret', 'webhook', 3) RETURNING id::text`)
	apiB := scalar(`INSERT INTO api_tokens(name, prefix, token_hash, role, created_by, expires_at, tenant_id) VALUES ('api-b-secret', 'lma_x', $1, 'admin', 'b@b.test', now() + interval '1 day', 3) RETURNING id::text`, sha("lma_b"))
	cmdB := scalar(`INSERT INTO commands(device_id, type, output, created_by) VALUES ('devb', 'diagnostics', 'cmd-b-secret', 'b@b.test') RETURNING id::text`)
	exec(`INSERT INTO diagnostics(device_id, command_id, content) VALUES ('devb', $1, 'diag-b-secret')`, cmdB)
	exec(`INSERT INTO shell_sessions(id, device_id, requested_by, local_user, ended_at, transcript) VALUES ('sidb', 'devb', 'b@b.test', 'root', now(), 'shell-b-secret')`)
	exec(`INSERT INTO network_certs(serial, device_id, subject, not_before, not_after) VALUES ('ab12', 'devb', 'cert-b-secret', now(), now() + interval '1 year')`)
	exec(`INSERT INTO device_events(device_id, at, detail) VALUES ('devb', now(), 'event-b-secret')`)
	exec(`INSERT INTO compliance_changes(device_id, at, check_id, status, detail) VALUES ('devb', now() - interval '2 days', 'ssh.root', 'fail', 'hist-b-secret')`)
	if err := s.auditAction(withTenant(ctx, 3), "b@b.test", "test.entry", "", "audit-b-secret", nil); err != nil {
		t.Fatal(err)
	}
	if got := scalar(`SELECT tenant_id::text FROM network_certs WHERE serial='ab12'`); got != "3" {
		t.Fatalf("rows per device take the device's tenant, got %s", got)
	}
	snapshot := func() string {
		return scalar(`SELECT concat_ws('|', (SELECT count(*) FROM library_items WHERE tenant_id=3), (SELECT string_agg(name || payload::text, ',') FROM library_items WHERE tenant_id=3),
			(SELECT string_agg(name || tree::text || coalesce(parent_id, 0), ',') FROM blueprints WHERE tenant_id=3), (SELECT count(*) FROM enroll_tokens WHERE tenant_id=3),
			(SELECT string_agg(coalesce(revoked_at::text, 'open'), ',') FROM risk_exceptions WHERE tenant_id=3), (SELECT string_agg(status, ',') FROM approvals WHERE tenant_id=3),
			(SELECT string_agg(enabled::text, ',') FROM notification_channels WHERE tenant_id=3), (SELECT string_agg(coalesce(revoked_at::text, 'open'), ',') FROM api_tokens WHERE tenant_id=3),
			(SELECT string_agg(hostname || retired::text || tags::text || coalesce(blueprint_id, 0) || update_requested::text, ',') FROM devices WHERE tenant_id=3),
			(SELECT count(*) FROM commands WHERE device_id='devb'), (SELECT string_agg(role || disabled::text || session_gen, ',') FROM local_admins WHERE tenant_id=3),
			(SELECT string_agg(name || disabled::text || company_name, ',') FROM tenants WHERE id=3))`)
	}
	before := snapshot()

	admin := httptest.NewServer(s.AdminHandler())
	defer admin.Close()
	sessA := session{Email: "a@a.test", Role: "admin", IAT: time.Now(), Last: time.Now()}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path string, form url.Values) (int, string) {
		t.Helper()
		if form == nil {
			form = url.Values{}
		}
		form.Set("csrf", s.csrfToken(sessA))
		body := io.Reader(nil)
		if method == http.MethodPost {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, admin.URL+path, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sessA)})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := do("GET", "/devices", nil); code != 200 || !strings.Contains(body, "host-a") {
		t.Fatalf("tenant admin sees their own devices: %d", code)
	}

	// every console route registered in the package
	re := regexp.MustCompile(`HandleFunc\("([A-Z]+) (/[^"]*)"`)
	files, _ := filepath.Glob("*.go")
	var routes [][2]string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			routes = append(routes, [2]string{m[1], m[2]})
		}
	}
	public := []string{"/healthz", "/login", "/lang/{lang}", "/datefmt/{format}", "/branding/logo.png", "/install.sh", "/login/oidc",
		"/login/local", "/auth/callback", "/logout", "/static/", "/shell/{sid}/ws"}
	ids := map[string]string{"/devices/": "devb", "/blueprints/": bpB, "/library/": itemB, "/tokens/": hex.EncodeToString(tokB),
		"/compliance/exceptions/": excB, "/approvals/": apprB, "/settings/notifications/": chanB, "/settings/api/": apiB, "/tenants/": "3"}
	ops := map[string]string{"/approvals/": "approve", "/settings/notifications/": "disable"}
	// form values pointing at B's objects for routes that take them from the body
	forms := map[string]url.Values{
		"/devices/bulk":          {"id": {"devb"}, "action": {"tag-add"}, "tag": {"x"}},
		"/library":               {"id": {itemB}, "name": {"probe-item"}, "type": {"com.limdm.banner"}, "payload": {`{"text":"changed"}`}},
		"/blueprints":            {"id": {bpB}, "name": {"probe-bp"}, "tree": {"[]"}},
		"/tokens":                {"uses": {"1"}, "days": {"1"}, "blueprint_id": {bpB}},
		"/users/update":          {"login": {"local:userb"}, "role": {"auditor"}},
		"/users/reset":           {"login": {"local:userb"}},
		"/compliance/exceptions": {"check_id": {"x"}, "mode": {"exclude"}, "reason": {"r"}, "owner": {"o"}, "approver": {"p"}, "expires": {time.Now().AddDate(0, 0, 3).Format("2006-01-02")}},
	}
	tested := 0
	for _, rt := range routes {
		method, pattern := rt[0], rt[1]
		if slices.Contains(public, pattern) || strings.HasPrefix(pattern, "/api/") || strings.HasPrefix(pattern, "/scim/") || pattern == "/metrics" {
			continue
		}
		path := strings.TrimSuffix(pattern, "{$}")
		ownsB := false
		for prefix, id := range ids {
			if strings.HasPrefix(path, prefix+"{id}") {
				path, ownsB = strings.Replace(path, "{id}", id, 1), true
				if op, ok := ops[prefix]; ok {
					path = strings.Replace(path, "{op}", op, 1)
				}
			}
		}
		path = strings.NewReplacer("{cid}", cmdB, "{sid}", "sidb", "{op}", "approve", "{name}", "x", "{version}", "1.0.0", "{file}", "x", "{id}", "x").Replace(path)
		kinds := []string{""}
		if strings.Contains(path, "{kind}") {
			kinds = []string{"compliance.csv", "compliance-history.csv", "inventory.csv", "packages.csv", "audit.csv", "audit.jsonl", "exceptions.csv"}
		}
		for _, k := range kinds {
			p := strings.Replace(path, "{kind}", k, 1)
			form := url.Values{}
			for key, vals := range forms[pattern] {
				form[key] = slices.Clone(vals)
			}
			form.Set("version", "1")
			code, body := do(method, p, form)
			tested++
			if strings.Contains(body, "-b-secret") {
				t.Errorf("%s %s (%d) shows data of tenant B", method, p, code)
			}
			denied := code == http.StatusForbidden || code == http.StatusNotFound
			if pattern == "/shell/{sid}/end" && code == http.StatusSeeOther { // no live session: only a redirect to the (denied) view
				continue
			}
			if (ownsB || pattern == "/network/crl.pem") && !denied {
				t.Errorf("%s %s: want 403 or 404 for tenant B's object, got %d", method, p, code)
			}
		}
	}
	if tested < 60 {
		t.Fatalf("only %d routes walked", tested)
	}

	// admin API with a tenant A token
	exec(`INSERT INTO api_tokens(name, prefix, token_hash, role, created_by, expires_at, tenant_id) VALUES ('a', 'lma_a', $1, 'admin', 'a@a.test', now() + interval '1 day', 2)`, sha("lma_a"))
	apiDo := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, admin.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer lma_a")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, c := range [][3]string{
		{"GET", "/api/v1/devices/devb", ""}, {"PATCH", "/api/v1/devices/devb", `{"tags":["x"]}`}, {"GET", "/api/v1/devices/devb/commands", ""},
		{"POST", "/api/v1/devices/devb/commands", `{"type":"sync"}`}, {"GET", "/api/v1/commands/" + cmdB, ""},
		{"GET", "/api/v1/library-items/" + itemB, ""}, {"PUT", "/api/v1/library-items/" + itemB, `{"name":"item-b-secret","type":"com.limdm.banner","payload":{"text":"y"}}`},
		{"DELETE", "/api/v1/library-items/" + itemB, ""}, {"GET", "/api/v1/blueprints/" + bpB, ""},
		{"PUT", "/api/v1/blueprints/" + bpB, `{"name":"bp-b-secret","tree":[]}`}, {"DELETE", "/api/v1/blueprints/" + bpB, ""},
	} {
		if code, _ := apiDo(c[0], c[1], c[2]); code != http.StatusNotFound && code != http.StatusForbidden {
			t.Errorf("API %s %s: want 403 or 404, got %d", c[0], c[1], code)
		}
	}
	for _, p := range []string{"/api/v1/devices", "/api/v1/library-items", "/api/v1/blueprints", "/api/v1/tags", "/api/v1/audit"} {
		if code, body := apiDo("GET", p, ""); code != 200 || strings.Contains(body, "-b-secret") || strings.Contains(body, `"b"`) {
			t.Errorf("API %s: %d, shows tenant B", p, code)
		}
	}
	if code, _ := apiDo("GET", "/metrics", ""); code != http.StatusForbidden {
		t.Errorf("metrics are global only, got %d", code)
	}

	if after := snapshot(); after != before {
		t.Fatalf("tenant B changed:\nbefore %s\nafter  %s", before, after)
	}

	// a blueprint of tenant A cannot reference B's private item (console
	// and API), a shared item of the default tenant it can
	refB := `[{"kind":"assign","items":[` + itemB + `]}]`
	do("POST", "/blueprints", url.Values{"name": {"bp-a-ref"}, "tree": {refB}})
	if code, _ := apiDo("POST", "/api/v1/blueprints", `{"name":"bp-a-ref2","tree":`+refB+`}`); code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
		t.Errorf("API blueprint with tenant B's item: %d", code)
	}
	if n := scalar(`SELECT count(*)::text FROM blueprints WHERE name LIKE 'bp-a-ref%'`); n != "0" {
		t.Fatal("blueprint referencing another tenant's item was saved")
	}
	shared := scalar(`INSERT INTO library_items(name, type, payload, tenant_id, shared) VALUES ('shared-item', 'com.limdm.banner', '{"text":"s"}', 1, true) RETURNING id::text`)
	do("POST", "/blueprints", url.Values{"name": {"bp-a-shared"}, "tree": {`[{"kind":"assign","items":[` + shared + `]}]`}})
	if got := scalar(`SELECT coalesce((SELECT tenant_id::text FROM blueprints WHERE name='bp-a-shared'), 'missing')`); got != "2" {
		t.Fatalf("blueprint with a shared item: %s", got)
	}
	// resolution ignores a cross tenant reference written to the database directly
	exec(`INSERT INTO blueprints(name, tenant_id, tree) VALUES ('bp-a-forged', 2, $1)`, refB)
	exec(`UPDATE devices SET blueprint_id=(SELECT id FROM blueprints WHERE name='bp-a-forged') WHERE id='deva'`)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolveDevice(ctx, tx, "deva")
	tx.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		if strconv.FormatInt(it.ID, 10) == itemB {
			t.Fatal("tenant B's item resolved for a device of tenant A")
		}
	}

	// enrollment tokens enroll into their tenant
	if _, err := db.Exec(ctx, `UPDATE enroll_tokens SET uses_left=1 WHERE token_hash=$1`, tokB); err != nil {
		t.Fatal(err)
	}
	if got := scalar(`SELECT tenant_id::text FROM enroll_tokens WHERE token_hash=$1`, tokB); got != "3" {
		t.Fatal(got)
	}

	// keys belong to the whole installation: tenant admins neither see the
	// Keys card nor reach the rotation steps
	if code, body := do("GET", "/settings?tab=security", nil); code != 200 || strings.Contains(body, "/settings/keys/") {
		t.Fatalf("tenant admin sees the Keys card: %d", code)
	}
	for _, op := range []string{"rotate", "finish"} {
		if code, _ := do("POST", "/settings/keys/"+op+"/ca", url.Values{}); code != http.StatusForbidden {
			t.Fatalf("tenant admin %s: %d", op, code)
		}
	}

	// a super admin sees both tenants; switching narrows the view
	root := session{Email: "root@msp.test", Role: "admin", IAT: time.Now(), Last: time.Now()}
	sessA = root
	if _, body := do("GET", "/settings?tab=security", nil); !strings.Contains(body, "/settings/keys/rotate/ca") {
		t.Fatal("super admin misses the Keys card")
	}
	if code, body := do("GET", "/devices", nil); code != 200 || !strings.Contains(body, "host-b-secret") || !strings.Contains(body, "host-a") {
		t.Fatalf("global view: %d", code)
	}
	if code, _ := do("GET", "/tenants", nil); code != 200 {
		t.Fatalf("tenant list: %d", code)
	}
	sessA.Tenant = 2
	if _, body := do("GET", "/devices", nil); strings.Contains(body, "host-b-secret") {
		t.Fatal("super admin switched to tenant A still sees tenant B")
	}
	// tenant B's admin sees the audit entry of B
	sessA = session{Email: "b@b.test", Role: "admin", IAT: time.Now(), Last: time.Now()}
	if _, body := do("GET", "/audit", nil); !strings.Contains(body, "audit-b-secret") {
		t.Fatal("tenant B's audit view misses its entry")
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("chain with tenant entries: broken=%d err=%v", broken, err)
	}
	// a disabled tenant cannot sign in
	exec(`UPDATE tenants SET disabled=true WHERE id=3`)
	if code, _ := do("GET", "/classic", nil); code != http.StatusFound {
		t.Fatalf("disabled tenant still signed in: %d", code)
	}
}
