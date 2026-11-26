package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDeviceFilterAliases: the German names of the query language mean the
// same as the English ones, so both build the same conditions.
func TestDeviceFilterAliases(t *testing.T) {
	for _, tc := range [][2]string{
		{"status:nicht-konform", "status:non-compliant"},
		{"zustand:konform", "status:compliant"},
		{"status:in-karenz", "status:in-grace"},
		{"status:veraltet", "status:stale"},
		{"status:offline", "status:stale"},
		{"status:ausgemustert", "status:retired"},
		{"system:ubuntu schlagwort:prod", "os:ubuntu tag:prod"},
		{"pruefung:ssh.root paket:openssl", "check:ssh.root pkg:openssl"},
		{"offline:7d", "seen:>7d"},
		{"zuletzt:<2h", "seen:<2h"},
		{"art:arbeitsplatz", "kind:desktop"},
		{"status:gesperrt", "status:locked"},
	} {
		de, err1 := parseDeviceFilter(tc[0], time.Hour)
		en, err2 := parseDeviceFilter(tc[1], time.Hour)
		if err1 != nil || err2 != nil || strings.Join(de.conds, "|") != strings.Join(en.conds, "|") || len(de.args) != len(en.args) {
			t.Errorf("%q vs %q: %v %v %v %v", tc[0], tc[1], de.conds, en.conds, err1, err2)
		}
	}
	if w, err := parseDeviceFilter("status:gesperrt", time.Hour); err != nil || !strings.Contains(w.conds[0], "auto_locked") {
		t.Fatalf("locked: %v %v", w.conds, err)
	}
	for _, bad := range []string{"art:toaster", "status:kaputt"} {
		if _, err := parseDeviceFilter(bad, time.Hour); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
}

// TestAppDevicesAPI runs the device page endpoints of the console app
// against a database: detail, packages, timeline, details edit, bulk,
// agent update, retire and delete, enrollment tokens and the role checks.
func TestAppDevicesAPI(t *testing.T) {
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
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ca: ca, db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", AgentURL: "https://mdm.test:8444", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{3}, 32),
		Admins: []string{"admin@firma.de"}, Auditors: []string{"audit@firma.de"},
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO console_users(email, role) VALUES ('help@firma.de', 'helpdesk')`); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version) VALUES
		('d1', 's', now(), 'alpha', '{"os_name":"Ubuntu 24.04","desktop":"GNOME"}', '{prod}', now(), '[{"id":"c1","status":"fail"}]', 1, '0.17.0'),
		('d2', 's', now(), 'beta', '{"os_name":"Debian 12"}', '{}', now(), '[]', 0, '0.17.0');
		INSERT INTO device_events(device_id, at, detail) VALUES ('d1', now() - interval '1 minute', 'checked in');
		INSERT INTO dir_users(source, user_name, email) VALUES ('scim', 'jane', 'jane@firma.de')`); err != nil {
		t.Fatal(err)
	}
	admin := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	help := session{Email: "help@firma.de", Role: "helpdesk", IAT: time.Now(), Last: time.Now()}
	auditor := session{Email: "audit@firma.de", Role: "auditor", IAT: time.Now(), Last: time.Now()}
	call := func(sess session, method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		req.Header.Set(csrfHeader, s.csrfToken(sess))
		req.Header.Set("Origin", "https://mdm.test")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, d := call(auditor, "GET", "/api/v1/devices/d1/detail", "")
	if code != 200 || d["hostname"] != "alpha" || d["inventory"].(map[string]any)["desktop"] != "GNOME" || len(d["check_results"].([]any)) != 1 {
		t.Fatalf("detail: %d %v", code, d)
	}
	if code, _ := call(auditor, "GET", "/api/v1/devices/nope/detail", ""); code != 404 {
		t.Fatalf("unknown device: %d", code)
	}
	if code, p := call(auditor, "GET", "/api/v1/devices/d1/packages", ""); code != 200 || p["items"] == nil {
		t.Fatalf("packages: %d %v", code, p)
	}
	if code, apps := call(help, "GET", "/api/v1/devices/catalog-apps", ""); code != 200 || apps["items"] == nil {
		t.Fatalf("catalog apps: %d %v", code, apps)
	}
	if code, list := call(admin, "GET", "/api/v1/devices?filter=art:arbeitsplatz", ""); code != 200 || len(list["items"].([]any)) != 1 {
		t.Fatalf("german filter: %d %v", code, list)
	}

	// edit details: users, primary user, tags
	if code, _ := call(admin, "PATCH", "/api/v1/devices/d1", `{"users":[{"username":"jdoe","email":"Jane@Firma.de","admin":true}],"primary_user":"jane@firma.de","tags":["prod","berlin"]}`); code != 200 {
		t.Fatalf("patch: %d", code)
	}
	var users string
	var primary *int64
	if err := db.QueryRow(ctx, `SELECT users::text, primary_user_id FROM devices WHERE id='d1'`).Scan(&users, &primary); err != nil || !strings.Contains(users, "jane@firma.de") || primary == nil {
		t.Fatalf("patch stored: %s %v %v", users, primary, err)
	}
	if code, _ := call(admin, "PATCH", "/api/v1/devices/d1", `{"primary_user":"ghost@firma.de"}`); code != 422 {
		t.Fatalf("unknown primary user: %d", code)
	}
	if code, p := call(admin, "GET", "/api/v1/devices/primary-users?q=jane", ""); code != 200 || len(p["items"].([]any)) != 1 {
		t.Fatalf("people: %d %v", code, p)
	}

	// bulk: the helpdesk syncs, but tags are for admins
	if code, b := call(help, "POST", "/api/v1/devices/bulk", `{"ids":["d1","d2"],"action":"command:sync"}`); code != 202 || b["status"] != "queued" {
		t.Fatalf("bulk sync: %d %v", code, b)
	}
	if code, _ := call(help, "POST", "/api/v1/devices/bulk", `{"ids":["d1"],"action":"tag-add","params":{"tag":"x"}}`); code != 403 {
		t.Fatalf("helpdesk tag: %d", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/devices/bulk", `{"ids":["d1","d2"],"action":"tag-add","params":{"tag":"vip"}}`); code != 202 {
		t.Fatalf("bulk tag: %d", code)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM devices WHERE 'vip' = ANY(tags)`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("bulk tag stored: %d %v", n, err)
	}
	if code, _ := call(admin, "POST", "/api/v1/devices/bulk", `{"ids":["d1"],"action":"command:wipe"}`); code != 422 {
		t.Fatalf("bulk wipe: %d", code)
	}

	// the timeline merges events and the commands just sent, newest first;
	// the helpdesk has no audit permission, so it sees no audit entries
	code, tl := call(help, "GET", "/api/v1/devices/d1/timeline?limit=1", "")
	if code != 200 || len(tl["items"].([]any)) != 1 || tl["next_cursor"] == nil || tl["items"].([]any)[0].(map[string]any)["kind"] != "command" {
		t.Fatalf("timeline: %d %v", code, tl)
	}
	code, tl2 := call(help, "GET", "/api/v1/devices/d1/timeline?cursor="+tl["next_cursor"].(string), "")
	if code != 200 || len(tl2["items"].([]any)) != 1 || tl2["items"].([]any)[0].(map[string]any)["kind"] != "event" {
		t.Fatalf("timeline page 2: %d %v", code, tl2)
	}
	if code, tl := call(help, "GET", "/api/v1/devices/d1/timeline?kind=audit", ""); code != 200 || len(tl["items"].([]any)) != 0 {
		t.Fatalf("helpdesk audit timeline: %d %v", code, tl)
	}
	// compliance changes and, with the audit permission, audit entries about the device
	if _, err := db.Exec(ctx, `INSERT INTO compliance_changes(device_id, at, check_id, status) VALUES ('d1', now(), 'c1', 'fail')`); err != nil {
		t.Fatal(err)
	}
	code, tl = call(auditor, "GET", "/api/v1/devices/d1/timeline?kind=compliance", "")
	if code != 200 || len(tl["items"].([]any)) != 1 || tl["items"].([]any)[0].(map[string]any)["title"] != "c1" || tl["items"].([]any)[0].(map[string]any)["status"] != "fail" {
		t.Fatalf("compliance timeline: %d %v", code, tl)
	}
	code, tl = call(auditor, "GET", "/api/v1/devices/d1/timeline?kind=audit", "")
	if code != 200 || len(tl["items"].([]any)) == 0 || tl["items"].([]any)[0].(map[string]any)["by"] != "admin@firma.de" {
		t.Fatalf("audit timeline: %d %v", code, tl)
	}
	if code, _ := call(auditor, "GET", "/api/v1/devices/d1/timeline?kind=nope", ""); code != 400 {
		t.Fatalf("bad kind: %d", code)
	}

	// agent update and recovery key: role checks and validation
	if code, _ := call(help, "POST", "/api/v1/devices/d1/agent-update", `{}`); code != 403 {
		t.Fatalf("helpdesk agent update: %d", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/devices/d1/agent-update", `{"version":"9.9.9"}`); code != 422 {
		t.Fatalf("unknown version: %d", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/devices/d1/agent-update", `{}`); code != 202 {
		t.Fatalf("agent update: %d", code)
	}
	if code, _ := call(auditor, "POST", "/api/v1/devices/d1/recovery-keys/u1/view", `{}`); code != 403 {
		t.Fatalf("auditor recovery: %d", code)
	}
	if code, _ := call(help, "POST", "/api/v1/devices/d1/recovery-keys/u1/view", `{}`); code != 404 {
		t.Fatalf("missing recovery key: %d", code)
	}
	if code, _ := call(help, "POST", "/api/v1/devices/d1/shell", `{}`); code != 403 {
		t.Fatalf("shell while disabled: %d", code)
	}

	// retire, then delete with the host name
	if code, _ := call(admin, "DELETE", "/api/v1/devices/d2?confirm=beta", ""); code != 409 {
		t.Fatalf("delete before retire: %d", code)
	}
	if code, _ := call(admin, "POST", "/api/v1/devices/d2/retire", ""); code != 200 {
		t.Fatalf("retire: %d", code)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/devices/d2?confirm=wrong", ""); code != 422 {
		t.Fatalf("delete wrong name: %d", code)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/devices/d2?confirm=BETA", ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}

	// enrollment tokens
	if code, _ := call(admin, "POST", "/api/v1/enrollment-tokens", `{"note":"batch","uses":0,"days":7}`); code != 422 {
		t.Fatalf("token validation: %d", code)
	}
	code, tok := call(admin, "POST", "/api/v1/enrollment-tokens", `{"note":"batch","uses":3,"days":7}`)
	if code != 201 || !strings.HasPrefix(tok["token"].(string), "lmt_") {
		t.Fatalf("token: %d %v", code, tok)
	}
	if code, _ := call(help, "POST", "/api/v1/enrollment-tokens", `{"uses":1,"days":1}`); code != 403 {
		t.Fatalf("helpdesk token: %d", code)
	}
	if code, l := call(auditor, "GET", "/api/v1/enrollment-tokens", ""); code != 200 || len(l["items"].([]any)) != 1 || l["agent_url"] != "https://mdm.test:8444" {
		t.Fatalf("tokens: %d %v", code, l)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/enrollment-tokens/"+tok["id"].(string), ""); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action IN ('device.assign','device.tag-add','agent_update.request','device.retire','device.delete','token.create','token.revoke')`).Scan(&audits); err != nil || audits < 8 {
		t.Fatalf("audit entries: %d %v", audits, err)
	}

	// a tenant admin sees only the directory people of its own devices and
	// cannot make someone else's person the primary user
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'b');
		INSERT INTO dir_users(source, user_name, email) VALUES ('scim', 'bob', 'bob@b.de'), ('scim', 'eve', 'eve@firma.de');
		INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tenant_id, primary_user_id)
			VALUES ('d3', 's', now(), 'delta', '{}', 2, (SELECT id FROM dir_users WHERE email='bob@b.de'));
		INSERT INTO console_users(email, role, tenant_id) VALUES ('tadmin@b.de', 'admin', 2)`); err != nil {
		t.Fatal(err)
	}
	tadmin := session{Email: "tadmin@b.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	if code, p := call(tadmin, "GET", "/api/v1/devices/primary-users?q=", ""); code != 200 || len(p["items"].([]any)) != 1 || p["items"].([]any)[0] != "bob@b.de" {
		t.Fatalf("tenant people: %d %v", code, p)
	}
	if code, p := call(admin, "GET", "/api/v1/devices/primary-users?q=", ""); code != 200 || len(p["items"].([]any)) != 3 {
		t.Fatalf("global people: %d %v", code, p)
	}
	if code, _ := call(tadmin, "PATCH", "/api/v1/devices/d3", `{"primary_user":"jane@firma.de"}`); code != 422 {
		t.Fatalf("tenant sets a foreign person: %d", code)
	}
	if code, _ := call(tadmin, "PATCH", "/api/v1/devices/d3", `{"primary_user":"bob@b.de"}`); code != 200 {
		t.Fatalf("tenant keeps its person: %d", code)
	}
	if code, _ := call(tadmin, "GET", "/api/v1/devices/d1/detail", ""); code != 404 {
		t.Fatalf("tenant sees a foreign device: %d", code)
	}
}
