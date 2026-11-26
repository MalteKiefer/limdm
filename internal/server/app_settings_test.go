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

	"filippo.io/age"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAppSettingsAPI runs the settings area endpoints with a console
// session: the same rules as the console pages (self protection, four
// eyes, global only, secrets never in answers).
func TestAppSettingsAPI(t *testing.T) {
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
	s := &Server{db: db, cmdKey: testCmdKey, whKey: bytes.Repeat([]byte{7}, 32), log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{3}, 32), CADir: t.TempDir(),
		Admins: []string{"admin@firma.de"}, Auditors: []string{"audit@firma.de"},
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, LocalLogin: true, OIDCIssuer: "https://idp.test", OIDCClientID: "x", OIDCClientSecret: "topsecret"}, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	admin := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	auditor := session{Email: "audit@firma.de", Role: "auditor", IAT: time.Now(), Last: time.Now()}
	call := func(sess session, method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrfHeader, s.csrfToken(sess))
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	want := func(code int, body string, status int, what string) {
		t.Helper()
		if code != status {
			t.Fatalf("%s: %d %s", what, code, body)
		}
	}

	// settings: no secret in the answer, sections save through saveSettings
	code, body := call(auditor, "GET", "/api/v1/settings", "")
	want(code, body, 200, "settings as auditor")
	if strings.Contains(body, "topsecret") || !strings.Contains(body, `"has_oidc_secret":true`) || strings.Contains(body, "webhook_secret") {
		t.Fatalf("settings view leaks or misses: %s", body)
	}
	code, body = call(auditor, "PATCH", "/api/v1/settings/general", `{"stale_hours":48}`)
	want(code, body, 403, "auditor saves settings")
	code, body = call(admin, "PATCH", "/api/v1/settings/general", `{"stale_hours":48}`)
	want(code, body, 200, "save general")
	if s.settings().StaleHours != 48 || !s.settings().LocalLogin || s.settings().OIDCClientSecret != "topsecret" {
		t.Fatalf("general save changed more than its fields: %+v", s.settings())
	}
	code, body = call(admin, "PATCH", "/api/v1/settings/general", `{"stale_hours":0}`)
	want(code, body, 422, "invalid stale hours")
	code, body = call(admin, "PATCH", "/api/v1/settings/colors", `{}`)
	want(code, body, 400, "unknown section")
	code, body = call(admin, "PATCH", "/api/v1/settings/security", `{"four_eyes":true}`)
	want(code, body, 422, "four eyes with one admin")
	code, body = call(admin, "PATCH", "/api/v1/settings/network", `{"console_allow":["10.9.0.0/33"]}`)
	want(code, body, 422, "bad network")
	code, body = call(admin, "PATCH", "/api/v1/settings/sso", `{"role_groups":[{"group":"it","role":"owner"}]}`)
	want(code, body, 422, "bad role group")
	code, body = call(admin, "PATCH", "/api/v1/settings/retention", `{"retention":{"metrics":14}}`)
	want(code, body, 200, "retention")
	if s.settings().retentionDays("metrics") != 14 || s.settings().retentionDays("audit") != 1095 {
		t.Fatalf("retention: %v", s.settings().Retention)
	}
	var audited int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='settings.save'`).Scan(&audited)
	if audited != 2 {
		t.Fatalf("settings saves audited: %d", audited)
	}

	// users: local account with credentials once, self protection
	code, body = call(admin, "POST", "/api/v1/users", `{"kind":"local","login":"ops","role":"helpdesk"}`)
	want(code, body, 201, "add local user")
	if !strings.Contains(body, "password:") {
		t.Fatalf("no credentials: %s", body)
	}
	code, body = call(admin, "POST", "/api/v1/users", `{"kind":"local","login":"ops","role":"helpdesk"}`)
	want(code, body, 409, "duplicate user")
	code, body = call(admin, "PATCH", "/api/v1/users/admin@firma.de", `{"role":"auditor"}`)
	want(code, body, 422, "demote self")
	code, body = call(admin, "PATCH", "/api/v1/users/local:ops", `{"role":"helpdesk","scope_tags":["berlin"]}`)
	want(code, body, 204, "scope user")
	code, body = call(admin, "POST", "/api/v1/users/local:ops/reset", ``)
	want(code, body, 200, "reset")
	code, body = call(admin, "POST", "/api/v1/users/admin@firma.de/reset", ``)
	want(code, body, 422, "reset an OIDC account")
	code, body = call(auditor, "GET", "/api/v1/users", "")
	want(code, body, 200, "list users")
	var users struct {
		Items []apiUser `json:"items"`
	}
	json.Unmarshal([]byte(body), &users)
	if len(users.Items) != 3 || !strings.Contains(body, `"scope_tags":["berlin"]`) {
		t.Fatalf("users: %s", body)
	}

	// four eyes: with two admins, a new admin waits for approval
	call(admin, "POST", "/api/v1/users", `{"kind":"oidc","login":"second@firma.de","role":"admin"}`)
	code, body = call(admin, "PATCH", "/api/v1/settings/security", `{"four_eyes":true}`)
	want(code, body, 200, "four eyes on")
	code, body = call(admin, "POST", "/api/v1/users", `{"kind":"local","login":"boss","role":"admin","reason":"T-1"}`)
	want(code, body, 202, "admin add waits for approval")

	// tenants: multi tenancy off
	code, body = call(admin, "POST", "/api/v1/tenants/switch", `{"tenant":1}`)
	want(code, body, 403, "switch without multi tenancy")

	// backup: targets keep secrets server side, preview without saving
	dir := t.TempDir()
	code, body = call(admin, "PUT", "/api/v1/backup/targets/disk", `{"kind":"local","dir":"`+dir+`","secret_enc":"forged"}`)
	want(code, body, 204, "save target")
	code, body = call(admin, "POST", "/api/v1/backup/targets/disk/test", ``)
	want(code, body, 200, "test target")
	code, body = call(admin, "POST", "/api/v1/backup/schedules/preview", `{"name":"nightly","kind":"weekly","days":[1,2,3,4,5],"times":["02:00"],"targets":["disk"],"keep":{"daily":7}}`)
	want(code, body, 200, "preview")
	if !strings.Contains(body, `"next":["`) {
		t.Fatalf("preview: %s", body)
	}
	id, _ := age.GenerateX25519Identity()
	code, body = call(admin, "PUT", "/api/v1/backup", `{"recipients":["`+id.Recipient().String()+`"],"keep":{"last":3}}`)
	want(code, body, 204, "backup general")
	code, body = call(admin, "PUT", "/api/v1/backup/schedules/nightly", `{"kind":"weekly","days":[1],"times":["02:00"],"targets":["disk"],"keep":{"daily":7}}`)
	want(code, body, 204, "save schedule")
	code, body = call(admin, "DELETE", "/api/v1/backup/targets/disk", ``)
	want(code, body, 409, "delete a used target")
	code, body = call(admin, "GET", "/api/v1/backup", "")
	want(code, body, 200, "backup")
	if strings.Contains(body, "forged") || strings.Contains(body, "secret_enc") {
		t.Fatalf("backup answer: %s", body)
	}
	code, body = call(auditor, "GET", "/api/v1/backup", "")
	want(code, body, 403, "backup as auditor")

	// notification channels
	code, body = call(admin, "POST", "/api/v1/notification-channels", `{"name":"ops","kind":"slack","url":"https://hooks.slack.com/services/T/B/x","events":["device.tamper"]}`)
	want(code, body, 201, "add channel")
	var ch struct{ ID int64 }
	json.Unmarshal([]byte(body), &ch)
	code, body = call(admin, "POST", "/api/v1/notification-channels", `{"name":"bad","kind":"slack","url":"http://10.0.0.1/x"}`)
	want(code, body, 422, "plain http channel")
	code, body = call(admin, "PATCH", "/api/v1/notification-channels/"+itoa(ch.ID), `{"enabled":false}`)
	want(code, body, 204, "switch off")
	code, body = call(auditor, "GET", "/api/v1/notification-channels", "")
	want(code, body, 200, "channels")
	if strings.Contains(body, "/services/T/B/x") || !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("channels: %s", body)
	}
	code, body = call(admin, "DELETE", "/api/v1/notification-channels/"+itoa(ch.ID), ``)
	want(code, body, 204, "delete channel")
	code, body = call(admin, "DELETE", "/api/v1/notification-channels/"+itoa(ch.ID), ``)
	want(code, body, 404, "delete twice")

	// directory, agents, profile
	code, body = call(auditor, "GET", "/api/v1/directory", "")
	want(code, body, 200, "directory")
	code, body = call(admin, "POST", "/api/v1/directory/scim-token", ``)
	want(code, body, 201, "scim token")
	code, body = call(admin, "PUT", "/api/v1/agents/policy", `{"auto":true,"delay_days":200}`)
	want(code, body, 422, "policy delay")
	code, body = call(admin, "PUT", "/api/v1/agents/policy", `{"auto":true,"delay_days":3,"pilot_tag":"Pilot","spread_hours":24}`)
	want(code, body, 204, "policy")
	code, body = call(auditor, "GET", "/api/v1/agents", "")
	want(code, body, 200, "agents")
	if !strings.Contains(body, `"pilot_tag":"pilot"`) {
		t.Fatalf("agents: %s", body)
	}
	code, body = call(admin, "POST", "/api/v1/profile/password", `{"current":"x","new":"y","repeat":"y"}`)
	want(code, body, 422, "OIDC password")
	code, body = call(admin, "GET", "/api/v1/profile", "")
	want(code, body, 200, "profile")
}
