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

// dashServer is a server on a fresh schema with three devices (alpha
// compliant, beta failing, gamma stale) and a client for console sessions
// of the app API (the dashboard areas: home, inbox, activity, reports).
func dashServer(t *testing.T) (*Server, *pgxpool.Pool, func(sess session, method, path, body string) (int, string)) {
	t.Helper()
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
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
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{3}, 32), MultiTenant: true,
		Admins: []string{"admin@firma.de", "boss@firma.de"}, Auditors: []string{"audit@firma.de"},
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO console_users(email, role) VALUES ('desk@firma.de', 'helpdesk')`); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, FourEyes: true, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	t.Cleanup(srv.Close)
	ok, fail := `[{"id":"c1","status":"pass"}]`, `[{"id":"c1","title":"SSH root","status":"fail"}]`
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags, last_seen, checks, failing) VALUES
		('d1', 's', now(), 'alpha', '{prod}', now(), $1, 0),
		('d2', 's', now(), 'beta', '{prod}', now(), $2, 1),
		('d3', 's', now(), 'gamma', '{}', now() - interval '3 days', $1, 0)`, ok, fail); err != nil {
		t.Fatal(err)
	}
	call := func(sess session, method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		sess.IAT, sess.Last = time.Now(), time.Now()
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		req.Header.Set("Origin", "https://mdm.test")
		req.Header.Set(csrfHeader, s.csrfToken(sess))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	return s, db, call
}

var (
	dashAdmin    = session{Email: "admin@firma.de", Role: "admin", Super: true}
	dashAuditor  = session{Email: "audit@firma.de", Role: "auditor"}
	dashHelpdesk = session{Email: "desk@firma.de", Role: "helpdesk"}
)

func TestAppHome(t *testing.T) {
	_, db, call := dashServer(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'Zweig');
		INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags, last_seen, checks, failing, tenant_id)
			VALUES ('t2', 's', now(), 'other', '{}', now(), '[{"id":"c1","status":"pass"}]', 0, 2);
		INSERT INTO commands(device_id, type, status, created_by) VALUES ('d1', 'sync', 'failed', 'x'), ('d1', 'sync', 'ok', 'x'), ('t2', 'sync', 'failed', 'x')`); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items []statsTenant `json:"items"`
	}
	code, body := call(dashAdmin, "GET", "/api/v1/stats/tenants", "")
	if json.Unmarshal([]byte(body), &page); code != 200 || len(page.Items) != 2 || page.Items[0].Devices != 3 || page.Items[0].Score != 50 || page.Items[1].Score != 100 {
		t.Fatalf("tenants: %d %s", code, body)
	}
	if code, _ := call(session{Email: "admin@firma.de", Role: "admin", Super: true, Tenant: 2}, "GET", "/api/v1/stats/tenants", ""); code != 403 {
		t.Fatalf("one tenant's view: %d", code)
	}
	if code, _ := call(dashAuditor, "GET", "/api/v1/stats/tenants", ""); code != 403 {
		t.Fatalf("auditor: %d", code)
	}
	var days struct {
		Items []statsCommandDay `json:"items"`
	}
	code, body = call(session{Email: "admin@firma.de", Role: "admin", Tenant: 1}, "GET", "/api/v1/stats/commands?days=3", "")
	if json.Unmarshal([]byte(body), &days); code != 200 || len(days.Items) != 3 || days.Items[2].Failed != 1 || days.Items[2].Total != 2 {
		t.Fatalf("command days: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "GET", "/api/v1/onboarding", ""); code != 200 || !strings.Contains(body, `"id":"device","done":true`) || !strings.Contains(body, `"id":"sso","done":true`) {
		t.Fatalf("onboarding: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/onboarding", ""); code != 200 || body != "{\"items\":[]}\n" {
		t.Fatalf("auditor onboarding: %d %s", code, body)
	}
}
