package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// evidenceServer gives a fresh schema, a server and a console client for an
// admin session.
func evidenceServer(t *testing.T) (*Server, *pgxpool.Pool, func(method, path string, form url.Values) (int, string)) {
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
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{7}, 32),
		Admins: []string{"admin@firma.de"}, LocalLogin: true,
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{LocalLogin: true, StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	web := httptest.NewServer(s.AdminHandler())
	t.Cleanup(web.Close)
	sess := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	ui := func(method, path string, form url.Values) (int, string) {
		t.Helper()
		if form != nil {
			form.Set("csrf", s.csrfToken(sess))
		}
		req, _ := http.NewRequest(method, web.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	return s, db, ui
}

func TestKeyedAuditChain(t *testing.T) {
	s, db, ui := evidenceServer(t)
	ctx := context.Background()
	prevKey, prevFrom := auditKey, auditKeyedFrom
	t.Cleanup(func() { auditKey, auditKeyedFrom = prevKey, prevFrom })
	auditKey, auditKeyedFrom = nil, 0
	for range 3 { // plain entries written before the upgrade
		if err := s.auditAction(ctx, "admin@firma.de", "test.plain", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := initAuditKey(ctx, db, dir, testCmdKey); err != nil {
		t.Fatal(err)
	}
	if auditKeyedFrom != 4 {
		t.Fatalf("switch point %d, want 4", auditKeyedFrom)
	}
	if err := initAuditKey(ctx, db, dir, testCmdKey); err != nil { // a restart reads the recorded switch point
		t.Fatal(err)
	}
	var switches int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='audit.keyed'`).Scan(&switches)
	if switches != 1 || auditKeyedFrom != 4 {
		t.Fatalf("switch recorded %d times, from %d", switches, auditKeyedFrom)
	}
	for i := range 150 { // more than one page
		if err := s.auditAction(ctx, "admin@firma.de", "test.keyed", "t"+string(rune('a'+i%26)), "", nil); err != nil {
			t.Fatal(err)
		}
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("keyed chain: broken=%d err=%v", broken, err)
	}

	// paging: the first page links to older entries, which end at entry 1
	code, body := ui("GET", "/audit", nil)
	if code != 200 || !strings.Contains(body, "before=") {
		t.Fatalf("audit page has no paging: %d", code)
	}
	if code, body = ui("GET", "/audit?before=60", nil); code != 200 || strings.Contains(body, ">60<") || !strings.Contains(body, ">59<") {
		t.Fatalf("second page: %d", code)
	}
	if code, _ := ui("POST", "/audit/verify", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("verify action: %d", code)
	}
	var verified string
	db.QueryRow(ctx, `SELECT detail FROM audit_log WHERE action='audit.verify'`).Scan(&verified)
	if verified != "chain intact" {
		t.Fatalf("verify result %q", verified)
	}

	// the JSON Lines export verifies outside the database, and its SHA-256 is audited
	code, export := ui("GET", "/export/audit.jsonl?from="+time.Now().Format("2006-01-02"), nil)
	if code != 200 {
		t.Fatalf("export: %d", code)
	}
	n, first, _, broken, err := VerifyAuditExport(strings.NewReader(export), AuditKey(testCmdKey), auditKeyedFrom)
	if err != nil || broken != 0 || first != 1 || n < 150 {
		t.Fatalf("export verification: n=%d first=%d broken=%d err=%v", n, first, broken, err)
	}
	sum := sha256.Sum256([]byte(export))
	var done string
	db.QueryRow(ctx, `SELECT detail FROM audit_log WHERE action='export.done' AND target='audit.jsonl'`).Scan(&done)
	if !strings.Contains(done, hex.EncodeToString(sum[:])) {
		t.Fatalf("export.done %q lacks the file hash", done)
	}

	// syslog forwarding sends every entry once and resumes after the last sent
	var sent []string
	last := int64(0)
	var total int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&total)
	for range 2 {
		if err := s.forwardAudit(ctx, "mdm", &last, func(m string) error { sent = append(sent, m); return nil }); err != nil || len(sent) != total {
			t.Fatalf("forward: %v sent %d of %d", err, len(sent), total)
		}
	}

	// a row changed with database rights breaks the keyed chain
	if _, err := db.Exec(ctx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change; UPDATE audit_log SET detail='forged' WHERE id=10;
		ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change`); err != nil {
		t.Skip("cannot disable the trigger with this role: ", err)
	}
	if broken, _ := s.verifyAuditFrom(ctx, false); broken != 10 {
		t.Fatalf("forged entry not detected: %d", broken)
	}
}

func TestComplianceHistory(t *testing.T) {
	_, db, ui := evidenceServer(t)
	ctx := context.Background()
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1', 's', now(), 'pc1')`)
	report := func(checks ...api.CheckResult) {
		t.Helper()
		tx, _ := db.Begin(ctx)
		defer tx.Rollback(ctx)
		if err := recordCheckChanges(ctx, tx, "d1", checks, "2026.11.1"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET checks=$2 WHERE id=$1`, "d1", jsonb(checks)); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	report(api.CheckResult{ID: "firewall.active", Status: "fail"}, api.CheckResult{ID: "time.sync", Status: "pass"})
	db.Exec(ctx, `ALTER TABLE compliance_changes DISABLE TRIGGER compliance_changes_append_only;
		UPDATE compliance_changes SET at = now() - interval '3 days'; ALTER TABLE compliance_changes ENABLE TRIGGER compliance_changes_append_only`)
	report(api.CheckResult{ID: "firewall.active", Status: "fail", Detail: "other detail"}, api.CheckResult{ID: "time.sync", Status: "pass"}) // no change
	report(api.CheckResult{ID: "firewall.active", Status: "pass"})                                                                           // fixed, time.sync gone
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM compliance_changes`).Scan(&n)
	if n != 4 {
		t.Fatalf("want 4 changes (2 initial, 1 fixed, 1 removed), got %d", n)
	}
	twoDaysAgo := time.Now().AddDate(0, 0, -2).Format("2006-01-02")
	code, body := ui("GET", "/compliance/history?device=d1&at="+twoDaysAgo, nil)
	if code != 200 || !strings.Contains(body, "firewall.active") || !strings.Contains(body, "time.sync") {
		t.Fatalf("history two days ago: %d", code)
	}
	code, csv := ui("GET", "/export/compliance-history.csv?device=d1", nil)
	if code != 200 || !strings.Contains(csv, "firewall.active,pass") || strings.Contains(csv, "time.sync") {
		t.Fatalf("history today:\n%s", csv)
	}
	code, csv = ui("GET", "/export/compliance-history.csv?at="+twoDaysAgo, nil)
	if code != 200 || !strings.Contains(csv, "firewall.active,fail") || !strings.Contains(csv, "2026.11.1") {
		t.Fatalf("history two days ago:\n%s", csv)
	}
	if code, _ := ui("GET", "/export/compliance-history.csv?at=yesterday", nil); code != http.StatusBadRequest {
		t.Fatalf("bad date accepted: %d", code)
	}
	if code, csv = ui("GET", "/export/compliance.csv", nil); code != 200 || !strings.HasPrefix(csv, "device_id,hostname,last_seen,agent_version,catalog_version") {
		t.Fatalf("evidence export header:\n%s", csv)
	}
}
