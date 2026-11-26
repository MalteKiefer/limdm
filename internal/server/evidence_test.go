package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
func evidenceServer(t *testing.T) (*Server, *pgxpool.Pool, func(method, path, body string) (int, string)) {
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
	return s, db, consoleAPI(t, s, web.URL, sess)
}

func TestKeyedAuditChain(t *testing.T) {
	s, db, ui := evidenceServer(t)
	ctx := context.Background()
	prevKey, prevFrom, prevKeys, prevCur := auditKey, auditKeyedFrom, auditKeys, auditKeyCur
	t.Cleanup(func() { auditKey, auditKeyedFrom, auditKeys, auditKeyCur = prevKey, prevFrom, prevKeys, prevCur })
	auditKey, auditKeyedFrom, auditKeys = nil, 0, nil
	for range 3 { // plain entries written before the upgrade
		if err := s.auditAction(ctx, "admin@firma.de", "test.plain", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := initAuditKey(ctx, db, dir, testCmdKey, nil); err != nil {
		t.Fatal(err)
	}
	if auditKeyedFrom != 4 {
		t.Fatalf("switch point %d, want 4", auditKeyedFrom)
	}
	if err := initAuditKey(ctx, db, dir, testCmdKey, nil); err != nil { // a restart reads the recorded switch point
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

	// paging: the first page has a cursor to older entries, the next page goes on below it
	type auditPage struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	var p1, p2 auditPage
	code, body := ui("GET", "/api/v1/audit?limit=50", "")
	if json.Unmarshal([]byte(body), &p1); code != 200 || p1.Next == "" || len(p1.Items) != 50 {
		t.Fatalf("audit has no paging: %d", code)
	}
	code, body = ui("GET", "/api/v1/audit?limit=50&cursor="+url.QueryEscape(p1.Next), "")
	if json.Unmarshal([]byte(body), &p2); code != 200 || len(p2.Items) == 0 || p2.Items[0].ID != p1.Items[49].ID-1 {
		t.Fatalf("second page: %d", code)
	}
	if code, _ := ui("POST", "/api/v1/audit/verify", ""); code != http.StatusOK {
		t.Fatalf("verify action: %d", code)
	}
	var verified string
	db.QueryRow(ctx, `SELECT detail FROM audit_log WHERE action='audit.verify'`).Scan(&verified)
	if verified != "chain intact" {
		t.Fatalf("verify result %q", verified)
	}

	// the JSON Lines export verifies outside the database, and its SHA-256 is audited
	code, export := ui("GET", "/api/v1/exports/audit.jsonl?from="+time.Now().Format("2006-01-02"), "")
	if code != 200 {
		t.Fatalf("export: %d", code)
	}
	n, first, _, broken, err := VerifyAuditExport(strings.NewReader(export), auditKeys)
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

	// a command key rotation starts a new segment; the whole chain still
	// verifies, and an instance with the old key cannot write any more
	oldCur := auditKeyCur
	newCmd := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if err := initAuditKey(ctx, db, dir, newCmd, nil); err == nil {
		t.Fatal("rotation without the previous key accepted")
	}
	if err := initAuditKey(ctx, db, dir, newCmd, testCmdKey); err != nil {
		t.Fatal(err)
	}
	if err := initAuditKey(ctx, db, dir, newCmd, nil); err != nil { // restart after finish
		t.Fatal(err)
	}
	if len(auditKeys) != 2 || !bytes.Equal(auditKey, AuditKey(newCmd)) {
		t.Fatalf("segments %d", len(auditKeys))
	}
	if err := s.auditAction(ctx, "admin@firma.de", "test.rotated", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("chain across the rotation: broken=%d err=%v", broken, err)
	}
	auditKeyCur = oldCur
	if err := s.auditAction(ctx, "admin@firma.de", "test.stale", "", "", nil); err == nil {
		t.Fatal("an instance with the old audit key wrote an entry")
	}
	auditKeyCur = auditKeyID(auditKey)

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
	code, body := ui("GET", "/api/v1/compliance/history?device=d1&at="+twoDaysAgo, "")
	if code != 200 || !strings.Contains(body, "firewall.active") || !strings.Contains(body, "time.sync") {
		t.Fatalf("history two days ago: %d", code)
	}
	code, csv := ui("GET", "/api/v1/exports/compliance-history.csv?device=d1", "")
	if code != 200 || !strings.Contains(csv, "firewall.active,pass") || strings.Contains(csv, "time.sync") {
		t.Fatalf("history today:\n%s", csv)
	}
	code, csv = ui("GET", "/api/v1/exports/compliance-history.csv?at="+twoDaysAgo, "")
	if code != 200 || !strings.Contains(csv, "firewall.active,fail") || !strings.Contains(csv, "2026.11.1") {
		t.Fatalf("history two days ago:\n%s", csv)
	}
	if code, _ := ui("GET", "/api/v1/exports/compliance-history.csv?at=yesterday", ""); code != http.StatusBadRequest {
		t.Fatalf("bad date accepted: %d", code)
	}
	if code, csv = ui("GET", "/api/v1/exports/compliance.csv", ""); code != 200 || !strings.HasPrefix(csv, "device_id,hostname,last_seen,agent_version,catalog_version") {
		t.Fatalf("evidence export header:\n%s", csv)
	}
}
