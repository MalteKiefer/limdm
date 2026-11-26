package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestLocalAdminKeyedAudit runs local-admin as its own process would (no
// audit key loaded) after a server keyed the chain: the entry must be keyed
// with the key from the CA directory, or refused without it.
func TestLocalAdminKeyedAudit(t *testing.T) {
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
	prevKey, prevFrom, prevKeys, prevCur := auditKey, auditKeyedFrom, auditKeys, auditKeyCur
	t.Cleanup(func() { auditKey, auditKeyedFrom, auditKeys, auditKeyCur = prevKey, prevFrom, prevKeys, prevCur })
	dir := t.TempDir()
	s, err := openCore(ctx, Config{CADir: dir, SessionKey: bytes.Repeat([]byte{4}, 32)}, slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	if err != nil {
		t.Fatal(err)
	}
	s.kr.cli = true
	if auditKey == nil {
		t.Fatal("the server did not key the audit chain")
	}
	cliProcess := func() { auditKey, auditKeyedFrom, auditKeys, auditKeyCur = nil, 0, nil, "" }

	cliProcess()
	t.Setenv("LIMDM_CA_DIR", t.TempDir()) // no command key there
	if _, err := LocalAdmin(ctx, dsn, "add", "breakglass", "admin"); err == nil {
		t.Fatal("local-admin wrote an unkeyed entry into a keyed chain")
	}
	cliProcess()
	t.Setenv("LIMDM_CA_DIR", dir)
	if _, err := LocalAdmin(ctx, dsn, "add", "breakglass", "admin"); err != nil {
		t.Fatal(err)
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("audit chain after local-admin: broken at %d, %v", broken, err)
	}
}
