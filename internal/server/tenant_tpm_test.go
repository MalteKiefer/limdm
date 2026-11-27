package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
)

// A tenant's own admins may require a TPM bound key but not lift it.
func TestTenantRequireTPM(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db := resetDB(t, dsn)
	s := &Server{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{MultiTenant: true}}
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'tenant-a')`); err != nil {
		t.Fatal(err)
	}
	set := func(sess session, on bool) bool {
		t.Helper()
		cur, err := s.loadTenantFor(ctx, sess, 2)
		if err != nil {
			t.Fatal(err)
		}
		in := cur
		in.RequireTPM = on
		if err := s.updateTenant(ctx, sess, cur, in, nil, true); err != nil {
			t.Fatal(err)
		}
		got, _ := s.loadTenantFor(ctx, sess, 2)
		return got.RequireTPM
	}
	own := session{Email: "a@a.test", Role: "admin", Tenant: 2}
	if !set(own, true) {
		t.Fatal("tenant admin could not require a TPM")
	}
	if !set(own, false) {
		t.Fatal("tenant admin lifted the TPM requirement")
	}
	if set(session{Email: "root@msp.test", Role: "admin", Super: true}, false) {
		t.Fatal("super admin could not lift the TPM requirement")
	}
}
