package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// A library item may reference only approved uploads of its own tenant,
// with the uploaded kind and size.
func TestArtifactRefs(t *testing.T) {
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
	db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'other')`)
	ok, pending := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := db.Exec(ctx, `INSERT INTO artifacts(tenant_id, sha256, name, kind, filename, size, store, uploaded_by, approved_by) VALUES
		(1, $1, 'vpn', 'deb', 'vpn.deb', 10, 'local', 'a', 'a'), (1, $2, 'tool', 'rpm', 't.rpm', 5, 'local', 'a', NULL)`, ok, pending); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	item := func(sha, kind string, size int64) *api.LibraryItem {
		p, _ := json.Marshal(api.Artifacts{Artifacts: []api.Artifact{{SHA256: sha, Name: "x", Kind: kind, Size: size}}})
		return &api.LibraryItem{Type: api.TypeArtifacts, Name: "pkg", Payload: p}
	}
	if err := s.checkArtifactRefs(ctx, item(ok, "deb", 10)); err != nil {
		t.Fatal(err)
	}
	for _, it := range []*api.LibraryItem{item(pending, "rpm", 5), item(ok, "deb", 11), item(ok, "rpm", 10)} {
		if s.checkArtifactRefs(ctx, it) == nil {
			t.Fatalf("accepted %s", it.Payload)
		}
	}
	if s.checkArtifactRefs(withTenant(ctx, 2), item(ok, "deb", 10)) == nil {
		t.Fatal("another tenant's item may reference a default tenant upload")
	}
}
