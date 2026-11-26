package server

import (
	"context"
	"net/http"
	"testing"
)

// TestNamesPerTenant: library item and blueprint names are unique per
// tenant (M9); "default" stays the Default tenant's.
func TestNamesPerTenant(t *testing.T) {
	s, db, _ := evidenceServer(t)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id, name) VALUES (2, 'acme')`); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []int{1, 2} {
		if _, err := db.Exec(ctx, `INSERT INTO library_items(name, type, payload, tenant_id) VALUES ('same', 'com.limdm.banner', '{}', $1)`, tn); err != nil {
			t.Fatalf("tenant %d: %v", tn, err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO blueprints(name, tenant_id) VALUES ('same', $1)`, tn); err != nil {
			t.Fatalf("tenant %d: %v", tn, err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO library_items(name, type, payload, tenant_id) VALUES ('same', 'com.limdm.banner', '{}', 2)`); !isUnique(err) {
		t.Fatalf("names stay unique within a tenant: %v", err)
	}
	err := s.validateBlueprint(withTenant(ctx, 2), blueprintRec{Name: "default"})
	if code, _ := errStatus(err); code != http.StatusConflict {
		t.Fatalf("a tenant must not name a blueprint default: %v", err)
	}
}
