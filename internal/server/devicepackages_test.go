package server

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// TestSavePackagesDiff: a new list touches only the changed rows.
func TestSavePackagesDiff(t *testing.T) {
	db := loadTestDB(t, 4)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('pk1', 's', now(), 'pc')`); err != nil {
		t.Fatal(err)
	}
	save := func(pkgs ...api.Package) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error { return savePackages(ctx, tx, "pk1", pkgs, "h") }); err != nil {
			t.Fatal(err)
		}
	}
	xmin := func(name string) (v string) {
		db.QueryRow(ctx, `SELECT xmin::text FROM device_packages WHERE device_id='pk1' AND name=$1`, name).Scan(&v)
		return v
	}
	save(api.Package{Name: "a", Version: "1"}, api.Package{Name: "b", Version: "1"}, api.Package{Name: "b", Version: "1"})
	before := xmin("a")
	save(api.Package{Name: "a", Version: "1"}, api.Package{Name: "b", Version: "2", Arch: "amd64"}, api.Package{Name: "c", Version: "1"})
	got, err := devicePackages(ctx, db, "pk1")
	if err != nil || len(got) != 3 || got[1] != (api.Package{Name: "b", Version: "2", Arch: "amd64"}) || got[2].Name != "c" {
		t.Fatalf("packages: %+v %v", got, err)
	}
	if xmin("a") != before {
		t.Fatal("an unchanged package was written again")
	}
	cond, args, _ := pkgCond("b >= 2")
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM devices d WHERE d.id='pk1' AND `+cond, args...).Scan(&n); err != nil || n != 1 {
		t.Fatalf("package filter: %d %v", n, err)
	}
	save()
	if got, _ := devicePackages(ctx, db, "pk1"); len(got) != 0 {
		t.Fatalf("empty list left %d packages", len(got))
	}

	// migration 12 moves the JSONB list of earlier versions
	if _, err := db.Exec(ctx, `UPDATE devices SET packages='[{"n":"x","v":"1","a":"arm64"},{"v":"no name"}]' WHERE id='pk1'`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version == 12 {
			if err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error { return m.run(ctx, tx) }); err != nil {
				t.Fatal(err)
			}
		}
	}
	var left string
	db.QueryRow(ctx, `SELECT packages::text FROM devices WHERE id='pk1'`).Scan(&left)
	if got, _ := devicePackages(ctx, db, "pk1"); len(got) != 1 || got[0] != (api.Package{Name: "x", Version: "1", Arch: "arm64"}) || left != "[]" {
		t.Fatalf("migrated: %+v, left %s", got, left)
	}
}
