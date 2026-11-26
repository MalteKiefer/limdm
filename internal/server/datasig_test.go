package server

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// TestSignedCatalogAndUsers: catalog apps, remotes and device user lists
// are signed when an admin saves them; what changed in the database alone
// is not delivered and cannot be signed by a later partial change.
func TestSignedCatalogAndUsers(t *testing.T) {
	s, db, ui := evidenceServer(t)
	ctx := context.Background()
	prev, prevOld := itemKey, itemPrevKey
	itemKey, itemPrevKey = testCmdKey, nil
	t.Cleanup(func() { itemKey, itemPrevKey = prev, prevOld })
	s.cfg.CADir = t.TempDir()
	if err := s.signExistingData(ctx); err != nil { // seeded apps and Flathub
		t.Fatal(err)
	}
	// recorded in the database: another instance (its own CA directory
	// copy) never signs a row emptied in the database later
	var firefoxSig string
	db.QueryRow(ctx, `SELECT signature FROM catalog_apps WHERE slug='firefox'`).Scan(&firefoxSig)
	db.Exec(ctx, `UPDATE catalog_apps SET signature='' WHERE slug='firefox'`)
	s.cfg.CADir = t.TempDir()
	if err := s.signExistingData(ctx); err != nil {
		t.Fatal(err)
	}
	var sig string
	if db.QueryRow(ctx, `SELECT signature FROM catalog_apps WHERE slug='firefox'`).Scan(&sig); sig != "" || firefoxSig == "" {
		t.Fatalf("signed again on a second instance: %q (first %q)", sig, firefoxSig)
	}
	db.Exec(ctx, `UPDATE catalog_apps SET signature=$1 WHERE slug='firefox'`, firefoxSig)
	if code, _ := ui("POST", "/api/v1/software/apps", `{"id":"tool","name":"Tool","mode":"available","enabled":true,
		"sources":[{"kind":"flatpak","flatpak":"org.example.Tool"}]}`); code != http.StatusOK {
		t.Fatalf("save app: %d", code)
	}
	catalog := func() *api.Catalog {
		t.Helper()
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		c, err := s.deviceCatalog(ctx, tx, "none", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	has := func(c *api.Catalog, id string) bool {
		return slices.ContainsFunc(c.Apps, func(a api.CatalogApp) bool { return a.ID == id })
	}
	if c := catalog(); !has(c, "tool") || !has(c, "firefox") || len(c.Remotes) != 1 {
		t.Fatalf("signed entries missing: %d apps, %d remotes", len(c.Apps), len(c.Remotes))
	}
	db.Exec(ctx, `UPDATE catalog_apps SET mode='required', sources='[{"kind":"package","debian":"evil"}]' WHERE slug='tool'`)
	db.Exec(ctx, `UPDATE catalog_remotes SET url='https://evil.example/repo' WHERE name='flathub'`)
	if c := catalog(); has(c, "tool") || !has(c, "firefox") || len(c.Remotes) != 0 {
		t.Fatal("entries changed in the database must not be delivered")
	}
	if code, _ := ui("POST", "/api/v1/software/remotes/flathub/filter", ""); code != http.StatusConflict {
		t.Fatalf("a partial change must not sign a tampered remote: %d", code)
	}

	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, users) VALUES ('d1', 's1', now(), 'h', '[{"username":"mm","email":"m@firma.de","admin":false}]')`); err != nil {
		t.Fatal(err)
	}
	tx, _ := db.Begin(ctx)
	if err := signDeviceUsers(ctx, tx, "d1"); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	var seq int64
	check := func() bool {
		var sig string
		var users []api.User
		db.QueryRow(ctx, `SELECT users, users_sig, users_seq FROM devices WHERE id='d1'`).Scan(&users, &sig, &seq)
		return dataSigOK(api.UsersSigned("d1", users, seq), sig)
	}
	if !check() || seq == 0 {
		t.Fatalf("signed user list does not verify or has no sequence number (%d)", seq)
	}
	// every signed change takes a higher number (agents refuse lower ones)
	first := seq
	tx, _ = db.Begin(ctx)
	if err := signDeviceUsers(ctx, tx, "d1"); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if !check() || seq <= first {
		t.Fatalf("sequence number did not grow: %d -> %d", first, seq)
	}
	var appSeq int64
	if db.QueryRow(ctx, `SELECT seq FROM catalog_apps WHERE slug='tool'`).Scan(&appSeq); appSeq == 0 {
		t.Fatal("a saved catalog app has no sequence number")
	}
	db.Exec(ctx, `UPDATE devices SET users='[{"username":"mm","email":"m@firma.de","admin":true}]' WHERE id='d1'`)
	if check() {
		t.Fatal("an admin flag set in the database must not verify")
	}
}
