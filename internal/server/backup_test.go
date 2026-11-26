package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOrderTables(t *testing.T) {
	all := []backupTable{{Name: "commands"}, {Name: "devices"}, {Name: "tenants"}}
	out, err := orderTables(all, map[string][]string{"commands": {"devices"}, "devices": {"tenants"}})
	if err != nil || out[0].Name != "tenants" || out[2].Name != "commands" {
		t.Fatalf("%v %v", out, err)
	}
	if _, err := orderTables(all, map[string][]string{"commands": {"devices"}, "devices": {"commands"}}); err == nil {
		t.Fatal("cycle not detected")
	}
}

// The example "GET Object" request of the AWS Signature Version 4 documentation.
func TestS3Signature(t *testing.T) {
	c := &s3Store{endpoint: "https://s3.amazonaws.com", region: "us-east-1", bucket: "examplebucket", key: "AKIAIOSFODNN7EXAMPLE",
		secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", now: func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }}
	req, _ := http.NewRequest("GET", c.objectURL("test.txt", nil).String(), nil)
	req.Header.Set("Range", "bytes=0-9")
	c.sign(req, emptySHA256)
	want := "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, want) || !strings.Contains(got, "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("authorization %s", got)
	}
}

func TestParseReplay(t *testing.T) {
	in := `{"id":12,"action":"device.retire","target":"d2","detail":"client certificate revoked"}
<109>1 2026-11-26T10:00:00.000000Z mdm limdm-server - audit [limdm@32473 id="13" actor="a@b" action="api_token.revoke" target="ci \"x\"" hash="ab"] prefix=lma_abc
<109>1 2026-11-26T10:00:00.000000Z mdm limdm-server - event [limdm@32473 id="14" device="d1"] something
`
	got, err := parseReplay(strings.NewReader(in))
	if err != nil || len(got) != 2 || got[0].Action != "device.retire" || got[1].ID != 13 || got[1].Target != `ci "x"` || got[1].Detail != "prefix=lma_abc" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRetentionSettings(t *testing.T) {
	if (Settings{}).retentionDays("audit") != 1095 || (Settings{AuditRetentionDays: 400}).retentionDays("audit") != 400 ||
		(Settings{Retention: map[string]int{"audit": 0}}).retentionDays("audit") != 0 {
		t.Fatal("audit retention fallback")
	}
	if validRetention(map[string]int{"audit": 0, "diagnostics": 30}) != nil || validRetention(map[string]int{"diagnostics": 0}) == nil ||
		validRetention(map[string]int{"audit": 100}) == nil || validRetention(map[string]int{"nope": 30}) == nil {
		t.Fatal("retention bounds")
	}
}

func TestArtifactMagic(t *testing.T) {
	if !artifactMagic("deb", []byte("!<arch>\ndebian-binary")) || artifactMagic("deb", []byte("#!/bin/sh")) ||
		!artifactMagic("script", []byte("#!/bin/sh\n")) || artifactMagic("rpm", []byte("!<arch>")) {
		t.Fatal("magic")
	}
}

// TestBackupRestore: back up a database with devices, audit entries and a
// sealed secret, restore it into a second database and CA directory, check
// the chain and the sealed value, let a device with a certificate newer than
// the backup in again and re-apply a later revocation.
func TestBackupRestore(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	target := db.Config().ConnConfig.Database + "_restore"
	db.Exec(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{target}.Sanitize()+` WITH (FORCE)`)
	if _, err := db.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{target}.Sanitize()); err != nil {
		t.Skip("cannot create a second database:", err)
	}
	defer func() {
		if c, err := pgx.Connect(context.Background(), dsn); err == nil {
			c.Exec(context.Background(), `DROP DATABASE IF EXISTS `+pgx.Identifier{target}.Sanitize()+` WITH (FORCE)`)
			c.Close(context.Background())
		}
	}()
	db.Close()

	// OpenKeys sets the package wide keys; the other tests expect theirs
	k1, k2, k3, k4, k5, k6, k7 := itemKey, itemPrevKey, itemSecrets, auditKey, auditKeyCur, auditKeys, auditKeyedFrom
	defer func() {
		itemKey, itemPrevKey, itemSecrets, auditKey, auditKeyCur, auditKeys, auditKeyedFrom = k1, k2, k3, k4, k5, k6, k7
	}()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{DatabaseURL: dsn, CADir: t.TempDir(), ReleaseDir: t.TempDir(), PublicURL: "https://mdm.test",
		SessionKey: bytes.Repeat([]byte{7}, 32)}
	s, err := OpenKeys(ctx, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	secret, _ := s.sealField("settings.oidc_client_secret", "top secret")
	doc, _ := json.Marshal(storedSettings{SecretEnc: secret})
	s.db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('server', $1)`, string(doc))
	for _, id := range []string{"d1", "d2"} {
		if _, err := s.db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ($1, 'old', now(), $1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.auditAction(ctx, "admin", "test.before", "x", "before the backup", func(pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	bc := defaultBackupConfig()
	bc.Recipients = []string{id.Recipient().String()}
	bc.Targets = []StoreTarget{{Name: "local", Kind: "local", Dir: store}}
	if err := s.saveBackupConfig(ctx, "admin", bc, "test"); err != nil {
		t.Fatal(err)
	}
	res, err := s.runBackup(ctx, "admin", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	var backupID int64
	s.db.QueryRow(ctx, `SELECT id FROM backups WHERE name=$1`, res.Name).Scan(&backupID)
	if err := s.verifyStored(ctx, backupID, "admin"); err != nil {
		t.Fatal(err)
	}
	// after the backup: d2 is retired (in the audit log only, as after a loss)
	if err := s.auditAction(ctx, "admin", "device.retire", "d2", "client certificate revoked", func(pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var retireID int64
	s.db.QueryRow(ctx, `SELECT max(id) FROM audit_log`).Scan(&retireID)

	archive := filepath.Join(store, res.Name)
	open := func() (io.ReadCloser, error) { return os.Open(archive) }
	f, _ := open()
	m, err := readArchive(f, []age.Identity{id}, nil)
	f.Close()
	if err != nil || m.CommandKey != pubHex(s.cmdKey) {
		t.Fatalf("verify: %v", err)
	}
	other, _ := age.GenerateX25519Identity()
	f, _ = open()
	if _, err := readArchive(f, []age.Identity{other}, nil); err == nil {
		t.Fatal("decrypted with a foreign identity")
	}
	f.Close()

	cfg2 := cfg
	cfg2.DatabaseURL = strings.Replace(dsn, "/"+strings.TrimSuffix(target, "_restore")+"?", "/"+target+"?", 1)
	if !strings.Contains(cfg2.DatabaseURL, target) {
		cfg2.DatabaseURL = strings.Replace(dsn, "/"+strings.TrimSuffix(target, "_restore"), "/"+target, 1)
	}
	cfg2.CADir = filepath.Join(t.TempDir(), "ca")
	swapped := *m
	swapped.Name = "another archive"
	if err := restoreArchive(ctx, open, []age.Identity{id}, &swapped, restoreOptions{DatabaseURL: cfg2.DatabaseURL, CADir: cfg2.CADir, Window: time.Hour}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("restored an archive other than the verified one: %v", err)
	}
	if err := restoreArchive(ctx, open, []age.Identity{id}, m, restoreOptions{DatabaseURL: cfg2.DatabaseURL, CADir: cfg2.CADir, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := restoreArchive(ctx, open, []age.Identity{id}, m, restoreOptions{DatabaseURL: cfg2.DatabaseURL, CADir: t.TempDir(), Window: time.Hour}); err == nil {
		t.Fatal("restored over a database in use")
	}
	report, err := checkRestored(ctx, cfg2, log, cfg2.DatabaseURL, cfg2.CADir)
	if err != nil || !strings.Contains(report, "2 devices") {
		t.Fatalf("restored: %q %v", report, err)
	}
	rs, err := OpenKeys(ctx, cfg2, log)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if pubHex(rs.cmdKey) != pubHex(s.cmdKey) || rs.tlsCA().Fingerprint() != s.tlsCA().Fingerprint() {
		t.Fatal("restored keys differ")
	}
	cert := func(notBefore time.Time) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(notBefore.UnixNano()), Subject: pkix.Name{CommonName: "d1"},
			NotBefore: notBefore, NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, rs.ca.cert, &key.PublicKey, rs.ca.key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	if rs.restoreRepin(ctx, "d1", cert(m.CreatedAt.Add(-time.Hour))) {
		t.Fatal("a certificate older than the backup was pinned")
	}
	newer := cert(time.Now().Add(-5 * time.Minute))
	var serial string
	if !rs.restoreRepin(ctx, "d1", newer) || rs.db.QueryRow(ctx, `SELECT cert_serial FROM devices WHERE id='d1'`).Scan(&serial) != nil || serial != newer.SerialNumber.Text(16) {
		t.Fatal("renewed certificate not pinned")
	}
	superseded := cert(time.Now().Add(-6 * time.Minute))
	superseded.NotAfter = newer.NotAfter.Add(-time.Minute)
	if rs.restoreRepin(ctx, "d1", superseded) {
		t.Fatal("a certificate older than the pinned one took the pin back")
	}
	applied, manual, err := rs.replay(ctx, "admin", m.AuditHead.ID, []replayEntry{{ID: 1, Action: "device.retire", Target: "d1"},
		{ID: retireID, Action: "device.retire", Target: "d2"}, {ID: retireID + 1, Action: "user.update", Target: "x"}})
	var retired bool
	rs.db.QueryRow(ctx, `SELECT retired FROM devices WHERE id='d2'`).Scan(&retired)
	if err != nil || applied != 1 || len(manual) != 1 || !retired {
		t.Fatalf("replay: %d %v %v %v", applied, manual, err, retired)
	}
	if _, manual, err := rs.replay(ctx, "admin", m.AuditHead.ID, []replayEntry{{ID: retireID + 2, Action: "token.revoke", Target: "%%%%%%%%%%%%"}}); err != nil || len(manual) != 1 {
		t.Fatalf("token.revoke with wildcards applied: %v %v", manual, err)
	}
	if rs.restoreRepin(ctx, "d2", cert(time.Now())) {
		t.Fatal("retired device pinned")
	}
}

func TestWithDatabase(t *testing.T) {
	got, err := withDatabase("postgres://limdm:pw@db.example.com:5432/limdm?sslmode=require", "limdm_restore_test")
	if err != nil || got != "postgres://limdm:pw@db.example.com:5432/limdm_restore_test?sslmode=require" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := withDatabase("host=db dbname=limdm", "x"); err == nil {
		t.Fatal("key value DSN accepted")
	}
}
