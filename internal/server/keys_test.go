package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestKeyProviderSelection(t *testing.T) {
	if err := (KeyProvider{}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (KeyProvider{Kind: "vault"}).validate(); err == nil {
		t.Fatal("unknown provider accepted")
	}
	err := (KeyProvider{Kind: "pkcs11", Module: "/x.so", Token: "t"}).validate()
	if openPKCS11 == nil && !errors.Is(err, errNoPKCS11) {
		t.Fatalf("default build: %v", err)
	}
	if _, err := (KeyProvider{Kind: "pkcs11"}).signer(t.TempDir(), "ca", genP384); err == nil {
		t.Fatal("pkcs11 without module and token accepted")
	}
}

// Rotation steps are for global admins only, whatever the route wrappers
// do: helpdesk, auditor and admins limited to a scope get 403 before any
// key is touched.
func TestKeysActionRoles(t *testing.T) {
	s := &Server{cfg: Config{CADir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	call := func(sess session, op string) int {
		r := httptest.NewRequest("POST", "/settings/keys/"+op+"/ca", nil)
		r.SetPathValue("op", op)
		r.SetPathValue("kind", "ca")
		w := httptest.NewRecorder()
		s.keysAction(w, r, sess)
		return w.Code
	}
	for _, sess := range []session{{Role: "helpdesk"}, {Role: "auditor"}, {Role: "admin", Tags: []string{"finance"}}, {Role: "admin", Tenant: 2}} {
		for _, op := range []string{"rotate", "finish"} {
			if code := call(sess, op); code != 403 {
				t.Errorf("%s %v %s: %d", sess.Role, sess.Tags, op, code)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(s.cfg.CADir, keysFile)); err == nil {
		t.Fatal("a denied request changed keys.json")
	}
	for _, sess := range []session{{Role: "admin"}, {Role: "admin", Super: true, Tenant: 2}} {
		if code := call(sess, "bogus"); code != 404 { // passes the role check
			t.Fatalf("admin %+v: %d", sess, code)
		}
	}
}

func TestFileSigner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.key")
	if _, err := fileSigner(path, nil); err == nil {
		t.Fatal("missing key without gen")
	}
	k, err := fileSigner(path, genEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	again, err := fileSigner(path, genEd25519)
	if err != nil || !bytes.Equal(again.Public().(ed25519.PublicKey), k.Public().(ed25519.PublicKey)) {
		t.Fatal("reload gives another key")
	}
	os.Chmod(path, 0o640)
	if _, err := fileSigner(path, nil); err == nil {
		t.Fatal("group readable key accepted")
	}
	os.WriteFile(filepath.Join(dir, "bad.key"), []byte("junk"), 0o600)
	if _, err := fileSigner(filepath.Join(dir, "bad.key"), nil); err == nil {
		t.Fatal("junk accepted")
	}
}

func TestKeyStatesFile(t *testing.T) {
	dir := t.TempDir()
	st, err := readKeyStates(dir)
	if err != nil || st[kindCA].Active != "ca" || st[kindCommand].Active != "command" {
		t.Fatalf("defaults: %v %v", st, err)
	}
	st[kindCA] = keyState{Active: "ca-2", Previous: "ca"}
	if err := writeKeyStates(dir, st); err != nil {
		t.Fatal(err)
	}
	if got, _ := readKeyStates(dir); got[kindCA] != st[kindCA] {
		t.Fatalf("round trip: %v", got)
	}
	os.WriteFile(filepath.Join(dir, keysFile), []byte(`{"ca":{"active":"../ca"}}`), 0o600)
	if _, err := readKeyStates(dir); err == nil {
		t.Fatal("path in a key name accepted")
	}
}

// Values sealed with the old session key open after the rotation; the new
// key seals, and the console MAC of either key is accepted.
func TestSessionKeyRotation(t *testing.T) {
	if _, err := parseSessionKeys("abcd"); err == nil {
		t.Fatal("short key accepted")
	}
	old, cur := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	keys, err := parseSessionKeys(hex.EncodeToString(cur) + ", " + hex.EncodeToString(old))
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0], cur) {
		t.Fatalf("parse: %v", err)
	}
	before := &Server{cfg: Config{SessionKey: old}}
	sealed, _ := before.sealField("f", "secret")
	after := &Server{cfg: Config{SessionKey: cur, OldSessionKeys: [][]byte{old}}}
	if plain, err := after.openField("f", sealed); err != nil || plain != "secret" {
		t.Fatalf("old value: %q %v", plain, err)
	}
	out, changed, err := after.resealField("f", sealed)
	if err != nil || !changed {
		t.Fatalf("reseal: %v %v", changed, err)
	}
	if _, changed, _ := after.resealField("f", out); changed {
		t.Fatal("value sealed with the new key sealed again")
	}
	if plain, err := (&Server{cfg: Config{SessionKey: cur}}).openField("f", out); err != nil || plain != "secret" {
		t.Fatal("resealed value needs the old key")
	}
	if !after.macOK("p", before.mac("p")) || (&Server{cfg: Config{SessionKey: cur}}).macOK("p", before.mac("p")) {
		t.Fatal("MAC of the old key")
	}
}

// A rotation in progress: the retiring CA serves TLS and stays trusted, the
// new one issues; the rollover record verifies with the old command key.
func TestLoadKeysDuringRotation(t *testing.T) {
	dir := t.TempDir()
	s := &Server{cfg: Config{CADir: dir}}
	if err := s.loadKeys(); err != nil {
		t.Fatal(err)
	}
	oldCA, oldCmd := s.ca, s.cmdKey
	if s.tlsCA() != s.ca || s.kr.rollover != nil {
		t.Fatal("no rotation: active keys only")
	}
	if _, err := loadRoot(KeyProvider{}, dir, "ca-2", "LiMDM Device CA 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCommandKey(KeyProvider{}, dir, "command-2", true); err != nil {
		t.Fatal(err)
	}
	st, _ := readKeyStates(dir)
	st[kindCA] = keyState{Active: "ca-2", Previous: "ca"}
	st[kindCommand] = keyState{Active: "command-2", Previous: "command"}
	writeKeyStates(dir, st)
	if err := s.loadKeys(); err != nil {
		t.Fatal(err)
	}
	if !s.tlsCA().cert.Equal(oldCA.cert) || s.ca.cert.Equal(oldCA.cert) {
		t.Fatal("TLS must stay on the retiring CA, issuing on the new one")
	}
	cert, _, _, err := s.ca.signCSR(testCSR(t), "d1")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(cert))
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: s.devicePool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(s.kr.bundle, "BEGIN CERTIFICATE") != 2 {
		t.Fatal("bundle must carry both CAs")
	}
	if err := api.VerifyRollover(oldCmd.Public().(ed25519.PublicKey), *s.kr.rollover); err != nil || s.kr.rollover.Key != pubHex(s.cmdKey) {
		t.Fatalf("rollover: %v", err)
	}
	// a certificate that does not belong to its key is refused
	os.Rename(filepath.Join(dir, "ca-2.crt"), filepath.Join(dir, "ca.crt"))
	if err := s.loadKeys(); err == nil {
		t.Fatal("certificate of another key accepted")
	}
}

// The whole rotation against PostgreSQL: start, progress from check ins,
// refusal while devices lag, finish; session key resealing.
func TestKeyRotationFlow(t *testing.T) {
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
	prevKey, prevFrom, prevKeys, prevCur, prevItem, prevItemPrev := auditKey, auditKeyedFrom, auditKeys, auditKeyCur, itemKey, itemPrevKey
	t.Cleanup(func() {
		auditKey, auditKeyedFrom, auditKeys, auditKeyCur, itemKey, itemPrevKey = prevKey, prevFrom, prevKeys, prevCur, prevItem, prevItemPrev
	})
	dir := t.TempDir()
	oldSession := bytes.Repeat([]byte{4}, 32)
	cfg := Config{CADir: dir, SessionKey: oldSession}
	openErr := func(cfg Config) (*Server, error) {
		s, err := openCore(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), db)
		if err != nil {
			return nil, err
		}
		s.kr.cli = true
		return s, nil
	}
	open := func(cfg Config) *Server {
		t.Helper()
		s, err := openErr(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// snapshot copies the CA directory, as another instance would hold it
	snapshot := func() Config {
		t.Helper()
		c := cfg
		c.CADir = t.TempDir()
		if err := os.CopyFS(c.CADir, os.DirFS(dir)); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob(filepath.Join(c.CADir, "*"))
		for _, f := range files { // CopyFS does not keep the 0600 of keys
			if err := os.Chmod(f, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return c
	}
	storedFP := func() map[string]string {
		var m map[string]string
		if err := db.QueryRow(ctx, `SELECT value FROM settings WHERE key='key_fingerprints'`).Scan(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	s := open(cfg)
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1','s',now(),'pc1')`)
	checkin := func(s *Server, ca *deviceCA, req api.CheckinRequest) api.CheckinResponse {
		t.Helper()
		cert, _, _, err := ca.signCSR(testCSR(t), "d1")
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode([]byte(cert))
		leaf, _ := x509.ParseCertificate(blk.Bytes)
		r := httptest.NewRequest("POST", "/api/v1/checkin", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		var resp api.CheckinResponse
		tx, _ := db.Begin(ctx)
		defer tx.Rollback(ctx)
		if err := s.keyCheckin(ctx, tx, "d1", r, req, &resp); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
		return resp
	}

	// a rotation whose transaction fails at commit leaves keys.json, the new
	// key files and the stored fingerprints as they were
	fpBefore := storedFP()
	keysBefore, _ := os.ReadFile(filepath.Join(dir, keysFile))
	if _, err := db.Exec(ctx, `CREATE FUNCTION fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit fails'; END $$;
		CREATE CONSTRAINT TRIGGER fail_commit AFTER INSERT ON audit_log DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW WHEN (NEW.action = 'keys.rotate') EXECUTE FUNCTION fail_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateKey(ctx, "admin@x", kindCA, "ca-failed"); err == nil {
		t.Fatal("rotation with a failing commit succeeded")
	}
	if _, err := db.Exec(ctx, `DROP TRIGGER fail_commit ON audit_log; DROP FUNCTION fail_commit()`); err != nil {
		t.Fatal(err)
	}
	if keysAfter, _ := os.ReadFile(filepath.Join(dir, keysFile)); !bytes.Equal(keysAfter, keysBefore) {
		t.Fatalf("keys.json changed by a failed rotation: %s", keysAfter)
	}
	for _, f := range []string{keysFile + ".tmp", "ca-failed.key", "ca-failed.crt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind by a failed rotation", f)
		}
	}
	if fp := storedFP(); fp["device_ca"] != fpBefore["device_ca"] || fp["device_ca_previous"] != "" {
		t.Fatalf("stored fingerprints changed by a failed rotation: %v", fp)
	}

	// device CA
	oldCA := s.ca
	before := snapshot()
	if _, err := s.RotateKey(ctx, "admin@x", kindCA, ""); err != nil {
		t.Fatal(err)
	}
	overlap := snapshot()
	// during the overlap an instance with the directory from before the
	// rotation still starts: the old CA stays valid until finish
	if _, err := openErr(before); err != nil {
		t.Fatalf("instance on the retiring CA during the overlap: %v", err)
	}
	if _, err := s.RotateKey(ctx, "admin@x", kindCA, ""); err == nil {
		t.Fatal("second rotation while one runs")
	}
	if st, _ := s.KeysStatus(ctx); !st[0].Restart || st[0].Total != 1 || st[0].Done != 0 {
		t.Fatalf("status before restart: %+v", st[0])
	}
	if _, err := s.FinishKey(ctx, "admin@x", kindCA, false); err == nil {
		t.Fatal("finish while the device uses the old CA")
	}
	s = open(cfg) // restart
	resp := checkin(s, oldCA, api.CheckinRequest{})
	if !resp.RenewCert || resp.DeviceCAs != s.kr.bundle {
		t.Fatal("device on the old CA gets the bundle and a renewal request")
	}
	resp = checkin(s, s.ca, api.CheckinRequest{})
	if _, err := s.FinishKey(ctx, "admin@x", kindCA, false); err == nil {
		t.Fatal("finish before the device confirmed the bundle")
	}
	resp = checkin(s, s.ca, api.CheckinRequest{CAHash: sha256Hex([]byte(s.kr.bundle))})
	if resp.RenewCert || resp.DeviceCAs != "" {
		t.Fatal("device on the new CA with the bundle needs nothing")
	}
	prevName := s.kr.states[kindCA].Previous
	if _, err := s.FinishKey(ctx, "admin@x", kindCA, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, prevName+".key")); !os.IsNotExist(err) {
		t.Fatal("retired CA key not deleted")
	}
	// after finish the stored fingerprints are the new keys: the updated
	// directory starts, stale ones are refused
	s = open(cfg)
	if fp := storedFP(); fp["device_ca"] != s.ca.Fingerprint() || fp["device_ca_previous"] != "" || fp["device_ca"] == oldCA.Fingerprint() {
		t.Fatalf("stored fingerprints after finish: %v", fp)
	}
	for name, c := range map[string]Config{"before the rotation": before, "during the overlap": overlap} {
		if _, err := openErr(c); err == nil || !strings.Contains(err.Error(), "same CA directory") {
			t.Fatalf("stale directory from %s: %v", name, err)
		}
	}

	// command key: the audit chain gets a new segment at the restart
	s = open(cfg)
	oldPub := pubHex(s.cmdKey)
	beforeCmd := snapshot()
	oldAuditKey := auditKeyCur
	if _, err := s.RotateKey(ctx, "admin@x", kindCommand, "cmd-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FinishKey(ctx, "admin@x", kindCommand, true); err == nil {
		t.Fatal("finish before a server started with the new key")
	}
	copied := snapshot() // keys.json with the new key, audit-keys without its segment
	s = open(cfg)
	if len(auditKeys) != 2 || s.kr.rollover == nil {
		t.Fatalf("segments %d", len(auditKeys))
	}
	// an instance with the directory from before the rotation would key
	// entries with the retired key; a copy taken before the first restart
	// would start a second segment: both refuse to start
	if _, err := openErr(beforeCmd); !errors.Is(err, errAuditKeyStale) {
		t.Fatalf("directory from before the command key rotation: %v", err)
	}
	if _, err := openErr(copied); err == nil || !strings.Contains(err.Error(), "older than the audit chain") {
		t.Fatalf("copied directory without the new segment: %v", err)
	}
	s = open(cfg)
	// an instance still running the old key (simulated: the process wide
	// key id) writes no entries, is not ready and leads no background job
	newAuditKey := auditKeyCur
	auditKeyCur = oldAuditKey
	if err := s.auditAction(ctx, "admin@x", "test", "", "", nil); !errors.Is(err, errAuditKeyStale) {
		t.Fatalf("entry with the outdated audit key: %v", err)
	}
	s.ha.listening.Store(true)
	w := httptest.NewRecorder()
	s.readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "audit key outdated") {
		t.Fatalf("readyz with the outdated audit key: %d %s", w.Code, w.Body.String())
	}
	defer func(d time.Duration) { leaderRetry = d }(leaderRetry)
	leaderRetry = 20 * time.Millisecond
	bctx, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	led := false
	s.background(bctx, "stale test", func(context.Context) { led = true }, true)
	stop()
	if led {
		t.Fatal("instance with the outdated audit key led a background job")
	}
	auditKeyCur = newAuditKey
	w = httptest.NewRecorder()
	s.readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 200 {
		t.Fatalf("readyz after the restart: %d %s", w.Code, w.Body.String())
	}
	resp = checkin(s, s.ca, api.CheckinRequest{CommandKey: oldPub})
	if resp.CommandKeyRollover == nil || resp.CommandKey == oldPub {
		t.Fatal("rollover not announced")
	}
	if _, err := s.FinishKey(ctx, "admin@x", kindCommand, false); err == nil {
		t.Fatal("finish while the device pins the old key")
	}
	checkin(s, s.ca, api.CheckinRequest{CommandKey: resp.CommandKey})
	if _, err := s.FinishKey(ctx, "admin@x", kindCommand, false); err != nil {
		t.Fatal(err)
	}
	s = open(cfg)
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("audit chain across the rotation: %d %v", broken, err)
	}
	segs, err := AuditKeysFromDir(dir, KeyProvider{})
	if err != nil || len(segs) != 2 {
		t.Fatalf("segments from the directory: %d %v", len(segs), err)
	}

	// session key
	if _, err := s.escrowKeysForTest(ctx); err != nil {
		t.Fatal(err)
	}
	cfg.SessionKey, cfg.OldSessionKeys = bytes.Repeat([]byte{5}, 32), [][]byte{oldSession}
	s = open(cfg)
	if n, err := s.reseal(ctx, true); err != nil || n != 1 {
		t.Fatalf("to reseal: %d %v", n, err)
	}
	if _, err := s.FinishKey(ctx, "admin@x", kindSession, false); err == nil {
		t.Fatal("finish with values on the old key")
	}
	if n, err := s.reseal(ctx, false); err != nil || n != 1 {
		t.Fatalf("resealed: %d %v", n, err)
	}
	if _, err := s.FinishKey(ctx, "admin@x", kindSession, false); err != nil {
		t.Fatal(err)
	}
	cfg.OldSessionKeys = nil
	if k, err := open(cfg).openRecovery("d1", "u1", s.mustSealed(ctx)); err != nil || k != "key" {
		t.Fatalf("recovery key after the rotation: %v", err)
	}
}

func (s *Server) escrowKeysForTest(ctx context.Context) (int, error) {
	sealed, err := s.sealRecovery("d1", "u1", "key")
	if err != nil {
		return 0, err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO recovery_keys(device_id, uuid, device_path, sealed, escrowed_at) VALUES ('d1','u1','/dev/x',$1,now())`, sealed)
	return 1, err
}

func (s *Server) mustSealed(ctx context.Context) []byte {
	var b []byte
	s.db.QueryRow(ctx, `SELECT sealed FROM recovery_keys WHERE device_id='d1'`).Scan(&b)
	return b
}
