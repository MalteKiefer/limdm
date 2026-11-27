package server

import (
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Key inventory, signer provider and rotation (docs/keys.md).
//
// Every private key the server signs with is a crypto.Signer from one
// provider: "file" keeps PEM files in the CA directory (the default),
// "pkcs11" keeps them in an HSM (builds with -tags pkcs11, keys_pkcs11.go).
// keys.json in the CA directory names the active key of each kind and,
// while a rotation runs, the previous one; certificates stay files.
//
// A rotation step changes keys.json and takes effect when the server
// instances restart, so all of them load the same keys. An instance still
// running an old command key can no longer write audit entries (audit.go).

const (
	kindCA      = "ca"
	kindNetCA   = "network-ca"
	kindCommand = "command"
	kindSession = "session"
	kindWebhook = "webhook"
	kindLogs    = "logs" // wraps the log archive data keys (logs_archive.go)
	keysFile    = "keys.json"
)

// keyKinds is the order of the status table.
var keyKinds = []string{kindCA, kindNetCA, kindCommand, kindSession, kindWebhook, kindLogs}

// KeyProvider says where private keys live: "file" (or empty) or "pkcs11".
type KeyProvider struct {
	Kind   string
	Module string // PKCS#11 module (shared library)
	Token  string // token label
	PIN    string
}

// KeyProviderFromEnv reads LIMDM_KEY_PROVIDER and the LIMDM_PKCS11_* settings.
func KeyProviderFromEnv() KeyProvider {
	return KeyProvider{Kind: os.Getenv("LIMDM_KEY_PROVIDER"), Module: os.Getenv("LIMDM_PKCS11_MODULE"),
		Token: os.Getenv("LIMDM_PKCS11_TOKEN"), PIN: os.Getenv("LIMDM_PKCS11_PIN")}
}

// openPKCS11 opens the private key with the label in the token; set by
// keys_pkcs11.go, nil in the default (CGO free) build.
var openPKCS11 func(module, token, pin, label string) (crypto.Signer, error)

var errNoPKCS11 = errors.New("LIMDM_KEY_PROVIDER=pkcs11 needs a server built with -tags pkcs11 (see docs/keys.md)")

func (p KeyProvider) validate() error {
	switch p.Kind {
	case "", "file":
		return nil
	case "pkcs11":
		if openPKCS11 == nil {
			return errNoPKCS11
		}
		if p.Module == "" || p.Token == "" {
			return errors.New("LIMDM_KEY_PROVIDER=pkcs11 needs LIMDM_PKCS11_MODULE and LIMDM_PKCS11_TOKEN")
		}
		return nil
	}
	return fmt.Errorf("LIMDM_KEY_PROVIDER %q: use file or pkcs11", p.Kind)
}

func (p KeyProvider) hsm() bool { return p.Kind == "pkcs11" }

// signer opens the key name: the file <name>.key in dir, created with gen
// when missing and gen is not nil, or the HSM object labeled limdm-<name>.
func (p KeyProvider) signer(dir, name string, gen func() (crypto.Signer, error)) (crypto.Signer, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if p.hsm() {
		return openPKCS11(p.Module, p.Token, p.PIN, "limdm-"+name)
	}
	return fileSigner(filepath.Join(dir, name+".key"), gen)
}

func fileSigner(path string, gen func() (crypto.Signer, error)) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && gen != nil {
		key, err := gen()
		if err != nil {
			return nil, err
		}
		blk, err := marshalKey(key)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(pem.EncodeToMemory(blk)); err != nil {
			f.Close()
			return nil, err
		}
		return key, f.Close()
	}
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be readable by group/others", path)
	}
	blk, _ := pem.Decode(b)
	switch {
	case blk == nil:
	case blk.Type == "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case blk.Type == "ED25519 PRIVATE KEY" && len(blk.Bytes) == ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(blk.Bytes), nil
	case blk.Type == "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if s, ok := k.(crypto.Signer); ok && err == nil {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%s: not an EC or Ed25519 private key", path)
}

func marshalKey(k crypto.Signer) (*pem.Block, error) {
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, err
	case ed25519.PrivateKey:
		return &pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: k.Seed()}, nil
	}
	return nil, fmt.Errorf("unsupported key type %T", k)
}

func genP384() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }

func genEd25519() (crypto.Signer, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	return k, err
}

// signEd25519 signs msg with an Ed25519 signer (pure Ed25519, no prehash).
func signEd25519(k crypto.Signer, msg []byte) ([]byte, error) {
	return k.Sign(rand.Reader, msg, crypto.Hash(0))
}

func pubHex(k crypto.Signer) string {
	pub, _ := k.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

// ---- keys.json ----

// keyState is the active key of a kind and, during a rotation, the one
// being retired. Names are file names without .key/.crt, or HSM labels
// without the "limdm-" prefix.
type keyState struct {
	Active   string    `json:"active"`
	Previous string    `json:"previous,omitempty"`
	Since    time.Time `json:"since,omitzero"`
}

var keyNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func readKeyStates(dir string) (map[string]keyState, error) {
	st := map[string]keyState{kindCA: {Active: kindCA}, kindNetCA: {Active: kindNetCA}, kindCommand: {Active: kindCommand}, kindLogs: {Active: kindLogs}}
	b, err := os.ReadFile(filepath.Join(dir, keysFile))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var f map[string]keyState
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", keysFile, err)
	}
	for k, v := range f {
		if _, ok := st[k]; !ok || !keyNameRe.MatchString(v.Active) || (v.Previous != "" && !keyNameRe.MatchString(v.Previous)) {
			return nil, fmt.Errorf("%s: invalid entry %q", keysFile, k)
		}
		st[k] = v
	}
	return st, nil
}

func writeKeyStates(dir string, st map[string]keyState) error {
	tmp, err := stageKeyStates(dir, st)
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, keysFile))
}

// stageKeyStates writes st next to keys.json and returns the file's path;
// renaming it over keys.json applies it.
func stageKeyStates(dir string, st map[string]keyState) (string, error) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, keysFile+".tmp")
	return tmp, os.WriteFile(tmp, append(b, '\n'), 0o600)
}

// saveKeyStates applies a rotation step: the new keys.json is staged, the
// fingerprints and the audit entry commit in one transaction, and only then
// does the staged file replace keys.json. A failed transaction leaves both
// as they were.
func (s *Server) saveKeyStates(ctx context.Context, actor, action, kind, detail string, st map[string]keyState) error {
	dir := s.cfg.CADir
	tmp, err := stageKeyStates(dir, st)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := s.auditAction(ctx, actor, action, kind, detail, func(tx pgx.Tx) error {
		return s.storeKeyFingerprints(ctx, tx, st)
	}); err != nil {
		os.Remove(tmp)
		return err
	}
	// ponytail: a rename failing after the commit (same directory, so only on
	// a broken file system) is reported, not rolled back
	if err := os.Rename(tmp, filepath.Join(dir, keysFile)); err != nil {
		return fmt.Errorf("the database records the new keys, but %s was not replaced: move %s over it by hand: %w", keysFile, tmp, err)
	}
	return nil
}

// ---- the keys of a running server ----

// keyring is what a rotation adds next to the active keys (Server.ca,
// netCA, cmdKey).
type keyring struct {
	states   map[string]keyState // as loaded at startup
	caPrev   *deviceCA           // device CA being retired: still trusted, issues the agent TLS certificate
	netPrev  *deviceCA           // network CA being retired: in the CA bundle and the CRLs
	cmdPrev  crypto.Signer       // command key being retired: signs the rollover record
	rollover *api.KeyRollover
	bundle   string // PEM of the trusted device CAs, as agents store it
	cli      bool   // limdm-server keys: notifications are sent before the process ends
	// log archive key encryption keys: the active one, the one being
	// retired, and why the active one is missing (an HSM without the object)
	logKEK, logPrev *logKEK
	logErr          error
}

// loadKeys loads the active keys and those of running rotations.
func (s *Server) loadKeys() error {
	st, err := readKeyStates(s.cfg.CADir)
	if err != nil {
		return err
	}
	return s.loadKeyStates(st)
}

// loadKeyStates loads the keys st names from the CA directory or the HSM.
func (s *Server) loadKeyStates(st map[string]keyState) error {
	var err error
	dir, p := s.cfg.CADir, s.cfg.Keys
	kr := keyring{states: st, cli: s.kr.cli}
	if s.ca, err = loadRoot(p, dir, st[kindCA].Active, "LiMDM Device CA"); err != nil {
		return fmt.Errorf("device CA: %w", err)
	}
	if s.netCA, err = loadRoot(p, dir, st[kindNetCA].Active, "LiMDM Network CA"); err != nil {
		return fmt.Errorf("network CA: %w", err)
	}
	if s.cmdKey, err = loadCommandKey(p, dir, st[kindCommand].Active, true); err != nil {
		return err
	}
	// the archive key does not stop the server: archiving reports its error
	kr.logKEK, kr.logErr = loadLogKEK(p, dir, st[kindLogs].Active, true)
	if prev := st[kindLogs].Previous; prev != "" {
		if kr.logPrev, err = loadLogKEK(p, dir, prev, false); err != nil {
			return fmt.Errorf("previous log archive key: %w", err)
		}
	}
	kr.bundle = string(s.ca.pem)
	if prev := st[kindCA].Previous; prev != "" {
		if kr.caPrev, err = loadPrevRoot(p, dir, prev); err != nil {
			return fmt.Errorf("previous device CA: %w", err)
		}
		kr.bundle += string(kr.caPrev.pem)
	}
	if prev := st[kindNetCA].Previous; prev != "" {
		if kr.netPrev, err = loadPrevRoot(p, dir, prev); err != nil {
			return fmt.Errorf("previous network CA: %w", err)
		}
	}
	if prev := st[kindCommand].Previous; prev != "" {
		if kr.cmdPrev, err = loadCommandKey(p, dir, prev, false); err != nil {
			return err
		}
		sig, err := signEd25519(kr.cmdPrev, api.RolloverSigned(pubHex(s.cmdKey)))
		if err != nil {
			return fmt.Errorf("signing the command key rollover: %w", err)
		}
		kr.rollover = &api.KeyRollover{Key: pubHex(s.cmdKey), Signature: hex.EncodeToString(sig)}
	}
	s.kr = kr
	return nil
}

// loadPrevRoot loads a retiring CA, which must exist.
func loadPrevRoot(p KeyProvider, dir, name string) (*deviceCA, error) {
	if _, err := os.Stat(filepath.Join(dir, name+".crt")); err != nil {
		return nil, err
	}
	return loadRoot(p, dir, name, "")
}

// tlsCA issues the agent listener certificate and is the CA new agents pin:
// the retiring CA while a rotation runs, since not every agent trusts the
// new one yet.
func (s *Server) tlsCA() *deviceCA {
	if s.kr.caPrev != nil {
		return s.kr.caPrev
	}
	return s.ca
}

// devicePool holds the device CAs client certificates may chain to.
func (s *Server) devicePool() *x509.CertPool {
	p := s.ca.pool()
	if s.kr.caPrev != nil {
		p.AddCert(s.kr.caPrev.cert)
	}
	return p
}

func (s *Server) keyStates() map[string]keyState {
	if s.kr.states == nil {
		return map[string]keyState{kindCA: {Active: kindCA}, kindNetCA: {Active: kindNetCA}, kindCommand: {Active: kindCommand}, kindLogs: {Active: kindLogs}}
	}
	return s.kr.states
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// keyCheckin fills the key fields of a check in answer and records how far
// the device has moved to the active keys.
func (s *Server) keyCheckin(ctx context.Context, tx pgx.Tx, id string, r *http.Request, req api.CheckinRequest, resp *api.CheckinResponse) error {
	st := s.keyStates()
	resp.CommandKey, resp.CommandKeyRollover = pubHex(s.cmdKey), s.kr.rollover
	if s.ca == nil {
		return nil // tests without a CA
	}
	bundle := s.kr.bundle
	if bundle == "" {
		bundle = string(s.ca.pem)
	}
	hasBundle := req.CAHash == sha256Hex([]byte(bundle))
	if !hasBundle {
		resp.DeviceCAs = bundle
	}
	// ready for the end of a device CA rotation: a certificate of the active
	// CA, and the agent confirmed it trusts the bundle with that CA
	certCA := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if r.TLS.PeerCertificates[0].CheckSignatureFrom(s.ca.cert) != nil {
			resp.RenewCert = true
		} else if hasBundle {
			certCA = st[kindCA].Active
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET cert_ca=$2, command_key=$3 WHERE id=$1
		AND (cert_ca IS DISTINCT FROM $2 OR command_key IS DISTINCT FROM $3)`, id, certCA, truncate(req.CommandKey, 64)); err != nil {
		return err
	}
	if s.kr.netPrev != nil {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM network_certs WHERE device_id=$1 AND revoked_at IS NULL
			AND not_after > now() AND ca <> $2)`, id, st[kindNetCA].Active).Scan(&resp.RenewNetworkCert)
	}
	return nil
}

// ---- status, rotation and finish ----

// KeyStatus is one row of the key inventory.
type KeyStatus struct {
	Kind, Active, Previous string
	Since                  time.Time
	Done, Total            int  // progress of a running rotation
	Restart                bool // keys.json differs from what this process loaded
	Location               string
}

// KeysStatus lists every key kind with the progress of running rotations.
func (s *Server) KeysStatus(ctx context.Context) ([]KeyStatus, error) {
	disk, err := readKeyStates(s.cfg.CADir)
	if err != nil {
		return nil, err
	}
	loc := "file " + s.cfg.CADir
	if s.cfg.Keys.hsm() {
		loc = "PKCS#11 token " + s.cfg.Keys.Token
	}
	var out []KeyStatus
	for _, kind := range keyKinds {
		if kind == kindWebhook {
			ks, err := s.webhookStatus(ctx)
			if err != nil {
				return nil, err
			}
			out = append(out, ks)
			continue
		}
		if kind == kindSession {
			ks := KeyStatus{Kind: kind, Active: fmt.Sprintf("%d key(s)", 1+len(s.cfg.OldSessionKeys)), Location: "LIMDM_SESSION_KEY"}
			if len(s.cfg.OldSessionKeys) > 0 {
				ks.Previous = fmt.Sprintf("%d old", len(s.cfg.OldSessionKeys))
				left, err := s.reseal(ctx, true)
				if err != nil {
					return nil, err
				}
				ks.Total, ks.Done = left, 0
			}
			out = append(out, ks)
			continue
		}
		st := disk[kind]
		ks := KeyStatus{Kind: kind, Active: st.Active, Previous: st.Previous, Since: st.Since, Location: loc,
			Restart: s.kr.states != nil && s.kr.states[kind] != st}
		if st.Previous != "" {
			if ks.Done, ks.Total, err = s.keyProgress(ctx, kind, st.Active); err != nil {
				return nil, err
			}
		}
		out = append(out, ks)
	}
	return out, nil
}

// keyProgress counts what already uses the active key: devices for the
// device CA and the command key, valid certificates for the network CA.
func (s *Server) keyProgress(ctx context.Context, kind, active string) (done, total int, err error) {
	var q string
	switch kind {
	case kindCA:
		q = `SELECT count(*) FILTER (WHERE cert_ca = $1), count(*) FROM devices WHERE NOT retired`
	case kindCommand:
		active = pubHex(s.cmdKey)
		if disk, err := loadCommandKey(s.cfg.Keys, s.cfg.CADir, s.mustState(kind).Active, false); err == nil {
			active = pubHex(disk) // the CLI or a server not restarted yet
		}
		q = `SELECT count(*) FILTER (WHERE command_key = $1), count(*) FROM devices WHERE NOT retired`
	case kindNetCA:
		q = `SELECT count(*) FILTER (WHERE ca = $1), count(*) FROM network_certs WHERE revoked_at IS NULL AND not_after > now()`
	case kindLogs:
		k, err := loadLogKEK(s.cfg.Keys, s.cfg.CADir, active, false)
		if err != nil {
			return 0, 0, err
		}
		active = k.id // data keys wrapped with it (the server rewraps them after its restart)
		q = `SELECT count(*) FILTER (WHERE kek_id = $1), count(*) FROM log_keys`
	default:
		return 0, 0, fmt.Errorf("unknown key kind %q", kind)
	}
	err = s.db.QueryRow(ctx, q, active).Scan(&done, &total)
	return done, total, err
}

func (s *Server) mustState(kind string) keyState {
	st, err := readKeyStates(s.cfg.CADir)
	if err != nil {
		return s.keyStates()[kind]
	}
	return st[kind]
}

const restartNote = "Restart every server instance to apply the change."

// RotateKey starts a rotation: a new key of kind becomes active, the
// current one stays usable until FinishKey. name is the new key's name
// (required with an HSM, where the key must exist with the label
// limdm-<name>). For the session key it returns the new LIMDM_SESSION_KEY.
func (s *Server) RotateKey(ctx context.Context, actor, kind, name string) (string, error) {
	switch kind {
	case kindSession:
		return s.rotateSession(ctx, actor)
	case kindWebhook:
		return s.rotateWebhook(ctx, actor)
	}
	// not while an instance starts and checks its keys (checkSharedKeys)
	unlock, err := clusterLock(ctx, s.db, lockStartup, 30*time.Second)
	if err != nil {
		return "", err
	}
	defer unlock()
	dir, p := s.cfg.CADir, s.cfg.Keys
	st, err := readKeyStates(dir)
	if err != nil {
		return "", err
	}
	cur, ok := st[kind]
	if !ok {
		return "", fmt.Errorf("unknown key kind %q (ca, network-ca, command, session, webhook, logs)", kind)
	}
	if cur.Previous != "" {
		return "", errors.New("a rotation of this key is running: finish it first")
	}
	if name == "" {
		if p.hsm() {
			return "", errors.New("name the new key: create it in the HSM with the label limdm-NAME first (docs/keys.md)")
		}
		name = kind + "-" + time.Now().UTC().Format("20060102-150405")
	}
	if !keyNameRe.MatchString(name) || name == cur.Active {
		return "", fmt.Errorf("invalid key name %q", name)
	}
	if !p.hsm() {
		for _, ext := range []string{".key", ".crt"} {
			if _, err := os.Stat(filepath.Join(dir, name+ext)); err == nil {
				return "", fmt.Errorf("%s%s exists already", name, ext)
			}
		}
	}
	date := time.Now().UTC().Format("2006-01-02")
	switch kind {
	case kindCA:
		_, err = loadRoot(p, dir, name, "LiMDM Device CA "+date)
	case kindNetCA:
		_, err = loadRoot(p, dir, name, "LiMDM Network CA "+date)
	case kindCommand:
		_, err = loadCommandKey(p, dir, name, true)
	case kindLogs:
		_, err = loadLogKEK(p, dir, name, true)
	}
	if err != nil {
		return "", err
	}
	st[kind] = keyState{Active: name, Previous: cur.Active, Since: time.Now().UTC()}
	if err := s.saveKeyStates(ctx, actor, "keys.rotate", kind, cur.Active+" -> "+name, st); err != nil {
		if !p.hsm() { // a retry starts clean
			os.Remove(filepath.Join(dir, name+".key"))
			os.Remove(filepath.Join(dir, name+".crt"))
		}
		return "", err
	}
	s.keyNotice(notice{Type: "keys.rotate", Severity: "warning", Title: "Key rotation started: " + kind,
		Text: actor + " started the rotation of the " + kind + " key (" + cur.Active + " to " + name + ")."})
	return restartNote, nil
}

// FinishKey ends a rotation: the previous key is no longer trusted and its
// key file is deleted. It refuses while devices still depend on the old
// key, unless force (those devices have to enroll again).
func (s *Server) FinishKey(ctx context.Context, actor, kind string, force bool) (string, error) {
	switch kind {
	case kindSession:
		return s.finishSession(ctx, actor)
	case kindWebhook:
		return "", errors.New("a webhook secret rotation takes effect at once: nothing to finish")
	}
	// not while an instance starts and checks its keys (checkSharedKeys)
	unlock, err := clusterLock(ctx, s.db, lockStartup, 30*time.Second)
	if err != nil {
		return "", err
	}
	defer unlock()
	dir, p := s.cfg.CADir, s.cfg.Keys
	st, err := readKeyStates(dir)
	if err != nil {
		return "", err
	}
	cur, ok := st[kind]
	if !ok {
		return "", fmt.Errorf("unknown key kind %q (ca, network-ca, command, session, webhook, logs)", kind)
	}
	if cur.Previous == "" {
		return "", errors.New("no rotation of this key is running")
	}
	done, total, err := s.keyProgress(ctx, kind, cur.Active)
	if err != nil {
		return "", err
	}
	if done < total && !force {
		return "", fmt.Errorf("%d of %d have not moved to the new key yet: wait, or force (they lose the connection and must enroll again)", total-done, total)
	}
	if kind == kindCommand {
		// the old key's audit segment must be recorded (audit-keys) before the key goes
		key, err := loadCommandKey(p, dir, cur.Active, false)
		if err != nil {
			return "", err
		}
		ak, err := auditKeyOf(key)
		if err != nil {
			return "", err
		}
		lines, err := readAuditKeyLines(dir)
		if err != nil || len(lines) == 0 || lines[len(lines)-1].id != auditKeyID(ak) {
			return "", errors.New("no server has started with the new command key yet: restart the server first")
		}
	}
	st[kind] = keyState{Active: cur.Active, Since: time.Now().UTC()}
	detail := fmt.Sprintf("%s retired, %d of %d moved", cur.Previous, done, total)
	if done < total {
		detail += " (forced)"
	}
	if err := s.saveKeyStates(ctx, actor, "keys.finish", kind, detail, st); err != nil {
		return "", err
	}
	msg := restartNote
	if p.hsm() {
		msg += " Destroy the HSM object limdm-" + cur.Previous + " once every instance runs without it."
	} else if err := os.Remove(filepath.Join(dir, cur.Previous+".key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("deleting the retired key: %w", err)
	}
	s.keyNotice(notice{Type: "keys.rotate", Severity: "warning", Title: "Key rotation finished: " + kind,
		Text: actor + " finished the rotation of the " + kind + " key; " + detail + "."})
	return msg, nil
}

func (s *Server) rotateSession(ctx context.Context, actor string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b) // never fails since Go 1.24
	keys := []string{hex.EncodeToString(b), hex.EncodeToString(s.cfg.SessionKey)}
	for _, k := range s.cfg.OldSessionKeys {
		keys = append(keys, hex.EncodeToString(k))
	}
	if err := s.auditAction(ctx, actor, "keys.rotate", kindSession, "new session key generated; it goes first in LIMDM_SESSION_KEY", nil); err != nil {
		return "", err
	}
	s.keyNotice(notice{Type: "keys.rotate", Severity: "warning", Title: "Key rotation started: session",
		Text: actor + " generated a new session key; sealed values are sealed again after the restart."})
	return "LIMDM_SESSION_KEY=" + strings.Join(keys, ","), nil
}

func (s *Server) finishSession(ctx context.Context, actor string) (string, error) {
	if len(s.cfg.OldSessionKeys) == 0 {
		return "", errors.New("LIMDM_SESSION_KEY holds a single key: nothing to finish")
	}
	left, err := s.reseal(ctx, true)
	if err != nil {
		return "", err
	}
	if left > 0 {
		return "", fmt.Errorf("%d values are still sealed with an old session key: the server seals them again in the background after its restart", left)
	}
	if err := s.auditAction(ctx, actor, "keys.finish", kindSession, "every sealed value uses the first session key", nil); err != nil {
		return "", err
	}
	s.keyNotice(notice{Type: "keys.rotate", Severity: "warning", Title: "Key rotation finished: session",
		Text: actor + " confirmed that no value depends on an old session key any more."})
	return "Keep only the first key in LIMDM_SESSION_KEY, then " + strings.ToLower(restartNote[:1]) + restartNote[1:], nil
}

// keyNotice notifies; the CLI delivers before it exits.
func (s *Server) keyNotice(n notice) {
	if !s.kr.cli {
		s.notify(n)
		return
	}
	n.At = time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	chans, err := s.loadChannels(ctx, true)
	if err != nil {
		s.log.Error("notifications", "err", err)
		return
	}
	for _, c := range chans {
		if len(c.Events) == 0 || slices.Contains(c.Events, n.Type) {
			if err := s.deliver(ctx, c, n); err != nil {
				s.log.Warn("notification not delivered", "channel", c.Name, "err", err)
			}
		}
	}
}

// keysAllowed: key status and rotation are for global administrators only:
// no device scope and no tenant account (a super admin switched into a
// tenant still manages the keys of the whole installation).
func keysAllowed(sess session) bool {
	return sess.Role == "admin" && len(sess.Tags) == 0 && len(sess.Groups) == 0 && !sess.TenantOnly()
}

// ---- session keys ----

// parseSessionKeys reads LIMDM_SESSION_KEY: one or more hex keys of at
// least 32 bytes, separated by commas, the one in use first.
func parseSessionKeys(v string) ([][]byte, error) {
	var keys [][]byte
	for _, f := range strings.Split(v, ",") {
		k, err := hex.DecodeString(strings.TrimSpace(f))
		if err != nil || len(k) < 32 {
			return nil, errors.New("LIMDM_SESSION_KEY must be at least 32 bytes hex (openssl rand -hex 32); during a rotation several, comma separated, the new one first")
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// multiAEAD seals with the first AEAD and opens with any, so values sealed
// with an old session key stay readable until they are sealed again.
type multiAEAD []cipher.AEAD

func (m multiAEAD) NonceSize() int { return m[0].NonceSize() }
func (m multiAEAD) Overhead() int  { return m[0].Overhead() }
func (m multiAEAD) Seal(dst, nonce, plain, ad []byte) []byte {
	return m[0].Seal(dst, nonce, plain, ad)
}

func (m multiAEAD) Open(dst, nonce, sealed, ad []byte) ([]byte, error) {
	var err error
	for _, a := range m {
		var out []byte
		if out, err = a.Open(dst, nonce, sealed, ad); err == nil {
			return out, nil
		}
	}
	return nil, err
}

// openableWithPrimary reports whether sealed opens with the first session
// key alone, so it does not need sealing again.
func (s *Server) openableWithPrimary(info string, sealed, ad []byte) bool {
	a, err := aeadFor(s.cfg.SessionKey, info)
	if err != nil {
		return false
	}
	_, err = open(a, sealed, ad)
	return err == nil
}

// SignWithHSM signs msg with the Ed25519 key labeled label in the PKCS#11
// token of p (limdm-server sign -pkcs11, release signing).
func SignWithHSM(p KeyProvider, label string, msg []byte) ([]byte, error) {
	p.Kind = "pkcs11"
	if err := p.validate(); err != nil {
		return nil, err
	}
	k, err := openPKCS11(p.Module, p.Token, p.PIN, label)
	if err != nil {
		return nil, err
	}
	if _, ok := k.Public().(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", label)
	}
	return signEd25519(k, msg)
}
