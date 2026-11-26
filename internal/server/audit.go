package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The audit chain is keyed: each hash is an HMAC-SHA256 with a key derived
// from command.key, which lives next to the CA and never in the database.
// Whoever can only write to the database can no longer recompute the chain
// after changing a row. Entries written before the switch keep their plain
// SHA-256 hashes; auditKeyedFrom, recorded in a file next to the key, is the
// first keyed entry.
var (
	auditKey       []byte
	auditKeyedFrom int64 // 0: no keyed entries (no key, as in tools and tests)
)

const auditKeyedFile = "audit-keyed-from"

// AuditKey derives the audit chain key from the command key.
func AuditKey(cmdKey ed25519.PrivateKey) []byte {
	k, err := hkdf.Key(sha256.New, cmdKey.Seed(), nil, "limdm audit chain v1", 32)
	if err != nil {
		panic(err) // fixed parameters, cannot fail
	}
	return k
}

// ReadAuditKeyedFrom reads the first keyed entry ID recorded in the CA directory.
func ReadAuditKeyedFrom(caDir string) (int64, error) {
	b, err := os.ReadFile(filepath.Join(caDir, auditKeyedFile))
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || id < 1 {
		return 0, fmt.Errorf("%s: invalid entry id", auditKeyedFile)
	}
	return id, nil
}

// AuditKeyFromDir reads the audit key and switch point of a server's CA
// directory without creating anything (limdm-server audit). keyedFrom is 0
// when the server never wrote a keyed entry.
func AuditKeyFromDir(caDir string) (key []byte, keyedFrom int64, err error) {
	if _, err := os.Stat(filepath.Join(caDir, "command.key")); err != nil {
		return nil, 0, err
	}
	cmdKey, err := loadOrCreateCommandKey(caDir) // exists, so only loaded
	if err != nil {
		return nil, 0, err
	}
	keyedFrom, err = ReadAuditKeyedFrom(caDir)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return AuditKey(cmdKey), keyedFrom, err
}

// initAuditKey sets the audit key and, at the first start with it, records
// the switch point: in the file and as an audit entry that is itself keyed.
// The audit lock is held throughout, so no plain entry can follow the switch.
func initAuditKey(ctx context.Context, db *pgxpool.Pool, caDir string, cmdKey ed25519.PrivateKey) error {
	auditKey = AuditKey(cmdKey)
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7363)`); err != nil {
		return err
	}
	if auditKeyedFrom, err = ReadAuditKeyedFrom(caDir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var last int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&last); err != nil {
		return err
	}
	auditKeyedFrom = last + 1
	if err := os.WriteFile(filepath.Join(caDir, auditKeyedFile), []byte(strconv.FormatInt(auditKeyedFrom, 10)+"\n"), 0o600); err != nil {
		return err
	}
	if err := audit(ctx, tx, "system", "audit.keyed", "", fmt.Sprintf("entries from id %d on are keyed with HMAC-SHA256", auditKeyedFrom)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// auditHash is the chain hash of an entry: HMAC-SHA256 with key, or plain
// SHA-256 when key is nil (entries before the switch).
func auditHash(key, prev []byte, at time.Time, fields ...string) []byte {
	h := sha256.New()
	if key != nil {
		h = hmac.New(sha256.New, key)
	}
	h.Write(prev)
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(at.UnixMicro())))
	for _, f := range fields {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(f))))
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

// auditEntryOK checks one entry against the hash of the entry before it.
func auditEntryOK(key []byte, keyedFrom int64, prev []byte, a auditRow) bool {
	var k []byte
	if keyedFrom > 0 && a.ID >= keyedFrom {
		k = key
	}
	return bytes.Equal(a.Prev, prev) && hmac.Equal(a.Hash, auditHash(k, a.Prev, a.At, auditFields(a.Actor, a.Action, a.Target, a.Detail, a.Tenant)...))
}

// auditFields are the hashed fields of an entry: the tenant, when set, is
// a fifth field, so entries without one (all before tenants existed) keep
// their hashes and moving an entry to another tenant breaks the chain.
func auditFields(actor, action, target, detail string, tenant *int64) []string {
	f := []string{actor, action, target, detail}
	if tenant != nil {
		f = append(f, strconv.FormatInt(*tenant, 10))
	}
	return f
}

// auditLine is one line of the JSON Lines export: the raw values the hash
// covers, so the chain can be recomputed outside LiMDM.
type auditLine struct {
	ID     int64  `json:"id"`
	At     string `json:"at"`    // RFC 3339, UTC, microseconds
	AtUS   int64  `json:"at_us"` // the value hashed: Unix time in microseconds
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	Prev   string `json:"prev"` // hex
	Hash   string `json:"hash"` // hex
	Scheme string `json:"scheme"`
	Tenant *int64 `json:"tenant_id,omitempty"` // hashed as a fifth field when set
}

func auditScheme(id int64) string {
	if auditKeyedFrom > 0 && id >= auditKeyedFrom {
		return "hmac-sha256"
	}
	return "sha256"
}

// VerifyAuditExport recomputes the chain of a JSON Lines audit export. The
// first entry's prev is taken as given (an export can start anywhere); every
// following entry must continue the chain. It returns the number of entries,
// the first and last ID, and the first broken entry (0: intact).
func VerifyAuditExport(r io.Reader, key []byte, keyedFrom int64) (n int, first, last, broken int64, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var prev []byte
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var l auditLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return n, first, last, 0, fmt.Errorf("line %d: %w", n+1, err)
		}
		a := auditRow{ID: l.ID, At: time.UnixMicro(l.AtUS).UTC(), Actor: l.Actor, Action: l.Action, Target: l.Target, Detail: l.Detail, Tenant: l.Tenant}
		if a.Prev, err = hex.DecodeString(l.Prev); err != nil {
			return n, first, last, 0, fmt.Errorf("entry %d: prev: %w", l.ID, err)
		}
		if a.Hash, err = hex.DecodeString(l.Hash); err != nil {
			return n, first, last, 0, fmt.Errorf("entry %d: hash: %w", l.ID, err)
		}
		if n == 0 {
			prev, first = a.Prev, a.ID
		}
		n++
		if !auditEntryOK(key, keyedFrom, prev, a) {
			return n, first, last, a.ID, nil
		}
		prev, last = a.Hash, a.ID
	}
	return n, first, last, 0, sc.Err()
}

// auditFilter turns the audit page query into a condition on audit_log,
// limited to the device scope of sess. Every value is a bind parameter; f
// holds the cleaned values for the form. Page, CSV and JSON Lines export use it.
func auditFilter(q url.Values, sess session) (f map[string]string, where string, args []any) {
	f = map[string]string{"q": strings.TrimSpace(q.Get("q")), "actor": strings.TrimSpace(q.Get("actor")), "action": strings.TrimSpace(q.Get("action")),
		"target": strings.TrimSpace(q.Get("target")), "from": q.Get("from"), "to": q.Get("to")}
	conds := []string{"true"}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if f["q"] != "" {
		add(`(actor || ' ' || action || ' ' || target || ' ' || detail) ILIKE '%' || $? || '%'`, f["q"])
	}
	if f["actor"] != "" {
		add(`actor ILIKE '%' || $? || '%'`, f["actor"])
	}
	if f["action"] != "" {
		add(`action LIKE $? || '%'`, f["action"])
	}
	if f["target"] != "" {
		add(`target = $?`, f["target"])
	}
	for _, k := range []string{"from", "to"} {
		if _, err := time.Parse("2006-01-02", f[k]); err != nil {
			f[k] = ""
			continue
		}
		if k == "from" {
			add(`at >= $?::date`, f[k])
		} else {
			add(`at < $?::date + 1`, f[k])
		}
	}
	cond, sargs := auditScope(sess, len(args))
	conds, args = append(conds, cond), append(args, sargs...)
	return f, strings.Join(conds, " AND "), args
}

// auditExportJSONL streams the (filtered) audit log as JSON Lines with the
// raw hashed values. Like every export it ends with an audit entry carrying
// the SHA-256 of the file.
func (s *Server) auditExportJSONL(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	_, where, args := auditFilter(r.URL.Query(), sess)
	s.streamExport(w, r, sess, "audit.jsonl", "application/x-ndjson", func(tx pgx.Tx, out io.Writer) (int, error) {
		rows, err := tx.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash, tenant_id FROM audit_log WHERE `+where+` ORDER BY id`, args...)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		enc := json.NewEncoder(out)
		n := 0
		for rows.Next() {
			var a auditRow
			if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.Prev, &a.Hash, &a.Tenant); err != nil {
				return n, err
			}
			if err := enc.Encode(auditLine{ID: a.ID, At: a.At.UTC().Format("2006-01-02T15:04:05.000000Z"), AtUS: a.At.UnixMicro(), Actor: a.Actor,
				Action: a.Action, Target: a.Target, Detail: a.Detail, Prev: hex.EncodeToString(a.Prev), Hash: hex.EncodeToString(a.Hash), Scheme: auditScheme(a.ID), Tenant: a.Tenant}); err != nil {
				return n, err
			}
			n++
		}
		return n, rows.Err()
	})
}

// auditVerify runs the full chain verification on demand (admins and auditors).
func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	broken, err := s.verifyAuditFrom(ctx, false)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.auditBroken.Store(broken)
	s.auditVerifiedAt.Store(time.Now().Unix())
	result := "chain intact"
	if broken != 0 {
		result = fmt.Sprintf("chain broken at entry %d", broken)
	}
	if err := s.auditAction(ctx, sess.Email, "audit.verify", "", result, nil); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/audit", http.StatusSeeOther)
}

// oidcFailures limits failed OIDC sign in entries: anyone can call the
// callback, and each entry takes the audit lock.
// ponytail: one global window, per address limits if this gets noisy.
var oidcFailures struct {
	sync.Mutex
	window time.Time
	n      int
}

// auditLoginFailure records a failed OIDC sign in (reason only, never codes
// or tokens), at most 30 per minute; the process log gets every one.
func (s *Server) auditLoginFailure(ctx context.Context, r *http.Request, reason string) {
	ip := "invalid"
	if a, err := netip.ParseAddr(clientIP(r)); err == nil {
		ip = a.String() // parsed, never the raw header text
	}
	s.log.Warn("oidc login failed", "remote", ip, "reason", reason)
	oidcFailures.Lock()
	if time.Since(oidcFailures.window) > time.Minute {
		oidcFailures.window, oidcFailures.n = time.Now(), 0
	}
	oidcFailures.n++
	over := oidcFailures.n > 30
	oidcFailures.Unlock()
	if over {
		return
	}
	if err := s.auditAction(context.WithoutCancel(ctx), "oidc", "login.failed", "", truncate("reason="+reason+" remote="+ip, 300), nil); err != nil {
		s.log.Error("audit login.failed", "err", err)
	}
}
