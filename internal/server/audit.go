package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
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
// from the command key, which lives next to the CA (or in the HSM) and never
// in the database. Whoever can only write to the database can no longer
// recompute the chain after changing a row. Entries written before the
// switch keep their plain SHA-256 hashes; auditKeyedFrom, recorded in a file
// next to the key, is the first keyed entry.
//
// A command key rotation starts a new segment with a new audit key. The file
// audit-keys lists the segments ("<first id> <key id> [<key hex>]"); the
// keys of earlier segments are kept there, so old entries stay verifiable
// after the old command key is gone. The audit_key row names the current
// key, so an instance still running the old key cannot write entries.
var (
	auditKey       []byte    // current segment, for new entries
	auditKeyCur    string    // auditKeyID(auditKey)
	auditKeys      AuditKeys // every segment, for verification
	auditKeyedFrom int64     // 0: no keyed entries (no key, as in tools and tests)
)

const (
	auditKeyedFile = "audit-keyed-from"
	auditKeysFile  = "audit-keys"
	auditKeyLabel  = "limdm audit chain v1"
)

// AuditSegment is a range of keyed entries: from From up to the next segment.
type AuditSegment struct {
	From int64
	Key  []byte
}

// AuditKeys are the segments of the chain in ascending order.
type AuditKeys []AuditSegment

// keyFor is the key of entry id, nil before the first segment (plain SHA-256).
func (k AuditKeys) keyFor(id int64) []byte {
	var key []byte
	for _, s := range k {
		if id >= s.From {
			key = s.Key
		}
	}
	return key
}

// AuditKey derives the audit chain key from a file command key.
func AuditKey(cmdKey ed25519.PrivateKey) []byte {
	k, err := hkdf.Key(sha256.New, cmdKey.Seed(), nil, auditKeyLabel, 32)
	if err != nil {
		panic(err) // fixed parameters, cannot fail
	}
	return k
}

// auditKeyOf derives the audit key from any command key. A key in an HSM
// has no readable seed: Ed25519 signatures are deterministic (RFC 8032), so
// the signature over a fixed label, which is never published, is a secret
// only the key holder can compute.
func auditKeyOf(cmd crypto.Signer) ([]byte, error) {
	if k, ok := cmd.(ed25519.PrivateKey); ok {
		return AuditKey(k), nil
	}
	a, err := signEd25519(cmd, []byte(auditKeyLabel))
	if err != nil {
		return nil, err
	}
	b, err := signEd25519(cmd, []byte(auditKeyLabel))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(a, b) {
		return nil, errors.New("the HSM command key signs non deterministically: it cannot key the audit chain")
	}
	return hkdf.Key(sha256.New, a, nil, auditKeyLabel, 32)
}

// auditKeyID names a key without revealing it.
func auditKeyID(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:8])
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

type auditKeyLine struct {
	from int64
	id   string
	key  []byte // kept for retired segments only
}

func readAuditKeyLines(caDir string) ([]auditKeyLine, error) {
	b, err := os.ReadFile(filepath.Join(caDir, auditKeysFile))
	if err != nil {
		return nil, err
	}
	var out []auditKeyLine
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || len(f) > 3 {
			return nil, fmt.Errorf("%s: invalid line %q", auditKeysFile, l)
		}
		from, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil || from < 1 || (len(out) > 0 && from <= out[len(out)-1].from) {
			return nil, fmt.Errorf("%s: invalid entry id in %q", auditKeysFile, l)
		}
		line := auditKeyLine{from: from, id: f[1]}
		if len(f) == 3 {
			if line.key, err = hex.DecodeString(f[2]); err != nil || auditKeyID(line.key) != line.id {
				return nil, fmt.Errorf("%s: key of segment %d does not match its id", auditKeysFile, from)
			}
		}
		out = append(out, line)
	}
	return out, nil
}

func writeAuditKeyLines(caDir string, lines []auditKeyLine) error {
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%d %s", l.from, l.id)
		if l.key != nil {
			fmt.Fprintf(&b, " %x", l.key)
		}
		b.WriteByte('\n')
	}
	tmp := filepath.Join(caDir, auditKeysFile+".tmp")
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, auditKeysFile))
}

// segments turns the lines into keys: retired segments carry theirs, the
// last one gets cur (or prev, when no server started with cur yet).
func segments(lines []auditKeyLine, cur, prev []byte) (AuditKeys, error) {
	var out AuditKeys
	for i, l := range lines {
		k := l.key
		if i == len(lines)-1 && k == nil {
			switch l.id {
			case auditKeyID(cur):
				k = cur
			case auditKeyID(prev):
				k = prev
			}
		}
		if k == nil {
			return nil, fmt.Errorf("%s: no key for the segment from entry %d", auditKeysFile, l.from)
		}
		out = append(out, AuditSegment{From: l.from, Key: k})
	}
	return out, nil
}

// AuditKeysFromDir reads the audit segments of a server's CA directory
// without creating anything (limdm-server audit). It is empty when the
// server never wrote a keyed entry.
func AuditKeysFromDir(caDir string, p KeyProvider) (AuditKeys, error) {
	st, err := readKeyStates(caDir)
	if err != nil {
		return nil, err
	}
	cmd, err := loadCommandKey(p, caDir, st[kindCommand].Active, false)
	if err != nil {
		return nil, err
	}
	cur, err := auditKeyOf(cmd)
	if err != nil {
		return nil, err
	}
	var prev []byte
	if st[kindCommand].Previous != "" {
		if pk, err := loadCommandKey(p, caDir, st[kindCommand].Previous, false); err == nil {
			prev, _ = auditKeyOf(pk)
		}
	}
	lines, err := readAuditKeyLines(caDir)
	if errors.Is(err, os.ErrNotExist) {
		from, err := ReadAuditKeyedFrom(caDir)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return AuditKeys{{From: from, Key: cur}}, err
	}
	if err != nil {
		return nil, err
	}
	return segments(lines, cur, prev)
}

// errAuditKeyStale: another instance started with a new command key, so
// entries keyed by this process would break the chain.
var errAuditKeyStale = errors.New("the audit key changed with a key rotation: restart this server instance")

// auditKeyStale tells whether the chain moved on to a key this process does
// not have (readyz, leader jobs).
func auditKeyStale(ctx context.Context, db *pgxpool.Pool) (bool, error) {
	if auditKey == nil {
		return false, nil
	}
	var id string
	err := db.QueryRow(ctx, `SELECT key_id FROM audit_key`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil && id != auditKeyCur, err
}

// initAuditKey sets the audit keys. At the first start with a key it records
// the switch point; at the first start with a new command key (prev is the
// one being retired) it starts a new segment: in the file, in audit_key and
// as an audit entry keyed with the new key. The audit lock is held
// throughout, so no entry with the old key can follow the switch.
func initAuditKey(ctx context.Context, db *pgxpool.Pool, caDir string, cmd, prev crypto.Signer) error {
	key, err := auditKeyOf(cmd)
	if err != nil {
		return err
	}
	var prevKey []byte
	if prev != nil {
		if prevKey, err = auditKeyOf(prev); err != nil {
			return err
		}
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7363)`); err != nil {
		return err
	}
	var last int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM audit_log`).Scan(&last); err != nil {
		return err
	}
	var dbKey string
	if err := tx.QueryRow(ctx, `SELECT key_id FROM audit_key`).Scan(&dbKey); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	lines, err := readAuditKeyLines(caDir)
	var entry, action string
	switch {
	case errors.Is(err, os.ErrNotExist):
		from, err := ReadAuditKeyedFrom(caDir)
		if errors.Is(err, os.ErrNotExist) {
			from = last + 1
			if err := os.WriteFile(filepath.Join(caDir, auditKeyedFile), []byte(strconv.FormatInt(from, 10)+"\n"), 0o600); err != nil {
				return err
			}
			entry, action = fmt.Sprintf("entries from id %d on are keyed with HMAC-SHA256", from), "audit.keyed"
		} else if err != nil {
			return err
		}
		// before audit-keys existed the key never changed: one segment
		lines = []auditKeyLine{{from: from, id: auditKeyID(key)}}
		if err := writeAuditKeyLines(caDir, lines); err != nil {
			return err
		}
	case err != nil:
		return err
	case lines[len(lines)-1].id != auditKeyID(key):
		if dbKey == auditKeyID(key) {
			// another instance started the new segment in its own copy of the file
			return fmt.Errorf("%s/%s is older than the audit chain: give every instance the same CA directory (docs/high-availability.md)", caDir, auditKeysFile)
		}
		cur := &lines[len(lines)-1]
		if prevKey == nil || auditKeyID(prevKey) != cur.id {
			return errors.New("the command key changed, but the key of the current audit segment is not available: " +
				"keep the previous command key in keys.json until a server started with the new one (docs/keys.md)")
		}
		cur.key = prevKey
		prevID := cur.id
		lines = append(lines, auditKeyLine{from: last + 1, id: auditKeyID(key)})
		if err := writeAuditKeyLines(caDir, lines); err != nil {
			return err
		}
		// the retention cut is signed with the audit key: sign it again
		var cid int64
		var chash, cmac []byte
		err := tx.QueryRow(ctx, `SELECT last_id, last_hash, mac FROM audit_cut`).Scan(&cid, &chash, &cmac)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case hmac.Equal(cmac, cutMACWith(prevKey, cid, chash)):
			if _, err := tx.Exec(ctx, `UPDATE audit_cut SET mac=$1`, cutMACWith(key, cid, chash)); err != nil {
				return err
			}
		}
		entry = fmt.Sprintf("command key rotated: entries from id %d on are keyed with audit key %s (previous %s)", last+1, auditKeyID(key), prevID)
		action = "audit.key_rotate"
	}
	if entry == "" && dbKey != "" && dbKey != auditKeyID(key) {
		// a stale CA directory must not move the chain back to a retired key
		return errAuditKeyStale
	}
	segs, err := segments(lines, key, prevKey)
	if err != nil {
		return err
	}
	auditKey, auditKeyCur, auditKeys, auditKeyedFrom = key, auditKeyID(key), segs, segs[0].From
	if _, err := tx.Exec(ctx, `INSERT INTO audit_key(one, key_id) VALUES (true, $1) ON CONFLICT (one) DO UPDATE SET key_id=EXCLUDED.key_id`, auditKeyCur); err != nil {
		return err
	}
	if entry != "" {
		if err := audit(ctx, tx, "system", action, "", entry); err != nil {
			return err
		}
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
func auditEntryOK(keys AuditKeys, prev []byte, a auditRow) bool {
	return bytes.Equal(a.Prev, prev) && hmac.Equal(a.Hash, auditHash(keys.keyFor(a.ID), a.Prev, a.At, auditFields(a.Actor, a.Action, a.Target, a.Detail, a.Tenant)...))
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
	if auditKeys.keyFor(id) != nil {
		return "hmac-sha256"
	}
	return "sha256"
}

// VerifyAuditExport recomputes the chain of a JSON Lines audit export. The
// first entry's prev is taken as given (an export can start anywhere); every
// following entry must continue the chain. It returns the number of entries,
// the first and last ID, and the first broken entry (0: intact).
func VerifyAuditExport(r io.Reader, keys AuditKeys) (n int, first, last, broken int64, err error) {
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
		if !auditEntryOK(keys, prev, a) {
			return n, first, last, a.ID, nil
		}
		prev, last = a.Hash, a.ID
	}
	return n, first, last, 0, sc.Err()
}

// auditFilter turns the audit query into a condition on audit_log, limited
// to the device scope of sess. Every value is a bind parameter. The API
// list, CSV and JSON Lines export use it.
func auditFilter(q url.Values, sess session) (where string, args []any) {
	f := map[string]string{"q": strings.TrimSpace(q.Get("q")), "actor": strings.TrimSpace(q.Get("actor")), "action": strings.TrimSpace(q.Get("action")),
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
	return strings.Join(conds, " AND "), args
}

// auditExportJSONL streams the (filtered) audit log as JSON Lines with the
// raw hashed values. Like every export it ends with an audit entry carrying
// the SHA-256 of the file.
func (s *Server) auditExportJSONL(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	where, args := auditFilter(r.URL.Query(), sess)
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

// verifyAuditChain verifies the whole chain, stores and audits the result
// (the audit status shows it). Console and app share it.
func (s *Server) verifyAuditChain(ctx context.Context, actor string) error {
	broken, err := s.verifyAuditFrom(ctx, false)
	if err != nil {
		return err
	}
	if _, err := s.storeAuditVerification(ctx, broken); err != nil {
		return err
	}
	result := "chain intact"
	if broken != 0 {
		result = fmt.Sprintf("chain broken at entry %d", broken)
	}
	return s.auditAction(ctx, actor, "audit.verify", "", result, nil)
}

// auditBudget limits audit entries of failed sign ins: anyone can cause
// them, and each entry takes the audit lock. 30 per minute; the process
// log gets every one.
// ponytail: one global window, per address limits if this gets noisy.
type auditBudget struct {
	sync.Mutex
	window time.Time
	n      int
}

// take reports whether one more entry fits into the current minute.
func (b *auditBudget) take() bool {
	b.Lock()
	defer b.Unlock()
	if time.Since(b.window) > time.Minute {
		b.window, b.n = time.Now(), 0
	}
	b.n++
	return b.n <= 30
}

// oidcFailures and localFailures budget failed OIDC and local sign ins.
var oidcFailures, localFailures auditBudget

// auditLoginFailure records a failed OIDC sign in (reason only, never codes
// or tokens), at most 30 per minute; the process log gets every one.
func (s *Server) auditLoginFailure(ctx context.Context, r *http.Request, reason string) {
	ip := "invalid"
	if a, err := netip.ParseAddr(clientIP(r)); err == nil {
		ip = a.String() // parsed, never the raw header text
	}
	s.log.Warn("oidc login failed", "remote", ip, "reason", reason)
	if !oidcFailures.take() {
		return
	}
	if err := s.auditAction(context.WithoutCancel(ctx), "oidc", "login.failed", "", truncate("reason="+reason+" remote="+ip, 300), nil); err != nil {
		s.log.Error("audit login.failed", "err", err)
	}
}
