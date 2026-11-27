package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Log archive (docs/logs.md#archive). Each finished day is exported per
// tenant and device as gzip compressed NDJSON, encrypted before upload with
// AES-256-GCM in 64 KiB chunks under a data key of the tenant. Data keys are
// random and stored in log_keys with an ID, wrapped with a key encryption
// key derived from the key kind logs of the server key management (keys.go:
// a file in the CA directory or an HSM object), independent of
// LIMDM_SESSION_KEY. Rotating data keys starts a new key per tenant, old
// ones stay for reading; rotating the key kind logs rewraps every data key. A manifest per tenant and day lists every object
// with its SHA-256; every upload is read back and compared before the day
// counts as archived, and a day's partition is dropped only then.
//
// Object layout under the target's prefix:
//
//	logs/t<tenant>/<device>/<YYYY-MM-DD>.ndjson.gz.enc
//	logs/t<tenant>/manifests/<YYYY-MM-DD>.json

// infoLogKeys sealed data keys with the session key in earlier builds; such
// rows (empty kek_id) are rewrapped at start (rewrapLogKeys).
const infoLogKeys = "limdm log archive keys v1"

// logArchiveMagic starts every encrypted object (format version 2);
// logArchiveMagicV1 objects are still read.
const (
	logArchiveMagic   = "LIMDMLG2"
	logArchiveMagicV1 = "LIMDMLG1"
	logObjectInfo     = "limdm log object v2"
)

const logChunk = 64 << 10

// logSealer encrypts a stream: a header (magic, key ID, a random 32 byte
// salt, the object name), then chunks of a 4 byte length and the sealed
// chunk. Every object gets its own AES-256 key, HKDF-SHA256 of the tenant's
// data key and the salt, so the chunk counter alone is a unique nonce under
// that key and no nonce repeats across objects. The additional data binds
// the header (and with it tenant, device and day of the object name) and
// marks the last chunk, so reordering, truncation, appending and moving an
// object to another name fail.
type logSealer struct {
	w      io.Writer
	aead   cipher.AEAD
	header []byte
	prefix []byte
	n      uint64
	buf    []byte
}

func newLogSealer(w io.Writer, keyID string, key []byte, name string) (*logSealer, error) {
	if len(keyID) == 0 || len(keyID) > 255 || len(name) > 1024 {
		return nil, errors.New("invalid key ID or object name")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	a, err := logObjectAEAD(key, salt)
	if err != nil {
		return nil, err
	}
	h := append([]byte(logArchiveMagic), byte(len(keyID))) //nolint:gosec // checked above: at most 255
	h = append(append(h, keyID...), salt...)
	h = binary.BigEndian.AppendUint16(h, uint16(len(name))) //nolint:gosec // checked above: at most 1024
	h = append(h, name...)
	if _, err := w.Write(h); err != nil {
		return nil, err
	}
	return &logSealer{w: w, aead: a, header: h, prefix: make([]byte, 4)}, nil
}

// logObjectAEAD derives the AES-256-GCM key of one object from the data key
// and the object's salt.
func logObjectAEAD(key, salt []byte) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, key, salt, logObjectInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *logSealer) seal(chunk []byte, last bool) error {
	nonce := binary.BigEndian.AppendUint64(append([]byte{}, s.prefix...), s.n)
	s.n++
	flag := byte(0)
	if last {
		flag = 1
	}
	out := s.aead.Seal(nil, nonce, chunk, append(append([]byte{}, s.header...), flag))
	if _, err := s.w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(out)))); err != nil { //nolint:gosec // a chunk is at most 64 KiB and the tag
		return err
	}
	_, err := s.w.Write(out)
	return err
}

func (s *logSealer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		take := min(logChunk-len(s.buf), len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		if len(s.buf) == logChunk {
			if err := s.seal(s.buf, false); err != nil {
				return 0, err
			}
			s.buf = s.buf[:0]
		}
	}
	return n, nil
}

// Close seals the last chunk (possibly empty).
func (s *logSealer) Close() error { return s.seal(s.buf, true) }

// logOpener decrypts what logSealer wrote.
type logOpener struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	header []byte
	prefix []byte
	n      uint64
	plain  []byte
	done   bool
}

// openLogArchive reads the header and returns a reader of the plain text
// and the key ID; key looks the data key up. name is the object's name in
// the store: a version 2 object written under another name is refused.
func openLogArchive(r io.Reader, key func(id string) ([]byte, error), name string) (io.Reader, string, error) {
	br := bufio.NewReader(r)
	head := make([]byte, len(logArchiveMagic)+1)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, "", errors.New("not a LiMDM log archive")
	}
	v1 := string(head[:len(logArchiveMagic)]) == logArchiveMagicV1
	if !v1 && string(head[:len(logArchiveMagic)]) != logArchiveMagic {
		return nil, "", errors.New("not a LiMDM log archive")
	}
	idLen := int(head[len(head)-1])
	if v1 { // key ID and a 4 byte nonce prefix under the data key itself
		rest := make([]byte, idLen+4)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, "", errors.New("truncated archive header")
		}
		id := string(rest[:idLen])
		k, err := key(id)
		if err != nil {
			return nil, id, fmt.Errorf("key %s: %w", id, err)
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, id, err
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, id, err
		}
		return &logOpener{r: br, aead: a, header: append(head, rest...), prefix: rest[idLen:]}, id, nil
	}
	rest := make([]byte, idLen+32+2)
	if _, err := io.ReadFull(br, rest); err != nil {
		return nil, "", errors.New("truncated archive header")
	}
	id, salt := string(rest[:idLen]), rest[idLen:idLen+32]
	stored := make([]byte, binary.BigEndian.Uint16(rest[idLen+32:]))
	if len(stored) > 1024 {
		return nil, id, errors.New("invalid archive header")
	}
	if _, err := io.ReadFull(br, stored); err != nil {
		return nil, id, errors.New("truncated archive header")
	}
	if name != "" && string(stored) != name {
		return nil, id, errors.New("the object belongs to another tenant, device or day")
	}
	k, err := key(id)
	if err != nil {
		return nil, id, fmt.Errorf("key %s: %w", id, err)
	}
	a, err := logObjectAEAD(k, salt)
	if err != nil {
		return nil, id, err
	}
	h := append(append(head, rest...), stored...)
	return &logOpener{r: br, aead: a, header: h, prefix: make([]byte, 4)}, id, nil
}

func (o *logOpener) Read(p []byte) (int, error) {
	for len(o.plain) == 0 {
		if o.done {
			if _, err := o.r.ReadByte(); err != io.EOF {
				return 0, errors.New("data after the last chunk")
			}
			return 0, io.EOF
		}
		var l [4]byte
		if _, err := io.ReadFull(o.r, l[:]); err != nil {
			return 0, errors.New("archive truncated")
		}
		size := binary.BigEndian.Uint32(l[:])
		if size > logChunk+uint32(o.aead.Overhead()) { //nolint:gosec // the GCM tag, 16 bytes
			return 0, errors.New("chunk too large")
		}
		sealed := make([]byte, size)
		if _, err := io.ReadFull(o.r, sealed); err != nil {
			return 0, errors.New("archive truncated")
		}
		nonce := binary.BigEndian.AppendUint64(append([]byte{}, o.prefix...), o.n)
		o.n++
		plain, err := o.aead.Open(nil, nonce, sealed, append(append([]byte{}, o.header...), 0))
		if err != nil {
			plain, err = o.aead.Open(nil, nonce, sealed, append(append([]byte{}, o.header...), 1))
			if err != nil {
				return 0, errors.New("archive damaged or wrong key")
			}
			o.done = true
		}
		o.plain = plain
	}
	n := copy(p, o.plain)
	o.plain = o.plain[n:]
	return n, nil
}

// ---- key encryption keys and data keys ----

// logKEKLabel is signed to derive a key encryption key: Ed25519 signatures
// are deterministic (RFC 8032), so the signature over this label, never
// published, is a secret only the key holder computes, also in an HSM
// (as the audit key, audit.go).
const logKEKLabel = "limdm log archive kek v1"

// logKEK wraps the data keys; id names it in log_keys.kek_id.
type logKEK struct {
	id   string
	aead cipher.AEAD
}

// loadLogKEK opens the key kind logs named name (the file <name>.key in the
// CA directory, created when missing and create is set, or the HSM object
// limdm-<name>) and derives its key encryption key.
func loadLogKEK(p KeyProvider, dir, name string, create bool) (*logKEK, error) {
	gen := genEd25519
	if !create {
		gen = nil
	}
	key, err := p.signer(dir, name, gen)
	if err != nil {
		return nil, fmt.Errorf("log archive key %q: %w", name, err)
	}
	if _, ok := key.Public().(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("log archive key %q: not an Ed25519 key", name)
	}
	a, err := signEd25519(key, []byte(logKEKLabel))
	if err != nil {
		return nil, err
	}
	b, err := signEd25519(key, []byte(logKEKLabel))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(a, b) {
		return nil, fmt.Errorf("log archive key %q signs non deterministically", name)
	}
	k, err := hkdf.Key(sha256.New, a, nil, logKEKLabel, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &logKEK{id: "kek-" + pubHex(key)[:16], aead: g}, nil
}

// activeLogKEK is the key encryption key new data keys are wrapped with.
func (s *Server) activeLogKEK() (*logKEK, error) {
	if s.kr.logKEK == nil {
		if s.kr.logErr != nil {
			return nil, s.kr.logErr
		}
		return nil, errors.New("the log archive key (key kind logs) is not loaded")
	}
	return s.kr.logKEK, nil
}

// logDataKey returns the active data key of a tenant, creating one.
func (s *Server) logDataKey(ctx context.Context, tenant int64) (string, []byte, error) {
	for range 2 {
		var id, kek string
		var wrapped []byte
		err := s.db.QueryRow(ctx, `SELECT id, kek_id, wrapped FROM log_keys WHERE tenant_id = $1 AND active`, tenant).Scan(&id, &kek, &wrapped)
		if err == nil {
			k, err := s.unwrapLogKey(id, kek, wrapped)
			return id, k, err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", nil, err
		}
		if err := s.newLogKey(ctx, s.db, tenant); err != nil {
			return "", nil, err
		}
	}
	return "", nil, errors.New("no log data key")
}

// newLogKey stores a new active data key (none when one is active already).
func (s *Server) newLogKey(ctx context.Context, q execer, tenant int64) error {
	kek, err := s.activeLogKEK()
	if err != nil {
		return err
	}
	key := make([]byte, 32)
	rand.Read(key)
	id := fmt.Sprintf("lk-%d-%s", tenant, randToken(6))
	_, err = q.Exec(ctx, `INSERT INTO log_keys(id, tenant_id, wrapped, kek_id) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		id, tenant, seal(kek.aead, key, []byte(id)), kek.id)
	return err
}

// unwrapLogKey opens a data key with the key encryption key that wrapped
// it: the active or the retiring one, or, for an empty kek_id, the session
// key of earlier builds.
func (s *Server) unwrapLogKey(id, kekID string, wrapped []byte) ([]byte, error) {
	if kekID == "" {
		a, err := s.aead(infoLogKeys)
		if err != nil {
			return nil, err
		}
		return open(a, wrapped, []byte(id))
	}
	for _, k := range []*logKEK{s.kr.logKEK, s.kr.logPrev} {
		if k != nil && k.id == kekID {
			return open(k.aead, wrapped, []byte(id))
		}
	}
	return nil, fmt.Errorf("data key %s: its key encryption key %s is not loaded", id, kekID)
}

// openLogKey looks a data key up by ID (any, active or not).
func (s *Server) openLogKey(ctx context.Context, id string) ([]byte, error) {
	var kek string
	var wrapped []byte
	if err := s.db.QueryRow(ctx, `SELECT kek_id, wrapped FROM log_keys WHERE id = $1`, id).Scan(&kek, &wrapped); err != nil {
		return nil, err
	}
	return s.unwrapLogKey(id, kek, wrapped)
}

// rotateLogKeys gives every tenant with a key a new active one; archives
// already written keep their key, new ones use the new key.
func (s *Server) rotateLogKeys(ctx context.Context, actor string) (int, error) {
	n := 0
	err := s.auditAction(ctx, actor, "logs.key_rotate", "logs", "", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE log_keys SET active = false WHERE active RETURNING tenant_id`)
		if err != nil {
			return err
		}
		tenants, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		for _, t := range tenants {
			if err := s.newLogKey(ctx, tx, t); err != nil {
				return err
			}
		}
		n = len(tenants)
		return nil
	})
	return n, err
}

// rewrapLogKeys wraps every data key with the active key encryption key:
// after a rotation of the key kind logs (the retiring key is still
// loaded) and for data keys of earlier builds wrapped with the session key.
// The data keys stay the same, so every archive stays readable; once all
// are rewrapped the rotation can finish.
func (s *Server) rewrapLogKeys(ctx context.Context) (int, error) {
	kek, err := s.activeLogKEK()
	if err != nil {
		return 0, err
	}
	rows, err := s.db.Query(ctx, `SELECT id, kek_id, wrapped FROM log_keys WHERE kek_id <> $1`, kek.id)
	if err != nil {
		return 0, err
	}
	type k struct {
		id, kek string
		wrapped []byte
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (k, error) {
		var v k
		return v, r.Scan(&v.id, &v.kek, &v.wrapped)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, v := range list {
		plain, err := s.unwrapLogKey(v.id, v.kek, v.wrapped)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Exec(ctx, `UPDATE log_keys SET wrapped = $3, kek_id = $4 WHERE id = $1 AND wrapped = $2`,
			v.id, v.wrapped, seal(kek.aead, plain, []byte(v.id)), kek.id); err != nil {
			return n, err
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---- archive ----

// logRecord is one line in an archive object.
type logRecord struct {
	At       time.Time       `json:"t"`
	Device   string          `json:"device"`
	Source   string          `json:"source"`
	Unit     string          `json:"unit,omitempty"`
	Priority int16           `json:"priority"`
	Host     string          `json:"host,omitempty"`
	Message  string          `json:"message"`
	Fields   json.RawMessage `json:"fields,omitempty"`
	Dedup    string          `json:"dedup"`
}

type logManifest struct {
	Tenant  int64       `json:"tenant"`
	Day     string      `json:"day"`
	KeyID   string      `json:"key_id"`
	Created time.Time   `json:"created"`
	Format  string      `json:"format"`
	Objects []logObject `json:"objects"`
}

type logObject struct {
	Name   string `json:"name"`
	Device string `json:"device"`
	Lines  int64  `json:"lines"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var safeObjectRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func logObjectName(tenant int64, device string, day time.Time) string {
	if !safeObjectRe.MatchString(device) || strings.HasPrefix(device, ".") {
		device = "x" + hex.EncodeToString([]byte(device))
	}
	return fmt.Sprintf("logs/t%d/%s/%s.ndjson.gz.enc", tenant, device, day.Format(time.DateOnly))
}

func logManifestName(tenant int64, day time.Time) string {
	return fmt.Sprintf("logs/t%d/manifests/%s.json", tenant, day.Format(time.DateOnly))
}

// logTargetHook replaces the storage targets in tests (a fake S3).
var logTargetHook func(name string) blobStore

// logTarget opens a storage target of Settings, Backup by name.
func (s *Server) logTarget(ctx context.Context, name string) (blobStore, error) {
	if logTargetHook != nil {
		return logTargetHook(name), nil
	}
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(cfg.Targets, func(t StoreTarget) bool { return t.Name == name })
	if i < 0 {
		return nil, fmt.Errorf("storage target %q not found (Settings, Backup)", name)
	}
	return s.openStore(cfg.Targets[i])
}

// hashFile is the SHA-256 and size of a reader.
func hashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// putVerified uploads a file and reads it back: the stored object must
// have the same SHA-256.
func putVerified(ctx context.Context, st blobStore, name, file, sum string) error {
	if err := st.Put(ctx, name, file); err != nil {
		return fmt.Errorf("upload %s: %w", name, err)
	}
	rc, err := st.Get(ctx, name)
	if err != nil {
		return fmt.Errorf("read back %s: %w", name, err)
	}
	defer rc.Close()
	got, _, err := hashReader(rc)
	if err != nil {
		return fmt.Errorf("read back %s: %w", name, err)
	}
	if got != sum {
		return fmt.Errorf("%s: stored object differs from the upload", name)
	}
	return nil
}

// archiveLogs archives every finished day (older than yesterday, so late
// lines of offline devices are in) whose archive is missing or no longer
// matches the partition, then removes archives past their retention.
func (s *Server) archiveLogs(ctx context.Context, set LogSettings, today time.Time) error {
	st, err := s.logTarget(ctx, set.ArchiveTarget)
	if err != nil {
		return s.archiveFailed(err)
	}
	days, err := logDays(ctx, s.db)
	if err != nil {
		return err
	}
	for _, d := range days {
		if !d.Before(today.AddDate(0, 0, -1)) {
			continue
		}
		todo, err := s.unarchived(ctx, d)
		if err != nil {
			return err
		}
		for _, t := range todo {
			if err := s.archiveDay(ctx, st, set.ArchiveTarget, t, d); err != nil {
				return s.archiveFailed(fmt.Errorf("%s tenant %d: %w", d.Format(time.DateOnly), t, err))
			}
		}
	}
	if set.ArchiveRetentionDays > 0 {
		if err := s.pruneLogArchives(ctx, today.AddDate(0, 0, -set.ArchiveRetentionDays)); err != nil {
			return s.archiveFailed(err)
		}
	}
	return nil
}

// archiveFailed announces a failed archive run (at most once a day).
func (s *Server) archiveFailed(err error) error {
	g := s.logGuard()
	g.mu.Lock()
	notify := time.Since(g.archiveNoticed) > 24*time.Hour
	if notify {
		g.archiveNoticed = time.Now()
	}
	g.mu.Unlock()
	if notify {
		s.notify(notice{Type: "logs.guard", Severity: "warning", Title: "Log archive failed",
			Text: "Days stay on the server until their archive is verified: " + truncate(err.Error(), 300), URL: s.cfg.PublicURL + "/app/settings?s=logs"})
	}
	return err
}

// unarchived lists the tenants of a day whose verified archive is missing
// or has another line count than the partition.
func (s *Server) unarchived(ctx context.Context, day time.Time) ([]int64, error) {
	rows, err := s.db.Query(ctx, `SELECT p.tenant_id FROM (SELECT tenant_id, count(*) AS n FROM `+logPartition(day)+` GROUP BY tenant_id) p
		LEFT JOIN log_archives a ON a.tenant_id = p.tenant_id AND a.day = $1
		WHERE a.verified_at IS NULL OR a.lines <> p.n ORDER BY 1`, day)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// dayArchived reports whether every tenant of a day has its verified archive.
func (s *Server) dayArchived(ctx context.Context, day time.Time) (bool, error) {
	todo, err := s.unarchived(ctx, day)
	return len(todo) == 0, err
}

// archiveDay writes, uploads and verifies the objects and the manifest of
// one tenant and day.
func (s *Server) archiveDay(ctx context.Context, st blobStore, target string, tenant int64, day time.Time) error {
	keyID, key, err := s.logDataKey(ctx, tenant)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "limdm-logs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	part := logPartition(day)
	rows, err := s.db.Query(ctx, `SELECT DISTINCT device_id FROM `+part+` WHERE tenant_id = $1 ORDER BY 1`, tenant)
	if err != nil {
		return err
	}
	devices, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	man := logManifest{Tenant: tenant, Day: day.Format(time.DateOnly), KeyID: keyID, Created: time.Now().UTC(), Format: "ndjson+gzip+" + logArchiveMagic}
	var total, size int64
	for i, dev := range devices {
		file := filepath.Join(dir, strconv.Itoa(i))
		name := logObjectName(tenant, dev, day)
		obj, err := s.writeLogObject(ctx, file, part, name, tenant, dev, keyID, key)
		if err != nil {
			return err
		}
		obj.Name = name
		if err := putVerified(ctx, st, obj.Name, file, obj.SHA256); err != nil {
			return err
		}
		_ = os.Remove(file)
		man.Objects = append(man.Objects, obj)
		total += obj.Lines
		size += obj.Size
	}
	b, _ := json.MarshalIndent(man, "", " ")
	mf := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mf, b, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	msum := hex.EncodeToString(sum[:])
	if err := putVerified(ctx, st, logManifestName(tenant, day), mf, msum); err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO log_archives(tenant_id, day, target, manifest, sha256, objects, lines, bytes, key_id, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now()) ON CONFLICT (tenant_id, day) DO UPDATE SET target = EXCLUDED.target,
		manifest = EXCLUDED.manifest, sha256 = EXCLUDED.sha256, objects = EXCLUDED.objects, lines = EXCLUDED.lines, bytes = EXCLUDED.bytes,
		key_id = EXCLUDED.key_id, verified_at = now(), created_at = now()`,
		tenant, day, target, logManifestName(tenant, day), msum, len(man.Objects), total, size, keyID)
	return err
}

// countHash counts and hashes what is written through it.
type countHash struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (c *countHash) Write(p []byte) (int, error) {
	c.h.Write(p)
	c.n += int64(len(p))
	return c.w.Write(p)
}

// writeLogObject writes the encrypted object of one device and day.
func (s *Server) writeLogObject(ctx context.Context, file, part, name string, tenant int64, device, keyID string, key []byte) (logObject, error) {
	obj := logObject{Device: device}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return obj, err
	}
	defer f.Close()
	ch := &countHash{w: f, h: sha256.New()}
	sealer, err := newLogSealer(ch, keyID, key, name)
	if err != nil {
		return obj, err
	}
	zw := gzip.NewWriter(sealer)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	rows, err := s.db.Query(ctx, `SELECT at, source, unit, priority, host, message, fields, dedup FROM `+part+`
		WHERE tenant_id = $1 AND device_id = $2 ORDER BY at, dedup`, tenant, device)
	if err != nil {
		return obj, err
	}
	defer rows.Close()
	for rows.Next() {
		r := logRecord{Device: device}
		var dedup []byte
		if err := rows.Scan(&r.At, &r.Source, &r.Unit, &r.Priority, &r.Host, &r.Message, &r.Fields, &dedup); err != nil {
			return obj, err
		}
		r.Dedup = hex.EncodeToString(dedup)
		if err := enc.Encode(r); err != nil {
			return obj, err
		}
		obj.Lines++
	}
	if err := rows.Err(); err != nil {
		return obj, err
	}
	if err := zw.Close(); err != nil {
		return obj, err
	}
	if err := sealer.Close(); err != nil {
		return obj, err
	}
	if err := f.Sync(); err != nil {
		return obj, err
	}
	obj.Size, obj.SHA256 = ch.n, hex.EncodeToString(ch.h.Sum(nil))
	return obj, nil
}

// pruneLogArchives deletes archived days before cutoff from their target.
// A target with object lock refuses early deletes; those days stay listed.
func (s *Server) pruneLogArchives(ctx context.Context, cutoff time.Time) error {
	rows, err := s.db.Query(ctx, `SELECT tenant_id, day, target, manifest FROM log_archives WHERE day < $1`, cutoff)
	if err != nil {
		return err
	}
	type row struct {
		tenant           int64
		day              time.Time
		target, manifest string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var v row
		return v, r.Scan(&v.tenant, &v.day, &v.target, &v.manifest)
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range list {
		st, err := s.logTarget(ctx, a.target)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		man, err := readManifest(ctx, st, a.manifest, "")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, o := range man.Objects {
			errs = append(errs, st.Delete(ctx, o.Name))
		}
		if err := st.Delete(ctx, a.manifest); err != nil {
			errs = append(errs, err)
			continue
		}
		_, err = s.db.Exec(ctx, `DELETE FROM log_archives WHERE tenant_id = $1 AND day = $2`, a.tenant, a.day)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// readManifest downloads a manifest; with sum its SHA-256 must match.
func readManifest(ctx context.Context, st blobStore, name, sum string) (logManifest, error) {
	var m logManifest
	rc, err := st.Get(ctx, name)
	if err != nil {
		return m, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
	if err != nil {
		return m, err
	}
	if h := sha256.Sum256(b); sum != "" && hex.EncodeToString(h[:]) != sum {
		return m, fmt.Errorf("%s: manifest checksum mismatch", name)
	}
	return m, json.Unmarshal(b, &m)
}

// restoreLogDay loads an archived day back into its partition, searchable
// for RestoreHours; tenant 0 restores every tenant of the day.
func (s *Server) restoreLogDay(ctx context.Context, actor string, day time.Time, tenant int64) (int64, error) {
	day = day.UTC().Truncate(24 * time.Hour)
	rows, err := s.db.Query(ctx, `SELECT tenant_id, target, manifest, sha256 FROM log_archives WHERE day = $1 AND ($2 = 0 OR tenant_id = $2) ORDER BY 1`, day, tenant)
	if err != nil {
		return 0, err
	}
	type row struct {
		tenant                int64
		target, manifest, sum string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var v row
		return v, r.Scan(&v.tenant, &v.target, &v.manifest, &v.sum)
	})
	if err != nil {
		return 0, err
	}
	if len(list) == 0 {
		return 0, &userError{http.StatusNotFound, "no archive for this day"}
	}
	if err := ensureLogPartitions(ctx, s.db, day, day); err != nil {
		return 0, err
	}
	hours := s.settings().Logs.withDefaults().RestoreHours
	if _, err := s.db.Exec(ctx, `INSERT INTO log_restores(day, until, restored_by) VALUES ($1, now() + make_interval(hours => $2), $3)
		ON CONFLICT (day) DO UPDATE SET until = EXCLUDED.until, restored_by = EXCLUDED.restored_by`, day, hours, actor); err != nil {
		return 0, err
	}
	dir, err := os.MkdirTemp("", "limdm-logs-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	var n int64
	for _, a := range list {
		st, err := s.logTarget(ctx, a.target)
		if err != nil {
			return n, err
		}
		man, err := readManifest(ctx, st, a.manifest, a.sum)
		if err != nil {
			return n, err
		}
		for _, o := range man.Objects {
			got, err := s.restoreObject(ctx, st, dir, a.tenant, o)
			n += got
			if err != nil {
				return n, fmt.Errorf("%s: %w", o.Name, err)
			}
		}
	}
	err = s.auditAction(ctx, actor, "logs.restore", day.Format(time.DateOnly), fmt.Sprintf("tenant=%d lines=%d hours=%d", tenant, n, hours), nil)
	return n, err
}

// restoreObject downloads, verifies, decrypts and inserts one object.
func (s *Server) restoreObject(ctx context.Context, st blobStore, dir string, tenant int64, o logObject) (int64, error) {
	rc, err := st.Get(ctx, o.Name)
	if err != nil {
		return 0, err
	}
	file := filepath.Join(dir, "object")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		rc.Close()
		return 0, err
	}
	defer f.Close()
	sum, size, err := hashReader(io.TeeReader(rc, f))
	rc.Close()
	if err != nil {
		return 0, err
	}
	if sum != o.SHA256 || size != o.Size {
		return 0, errors.New("checksum mismatch: the object was changed or damaged")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	plain, _, err := openLogArchive(f, func(id string) ([]byte, error) { return s.openLogKey(ctx, id) }, o.Name)
	if err != nil {
		return 0, err
	}
	zr, err := gzip.NewReader(plain)
	if err != nil {
		return 0, err
	}
	dec := json.NewDecoder(zr)
	var batch []logRecord
	var n int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := insertLogRecords(ctx, s.db, tenant, batch)
		n += int64(len(batch))
		batch = batch[:0]
		return err
	}
	for {
		var r logRecord
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			return n, err
		}
		batch = append(batch, r)
		if len(batch) == 1000 {
			if err := flush(); err != nil {
				return n, err
			}
		}
	}
	return n, flush()
}

// insertLogRecords inserts archived lines (duplicates are skipped).
func insertLogRecords(ctx context.Context, q execer, tenant int64, recs []logRecord) error {
	var (
		ats                                      []time.Time
		devices, sources, units, hosts, messages []string
		prios                                    []int16
		fields                                   []*string
		dedups                                   [][]byte
	)
	for _, r := range recs {
		d, err := hex.DecodeString(r.Dedup)
		if err != nil {
			return err
		}
		var f *string
		if len(r.Fields) > 0 && !bytes.Equal(r.Fields, []byte("null")) {
			v := string(r.Fields)
			f = &v
		}
		ats, devices, sources, units, hosts, messages = append(ats, r.At), append(devices, r.Device), append(sources, r.Source),
			append(units, r.Unit), append(hosts, r.Host), append(messages, r.Message)
		prios, fields, dedups = append(prios, r.Priority), append(fields, f), append(dedups, d)
	}
	_, err := q.Exec(ctx, `INSERT INTO device_logs(at, device_id, tenant_id, source, unit, priority, host, message, fields, dedup)
		SELECT u.at, u.device, $1, u.source, u.unit, u.priority, u.host, u.message, u.fields::jsonb, u.dedup
		FROM unnest($2::timestamptz[], $3::text[], $4::text[], $5::text[], $6::smallint[], $7::text[], $8::text[], $9::text[], $10::bytea[])
			u(at, device, source, unit, priority, host, message, fields, dedup)
		ON CONFLICT DO NOTHING`, tenant, ats, devices, sources, units, prios, hosts, messages, fields, dedups)
	return err
}

// ---- command line ----

const logsUsage = `usage: limdm-server logs [-env FILE] status | archive | restore -day YYYY-MM-DD [-tenant ID]`

// LogsCommand archives and restores logs from the command line
// (docs/logs.md#restore).
func LogsCommand(ctx context.Context, log *slog.Logger, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(logsUsage)
	}
	fs := flag.NewFlagSet("logs "+args[0], flag.ContinueOnError)
	day := fs.String("day", "", "day to restore (UTC), YYYY-MM-DD")
	tenant := fs.Int64("tenant", 0, "restore only this tenant (0: every tenant of the day)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := ConfigFromEnv()
	if err != nil {
		return err
	}
	s, err := OpenKeys(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer s.Close()
	actor := "cli:" + os.Getenv("USER")
	switch args[0] {
	case "status":
		rows, err := s.db.Query(ctx, `SELECT tenant_id, day, target, objects, lines, bytes, key_id, verified_at IS NOT NULL FROM log_archives ORDER BY day, tenant_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t, lines, size int64
			var d time.Time
			var target, key string
			var objects int
			var verified bool
			if err := rows.Scan(&t, &d, &target, &objects, &lines, &size, &key, &verified); err != nil {
				return err
			}
			fmt.Fprintf(out, "%s tenant=%d target=%s objects=%d lines=%d bytes=%d key=%s verified=%v\n", d.Format(time.DateOnly), t, target, objects, lines, size, key, verified)
		}
		return rows.Err()
	case "archive":
		set := s.settings().Logs.withDefaults()
		if !set.Archive {
			return errors.New("archiving is off (Settings, Logs)")
		}
		if err := s.archiveLogs(ctx, set, time.Now().UTC().Truncate(24*time.Hour)); err != nil {
			return err
		}
		fmt.Fprintln(out, "archive up to date")
		return nil
	case "restore":
		d, err := time.Parse(time.DateOnly, *day)
		if err != nil {
			return errors.New("restore needs -day YYYY-MM-DD")
		}
		n, err := s.restoreLogDay(ctx, actor, d, *tenant)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%d lines of %s restored\n", n, d.Format(time.DateOnly))
		return nil
	}
	return errors.New(logsUsage)
}
