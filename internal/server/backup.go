package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
)

// Backups (docs/backup.md). One run writes one archive: a tar with the
// database (a COPY export from one consistent snapshot), the CA directory
// (keys.json, the audit key files, certificates and the file keys) and the
// local package store, closed by manifest.json and its signature by the
// command key. The tar is compressed and encrypted with age to X25519
// recipients whose private keys never touch the server. LIMDM_SESSION_KEY
// is not in the archive: the manifest names it only by an identifier, it
// is kept separately (operations.md).

const (
	backupFormat   = 1
	lockBackup     = 7369 // one backup run at a time across instances
	backupSuffix   = ".lbk"
	manifestName   = "manifest.json"
	manifestSig    = "manifest.sig"
	manifestDomain = "limdm backup manifest v1\n"
)

// tables a backup leaves out: the instance registry and the record of
// applied schemas are rebuilt by every server start.
var backupSkip = []string{"server_instances", "schema_applied"}

// BackupConfig is the backup setup (settings key "backup").
type BackupConfig struct {
	Recipients []string         `json:"recipients"`          // age X25519 public keys (age1...)
	TimeZone   string           `json:"time_zone,omitempty"` // IANA name; empty: server local time
	Targets    []StoreTarget    `json:"targets"`
	Schedules  []BackupSchedule `json:"schedules"`
	// Keep is the retention of archives outside a schedule: manual runs,
	// runs after key rotations and before upgrades.
	Keep KeepRule `json:"keep"`

	// the single daily schedule of the first version; backupConfig turns it
	// into a schedule named daily
	Enabled bool `json:"enabled,omitempty"`
	Hour    int  `json:"hour,omitempty"`
	Daily   int  `json:"daily,omitempty"`
	Weekly  int  `json:"weekly,omitempty"`
	Monthly int  `json:"monthly,omitempty"`
}

func defaultBackupConfig() BackupConfig {
	return BackupConfig{Keep: KeepRule{Last: 3, Daily: 7, Weekly: 4, Monthly: 12}}
}

// location is the schedule time zone.
func (c BackupConfig) location() *time.Location {
	if loc, err := time.LoadLocation(c.TimeZone); err == nil && c.TimeZone != "" {
		return loc
	}
	return time.Local
}

func (c BackupConfig) validate() error {
	if c.TimeZone != "" {
		if _, err := time.LoadLocation(c.TimeZone); err != nil || c.TimeZone == "Local" {
			return fmt.Errorf("time zone %q: an IANA name such as Europe/Berlin, or empty for the server time", c.TimeZone)
		}
	}
	if len(c.Recipients) > 10 || len(c.Targets) > 10 || len(c.Schedules) > 20 {
		return errors.New("at most 10 recipients, 10 targets and 20 schedules")
	}
	if _, err := parseRecipients(c.Recipients); err != nil {
		return err
	}
	if err := c.Keep.validate(); err != nil {
		return fmt.Errorf("archives outside a schedule: %w", err)
	}
	names := map[string]bool{}
	for _, t := range c.Targets {
		if err := t.validate(); err != nil {
			return err
		}
		if names[t.Name] {
			return fmt.Errorf("target %q exists twice", t.Name)
		}
		names[t.Name] = true
	}
	scheds := map[string]bool{}
	active := false
	for _, sc := range c.Schedules {
		if err := sc.validate(c.Targets); err != nil {
			return fmt.Errorf("schedule %s: %w", sc.Name, err)
		}
		if scheds[sc.Name] {
			return fmt.Errorf("schedule %q exists twice", sc.Name)
		}
		scheds[sc.Name] = true
		active = active || !sc.Paused
	}
	if active && len(c.Recipients) == 0 {
		return errors.New("active schedules need at least one recipient")
	}
	return nil
}

func parseRecipients(list []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, r := range list {
		rec, err := age.ParseX25519Recipient(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("recipient %q: an age public key (age1...): %w", truncate(r, 20), err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func (s *Server) backupConfig(ctx context.Context, q querier) (BackupConfig, error) {
	c := defaultBackupConfig()
	var raw []byte
	err := q.QueryRow(ctx, `SELECT value FROM settings WHERE key='backup'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if c.Schedules == nil && (c.Enabled || c.Daily > 0) { // the first version's daily run
		var targets []string
		for _, t := range c.Targets {
			targets = append(targets, t.Name)
		}
		c.Schedules = []BackupSchedule{{Name: "daily", Paused: !c.Enabled || len(targets) == 0, Kind: "weekly", Days: []int{0, 1, 2, 3, 4, 5, 6},
			Times: []string{fmt.Sprintf("%02d:00", c.Hour)}, Targets: targets, Keep: KeepRule{Daily: max(c.Daily, 1), Weekly: c.Weekly, Monthly: c.Monthly}}}
	}
	c.Enabled, c.Hour, c.Daily, c.Weekly, c.Monthly = false, 0, 0, 0, 0
	return c, nil
}

// backupManifest describes an archive. It lists every other entry with its
// SHA-256 and is signed with the command key (manifest.sig).
type backupManifest struct {
	Format     int       `json:"format"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	Reason     string    `json:"reason"`
	Server     string    `json:"server_version"`
	SchemaHash string    `json:"schema_hash"`
	// Database is the format of db/: COPY text, one file per table, in
	// restore order (referenced tables first).
	Database  string            `json:"database"`
	Tables    []backupTable     `json:"tables"`
	Sequences map[string]int64  `json:"sequences"`
	Files     map[string]string `json:"files"` // archive path -> SHA-256 (hex)
	// Keys is keys.json: the active and retiring key generation of every
	// kind, so the archive is restored with the matching key files.
	Keys       map[string]keyState `json:"keys"`
	CommandKey string              `json:"command_key"` // Ed25519 public key (hex) that signed this manifest
	DeviceCA   string              `json:"device_ca"`   // fingerprint of the active device CA
	// SessionKeyID identifies the LIMDM_SESSION_KEY the sealed values in the
	// database need. The key itself is never in the archive.
	SessionKeyID string    `json:"session_key_id"`
	AuditHead    auditHead `json:"audit_head"`
}

type backupTable struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

type auditHead struct {
	ID   int64  `json:"id"`
	Hash string `json:"hash"`
}

// sessionKeyID derives a public identifier of a session key.
func sessionKeyID(key []byte) string {
	id, _ := hkdf.Key(sha256.New, key, nil, "limdm backup session key id v1", 8)
	return hex.EncodeToString(id)
}

// backupResult is one finished run.
type backupResult struct {
	Name    string
	Size    int64
	SHA256  string
	Targets []string // targets that hold the archive
	Errors  []string // per target failures
}

var hostToken = regexp.MustCompile(`[^a-z0-9.-]+`)

// backupName is limdm-<public host>-<UTC time>[-<schedule>].lbk.
func (s *Server) backupName(at time.Time, schedule string) string {
	host := "server"
	if u, err := url.Parse(s.cfg.PublicURL); err == nil && u.Hostname() != "" {
		host = hostToken.ReplaceAllString(strings.ToLower(u.Hostname()), "-")
	}
	name := "limdm-" + host + "-" + at.UTC().Format("20060102T150405Z")
	if schedule != "" {
		name += "-" + schedule
	}
	return name + backupSuffix
}

var backupNameRe = regexp.MustCompile(`^limdm-[a-z0-9.-]+-(\d{8}T\d{6}Z)(?:-([a-z0-9_]{1,32}))?\.lbk$`)

// backupTime reads the time and the schedule from an archive name.
func backupTime(name string) (time.Time, bool) {
	t, _, ok := parseBackupName(name)
	return t, ok
}

func parseBackupName(name string) (time.Time, string, bool) {
	m := backupNameRe.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, "", false
	}
	t, err := time.Parse("20060102T150405Z", m[1])
	return t, m[2], err == nil
}

// runBackup creates an archive, stores it on every target, prunes old
// archives (GFS), and records and audits the run. A failure notifies.
// schedule names the schedule whose targets get the archive; "" sends it
// to every target (manual, key rotation, upgrade).
func (s *Server) runBackup(ctx context.Context, actor, reason, schedule string) (backupResult, error) {
	res, err := s.backupOnce(ctx, reason, schedule)
	status, detail := "ok", fmt.Sprintf("%s reason=%q size=%d sha256=%s targets=%v", res.Name, reason, res.Size, res.SHA256, res.Targets)
	if err != nil {
		status, detail = "failed", fmt.Sprintf("%s reason=%q: %v", res.Name, reason, err)
	}
	keysHash, _ := s.keysHash()
	if _, dbErr := s.db.Exec(ctx, `INSERT INTO backups(name, reason, actor, size, sha256, targets, status, error, keys_hash, server_version, started_at, schedule)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), $11)`, res.Name, reason, actor, res.Size, res.SHA256, res.Targets, status, errText(err), keysHash, Version, schedule); dbErr != nil {
		s.log.Error("record backup", "err", dbErr)
	}
	action := "backup.create"
	if err != nil {
		action = "backup.fail"
	}
	if aErr := s.auditAction(context.WithoutCancel(ctx), actor, action, res.Name, detail, func(pgx.Tx) error { return nil }); aErr != nil {
		s.log.Error("audit backup", "err", aErr)
	}
	if err != nil {
		s.log.Error("backup failed", "err", err)
		backupFailures.Add(1)
		s.notify(notice{Type: "backup.failed", Severity: "critical", Title: "Backup failed",
			Text: "The backup run (" + reason + ") failed: " + truncate(err.Error(), 500), URL: s.cfg.PublicURL + "/settings/backup"})
		return res, err
	}
	if pErr := s.pruneBackups(ctx, actor); pErr != nil {
		s.log.Error("prune backups", "err", pErr)
	}
	return res, nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return truncate(err.Error(), 2000)
}

func (s *Server) backupOnce(ctx context.Context, reason, schedule string) (backupResult, error) {
	var res backupResult
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return res, err
	}
	recipients, err := parseRecipients(cfg.Recipients)
	if err != nil {
		return res, err
	}
	targets := cfg.Targets
	if schedule != "" {
		i := slices.IndexFunc(cfg.Schedules, func(sc BackupSchedule) bool { return sc.Name == schedule })
		if i < 0 {
			return res, fmt.Errorf("no schedule %q", schedule)
		}
		targets = slices.DeleteFunc(slices.Clone(targets), func(t StoreTarget) bool { return !slices.Contains(cfg.Schedules[i].Targets, t.Name) })
	}
	if len(recipients) == 0 || len(targets) == 0 {
		return res, errors.New("configure at least one age recipient and one target first (Settings, Backup)")
	}
	unlock, err := clusterLock(ctx, s.db, lockBackup, 5*time.Second)
	if err != nil {
		return res, fmt.Errorf("another backup is running: %w", err)
	}
	defer unlock()
	now := time.Now()
	res.Name = s.backupName(now, schedule)
	f, err := os.CreateTemp("", "limdm-backup-*"+backupSuffix)
	if err != nil {
		return res, fmt.Errorf("temporary file (set TMPDIR to a writable directory): %w", err)
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	n, err := s.writeArchive(ctx, io.MultiWriter(f, h), recipients, res.Name, reason, now)
	if err = errors.Join(err, f.Close()); err != nil {
		return res, err
	}
	res.Size, res.SHA256 = n, hex.EncodeToString(h.Sum(nil))
	for _, t := range targets {
		st, err := s.openStore(t)
		if err == nil {
			err = st.Put(ctx, res.Name, f.Name())
		}
		if err != nil {
			res.Errors = append(res.Errors, t.Name+": "+err.Error())
			continue
		}
		res.Targets = append(res.Targets, t.Name)
	}
	if len(res.Errors) > 0 {
		return res, errors.New(strings.Join(res.Errors, "; "))
	}
	return res, nil
}

// countWriter counts the bytes written through it.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// writeArchive writes the encrypted archive to w and returns its size.
func (s *Server) writeArchive(ctx context.Context, w io.Writer, recipients []age.Recipient, name, reason string, at time.Time) (int64, error) {
	cw := &countWriter{w: w}
	enc, err := age.Encrypt(cw, recipients...)
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(enc)
	tw := tar.NewWriter(gz)
	m := backupManifest{Format: backupFormat, Name: name, CreatedAt: at.UTC(), Reason: reason, Server: Version, SchemaHash: schemaHash(),
		Database: "copy-text-v1", Files: map[string]string{}, Sequences: map[string]int64{}, CommandKey: pubHex(s.cmdKey),
		SessionKeyID: sessionKeyID(s.cfg.SessionKey)}
	if s.ca != nil {
		m.DeviceCA = s.tlsCA().Fingerprint()
	}
	if m.Keys, err = readKeyStates(s.cfg.CADir); err != nil {
		return 0, err
	}
	if err := s.exportDatabase(ctx, tw, &m); err != nil {
		return 0, fmt.Errorf("database: %w", err)
	}
	if err := addDir(tw, &m, "ca", s.cfg.CADir, s.cfg.ReleaseDir); err != nil {
		return 0, fmt.Errorf("CA directory: %w", err)
	}
	if dir := s.localArtifactDir(ctx); dir != "" {
		if err := addDir(tw, &m, "artifacts", dir, ""); err != nil {
			return 0, fmt.Errorf("package store: %w", err)
		}
	}
	doc, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return 0, err
	}
	sig, err := signEd25519(s.cmdKey, append([]byte(manifestDomain), doc...))
	if err != nil {
		return 0, fmt.Errorf("sign manifest: %w", err)
	}
	if err := errors.Join(addBytes(tw, manifestName, doc), addBytes(tw, manifestSig, []byte(hex.EncodeToString(sig)))); err != nil {
		return 0, err
	}
	if err := errors.Join(tw.Close(), gz.Close(), enc.Close()); err != nil {
		return 0, err
	}
	return cw.n, nil
}

func addBytes(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// addFile copies a file into the archive and records its hash.
func addFile(tw *tar.Writer, m *backupManifest, name, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime()}); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tw, h), f); err != nil {
		return err
	}
	m.Files[name] = hex.EncodeToString(h.Sum(nil))
	return nil
}

// addDir adds the regular files below dir as prefix/..., without skip and
// without staged (*.tmp) files.
func addDir(tw *tar.Writer, m *backupManifest, prefix, dir, skip string) error {
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip != "" && filepath.Clean(p) == filepath.Clean(skip) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasSuffix(p, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		return addFile(tw, m, prefix+"/"+filepath.ToSlash(rel), p)
	})
}

// exportDatabase copies every table from one read only snapshot, in an
// order that loads referenced tables first.
func (s *Server) exportDatabase(ctx context.Context, tw *tar.Writer, m *backupManifest) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = 0`); err != nil {
		return err
	}
	if m.Tables, err = dbTables(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT sequencename, last_value FROM pg_sequences WHERE schemaname = current_schema() AND last_value IS NOT NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		var v int64
		if err := rows.Scan(&n, &v); err != nil {
			rows.Close()
			return err
		}
		m.Sequences[n] = v
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var hash []byte
	if err := tx.QueryRow(ctx, `SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&m.AuditHead.ID, &hash); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	m.AuditHead.Hash = hex.EncodeToString(hash)
	tmp, err := os.CreateTemp("", "limdm-table-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	for _, t := range m.Tables {
		if err := tmp.Truncate(0); err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		sql := `COPY (SELECT ` + columnList(t.Columns) + ` FROM ` + pgx.Identifier{t.Name}.Sanitize() + `) TO STDOUT`
		if _, err := tx.Conn().PgConn().CopyTo(ctx, tmp, sql); err != nil {
			return fmt.Errorf("%s: %w", t.Name, err)
		}
		if err := addFile(tw, m, "db/"+t.Name+".tsv", tmp.Name()); err != nil {
			return err
		}
	}
	return nil
}

func columnList(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = pgx.Identifier{c}.Sanitize()
	}
	return strings.Join(q, ", ")
}

// dbTables lists the tables of the schema with their columns, referenced
// tables before the tables that reference them.
func dbTables(ctx context.Context, q querier) ([]backupTable, error) {
	rows, err := q.Query(ctx, `SELECT c.relname, array_agg(a.attname::text ORDER BY a.attnum)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
		WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relispartition
		GROUP BY c.relname ORDER BY c.relname`)
	if err != nil {
		return nil, err
	}
	var all []backupTable
	for rows.Next() {
		var t backupTable
		if err := rows.Scan(&t.Name, &t.Columns); err != nil {
			rows.Close()
			return nil, err
		}
		if !slices.Contains(backupSkip, t.Name) {
			all = append(all, t)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT a.relname, b.relname FROM pg_constraint k
		JOIN pg_class a ON a.oid = k.conrelid JOIN pg_class b ON b.oid = k.confrelid
		JOIN pg_namespace n ON n.oid = a.relnamespace
		WHERE k.contype = 'f' AND n.nspname = current_schema() AND k.conrelid <> k.confrelid`)
	if err != nil {
		return nil, err
	}
	deps := map[string][]string{}
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			rows.Close()
			return nil, err
		}
		deps[from] = append(deps[from], to)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return orderTables(all, deps)
}

// orderTables sorts tables so every table follows those it references.
// References within one table need no order: COPY checks them at its end.
func orderTables(all []backupTable, deps map[string][]string) ([]backupTable, error) {
	byName := map[string]backupTable{}
	for _, t := range all {
		byName[t.Name] = t
	}
	done := map[string]bool{}
	var out []backupTable
	for len(out) < len(all) {
		progress := false
		for _, t := range all {
			if done[t.Name] {
				continue
			}
			ready := true
			for _, d := range deps[t.Name] {
				if _, known := byName[d]; known && !done[d] {
					ready = false
				}
			}
			if ready {
				done[t.Name], progress = true, true
				out = append(out, t)
			}
		}
		if !progress {
			return nil, errors.New("tables reference each other in a cycle")
		}
	}
	return out, nil
}

// keysHash identifies the key generations: keys.json and the audit key
// files. A change (rotation) triggers a backup.
func (s *Server) keysHash() (string, error) {
	h := sha256.New()
	for _, f := range []string{keysFile, auditKeysFile, auditKeyedFile} {
		b, err := os.ReadFile(filepath.Join(s.cfg.CADir, f))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		h.Write([]byte(f + "\x00"))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// pruneBackups deletes archives their retention rule no longer keeps, on
// every target: each schedule's archives by its rule, archives outside a
// schedule (or of a deleted one) by the general rule. An archive under
// Object Lock cannot be deleted before its lock ends; that is logged and
// retried at the next run.
func (s *Server) pruneBackups(ctx context.Context, actor string) error {
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return err
	}
	rules := map[string]KeepRule{}
	for _, sc := range cfg.Schedules {
		rules[sc.Name] = sc.Keep
	}
	loc, now := cfg.location(), time.Now()
	var errs []error
	for _, t := range cfg.Targets {
		st, err := s.openStore(t)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		list, err := st.List(ctx, "")
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Name, err))
			continue
		}
		type arch struct {
			name string
			at   time.Time
		}
		groups := map[string][]arch{}
		for _, o := range list {
			if at, sched, ok := parseBackupName(o.Name); ok {
				if _, known := rules[sched]; !known {
					sched = ""
				}
				groups[sched] = append(groups[sched], arch{o.Name, at})
			}
		}
		var deleted []string
		for sched, archives := range groups {
			rule, ok := rules[sched]
			if !ok {
				rule = cfg.Keep
			}
			slices.SortFunc(archives, func(a, b arch) int { return b.at.Compare(a.at) })
			times := make([]time.Time, len(archives))
			for i, a := range archives {
				times[i] = a.at
			}
			for i, keep := range keepArchives(times, rule, now, loc) {
				if keep {
					continue
				}
				if err := st.Delete(ctx, archives[i].name); err != nil {
					errs = append(errs, fmt.Errorf("%s: delete %s: %w", t.Name, archives[i].name, err))
					continue
				}
				deleted = append(deleted, archives[i].name)
			}
		}
		if len(deleted) > 0 {
			slices.Sort(deleted)
			if err := s.auditAction(ctx, actor, "backup.prune", t.Name, "deleted "+strings.Join(deleted, ", "), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE backups SET deleted_at=now() WHERE name = ANY($1) AND deleted_at IS NULL
					AND NOT EXISTS (SELECT 1 FROM unnest(targets) t WHERE t <> $2)`, deleted, t.Name)
				return err
			}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// verifyStored downloads an archive from each of its targets and compares
// its SHA-256 with the recorded one. It needs no private key: the content
// check (decryption, manifest, restore) is limdm-server backup verify and
// restore-test.
func (s *Server) verifyStored(ctx context.Context, id int64, actor string) error {
	var name, want string
	var targets []string
	if err := s.db.QueryRow(ctx, `SELECT name, sha256, targets FROM backups WHERE id=$1 AND status='ok'`, id).Scan(&name, &want, &targets); err != nil {
		return err
	}
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return err
	}
	var errs []string
	for _, t := range cfg.Targets {
		if !slices.Contains(targets, t.Name) {
			continue
		}
		err := func() error {
			st, err := s.openStore(t)
			if err != nil {
				return err
			}
			rc, err := st.Get(ctx, name)
			if err != nil {
				return err
			}
			defer rc.Close()
			h := sha256.New()
			if _, err := io.Copy(h, rc); err != nil {
				return err
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != want {
				return fmt.Errorf("checksum %s, expected %s", got[:12], want[:12])
			}
			return nil
		}()
		if err != nil {
			errs = append(errs, t.Name+": "+err.Error())
		}
	}
	verr := strings.Join(errs, "; ")
	action := "backup.verify"
	if verr != "" {
		action = "backup.verify_fail"
		s.notify(notice{Type: "backup.failed", Severity: "critical", Title: "Stored backup damaged or missing",
			Text: name + ": " + truncate(verr, 500), URL: s.cfg.PublicURL + "/settings/backup"})
	}
	return s.auditAction(ctx, actor, action, name, firstNonEmpty(verr, "checksum matches on "+strings.Join(targets, ", ")), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE backups SET verified_at=now(), verify_error=$2 WHERE id=$1`, id, verr)
		return err
	})
}

// backupLoop (leader) runs the daily backup, a backup after every key
// rotation, and a weekly checksum verification of the newest archive.
func (s *Server) backupLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		if err := s.backupTick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			s.log.Error("backup schedule", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) backupTick(ctx context.Context, now time.Time) error {
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return err
	}
	loc := cfg.location()
	for _, sc := range cfg.Schedules {
		if sc.Paused {
			continue
		}
		var lastOK, lastTry *time.Time
		if err := s.db.QueryRow(ctx, `SELECT (SELECT max(started_at) FROM backups WHERE schedule=$1 AND status='ok'),
			(SELECT max(started_at) FROM backups WHERE schedule=$1)`, sc.Name).Scan(&lastOK, &lastTry); err != nil {
			return err
		}
		base := sc.Since
		if lastOK != nil && lastOK.After(base) {
			base = *lastOK
		}
		if base.IsZero() {
			base = now.Add(-time.Minute) // created before Since existed: from now on
		}
		due := sc.next(base, loc)
		// a failed run is retried an hour later, not every five minutes
		if due.IsZero() || now.Before(due) || lastTry != nil && !lastTry.Before(due) && now.Sub(*lastTry) < time.Hour {
			continue
		}
		if _, err := s.runBackup(ctx, "system", "schedule "+sc.Name, sc.Name); err != nil {
			s.log.Error("scheduled backup", "schedule", sc.Name, "err", err)
		}
	}
	var lastKeys *string
	if err := s.db.QueryRow(ctx, `SELECT keys_hash FROM backups WHERE status='ok' ORDER BY started_at DESC LIMIT 1`).Scan(&lastKeys); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	keys, err := s.keysHash()
	if err != nil {
		return err
	}
	if lastKeys != nil && *lastKeys != keys && len(cfg.Recipients) > 0 && len(cfg.Targets) > 0 {
		var lastTry *time.Time
		if err := s.db.QueryRow(ctx, `SELECT max(started_at) FROM backups WHERE reason='key rotation'`).Scan(&lastTry); err != nil {
			return err
		}
		if lastTry == nil || now.Sub(*lastTry) > time.Hour {
			if _, err := s.runBackup(ctx, "system", "key rotation", ""); err != nil {
				return err
			}
		}
	}
	var id int64
	err = s.db.QueryRow(ctx, `SELECT id FROM backups WHERE status='ok' AND deleted_at IS NULL
		AND (verified_at IS NULL OR verified_at < now() - interval '7 days') AND started_at > now() - interval '2 days'
		ORDER BY started_at DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.verifyStored(ctx, id, "system")
}

// backupFailures counts failed runs of this process.
var backupFailures atomic.Int64

// backupMetrics adds the backup state to /metrics.
func (s *Server) backupMetrics(ctx context.Context, p *promWriter) error {
	var lastOK *time.Time
	var size int64
	var lastFailed bool
	if err := s.db.QueryRow(ctx, `SELECT (SELECT max(started_at) FROM backups WHERE status='ok'),
		coalesce((SELECT size FROM backups WHERE status='ok' ORDER BY started_at DESC LIMIT 1), 0),
		coalesce((SELECT status = 'failed' FROM backups ORDER BY started_at DESC LIMIT 1), false)`).Scan(&lastOK, &size, &lastFailed); err != nil {
		return err
	}
	if lastOK != nil {
		p.family("limdm_backup_last_success_timestamp_seconds", "gauge", "Start of the last successful backup run.")
		p.sample("limdm_backup_last_success_timestamp_seconds", float64(lastOK.Unix()))
	}
	p.family("limdm_backup_last_size_bytes", "gauge", "Size of the last successful backup archive.")
	p.sample("limdm_backup_last_size_bytes", float64(size))
	failed := 0.0
	if lastFailed {
		failed = 1
	}
	p.family("limdm_backup_last_run_failed", "gauge", "1 when the last backup run failed.")
	p.sample("limdm_backup_last_run_failed", failed)
	p.family("limdm_backup_failures_total", "counter", "Failed backup runs of this instance since its start.")
	p.sample("limdm_backup_failures_total", float64(backupFailures.Load()))
	return nil
}
