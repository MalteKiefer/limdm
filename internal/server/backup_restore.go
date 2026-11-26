package server

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// Reading, verifying and restoring archives (docs/backup.md).

// readArchive decrypts an archive and passes every data entry to fn (nil
// reads only). It checks every entry against the manifest and the manifest
// signature, and returns the manifest only when all of it holds.
func readArchive(r io.Reader, ids []age.Identity, fn func(name string, body io.Reader) error) (*backupManifest, error) {
	dec, err := age.Decrypt(r, ids...)
	if err != nil {
		return nil, fmt.Errorf("decrypt (wrong identity?): %w", err)
	}
	gz, err := gzip.NewReader(dec)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	seen := map[string]string{}
	var doc, sig []byte
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !validEntry(hdr.Name) {
			return nil, fmt.Errorf("archive: unexpected entry %q", hdr.Name)
		}
		switch hdr.Name {
		case manifestName:
			doc, err = io.ReadAll(io.LimitReader(tr, 64<<20))
		case manifestSig:
			sig, err = io.ReadAll(io.LimitReader(tr, 1024))
		default:
			if _, dup := seen[hdr.Name]; dup {
				return nil, fmt.Errorf("archive: %s twice", hdr.Name)
			}
			h := sha256.New()
			body := io.TeeReader(tr, h)
			if fn != nil {
				err = fn(hdr.Name, body)
			}
			if err == nil {
				_, err = io.Copy(io.Discard, body)
			}
			seen[hdr.Name] = hex.EncodeToString(h.Sum(nil))
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
	}
	if doc == nil || sig == nil {
		return nil, errors.New("archive: manifest or signature missing (incomplete archive?)")
	}
	var m backupManifest
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Format != backupFormat || m.Database != "copy-text-v1" {
		return nil, fmt.Errorf("archive format %d (%s) is not supported by this version", m.Format, m.Database)
	}
	pub, err := hex.DecodeString(m.CommandKey)
	rawSig, err2 := hex.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, append([]byte(manifestDomain), doc...), rawSig) {
		return nil, errors.New("manifest signature invalid")
	}
	for name, want := range m.Files {
		if got, ok := seen[name]; !ok || got != want {
			return nil, fmt.Errorf("%s: missing or changed", name)
		}
	}
	if len(seen) != len(m.Files) {
		return nil, errors.New("archive has entries the manifest does not list")
	}
	return &m, nil
}

var entryRe = regexp.MustCompile(`^(manifest\.json|manifest\.sig|db/[a-z0-9_]+\.tsv|(ca|artifacts)/[A-Za-z0-9._/-]+)$`)

func validEntry(name string) bool {
	return entryRe.MatchString(name) && path.Clean(name) == name && !strings.Contains(name, "..")
}

func readIdentities(file string) ([]age.Identity, error) {
	if file == "" {
		return nil, errors.New("-identity FILE (age private key) is required")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return age.ParseIdentities(f)
}

// openArchive opens a local file, or an archive by name on a target of the
// server configuration (from).
func openArchive(ctx context.Context, s *Server, from, name string) (io.ReadCloser, error) {
	if from == "" {
		return os.Open(name)
	}
	if s == nil {
		return nil, errors.New("-from needs the server database (use a local file on a new host)")
	}
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return nil, err
	}
	for _, t := range cfg.Targets {
		if t.Name == from {
			st, err := s.openStore(t)
			if err != nil {
				return nil, err
			}
			return st.Get(ctx, path.Base(name))
		}
	}
	return nil, fmt.Errorf("no target %q", from)
}

// restoreOptions control a restore.
type restoreOptions struct {
	DatabaseURL string
	CADir       string
	Force       bool
	Window      time.Duration
	SkipCA      bool // restore-test: CA files go to CADir, a temporary directory
}

// restoreArchive loads an archive into an empty database and CA directory.
// The database is replaced in one transaction: the tables of the archive
// are emptied and loaded with user triggers off (the append only guards of
// audit_log and device_events refuse truncation), sequences are set, and
// a restore window lets devices that renewed their certificate after the
// backup in again (deviceAuth, restoreRepin).
func restoreArchive(ctx context.Context, open func() (io.ReadCloser, error), ids []age.Identity, m *backupManifest, o restoreOptions) error {
	if err := ensureEmptyDir(o.CADir, o.Force); err != nil {
		return err
	}
	pc, err := pgxPoolConfig(o.DatabaseURL, 4)
	if err != nil {
		return err
	}
	db, err := newPool(ctx, pc)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := migrate(ctx, db); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	var used bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices) OR EXISTS(SELECT 1 FROM audit_log)`).Scan(&used); err != nil {
		return err
	}
	if used && !o.Force {
		return errors.New("the database already holds devices or audit entries; restore into a new, empty database (or -force)")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = 0`); err != nil {
		return err
	}
	current, err := dbTables(ctx, tx)
	if err != nil {
		return err
	}
	cols := map[string][]string{}
	for _, t := range current {
		cols[t.Name] = t.Columns
	}
	var names []string
	for _, t := range m.Tables {
		have, ok := cols[t.Name]
		if !ok {
			return fmt.Errorf("table %s of the backup does not exist in this version", t.Name)
		}
		for _, c := range t.Columns {
			if !slices.Contains(have, c) {
				return fmt.Errorf("column %s.%s of the backup does not exist in this version", t.Name, c)
			}
		}
		names = append(names, pgx.Identifier{t.Name}.Sanitize())
	}
	for _, n := range names {
		if _, err := tx.Exec(ctx, `ALTER TABLE `+n+` DISABLE TRIGGER USER`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `TRUNCATE `+strings.Join(names, ", ")+` CASCADE`); err != nil {
		return err
	}
	staged := o.CADir + ".restore"
	if err := os.RemoveAll(staged); err != nil {
		return err
	}
	// uploaded packages land next to the CA directory; nothing of a failed
	// or unverified restore stays behind, and staged is kept when only the
	// final move fails
	artDir := filepath.Join(filepath.Dir(o.CADir), "artifacts.restore")
	if !o.SkipCA {
		if err := os.RemoveAll(artDir); err != nil {
			return err
		}
	}
	committed, keep := false, false
	defer func() {
		if !keep {
			os.RemoveAll(staged)
		}
		if !committed && !o.SkipCA {
			os.RemoveAll(artDir)
		}
	}()
	byName := map[string]backupTable{}
	for _, t := range m.Tables {
		byName[t.Name] = t
	}
	rc, err := open()
	if err != nil {
		return err
	}
	defer rc.Close()
	m2, err := readArchive(rc, ids, func(name string, body io.Reader) error {
		dir, rest, _ := strings.Cut(name, "/")
		switch dir {
		case "db":
			t, ok := byName[strings.TrimSuffix(rest, ".tsv")]
			if !ok {
				return errors.New("table not in the manifest")
			}
			_, err := tx.Conn().PgConn().CopyFrom(ctx, body, `COPY `+pgx.Identifier{t.Name}.Sanitize()+` (`+columnList(t.Columns)+`) FROM STDIN`)
			return err
		case "ca":
			return writeStaged(filepath.Join(staged, filepath.FromSlash(rest)), body)
		case "artifacts":
			if o.SkipCA {
				return nil
			}
			// next to the CA directory; the operator moves them (docs/backup.md)
			return writeStaged(filepath.Join(artDir, filepath.FromSlash(rest)), body)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// the archive is opened twice: the second read must be the archive
	// whose signer and version were checked
	if !reflect.DeepEqual(m, m2) {
		return errors.New("the archive changed between verification and restore")
	}
	for seq, v := range m.Sequences {
		if _, err := tx.Exec(ctx, `SELECT setval(to_regclass($1), $2) WHERE to_regclass($1) IS NOT NULL`, pgx.Identifier{seq}.Sanitize(), v); err != nil {
			return fmt.Errorf("sequence %s: %w", seq, err)
		}
	}
	for _, n := range names {
		if _, err := tx.Exec(ctx, `ALTER TABLE `+n+` ENABLE TRIGGER USER`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO restore_state(one, backup_name, backup_at, restored_at, window_until) VALUES (true, $1, $2, now(), now() + make_interval(secs => $3))
		ON CONFLICT (one) DO UPDATE SET backup_name=EXCLUDED.backup_name, backup_at=EXCLUDED.backup_at, restored_at=now(), window_until=EXCLUDED.window_until`,
		m.Name, m.CreatedAt, o.Window.Seconds()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	if err := placeStaged(staged, o.CADir); err != nil {
		keep = true
		return fmt.Errorf("database restored, but moving the CA files into %s failed; they are in %s: %w", o.CADir, staged, err)
	}
	return nil
}

// ensureEmptyDir accepts a missing or empty directory (or any with force).
func ensureEmptyDir(dir string, force bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) || err == nil && (len(entries) == 0 || force) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%s is not empty; restore into an empty CA directory (or -force)", dir)
}

func writeStaged(dst string, body io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// placeStaged moves the verified files into dir (and the package store
// files next to it).
func placeStaged(staged, dir string) error {
	return filepath.WalkDir(staged, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(staged, p)
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return os.Rename(p, dst) //nolint:gosec // staged is our own new directory next to the CA directory
	})
}

// restoreRepin lets a device in whose certificate is newer than the
// restored backup: while the restore window is open, a certificate of our
// CA (verifyDevice checked the chain) issued after the backup becomes the
// device's pinned certificate. Retired and unknown devices stay out. Only
// a certificate that outlives the pinned one replaces it, so an older
// certificate of the same device (a stolen one, say) cannot take the pin
// back from the newest one.
func (s *Server) restoreRepin(ctx context.Context, id string, leaf *x509.Certificate) bool {
	var backupAt time.Time
	if err := s.db.QueryRow(ctx, `SELECT backup_at FROM restore_state WHERE window_until > now()`).Scan(&backupAt); err != nil {
		return false
	}
	// device certificates start five minutes before their issue (ca.go),
	// in whole seconds
	if leaf.NotBefore.Add(5 * time.Minute).Before(backupAt.Truncate(time.Second)) {
		return false
	}
	serial := leaf.SerialNumber.Text(16)
	err := s.auditAction(ctx, "device:"+id, "device.cert_repin", id,
		fmt.Sprintf("certificate %s issued %s, after the restored backup of %s, pinned during the restore window", serial, leaf.NotBefore.UTC().Format(time.RFC3339), backupAt.UTC().Format(time.RFC3339)),
		func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE devices SET cert_serial=$2, cert_not_after=$3, pending_serial=NULL, pending_not_after=NULL WHERE id=$1 AND NOT retired AND cert_not_after < $3`,
				id, serial, leaf.NotAfter)
			if err == nil && tag.RowsAffected() == 0 {
				err = pgx.ErrNoRows
			}
			return err
		})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.log.Error("pin renewed device certificate after restore", "device", id, "err", err)
	}
	return err == nil
}

// ---- replay after a restore ----

// replayEntry is an audit entry from an export or a syslog copy.
type replayEntry struct {
	ID                     int64
	Action, Target, Detail string
}

var (
	sdParamRe = regexp.MustCompile(`([a-z_]+)="((?:[^"\\]|\\.)*)"`)
	sdUnesc   = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\]`, `]`)
)

// parseReplay reads audit entries as JSON Lines (console export) or as
// RFC 5424 syslog messages the server forwarded (syslog.go).
func parseReplay(r io.Reader) ([]replayEntry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var out []replayEntry
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		switch {
		case len(line) == 0:
		case line[0] == '{':
			var l auditLine
			if err := json.Unmarshal(line, &l); err != nil {
				return nil, err
			}
			out = append(out, replayEntry{l.ID, l.Action, l.Target, l.Detail})
		default:
			i := bytes.Index(line, []byte("[limdm@32473 "))
			if i < 0 || !bytes.Contains(line[:i], []byte(" audit ")) {
				continue // device events and foreign lines
			}
			end := i
			for j := i; j < len(line); j++ { // the structured data ends at an unescaped ]
				if line[j] == '\\' {
					j++
					continue
				}
				if line[j] == ']' {
					end = j
					break
				}
			}
			e := replayEntry{Detail: strings.TrimSpace(string(line[min(end+1, len(line)):]))}
			for _, p := range sdParamRe.FindAllSubmatch(line[i:end], -1) {
				v := sdUnesc.Replace(string(p[2]))
				switch string(p[1]) {
				case "id":
					e.ID, _ = strconv.ParseInt(v, 10, 64)
				case "action":
					e.Action = v
				case "target":
					e.Target = v
				}
			}
			if e.ID != 0 {
				out = append(out, e)
			}
		}
	}
	return out, sc.Err()
}

// replay applies the revocations among entries written after the backup
// (id above the backup's audit head) and returns the entries it did not
// apply for a manual review.
func (s *Server) replay(ctx context.Context, actor string, head int64, entries []replayEntry) (applied int, manual []replayEntry, err error) {
	for _, e := range entries {
		if e.ID <= head {
			continue
		}
		var sql string
		var args []any
		switch e.Action {
		case "device.retire":
			sql, args = `UPDATE devices SET retired=true, cert_serial='', pending_serial=NULL WHERE id=$1 AND NOT retired`, []any{e.Target}
		case "device.delete":
			sql, args = `UPDATE devices SET retired=true, cert_serial='', pending_serial=NULL WHERE id=$1`, []any{e.Target}
		case "token.revoke":
			sql, args = `DELETE FROM enroll_tokens WHERE encode(token_hash, 'hex') LIKE $1 || '%' AND length($1) >= 12`, []any{e.Target}
		case "api_token.revoke":
			sql, args = `UPDATE api_tokens SET revoked_at=now() WHERE prefix=$1 AND revoked_at IS NULL`, []any{strings.TrimPrefix(e.Detail, "prefix=")}
		default:
			manual = append(manual, e)
			continue
		}
		if err := s.auditAction(ctx, actor, "backup.replay", e.Target, fmt.Sprintf("%s from audit entry #%d applied again after the restore", e.Action, e.ID), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			return applied, manual, err
		}
		applied++
	}
	return applied, manual, nil
}

// ---- command line ----

// BackupCommand runs limdm-server backup SUBCOMMAND (docs/backup.md).
func BackupCommand(ctx context.Context, log *slog.Logger, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(backupUsage)
	}
	fs := flag.NewFlagSet("backup "+args[0], flag.ContinueOnError)
	reason := fs.String("reason", "manual", "why this backup runs (create), e.g. upgrade")
	ifConfigured := fs.Bool("if-configured", false, "create: do nothing when no recipient or target is set (package upgrade hook)")
	from := fs.String("from", "", "target name: read the archive from this target instead of a local file")
	identity := fs.String("identity", "", "age identity file (private key) that decrypts the archive")
	cmdKey := fs.String("command-key", "", "expected command key (hex) that signed the manifest")
	dbURL := fs.String("db", "", "database URL to restore into (default LIMDM_DATABASE_URL; restore-test: a scratch database)")
	caDir := fs.String("ca", "", "CA directory to restore into (default LIMDM_CA_DIR)")
	force := fs.Bool("force", false, "restore into a database or CA directory that is not empty")
	window := fs.Duration("window", 7*24*time.Hour, "restore window: devices with a certificate newer than the backup may reconnect")
	replayFile := fs.String("replay", "", "audit export (JSON Lines) or syslog file: re-apply revocations after the backup")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, cfgErr := ConfigFromEnv()
	openServer := func() (*Server, error) {
		if cfgErr != nil {
			return nil, cfgErr
		}
		return OpenKeys(ctx, cfg, log)
	}
	actor := "cli:" + os.Getenv("USER")
	switch args[0] {
	case "create":
		s, err := openServer()
		if err != nil {
			return err
		}
		defer s.Close()
		if *ifConfigured {
			c, err := s.backupConfig(ctx, s.db)
			if err != nil {
				return err
			}
			if len(c.Recipients) == 0 || len(c.Targets) == 0 {
				fmt.Fprintln(out, "backups are not configured; nothing to do")
				return nil
			}
		}
		res, err := s.runBackup(ctx, actor, *reason, "")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: %d bytes, sha256 %s, stored on %s\n", res.Name, res.Size, res.SHA256, strings.Join(res.Targets, ", "))
		return nil
	case "list":
		s, err := openServer()
		if err != nil {
			return err
		}
		defer s.Close()
		return s.listBackups(ctx, *from, out)
	case "verify", "restore", "restore-test":
	default:
		return errors.New(backupUsage)
	}
	if fs.NArg() != 1 {
		return errors.New(backupUsage)
	}
	ids, err := readIdentities(*identity)
	if err != nil {
		return err
	}
	var s *Server
	if args[0] != "restore" || *from != "" {
		if s, err = openServer(); err != nil {
			return err
		}
		defer s.Close()
	}
	open := func() (io.ReadCloser, error) { return openArchive(ctx, s, *from, fs.Arg(0)) }
	rc, err := open()
	if err != nil {
		return err
	}
	m, err := readArchive(rc, ids, nil)
	rc.Close()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: created %s by server %s (%s), %d tables, %d files, audit head #%d\n",
		m.Name, m.CreatedAt.Format(time.RFC3339), m.Server, m.Reason, len(m.Tables), len(m.Files), m.AuditHead.ID)
	fmt.Fprintf(out, "manifest signed by command key %s\n", m.CommandKey)
	switch {
	case *cmdKey != "" && !strings.EqualFold(*cmdKey, m.CommandKey):
		return errors.New("the manifest is signed by another command key than -command-key")
	case *cmdKey != "":
		fmt.Fprintln(out, "signer matches -command-key")
	case s != nil && m.CommandKey == pubHex(s.cmdKey):
		fmt.Fprintln(out, "signer is the active command key of this server")
	case args[0] != "verify":
		// age recipients are public: anyone who can write to a target can
		// build an archive for them, only the signer proves who made it
		return errors.New("the signer is not pinned: pass -command-key with the command key from your records")
	default:
		fmt.Fprintln(out, "WARNING: signer not pinned; compare the key above with your records or pass -command-key")
	}
	if cfgErr == nil && sessionKeyID(cfg.SessionKey) != m.SessionKeyID && !slices.ContainsFunc(cfg.OldSessionKeys, func(k []byte) bool { return sessionKeyID(k) == m.SessionKeyID }) {
		fmt.Fprintf(out, "WARNING: LIMDM_SESSION_KEY is not the key of this backup (id %s): sealed values (recovery keys, secrets) will not open\n", m.SessionKeyID)
		if args[0] == "restore" && !*force {
			return errors.New("set the LIMDM_SESSION_KEY of the backup (kept separately) or pass -force")
		}
	}
	if api.NewerVersion(m.Server, Version) && Version != "dev" {
		return fmt.Errorf("the backup is from server %s, newer than this %s: restore with that version or newer", m.Server, Version)
	}
	switch args[0] {
	case "verify":
		fmt.Fprintln(out, "archive intact: every entry matches the signed manifest")
		if s != nil {
			_ = s.auditAction(ctx, actor, "backup.verify", m.Name, "decrypted and checked against the signed manifest", func(tx pgx.Tx) error { return nil })
		}
		return nil
	case "restore-test":
		return s.restoreTest(ctx, actor, open, ids, m, *dbURL, out)
	}
	// restore
	if cfgErr != nil {
		return fmt.Errorf("server environment: %w", cfgErr)
	}
	o := restoreOptions{DatabaseURL: firstNonEmpty(*dbURL, cfg.DatabaseURL), CADir: firstNonEmpty(*caDir, cfg.CADir), Force: *force, Window: *window}
	if o.Window < time.Hour || o.Window > 30*24*time.Hour {
		return errors.New("-window: 1h to 720h")
	}
	if err := restoreArchive(ctx, open, ids, m, o); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	cfg.DatabaseURL, cfg.CADir = o.DatabaseURL, o.CADir
	rs, err := OpenKeys(ctx, cfg, log)
	if err != nil {
		return fmt.Errorf("restored, but the server keys do not open: %w", err)
	}
	defer rs.Close()
	detail := fmt.Sprintf("%s from %s (server %s), restore window %s", m.Name, m.CreatedAt.Format(time.RFC3339), m.Server, o.Window)
	if err := rs.auditAction(ctx, actor, "backup.restore", m.Name, detail, func(pgx.Tx) error { return nil }); err != nil {
		return err
	}
	fmt.Fprintln(out, "restored:", detail)
	if *replayFile != "" {
		f, err := os.Open(*replayFile)
		if err != nil {
			return err
		}
		entries, err := parseReplay(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("replay: %w", err)
		}
		applied, manual, err := rs.replay(ctx, actor, m.AuditHead.ID, entries)
		if err != nil {
			return fmt.Errorf("replay: %w", err)
		}
		fmt.Fprintf(out, "replay: %d revocations applied again; review these %d later entries by hand:\n", applied, len(manual))
		for _, e := range manual {
			fmt.Fprintf(out, "  #%d %s %s %s\n", e.ID, e.Action, e.Target, truncate(e.Detail, 120))
		}
	}
	if dir := filepath.Join(filepath.Dir(o.CADir), "artifacts.restore"); dirExists(dir) {
		fmt.Fprintf(out, "uploaded packages restored to %s: move them into LIMDM_ARTIFACT_DIR\n", dir)
	}
	fmt.Fprintln(out, "next: start one instance, check /readyz and the audit chain, then open the agent port (docs/backup.md)")
	return nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

const backupUsage = `usage: limdm-server backup create [-reason TEXT] [-if-configured]
       limdm-server backup list [-from TARGET]
       limdm-server backup verify  -identity KEY [-from TARGET] [-command-key HEX] FILE
       limdm-server backup restore -identity KEY [-from TARGET] [-db URL] [-ca DIR] [-window 168h] [-replay FILE] [-force] FILE
       limdm-server backup restore-test -identity KEY [-from TARGET] [-db SCRATCH_URL] FILE`

func (s *Server) listBackups(ctx context.Context, from string, out io.Writer) error {
	if from != "" {
		cfg, err := s.backupConfig(ctx, s.db)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(cfg.Targets, func(t StoreTarget) bool { return t.Name == from })
		if i < 0 {
			return fmt.Errorf("no target %q", from)
		}
		st, err := s.openStore(cfg.Targets[i])
		if err != nil {
			return err
		}
		list, err := st.List(ctx, "")
		if err != nil {
			return err
		}
		storeSort(list)
		for _, o := range list {
			if _, ok := backupTime(o.Name); ok {
				fmt.Fprintf(out, "%s\t%d\t%s\n", o.Name, o.Size, o.Modified.UTC().Format(time.RFC3339))
			}
		}
		return nil
	}
	rows, err := s.db.Query(ctx, `SELECT started_at, name, status, size, array_to_string(targets, ','), reason FROM backups ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var at time.Time
		var name, status, targets, reason string
		var size int64
		if err := rows.Scan(&at, &name, &status, &size, &targets, &reason); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%d\t%s\t%s\n", at.UTC().Format(time.RFC3339), name, status, size, targets, reason)
	}
	return rows.Err()
}

// restoreTest restores an archive into a scratch database and a temporary
// CA directory, verifies the audit chain and that sealed values open, and
// records the result: the proof that backups can be restored (ISO 27001
// A.8.13). Without -db it creates and drops <database>_restore_test.
func (s *Server) restoreTest(ctx context.Context, actor string, open func() (io.ReadCloser, error), ids []age.Identity, m *backupManifest, scratch string, out io.Writer) error {
	created := ""
	if scratch == "" {
		pc, err := pgxpool.ParseConfig(s.cfg.DatabaseURL)
		if err != nil {
			return err
		}
		created = pc.ConnConfig.Database + "_restore_test"
		if _, err := s.db.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{created}.Sanitize()); err != nil {
			return fmt.Errorf("create %s (or pass -db with a scratch database): %w", created, err)
		}
		defer func() {
			if _, err := s.db.Exec(context.WithoutCancel(ctx), `DROP DATABASE IF EXISTS `+pgx.Identifier{created}.Sanitize()+` WITH (FORCE)`); err != nil {
				fmt.Fprintln(out, "drop scratch database:", err)
			}
		}()
		if scratch, err = withDatabase(s.cfg.DatabaseURL, created); err != nil {
			return err
		}
	}
	dir, err := os.MkdirTemp("", "limdm-restore-test-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ca := filepath.Join(dir, "ca")
	start := time.Now()
	if scratch == s.cfg.DatabaseURL {
		return errors.New("-db must name a scratch database, not the server database")
	}
	err = restoreArchive(ctx, open, ids, m, restoreOptions{DatabaseURL: scratch, CADir: ca, Window: time.Hour, SkipCA: true})
	var report string
	if err == nil {
		report, err = checkRestored(ctx, s.cfg, s.log, scratch, ca)
	}
	result := fmt.Sprintf("%s restored in %s: %s", m.Name, time.Since(start).Round(time.Second), report)
	action := "backup.restore_test"
	if err != nil {
		result, action = fmt.Sprintf("%s: %v", m.Name, err), "backup.restore_test_fail"
	}
	if aErr := s.auditAction(ctx, actor, action, m.Name, result, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE backups SET restore_tested_at=now(), restore_test_error=$2 WHERE name=$1`, m.Name, errText(err))
		return err
	}); aErr != nil {
		return errors.Join(err, aErr)
	}
	fmt.Fprintln(out, result)
	return err
}

// checkRestored opens a restored database with its restored keys and
// checks the audit chain and the sealed settings secret.
func checkRestored(ctx context.Context, cfg Config, log *slog.Logger, dbURL, caDir string) (string, error) {
	cfg.DatabaseURL, cfg.CADir = dbURL, caDir
	rs, err := OpenKeys(ctx, cfg, log)
	if err != nil {
		return "", fmt.Errorf("open restored keys: %w", err)
	}
	defer rs.Close()
	broken, err := rs.verifyAuditFrom(ctx, false)
	if err != nil {
		return "", err
	}
	if broken != 0 {
		return "", fmt.Errorf("audit chain broken at entry %d", broken)
	}
	var raw []byte
	if err := rs.db.QueryRow(ctx, `SELECT value FROM settings WHERE key='server'`).Scan(&raw); err == nil {
		var st storedSettings
		if err := json.Unmarshal(raw, &st); err != nil {
			return "", err
		}
		if _, err := rs.openField("settings.oidc_client_secret", st.SecretEnc); err != nil {
			return "", fmt.Errorf("sealed settings do not open with this LIMDM_SESSION_KEY: %w", err)
		}
	}
	var devices, entries int64
	if err := rs.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM devices), (SELECT count(*) FROM audit_log)`).Scan(&devices, &entries); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d devices, %d audit entries, chain intact, sealed values open", devices, entries), nil
}

// withDatabase returns the URL dsn with the database name replaced. A
// plain text replace also hits a user of the same name
// (postgres://limdm@host/limdm), so the URL is parsed.
func withDatabase(dsn, db string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", errors.New("cannot derive the scratch database URL; pass -db")
	}
	u.Path = "/" + db
	if q := u.Query(); q.Has("dbname") {
		q.Set("dbname", db)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}
