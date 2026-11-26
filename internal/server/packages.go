package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Package repository (docs/packages.md). Admins upload packages, scripts
// and files; the server keeps them content addressed per tenant in a local
// directory (LIMDM_ARTIFACT_DIR) or an S3 bucket. A com.limdm.artifacts
// library item references an upload by SHA-256 inside the signed payload;
// devices download it over the mTLS agent API (only uploads their own
// resolved declarations name) and check the hash before installing.

// PackageConfig is the package store setup (settings key "packages").
type PackageConfig struct {
	MaxUploadMB int          `json:"max_upload_mb"` // per file
	QuotaMB     int          `json:"quota_mb"`      // per tenant
	QuotaCount  int          `json:"quota_count"`   // per tenant
	S3          *StoreTarget `json:"s3,omitempty"`  // nil keeps uploads in LIMDM_ARTIFACT_DIR
}

func (c PackageConfig) validate() error {
	if c.MaxUploadMB < 1 || c.MaxUploadMB > 16384 || c.QuotaMB < 1 || c.QuotaMB > 10<<20 || c.QuotaCount < 1 || c.QuotaCount > 100000 {
		return errors.New("upload limit 1 to 16384 MiB, quota 1 MiB to 10 TiB and 1 to 100000 files")
	}
	if c.S3 != nil {
		if c.S3.Kind != "s3" {
			return errors.New("the package store is local or S3")
		}
		return c.S3.validate()
	}
	return nil
}

func (s *Server) packageConfig(ctx context.Context) (PackageConfig, error) {
	c := PackageConfig{MaxUploadMB: 512, QuotaMB: 20480, QuotaCount: 500}
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key='packages'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(raw, &c)
}

func artifactDir() string { return envOr("LIMDM_ARTIFACT_DIR", "/var/lib/limdm-server/artifacts") }

// localArtifactDir is the package store directory when uploads are kept
// locally, so backups include them; "" with S3 (or when unreadable).
func (s *Server) localArtifactDir(ctx context.Context) string {
	c, err := s.packageConfig(ctx)
	if err != nil || c.S3 != nil || !dirExists(artifactDir()) {
		return ""
	}
	return artifactDir()
}

func (s *Server) packageStore(ctx context.Context) (blobStore, string, error) {
	c, err := s.packageConfig(ctx)
	if err != nil {
		return nil, "", err
	}
	if c.S3 != nil {
		st, err := s.openStore(*c.S3)
		return st, "s3", err
	}
	return localStore{dir: artifactDir()}, "local", nil
}

func artifactObject(tenant int64, sha string) string {
	return fmt.Sprintf("t%d/sha256/%s/%s", tenant, sha[:2], sha)
}

func init() {
	for _, p := range []string{"GET /software/packages", "POST /software/packages", "POST /software/packages/{id}/delete"} {
		tenantRoutes[p] = true
	}
	typeInfo[api.TypeArtifacts] = struct{ Desc, Anchor string }{"Uploaded packages, scripts and files to install (Software, Packages).", "comlimdmartifacts-list"}
	typeLabels[api.TypeArtifacts] = "Uploaded packages"
	for k, v := range map[string]string{
		"artifact.upload": "Package uploaded", "artifact.delete": "Package deleted", "artifact.settings": "Package settings changed",
		"backup.create": "Backup created", "backup.fail": "Backup failed", "backup.prune": "Old backups deleted", "backup.settings": "Backup settings changed",
		"backup.verify": "Backup verified", "backup.verify_fail": "Backup verification failed", "backup.restore": "Backup restored",
		"backup.restore_test": "Restore test passed", "backup.restore_test_fail": "Restore test failed", "backup.replay": "Revocation applied again after restore",
		"device.cert_repin": "Device certificate pinned after restore",
	} {
		auditActions[k] = v
	}
}

// bodyLimit is the request size pageFor accepts: uploads get the package
// limit and more time, every other form 1 MiB.
func (s *Server) bodyLimit(w http.ResponseWriter, r *http.Request) int64 {
	if r.Pattern != "POST /software/packages" {
		return 1 << 20
	}
	c, err := s.packageConfig(r.Context())
	if err != nil {
		return 1 << 20
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(time.Hour))
	_ = rc.SetWriteDeadline(time.Now().Add(time.Hour))
	return int64(c.MaxUploadMB)<<20 + 1<<20
}

// artifactMagic checks the start of an upload against its kind.
func artifactMagic(kind string, head []byte) bool {
	switch kind {
	case "deb":
		return bytes.HasPrefix(head, []byte("!<arch>\ndebian"))
	case "rpm":
		return bytes.HasPrefix(head, []byte{0xed, 0xab, 0xee, 0xdb})
	case "apk":
		return bytes.HasPrefix(head, []byte{0x1f, 0x8b})
	case "pacman": // zstd or xz
		return bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}) || bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0})
	case "flatpak": // a GVariant single file bundle; checked by flatpak on the device
		return len(head) > 0
	case "script":
		return bytes.HasPrefix(head, []byte("#!"))
	case "file":
		return true
	}
	return false
}

var versionRe = regexp.MustCompile(`^[A-Za-z0-9._+:~-]{0,64}$`)

type artifactRow struct {
	ID                    int64
	Tenant                int64
	SHA256, Name, Version string
	Kind, Filename, Store string
	Size                  int64
	UploadedBy            string
	ApprovedBy            *string
	CreatedAt             time.Time
	Usage                 []string
}

// Snippet is the library payload that installs this upload.
func (a artifactRow) Snippet() string {
	b, _ := json.Marshal(api.Artifacts{Artifacts: []api.Artifact{{SHA256: a.SHA256, Name: a.Name, Kind: a.Kind, Size: a.Size}}})
	return string(b)
}

// packageNotes are the messages after a redirect, by key, so no free text
// travels in the URL.
var packageNotes = map[string]string{
	"uploaded": "Uploaded. Reference it in a library item of the type Uploaded packages.",
	"approval": "Uploaded. Another administrator approves it under Approvals before devices can install it.",
}

func (s *Server) packagesPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderPackages(w, r, sess, packageNotes[r.URL.Query().Get("done")], "")
}

func (s *Server) renderPackages(w http.ResponseWriter, r *http.Request, sess session, msg, errMsg string) {
	ctx := r.Context()
	tcond, targs := tenantCond(sess, "a.tenant_id", 0)
	icond, _ := tenantCond(sess, "i.tenant_id", 0) // same $1: only items the viewer may see
	rows, err := s.db.Query(ctx, `SELECT a.id, a.tenant_id, a.sha256, a.name, a.version, a.kind, a.filename, a.store, a.size, a.uploaded_by, a.approved_by, a.created_at,
		coalesce((SELECT array_agg(i.name ORDER BY i.name) FROM library_items i WHERE i.type = '`+api.TypeArtifacts+`' AND `+icond+`
			AND i.payload->'artifacts' @> jsonb_build_array(jsonb_build_object('sha256', a.sha256))), '{}')
		FROM artifacts a WHERE `+tcond+` ORDER BY a.name, a.created_at DESC`, targs...)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[artifactRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	cfg, err := s.packageConfig(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	var used int64
	for _, a := range list {
		if a.Tenant == ownerTenant(ctx) {
			used += a.Size
		}
	}
	s.render(w, r, sess, "packages", map[string]any{"Artifacts": list, "Cfg": cfg, "UsedMB": used >> 20, "Kinds": api.ArtifactKinds,
		"Tabs": softwareTabs, "Tab": "packages", "Msg": msg, "Error": errMsg, "Global": !sess.TenantOnly(), "FourEyes": s.settings().FourEyes,
		"Type": api.TypeArtifacts})
}

// packageUpload stores an upload: SHA-256 while copying, type and quota
// checks, then the store, the row and the audit entry. With four eyes on,
// the upload is usable only after another admin approved it.
func (s *Server) packageUpload(w http.ResponseWriter, r *http.Request, sess session) {
	if sess.Role != "admin" { // also checked by page; uploads install as root
		s.errorPage(w, r, sess, http.StatusForbidden, "your role cannot change this")
		return
	}
	ctx := r.Context()
	fail := func(msg string) { s.renderPackages(w, r, sess, "", msg) }
	cfg, err := s.packageConfig(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	name, version, kind := strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("version")), r.FormValue("kind")
	switch {
	case !api.ArtifactNameRe.MatchString(name):
		fail("Name: letters, digits and . _ + -, up to 100 characters.")
		return
	case !versionRe.MatchString(version):
		fail("Version: up to 64 characters without spaces.")
		return
	case !slices.Contains(api.ArtifactKinds, kind):
		fail("Choose the kind of the upload.")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail("Choose a file (at most the upload limit).")
		return
	}
	defer f.Close()
	tmp, err := os.CreateTemp("", "limdm-upload-*")
	if err != nil {
		s.fail(w, err)
		return
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	size, err := io.Copy(io.MultiWriter(tmp, h), io.MultiReader(bytes.NewReader(head), f))
	if err = errors.Join(err, tmp.Close()); err != nil {
		s.fail(w, err)
		return
	}
	if size == 0 || size > int64(cfg.MaxUploadMB)<<20 {
		fail(fmt.Sprintf("The file is empty or larger than the upload limit of %d MiB.", cfg.MaxUploadMB))
		return
	}
	if !artifactMagic(kind, head) {
		fail("The file content does not match the chosen kind.")
		return
	}
	sha := hex.EncodeToString(h.Sum(nil))
	tenant := ownerTenant(ctx)
	st, store, err := s.packageStore(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	var usedBytes, count int64
	if err := s.db.QueryRow(ctx, `SELECT coalesce(sum(size), 0), count(*) FROM artifacts WHERE tenant_id=$1`, tenant).Scan(&usedBytes, &count); err != nil {
		s.fail(w, err)
		return
	}
	if usedBytes+size > int64(cfg.QuotaMB)<<20 || count+1 > int64(cfg.QuotaCount) {
		fail(fmt.Sprintf("The package quota of this tenant (%d MiB, %d files) would be exceeded.", cfg.QuotaMB, cfg.QuotaCount))
		return
	}
	var exists string
	if err := s.db.QueryRow(ctx, `SELECT name FROM artifacts WHERE tenant_id=$1 AND sha256=$2`, tenant, sha).Scan(&exists); err == nil {
		fail("This file was uploaded already as " + exists + ".")
		return
	}
	if err := st.Put(ctx, artifactObject(tenant, sha), tmp.Name()); err != nil {
		s.fail(w, fmt.Errorf("package store: %w", err))
		return
	}
	var approver *string
	if !s.settings().FourEyes {
		approver = &sess.Email
	}
	filename := filepath.Base(hdr.Filename)
	detail := fmt.Sprintf("%s %s kind=%s size=%d sha256=%s file=%q", name, version, kind, size, sha, truncate(filename, 200))
	errQuota := errors.New("quota")
	err = s.auditAction(ctx, sess.Email, "artifact.upload", sha, detail, func(tx pgx.Tx) error {
		// the check above runs before the slow store write; parallel
		// uploads of a tenant are counted again here, one at a time
		// (two key lock space, apart from the cluster locks)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7371, $1::int)`, tenant); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(size), 0), count(*) FROM artifacts WHERE tenant_id=$1`, tenant).Scan(&usedBytes, &count); err != nil {
			return err
		}
		if usedBytes+size > int64(cfg.QuotaMB)<<20 || count+1 > int64(cfg.QuotaCount) {
			return errQuota
		}
		_, err := tx.Exec(ctx, `INSERT INTO artifacts(tenant_id, sha256, name, version, kind, filename, size, store, uploaded_by, approved_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, tenant, sha, name, version, kind, truncate(filename, 200), size, store, sess.Email, approver)
		return err
	})
	if errors.Is(err, errQuota) {
		fail(fmt.Sprintf("The package quota of this tenant (%d MiB, %d files) would be exceeded.", cfg.QuotaMB, cfg.QuotaCount))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	done := "uploaded"
	if approver == nil {
		if _, err := s.requestApproval(ctx, sess, "artifact.upload", sha, map[string]any{"tenant": tenant, "name": name, "kind": kind}, r.FormValue("reason")); err != nil {
			s.fail(w, err)
			return
		}
		done = "approval"
	}
	http.Redirect(w, r, "/software/packages?done="+done, http.StatusSeeOther)
}

// packageDelete removes an upload no library item references.
func (s *Server) packageDelete(w http.ResponseWriter, r *http.Request, sess session) {
	if sess.Role != "admin" { // also checked by page; tenantCond below limits to own artifacts
		s.errorPage(w, r, sess, http.StatusForbidden, "your role cannot change this")
		return
	}
	ctx := r.Context()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tcond, targs := tenantCond(sess, "tenant_id", 1)
	var tenant int64
	var sha, name string
	if err := s.db.QueryRow(ctx, `SELECT tenant_id, sha256, name FROM artifacts WHERE id=$1 AND `+tcond, append([]any{id}, targs...)...).Scan(&tenant, &sha, &name); err != nil {
		s.notFound(w, r, sess)
		return
	}
	var users []string
	if err := s.db.QueryRow(ctx, `SELECT coalesce(array_agg(name), '{}') FROM library_items WHERE type=$1 AND (tenant_id=$2 OR $2=1)
		AND payload->'artifacts' @> jsonb_build_array(jsonb_build_object('sha256', $3::text))`, api.TypeArtifacts, tenant, sha).Scan(&users); err != nil {
		s.fail(w, err)
		return
	}
	if len(users) > 0 {
		s.renderPackages(w, r, sess, "", "Still used by: "+strings.Join(users, ", ")+". Remove it from these library items first.")
		return
	}
	if err := s.auditAction(ctx, sess.Email, "artifact.delete", sha, name, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM artifacts WHERE id=$1`, id)
		return err
	}); err != nil {
		s.fail(w, err)
		return
	}
	if st, _, err := s.packageStore(ctx); err == nil {
		if err := st.Delete(ctx, artifactObject(tenant, sha)); err != nil {
			s.log.Error("delete package file", "sha256", sha, "err", err)
		}
	}
	http.Redirect(w, r, "/software/packages", http.StatusSeeOther)
}

// packagesSettings saves the limits and the store (global admins).
func (s *Server) packagesSettings(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) { // the store and its credentials serve every tenant
		s.errorPage(w, r, sess, http.StatusForbidden, "the package store is managed by global administrators")
		return
	}
	ctx := r.Context()
	cur, err := s.packageConfig(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	c := cur
	c.MaxUploadMB, _ = strconv.Atoi(r.FormValue("max_upload_mb"))
	c.QuotaMB, _ = strconv.Atoi(r.FormValue("quota_mb"))
	c.QuotaCount, _ = strconv.Atoi(r.FormValue("quota_count"))
	if r.FormValue("store") == "s3" {
		in := targetFromForm(r)
		in.Name, in.Kind = "packages", "s3"
		t, err := s.target(in, cur.S3)
		if err != nil {
			s.renderPackages(w, r, sess, "", err.Error())
			return
		}
		c.S3 = &t
	} else {
		c.S3 = nil
	}
	if err := c.validate(); err != nil {
		s.renderPackages(w, r, sess, "", err.Error())
		return
	}
	moved := (cur.S3 == nil) != (c.S3 == nil) || cur.S3 != nil && c.S3 != nil &&
		(cur.S3.Endpoint != c.S3.Endpoint || cur.S3.Region != c.S3.Region || cur.S3.Bucket != c.S3.Bucket || cur.S3.Prefix != c.S3.Prefix)
	if moved {
		var n int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM artifacts`).Scan(&n); err != nil {
			s.fail(w, err)
			return
		}
		if n > 0 {
			s.renderPackages(w, r, sess, "", "Delete the uploads or move them to the new store before switching it (docs/packages.md).")
			return
		}
	}
	doc, _ := json.Marshal(c)
	if err := s.auditAction(ctx, sess.Email, "artifact.settings", "packages", fmt.Sprintf("max_upload_mb=%d quota_mb=%d quota_count=%d s3=%v",
		c.MaxUploadMB, c.QuotaMB, c.QuotaCount, c.S3 != nil), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('packages', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	}); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/software/packages", http.StatusSeeOther)
}

// checkArtifactRefs: every upload a library item references exists in the
// item's tenant, is approved and matches kind and size.
func (s *Server) checkArtifactRefs(ctx context.Context, it *api.LibraryItem) error {
	if it.Type != api.TypeArtifacts {
		return nil
	}
	var v api.Artifacts
	if err := json.Unmarshal(it.Payload, &v); err != nil {
		return err
	}
	tenant := ownerTenant(ctx)
	if it.ID > 0 {
		if err := s.db.QueryRow(ctx, `SELECT tenant_id FROM library_items WHERE id=$1`, it.ID).Scan(&tenant); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	for _, a := range v.Artifacts {
		var kind string
		var size int64
		var approved bool
		err := s.db.QueryRow(ctx, `SELECT kind, size, approved_by IS NOT NULL FROM artifacts WHERE tenant_id=$1 AND sha256=$2`, tenant, a.SHA256).Scan(&kind, &size, &approved)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("artifact %q: no upload with this SHA-256 in this tenant (Software, Packages)", a.Name)
		case err != nil:
			return err
		case !approved:
			return fmt.Errorf("artifact %q: the upload waits for its four eyes approval", a.Name)
		case kind != a.Kind || size != a.Size:
			return fmt.Errorf("artifact %q: kind and size must be %s and %d as uploaded", a.Name, kind, size)
		}
	}
	return nil
}

// agentArtifact serves an upload to a device whose resolved declarations
// reference it (mTLS, deviceAuth). Local files support ranges.
func (s *Server) agentArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sha := r.PathValue("sha")
	device, _ := ctx.Value(deviceKey).(string)
	if len(sha) != 64 || strings.Trim(sha, "0123456789abcdef") != "" {
		http.NotFound(w, r)
		return
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		s.failAPI(w, err)
		return
	}
	defer tx.Rollback(ctx)
	res, err := resolveDevice(ctx, tx, device)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	declared := false
	for _, d := range res.Decls {
		var v api.Artifacts
		if d.Type == api.TypeArtifacts && json.Unmarshal(d.Payload, &v) == nil &&
			slices.ContainsFunc(v.Artifacts, func(a api.Artifact) bool { return a.SHA256 == sha }) {
			declared = true
		}
	}
	var tenant, size int64
	var store string
	if declared {
		err = tx.QueryRow(ctx, `SELECT tenant_id, size, store FROM artifacts WHERE sha256=$1 AND approved_by IS NOT NULL
			AND tenant_id IN (1, (SELECT tenant_id FROM devices WHERE id=$2)) ORDER BY tenant_id DESC LIMIT 1`, sha, device).Scan(&tenant, &size, &store)
	}
	if !declared || err != nil {
		http.NotFound(w, r)
		return
	}
	tx.Rollback(ctx)
	w.Header().Set("Content-Type", "application/octet-stream")
	if store == "local" {
		http.ServeFile(w, r, filepath.Join(artifactDir(), filepath.FromSlash(artifactObject(tenant, sha))))
		return
	}
	st, _, err := s.packageStore(ctx)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	rc, err := st.Get(ctx, artifactObject(tenant, sha))
	if err != nil {
		s.failAPI(w, err)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	_, _ = io.Copy(w, rc)
}
