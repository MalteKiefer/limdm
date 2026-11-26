package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Settings, Backup: targets, schedule, recipients and history (global
// admins only). Restores run on the command line (docs/backup.md).

type backupRow struct {
	ID                  int64
	Name, Reason, Actor string
	StartedAt           time.Time
	Size                int64
	SHA256              string
	Targets             []string
	Status, Error       string
	VerifiedAt          *time.Time
	VerifyError         string
	RestoreTestedAt     *time.Time
	RestoreTestError    string
	DeletedAt           *time.Time
}

// SizeMB is the archive size for the history table.
func (b backupRow) SizeMB() string { return fmt.Sprintf("%.1f MiB", float64(b.Size)/(1<<20)) }

// backupAdmin: backups hold every key and all data; only global admins see them.
func backupAdmin(sess session) bool { return sess.Role == "admin" && !sess.TenantOnly() }

func (s *Server) backupPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderBackup(w, r, sess, backupNotes[r.URL.Query().Get("done")], "")
}

var backupNotes = map[string]string{
	"saved":    "Settings saved and active.",
	"started":  "Backup started; the history shows the result in a few minutes.",
	"verified": "Checksum verification finished; see the history.",
	"deleted":  "Target removed. Archives on it are not deleted.",
}

func (s *Server) renderBackup(w http.ResponseWriter, r *http.Request, sess session, msg, errMsg string) {
	if !backupAdmin(sess) {
		s.errorPage(w, r, sess, http.StatusForbidden, "backups are managed by global administrators")
		return
	}
	ctx := r.Context()
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, err := s.db.Query(ctx, `SELECT id, name, reason, actor, started_at, size, sha256, targets, status, error, verified_at, verify_error,
		restore_tested_at, restore_test_error, deleted_at FROM backups ORDER BY started_at DESC LIMIT 50`)
	if err != nil {
		s.fail(w, err)
		return
	}
	history, err := pgx.CollectRows(rows, pgx.RowToStructByPos[backupRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	offsite, locked := false, false
	for _, t := range cfg.Targets {
		offsite = offsite || t.Kind != "local"
		locked = locked || t.LockMode != ""
	}
	s.render(w, r, sess, "backup", map[string]any{"Cfg": cfg, "History": history, "Tab": "backup", "Tabs": settingsTabLabels,
		"Rule321": len(cfg.Targets) >= 2 && offsite && locked, "Offsite": offsite, "Locked": locked,
		"Recipients": strings.Join(cfg.Recipients, "\n"), "Msg": msg, "Error": errMsg, "Test": r.Context().Value(testNoteKey{})})
}

type testNoteKey struct{}

// saveBackupConfig validates, stores and audits the configuration.
func (s *Server) saveBackupConfig(ctx context.Context, actor string, c BackupConfig, what string) error {
	if err := c.validate(); err != nil {
		return invalid(err)
	}
	doc, _ := json.Marshal(c)
	var targets []string
	for _, t := range c.Targets {
		targets = append(targets, t.Name+"("+t.Kind+")")
	}
	return s.auditAction(ctx, actor, "backup.settings", what, fmt.Sprintf("enabled=%v hour=%d recipients=%d gfs=%d/%d/%d targets=%v",
		c.Enabled, c.Hour, len(c.Recipients), c.Daily, c.Weekly, c.Monthly, targets), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('backup', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
}

func (s *Server) backupSave(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) {
		s.errorPage(w, r, sess, http.StatusForbidden, "backups are managed by global administrators")
		return
	}
	ctx := r.Context()
	c, err := s.backupConfig(ctx, s.db)
	if err != nil {
		s.fail(w, err)
		return
	}
	c.Enabled = r.FormValue("enabled") == "on"
	c.Hour, _ = strconv.Atoi(r.FormValue("hour"))
	c.Daily, _ = strconv.Atoi(r.FormValue("daily"))
	c.Weekly, _ = strconv.Atoi(r.FormValue("weekly"))
	c.Monthly, _ = strconv.Atoi(r.FormValue("monthly"))
	c.Recipients = strings.Fields(r.FormValue("recipients"))
	if err := s.saveBackupConfig(ctx, sess.Email, c, "schedule"); err != nil {
		s.renderBackup(w, r, sess, "", err.Error())
		return
	}
	http.Redirect(w, r, "/settings/backup?done=saved", http.StatusSeeOther)
}

// targetFromForm reads a target; empty secret fields keep the stored ones.
func (s *Server) targetFromForm(r *http.Request, name, kind string, prev *StoreTarget) (StoreTarget, error) {
	port, _ := strconv.Atoi(r.FormValue("port"))
	lockDays, _ := strconv.Atoi(r.FormValue("lock_days"))
	t := StoreTarget{Name: name, Kind: kind, Dir: strings.TrimSpace(r.FormValue("dir")),
		Endpoint: strings.TrimRight(strings.TrimSpace(r.FormValue("endpoint")), "/"), Region: strings.TrimSpace(r.FormValue("region")),
		Bucket: strings.TrimSpace(r.FormValue("bucket")), Prefix: strings.Trim(strings.TrimSpace(r.FormValue("prefix")), "/"),
		AccessKey: strings.TrimSpace(r.FormValue("access_key")), PathStyle: r.FormValue("path_style") == "on",
		LockMode: r.FormValue("lock_mode"), LockDays: lockDays,
		Host: strings.TrimSpace(r.FormValue("host")), Port: port, User: strings.TrimSpace(r.FormValue("user")), HostKey: strings.TrimSpace(r.FormValue("host_key"))}
	if t.LockMode == "" {
		t.LockDays = 0
	}
	if prev != nil && prev.Kind == kind {
		t.SecretEnc, t.KeyEnc = prev.SecretEnc, prev.KeyEnc
	}
	var err error
	if v := r.FormValue("secret"); v != "" {
		if t.SecretEnc, err = s.sealField("store."+name+".secret", v); err != nil {
			return t, err
		}
	}
	if v := strings.TrimSpace(r.FormValue("private_key")); v != "" {
		if t.KeyEnc, err = s.sealField("store."+name+".key", v+"\n"); err != nil {
			return t, err
		}
	}
	return t, t.validate()
}

func (s *Server) backupTargetSave(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) {
		s.errorPage(w, r, sess, http.StatusForbidden, "backups are managed by global administrators")
		return
	}
	ctx := r.Context()
	c, err := s.backupConfig(ctx, s.db)
	if err != nil {
		s.fail(w, err)
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	i := slices.IndexFunc(c.Targets, func(t StoreTarget) bool { return t.Name == name })
	var prev *StoreTarget
	if i >= 0 {
		prev = &c.Targets[i]
	}
	t, err := s.targetFromForm(r, name, r.FormValue("kind"), prev)
	if err != nil {
		s.renderBackup(w, r, sess, "", err.Error())
		return
	}
	if i >= 0 {
		c.Targets[i] = t
	} else {
		c.Targets = append(c.Targets, t)
	}
	if err := s.saveBackupConfig(ctx, sess.Email, c, "target "+name); err != nil {
		s.renderBackup(w, r, sess, "", err.Error())
		return
	}
	http.Redirect(w, r, "/settings/backup?done=saved", http.StatusSeeOther)
}

// backupTargetOp tests or removes a target.
func (s *Server) backupTargetOp(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) {
		s.errorPage(w, r, sess, http.StatusForbidden, "backups are managed by global administrators")
		return
	}
	ctx := r.Context()
	c, err := s.backupConfig(ctx, s.db)
	if err != nil {
		s.fail(w, err)
		return
	}
	name := r.PathValue("name")
	i := slices.IndexFunc(c.Targets, func(t StoreTarget) bool { return t.Name == name })
	if i < 0 {
		s.notFound(w, r, sess)
		return
	}
	switch r.PathValue("op") {
	case "test":
		tctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		st, err := s.openStore(c.Targets[i])
		note := ""
		if err == nil {
			note, err = testStore(tctx, st)
		}
		if err != nil {
			s.renderBackup(w, r, sess, "", name+": "+err.Error())
			return
		}
		s.renderBackup(w, r.WithContext(context.WithValue(ctx, testNoteKey{}, name+": "+note)), sess, "", "")
	case "delete":
		c.Targets = slices.Delete(c.Targets, i, i+1)
		if len(c.Targets) == 0 {
			c.Enabled = false
		}
		if err := s.saveBackupConfig(ctx, sess.Email, c, "target "+name+" removed"); err != nil {
			s.renderBackup(w, r, sess, "", err.Error())
			return
		}
		http.Redirect(w, r, "/settings/backup?done=deleted", http.StatusSeeOther)
	default:
		s.notFound(w, r, sess)
	}
}

func (s *Server) backupRunNow(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) {
		s.errorPage(w, r, sess, http.StatusForbidden, "backups are managed by global administrators")
		return
	}
	go func() { // minutes for large databases: the history shows the result
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		_, _ = s.runBackup(ctx, sess.Email, "manual")
	}()
	http.Redirect(w, r, "/settings/backup?done=started", http.StatusSeeOther)
}

func (s *Server) backupVerifyNow(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) {
		s.errorPage(w, r, sess, http.StatusForbidden, "backups are managed by global administrators")
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.verifyStored(r.Context(), id, sess.Email); err != nil {
		s.renderBackup(w, r, sess, "", err.Error())
		return
	}
	http.Redirect(w, r, "/settings/backup?done=verified", http.StatusSeeOther)
}
