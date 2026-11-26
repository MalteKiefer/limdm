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
	"schedule": "Schedule saved.",
	"removed":  "Schedule deleted. Its archives now follow the retention for archives outside a schedule.",
}

// scheduleView is a schedule with its next runs and retention preview.
type scheduleView struct {
	BackupSchedule
	Describe string
	Next     []string
	Preview  retentionPreview
	Kept     []string
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
	loc, now := cfg.location(), time.Now()
	stamp := func(t time.Time) string { return t.In(loc).Format("Mon 2006-01-02 15:04 MST") }
	var views []scheduleView
	for _, sc := range cfg.Schedules {
		v := scheduleView{BackupSchedule: sc, Describe: sc.describe(), Preview: sc.preview(now, loc)}
		for _, t := range sc.nextRuns(now, loc, 5) {
			v.Next = append(v.Next, stamp(t))
		}
		for _, t := range v.Preview.Dates {
			v.Kept = append(v.Kept, t.In(loc).Format("2006-01-02 15:04"))
		}
		views = append(views, v)
	}
	edit := BackupSchedule{Kind: "weekly", Days: []int{1, 2, 3, 4, 5, 6, 0}, Times: []string{"02:00"}, Keep: KeepRule{Daily: 7, Weekly: 4, Monthly: 12}}
	if e, ok := r.Context().Value(editKey{}).(BackupSchedule); ok {
		edit = e
	} else if i := slices.IndexFunc(cfg.Schedules, func(sc BackupSchedule) bool { return sc.Name == r.URL.Query().Get("edit") }); i >= 0 {
		edit = cfg.Schedules[i]
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
		"Recipients": strings.Join(cfg.Recipients, "\n"), "Schedules": views, "Edit": edit, "EditTargets": editTargets(edit), "Zone": loc.String(),
		"Weekdays": []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}, "Msg": msg, "Error": errMsg, "Test": r.Context().Value(testNoteKey{})})
}

type (
	testNoteKey struct{}
	editKey     struct{} // a schedule form that failed validation, shown again
)

// saveBackupConfig validates, stores and audits the configuration.
func (s *Server) saveBackupConfig(ctx context.Context, actor string, c BackupConfig, what string) error {
	if err := c.validate(); err != nil {
		return invalid("backup", err)
	}
	doc, _ := json.Marshal(c)
	var targets []string
	for _, t := range c.Targets {
		targets = append(targets, t.Name+"("+t.Kind+")")
	}
	var scheds []string
	for _, sc := range c.Schedules {
		scheds = append(scheds, fmt.Sprintf("%s(%s paused=%v targets=%v keep=%+v)", sc.Name, sc.describe(), sc.Paused, sc.Targets, sc.Keep))
	}
	return s.auditAction(ctx, actor, "backup.settings", what, fmt.Sprintf("recipients=%d time_zone=%q keep=%+v targets=%v schedules=%v",
		len(c.Recipients), c.TimeZone, c.Keep, targets, scheds), func(tx pgx.Tx) error {
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
	c.Recipients = strings.Fields(r.FormValue("recipients"))
	c.TimeZone = strings.TrimSpace(r.FormValue("time_zone"))
	c.Keep = keepFromForm(r)
	if err := s.saveBackupConfig(ctx, sess.Email, c, "general"); err != nil {
		s.renderBackup(w, r, sess, "", err.Error())
		return
	}
	http.Redirect(w, r, "/settings/backup?done=saved", http.StatusSeeOther)
}

// targetFromForm reads a target; empty secret fields keep the stored ones
// as long as the target still points at the same server (a stored
// secret is never sent to a host it was not entered for).
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
	if prev != nil && prev.Kind == kind && prev.Endpoint == t.Endpoint && prev.Region == t.Region && prev.Host == t.Host && prev.Port == t.Port {
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
		for _, sc := range c.Schedules {
			if slices.Contains(sc.Targets, name) {
				s.renderBackup(w, r, sess, "", "Schedule "+sc.Name+" still uses this target; change the schedule first.")
				return
			}
		}
		c.Targets = slices.Delete(c.Targets, i, i+1)
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
		_, _ = s.runBackup(ctx, sess.Email, "manual", "")
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

func formInt(r *http.Request, name string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
	return n
}

func keepFromForm(r *http.Request) KeepRule {
	return KeepRule{Last: formInt(r, "keep_last"), Days: formInt(r, "keep_days"), Daily: formInt(r, "keep_daily"),
		Weekly: formInt(r, "keep_weekly"), Monthly: formInt(r, "keep_monthly"), Yearly: formInt(r, "keep_yearly")}
}

// backupScheduleSave creates or replaces a schedule.
func (s *Server) backupScheduleSave(w http.ResponseWriter, r *http.Request, sess session) {
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
	if err := r.ParseForm(); err != nil {
		s.fail(w, err)
		return
	}
	sc := BackupSchedule{Name: strings.ToLower(strings.TrimSpace(r.FormValue("name"))), Paused: r.FormValue("paused") == "on",
		Kind: r.FormValue("kind"), Every: formInt(r, "every"), Offset: formInt(r, "offset"), Day: formInt(r, "day"),
		Times: strings.FieldsFunc(r.FormValue("times"), func(c rune) bool { return c == ' ' || c == ',' || c == '\n' || c == '\r' }),
		Cron:  strings.Join(strings.Fields(r.FormValue("cron")), " "), Targets: r.Form["targets"], Keep: keepFromForm(r), Since: time.Now().UTC()}
	for _, d := range r.Form["days"] {
		n, _ := strconv.Atoi(d)
		sc.Days = append(sc.Days, n)
	}
	if i := slices.IndexFunc(c.Schedules, func(x BackupSchedule) bool { return x.Name == sc.Name }); i >= 0 {
		if !c.Schedules[i].Since.IsZero() {
			sc.Since = c.Schedules[i].Since // an edit does not run missed slots of the old timing again
		}
		c.Schedules[i] = sc
	} else {
		c.Schedules = append(c.Schedules, sc)
	}
	if err := s.saveBackupConfig(ctx, sess.Email, c, "schedule "+sc.Name); err != nil {
		s.renderBackup(w, r.WithContext(context.WithValue(ctx, editKey{}, sc)), sess, "", err.Error())
		return
	}
	http.Redirect(w, r, "/settings/backup?done=schedule", http.StatusSeeOther)
}

// backupScheduleOp runs, pauses, resumes or deletes a schedule.
func (s *Server) backupScheduleOp(w http.ResponseWriter, r *http.Request, sess session) {
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
	i := slices.IndexFunc(c.Schedules, func(x BackupSchedule) bool { return x.Name == name })
	if i < 0 {
		s.notFound(w, r, sess)
		return
	}
	done := "schedule"
	switch r.PathValue("op") {
	case "run":
		go func() {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Hour) // outlives the request
			defer cancel()
			_, _ = s.runBackup(rctx, sess.Email, "manual, schedule "+name, name)
		}()
		http.Redirect(w, r, "/settings/backup?done=started", http.StatusSeeOther)
		return
	case "pause":
		c.Schedules[i].Paused = true
	case "resume":
		c.Schedules[i].Paused = false
		c.Schedules[i].Since = time.Now().UTC() // no catching up on slots missed while paused
	case "delete":
		c.Schedules = slices.Delete(c.Schedules, i, i+1)
		done = "removed"
	default:
		s.notFound(w, r, sess)
		return
	}
	if err := s.saveBackupConfig(ctx, sess.Email, c, "schedule "+name+" "+r.PathValue("op")); err != nil {
		s.renderBackup(w, r, sess, "", err.Error())
		return
	}
	http.Redirect(w, r, "/settings/backup?done="+done, http.StatusSeeOther)
}

func editTargets(sc BackupSchedule) map[string]bool {
	m := map[string]bool{}
	for _, t := range sc.Targets {
		m[t] = true
	}
	return m
}
