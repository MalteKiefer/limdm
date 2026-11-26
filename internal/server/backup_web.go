package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
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
	err := s.saveBackupGeneral(r.Context(), sess, strings.Fields(r.FormValue("recipients")), r.FormValue("time_zone"), keepFromForm(r))
	s.backupDone(w, r, sess, "saved", err)
}

// backupDone answers a backup form: the error on the page or the note.
func (s *Server) backupDone(w http.ResponseWriter, r *http.Request, sess session, done string, err error) {
	var ue *userError
	switch {
	case errors.As(err, &ue) && ue.Status == http.StatusForbidden:
		s.errorPage(w, r, sess, ue.Status, ue.Msg)
	case errors.As(err, &ue) && ue.Status == http.StatusNotFound:
		s.notFound(w, r, sess)
	case err != nil:
		s.renderBackup(w, r, sess, "", err.Error())
	default:
		http.Redirect(w, r, "/settings/backup?done="+done, http.StatusSeeOther)
	}
}

var errBackupAdmin = &userError{http.StatusForbidden, "backups are managed by global administrators"}

// changeBackup loads the backup configuration, lets fn change it and
// stores it (audited as what). The console forms and the admin API call
// the functions below, which all go through here.
func (s *Server) changeBackup(ctx context.Context, sess session, what string, fn func(c *BackupConfig) error) error {
	if !backupAdmin(sess) {
		return errBackupAdmin
	}
	c, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return err
	}
	if err := fn(&c); err != nil {
		return err
	}
	return s.saveBackupConfig(ctx, sess.Email, c, what)
}

// saveBackupGeneral stores recipients, time zone and the retention of
// archives outside a schedule.
func (s *Server) saveBackupGeneral(ctx context.Context, sess session, recipients []string, tz string, keep KeepRule) error {
	return s.changeBackup(ctx, sess, "general", func(c *BackupConfig) error {
		c.Recipients, c.TimeZone, c.Keep = recipients, strings.TrimSpace(tz), keep
		return nil
	})
}

// targetInput is a target as a form or the API sends it, with new secrets
// in plain text (empty: keep the stored ones).
type targetInput struct {
	StoreTarget
	Secret     string `json:"secret,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

// targetFromForm reads a target from the console form.
func targetFromForm(r *http.Request) targetInput {
	port, _ := strconv.Atoi(r.FormValue("port"))
	lockDays, _ := strconv.Atoi(r.FormValue("lock_days"))
	return targetInput{StoreTarget: StoreTarget{Name: r.FormValue("name"), Kind: r.FormValue("kind"), Dir: r.FormValue("dir"),
		Endpoint: r.FormValue("endpoint"), Region: r.FormValue("region"), Bucket: r.FormValue("bucket"), Prefix: r.FormValue("prefix"),
		AccessKey: r.FormValue("access_key"), PathStyle: r.FormValue("path_style") == "on", LockMode: r.FormValue("lock_mode"), LockDays: lockDays,
		Host: r.FormValue("host"), Port: port, User: r.FormValue("user"), HostKey: r.FormValue("host_key")},
		Secret: r.FormValue("secret"), PrivateKey: r.FormValue("private_key")}
}

// target normalizes in; empty secret fields keep the stored ones as long
// as the target still points at the same server (a stored secret is never
// sent to a host it was not entered for).
func (s *Server) target(in targetInput, prev *StoreTarget) (StoreTarget, error) {
	t := in.StoreTarget
	t.Name = strings.ToLower(strings.TrimSpace(t.Name))
	t.Dir, t.Region, t.Bucket = strings.TrimSpace(t.Dir), strings.TrimSpace(t.Region), strings.TrimSpace(t.Bucket)
	t.Endpoint, t.Prefix = strings.TrimRight(strings.TrimSpace(t.Endpoint), "/"), strings.Trim(strings.TrimSpace(t.Prefix), "/")
	t.AccessKey, t.Host, t.User, t.HostKey = strings.TrimSpace(t.AccessKey), strings.TrimSpace(t.Host), strings.TrimSpace(t.User), strings.TrimSpace(t.HostKey)
	t.SecretEnc, t.KeyEnc = "", "" // never taken from the request
	if t.LockMode == "" {
		t.LockDays = 0
	}
	if prev != nil && prev.Kind == t.Kind && prev.Endpoint == t.Endpoint && prev.Region == t.Region && prev.Host == t.Host && prev.Port == t.Port {
		t.SecretEnc, t.KeyEnc = prev.SecretEnc, prev.KeyEnc
	}
	var err error
	if in.Secret != "" {
		if t.SecretEnc, err = s.sealField("store."+t.Name+".secret", in.Secret); err != nil {
			return t, err
		}
	}
	if v := strings.TrimSpace(in.PrivateKey); v != "" {
		if t.KeyEnc, err = s.sealField("store."+t.Name+".key", v+"\n"); err != nil {
			return t, err
		}
	}
	if err := t.validate(); err != nil {
		return t, invalid("target", err)
	}
	return t, nil
}

func (s *Server) backupTargetSave(w http.ResponseWriter, r *http.Request, sess session) {
	s.backupDone(w, r, sess, "saved", s.saveTarget(r.Context(), sess, targetFromForm(r)))
}

// saveTarget adds or replaces a backup target.
func (s *Server) saveTarget(ctx context.Context, sess session, in targetInput) error {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	return s.changeBackup(ctx, sess, "target "+name, func(c *BackupConfig) error {
		i := slices.IndexFunc(c.Targets, func(t StoreTarget) bool { return t.Name == name })
		var prev *StoreTarget
		if i >= 0 {
			prev = &c.Targets[i]
		}
		t, err := s.target(in, prev)
		if err != nil {
			return err
		}
		if i >= 0 {
			c.Targets[i] = t
		} else {
			c.Targets = append(c.Targets, t)
		}
		return nil
	})
}

// backupTargetOp tests or removes a target.
func (s *Server) backupTargetOp(w http.ResponseWriter, r *http.Request, sess session) {
	name := r.PathValue("name")
	switch r.PathValue("op") {
	case "test":
		note, err := s.testTarget(r.Context(), sess, name)
		if err != nil {
			s.backupDone(w, r, sess, "", err)
			return
		}
		s.renderBackup(w, r.WithContext(context.WithValue(r.Context(), testNoteKey{}, name+": "+note)), sess, "", "")
	case "delete":
		s.backupDone(w, r, sess, "deleted", s.deleteTarget(r.Context(), sess, name))
	default:
		s.notFound(w, r, sess)
	}
}

var errNoTarget = &userError{http.StatusNotFound, "backup target not found"}

// testTarget writes, reads and deletes a test object on a target.
func (s *Server) testTarget(ctx context.Context, sess session, name string) (string, error) {
	if !backupAdmin(sess) {
		return "", errBackupAdmin
	}
	c, err := s.backupConfig(ctx, s.db)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(c.Targets, func(t StoreTarget) bool { return t.Name == name })
	if i < 0 {
		return "", errNoTarget
	}
	tctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	st, err := s.openStore(c.Targets[i])
	note := ""
	if err == nil {
		note, err = testStore(tctx, st)
	}
	if err != nil {
		return "", &userError{http.StatusUnprocessableEntity, name + ": " + err.Error()}
	}
	return note, nil
}

// deleteTarget removes a target no schedule uses; its archives stay.
func (s *Server) deleteTarget(ctx context.Context, sess session, name string) error {
	return s.changeBackup(ctx, sess, "target "+name+" removed", func(c *BackupConfig) error {
		i := slices.IndexFunc(c.Targets, func(t StoreTarget) bool { return t.Name == name })
		if i < 0 {
			return errNoTarget
		}
		for _, sc := range c.Schedules {
			if slices.Contains(sc.Targets, name) {
				return &userError{http.StatusConflict, "Schedule " + sc.Name + " still uses this target; change the schedule first."}
			}
		}
		c.Targets = slices.Delete(c.Targets, i, i+1)
		return nil
	})
}

func (s *Server) backupRunNow(w http.ResponseWriter, r *http.Request, sess session) {
	s.backupDone(w, r, sess, "started", s.startBackup(sess, ""))
}

// startBackup runs a backup in the background (all targets, or those of
// a schedule); the history shows the result.
func (s *Server) startBackup(sess session, schedule string) error {
	if !backupAdmin(sess) {
		return errBackupAdmin
	}
	reason := "manual"
	if schedule != "" {
		reason = "manual, schedule " + schedule
	}
	go func() { // minutes for large databases: the history shows the result
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		_, _ = s.runBackup(ctx, sess.Email, reason, schedule)
	}()
	return nil
}

func (s *Server) backupVerifyNow(w http.ResponseWriter, r *http.Request, sess session) {
	if !backupAdmin(sess) {
		s.backupDone(w, r, sess, "", errBackupAdmin)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.backupDone(w, r, sess, "verified", s.verifyStored(r.Context(), id, sess.Email))
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
	if err := r.ParseForm(); err != nil {
		s.fail(w, err)
		return
	}
	sc := BackupSchedule{Name: r.FormValue("name"), Paused: r.FormValue("paused") == "on",
		Kind: r.FormValue("kind"), Every: formInt(r, "every"), Offset: formInt(r, "offset"), Day: formInt(r, "day"),
		Times: strings.FieldsFunc(r.FormValue("times"), func(c rune) bool { return c == ' ' || c == ',' || c == '\n' || c == '\r' }),
		Cron:  r.FormValue("cron"), Targets: r.Form["targets"], Keep: keepFromForm(r)}
	for _, d := range r.Form["days"] {
		n, _ := strconv.Atoi(d)
		sc.Days = append(sc.Days, n)
	}
	err := s.saveSchedule(r.Context(), sess, sc)
	if ue := (*userError)(nil); err != nil && !errors.As(err, &ue) {
		s.renderBackup(w, r.WithContext(context.WithValue(r.Context(), editKey{}, sc)), sess, "", err.Error())
		return
	}
	s.backupDone(w, r, sess, "schedule", err)
}

// saveSchedule creates or replaces a backup schedule.
func (s *Server) saveSchedule(ctx context.Context, sess session, sc BackupSchedule) error {
	sc.Name = strings.ToLower(strings.TrimSpace(sc.Name))
	sc.Cron = strings.Join(strings.Fields(sc.Cron), " ")
	sc.Since = time.Now().UTC()
	return s.changeBackup(ctx, sess, "schedule "+sc.Name, func(c *BackupConfig) error {
		if i := slices.IndexFunc(c.Schedules, func(x BackupSchedule) bool { return x.Name == sc.Name }); i >= 0 {
			if !c.Schedules[i].Since.IsZero() {
				sc.Since = c.Schedules[i].Since // an edit does not run missed slots of the old timing again
			}
			c.Schedules[i] = sc
		} else {
			c.Schedules = append(c.Schedules, sc)
		}
		return nil
	})
}

// backupScheduleOp runs, pauses, resumes or deletes a schedule.
func (s *Server) backupScheduleOp(w http.ResponseWriter, r *http.Request, sess session) {
	op := r.PathValue("op")
	done := map[string]string{"run": "started", "delete": "removed"}[op]
	s.backupDone(w, r, sess, cmp.Or(done, "schedule"), s.scheduleOp(r.Context(), sess, r.PathValue("name"), op))
}

// scheduleOp runs, pauses, resumes or deletes a schedule.
func (s *Server) scheduleOp(ctx context.Context, sess session, name, op string) error {
	if !slices.Contains([]string{"run", "pause", "resume", "delete"}, op) {
		return &userError{http.StatusNotFound, "not found"}
	}
	noSchedule := &userError{http.StatusNotFound, "backup schedule not found"}
	if op == "run" {
		if !backupAdmin(sess) {
			return errBackupAdmin
		}
		c, err := s.backupConfig(ctx, s.db)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(c.Schedules, func(x BackupSchedule) bool { return x.Name == name }) {
			return noSchedule
		}
		return s.startBackup(sess, name)
	}
	return s.changeBackup(ctx, sess, "schedule "+name+" "+op, func(c *BackupConfig) error {
		i := slices.IndexFunc(c.Schedules, func(x BackupSchedule) bool { return x.Name == name })
		if i < 0 {
			return noSchedule
		}
		switch op {
		case "pause":
			c.Schedules[i].Paused = true
		case "resume":
			c.Schedules[i].Paused = false
			c.Schedules[i].Since = time.Now().UTC() // no catching up on slots missed while paused
		case "delete":
			c.Schedules = slices.Delete(c.Schedules, i, i+1)
		}
		return nil
	})
}

func editTargets(sc BackupSchedule) map[string]bool {
	m := map[string]bool{}
	for _, t := range sc.Targets {
		m[t] = true
	}
	return m
}
