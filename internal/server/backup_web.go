package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Settings, Backup: targets, schedule, recipients and history (global
// admins only). Restores run on the command line (docs/backup.md).

// backupAdmin: backups hold every key and all data; only global admins see them.
func backupAdmin(sess session) bool { return sess.Role == "admin" && !sess.TenantOnly() }

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
