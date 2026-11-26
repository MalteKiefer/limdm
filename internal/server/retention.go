package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Retention: the hourly history job deletes data older than the period set
// per data type in the settings (retentionKinds, docs/retention.md).
// audit_log and device_events refuse deletes unless the transaction sets
// limdm.retention (schema.sql), which only this file does. The latest
// protective commands (lock, lost mode, wipe) and the latest compliance
// change per device and check always stay.

// retentionKind is a data type with its default period and bounds in days.
// Forever allows 0 (keep everything); Hint names the legal reasoning shown
// next to the field.
type retentionKind struct {
	Key, Label, Hint  string
	Default, Min, Max int
	Forever           bool
}

var retentionKinds = []retentionKind{
	{"audit", "Audit log", "Proof of administrative actions (ISO 27001 A.5.33, A.8.15). Three years covers a certification cycle; longer only with a documented reason (GDPR Art. 5(1)(e)).", 1095, 365, 36500, true},
	{"device_events", "Device events", "Operational logs with user and host names: keep as short as troubleshooting and incident review allow (GDPR Art. 5(1)(e), works council agreements).", 365, 30, 3650, false},
	{"compliance", "Compliance history", "Evidence of the compliance state for audits (ISO 27001 A.5.36); the latest change per device and check always stays.", 1095, 90, 3650, false},
	{"commands", "Finished commands", "Who did what on which device; the latest lock, lost mode and wipe stay regardless.", 180, 30, 3650, false},
	{"script_results", "Script results", "Script output can contain personal data; besides the period at most 200 results per device are kept.", 90, 7, 3650, false},
	{"diagnostics", "Diagnostics bundles", "Logs with user and host names; besides the period at most 10 bundles per device are kept.", 30, 1, 365, false},
	{"shell_transcripts", "Remote shell transcripts", "Screen output of support sessions: subject to co-determination (BetrVG section 87(1) no. 6); keep short.", 90, 7, 3650, false},
	{"metrics", "Device metrics", "Performance samples for the device charts.", 30, 1, 365, false},
	{"notification_log", "Notification log", "Delivery results of notification channels, for troubleshooting.", 30, 7, 365, false},
}

// retentionDays is the period of a data type: the saved value, the legacy
// audit setting, or the default.
func (set Settings) retentionDays(key string) int {
	if d, ok := set.Retention[key]; ok {
		return d
	}
	if key == "audit" && set.AuditRetentionDays != 0 {
		return set.AuditRetentionDays
	}
	for _, k := range retentionKinds {
		if k.Key == key {
			return k.Default
		}
	}
	return 0
}

// validRetention checks every period against its bounds.
func validRetention(m map[string]int) error {
	for key, d := range m {
		i := slices.IndexFunc(retentionKinds, func(k retentionKind) bool { return k.Key == key })
		if i < 0 {
			return fmt.Errorf("retention: unknown data type %q", key)
		}
		k := retentionKinds[i]
		if (d != 0 || !k.Forever) && (d < k.Min || d > k.Max) {
			return fmt.Errorf("retention of %s: %d to %d days", strings.ToLower(k.Label), k.Min, k.Max)
		}
	}
	return nil
}

// retentionRow is one line of the retention form.
type retentionRow struct {
	retentionKind
	Days int
}

func retentionRows(set Settings) []retentionRow {
	out := make([]retentionRow, len(retentionKinds))
	for i, k := range retentionKinds {
		out[i] = retentionRow{k, set.retentionDays(k.Key)}
	}
	return out
}

func (s *Server) prune(ctx context.Context) error {
	set := s.settings()
	d := set.retentionDays
	// whole days are dropped by metricPartitions; this removes the rest
	if _, err := s.db.Exec(ctx, `DELETE FROM device_metrics WHERE at < now() - make_interval(days => $1)`, d("metrics")); err != nil {
		return err
	}
	for _, q := range []struct {
		sql  string
		days int
	}{
		{`DELETE FROM fleet_history WHERE day < current_date - 400`, 0},
		{`DELETE FROM commands WHERE status IN ('ok', 'failed', 'expired') AND updated_at < now() - make_interval(days => $1)
			AND type NOT IN ('lock', 'unlock', 'lost', 'found', 'wipe')`, d("commands")},
		{`DELETE FROM compliance_changes c WHERE c.at < now() - make_interval(days => $1) AND EXISTS (SELECT 1 FROM compliance_changes n
			WHERE n.device_id = c.device_id AND n.check_id = c.check_id AND n.id > c.id AND n.at < now() - make_interval(days => $1))`, d("compliance")},
		{`DELETE FROM script_results WHERE received_at < now() - make_interval(days => $1)`, d("script_results")},
		{`DELETE FROM diagnostics WHERE created_at < now() - make_interval(days => $1)`, d("diagnostics")},
		{`DELETE FROM shell_sessions WHERE created_at < now() - make_interval(days => $1)`, d("shell_transcripts")},
		{`DELETE FROM notification_log WHERE at < now() - make_interval(days => $1)`, d("notification_log")},
	} {
		args := []any{q.days}
		if q.days == 0 {
			args = nil
		}
		if _, err := s.db.Exec(ctx, q.sql, args...); err != nil {
			return err
		}
	}
	if err := s.retentionTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM device_events WHERE at < now() - make_interval(days => $1)`, d("device_events"))
		return err
	}); err != nil {
		return err
	}
	return s.expireApprovals(ctx)
}

// retentionTx runs fn in a transaction allowed to delete protected rows.
func (s *Server) retentionTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL limdm.retention = 'on'`); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// pruneAudit deletes audit entries older than the configured retention. The
// caller has just verified the whole chain (never cut into a broken one);
// the last deleted entry's id and hash become the cut, signed with the
// audit chain key (HKDF from command.key, audit.go), from which verification
// starts afterwards. The prune itself is an audit entry.
func (s *Server) pruneAudit(ctx context.Context) error {
	days := s.settings().retentionDays("audit")
	if days == 0 {
		return nil
	}
	return s.retentionTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7363)`); err != nil { // the lock audit() appends under
			return err
		}
		var id int64
		var hash []byte
		err := tx.QueryRow(ctx, `SELECT id, hash FROM audit_log WHERE at < now() - make_interval(days => $1) ORDER BY id DESC LIMIT 1`, days).Scan(&id, &hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE id <= $1`, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_cut(one, last_id, last_hash, mac, cut_at) VALUES (true, $1, $2, $3, now())
			ON CONFLICT (one) DO UPDATE SET last_id=EXCLUDED.last_id, last_hash=EXCLUDED.last_hash, mac=EXCLUDED.mac, cut_at=now()`,
			id, hash, cutMAC(id, hash)); err != nil {
			return err
		}
		return audit(ctx, tx, "system", "audit.prune", "", fmt.Sprintf("deleted %d entries up to #%d (older than %d days); the chain continues from hash %x",
			tag.RowsAffected(), id, days, hash))
	})
}

// cutMAC signs a retention cut with the audit chain key, like the keyed
// entries: whoever can only write to the database cannot move the cut.
func cutMAC(id int64, hash []byte) []byte { return cutMACWith(auditKey, id, hash) }

func cutMACWith(key []byte, id int64, hash []byte) []byte {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "audit-cut|%d|%x", id, hash)
	return m.Sum(nil)
}

// auditStart is where verification of the hash chain begins: behind the
// last retention cut, or at the start of the log. A cut whose signature
// does not match is ignored, so the first remaining entry shows as broken.
// verifyAuditFrom (web.go) calls it.
func (s *Server) auditStart(ctx context.Context) (int64, []byte, error) {
	var id int64
	var hash, mac []byte
	err := s.db.QueryRow(ctx, `SELECT last_id, last_hash, mac FROM audit_cut`).Scan(&id, &hash, &mac)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return 0, nil, err
	case hmac.Equal(mac, cutMAC(id, hash)):
		return id, hash, nil
	default:
		s.log.Error("audit retention cut has an invalid signature")
	}
	return 0, make([]byte, 32), nil
}

// deviceDelete removes a retired device and its personal data: events,
// metrics, commands, recovery keys and app requests. Audit entries about it
// stay (they follow the audit retention); the deletion is one of them.
func (s *Server) deviceDelete(w http.ResponseWriter, r *http.Request, sess session) {
	err := s.deleteDevice(r.Context(), sess.Email, r.PathValue("id"), r.FormValue("confirm"))
	var ue *userError
	switch {
	case errors.Is(err, errNotFound):
		http.NotFound(w, r)
	case errors.As(err, &ue):
		s.errorPage(w, r, sess, ue.Status, ue.Msg)
	case err != nil:
		s.fail(w, err)
	default:
		http.Redirect(w, r, "/devices", http.StatusSeeOther)
	}
}

// deleteDevice deletes a retired device whose host name confirm repeats.
func (s *Server) deleteDevice(ctx context.Context, actor, id, confirm string) error {
	var host string
	var retired bool
	if err := s.db.QueryRow(ctx, `SELECT hostname, retired FROM devices WHERE id=$1`, id).Scan(&host, &retired); err != nil {
		return errNotFound
	}
	if !retired {
		return &userError{http.StatusBadRequest, "retire the device before deleting it"}
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), host) {
		return &userError{http.StatusBadRequest, "type the host name to confirm"}
	}
	return s.retentionTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE id=$1 AND retired`, id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "device.delete", id, "hostname="+host+"; device, events, metrics, commands, recovery keys and app requests deleted")
	})
}
