package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Retention: finished commands, routine device events and (when configured)
// old audit entries are deleted by the hourly history job. audit_log and
// device_events refuse deletes unless the transaction sets limdm.retention
// (schema.sql), which only this file does.

// commandRetention keeps finished commands this long; the latest protective
// actions (lock, lost mode, wipe) stay, the device page shows them.
const commandRetention = "180 days"

func (s *Server) prune(ctx context.Context) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM device_metrics WHERE at < now() - interval '30 days';
		DELETE FROM fleet_history WHERE day < current_date - 400;
		DELETE FROM commands WHERE status IN ('ok', 'failed', 'expired') AND updated_at < now() - interval '`+commandRetention+`'
			AND type NOT IN ('lock', 'unlock', 'lost', 'found', 'wipe');
		DELETE FROM compliance_changes c WHERE c.at < now() - interval '365 days' AND EXISTS (SELECT 1 FROM compliance_changes n
			WHERE n.device_id = c.device_id AND n.check_id = c.check_id AND n.id > c.id AND n.at < now() - interval '365 days')`); err != nil {
		return err
	}
	if err := s.retentionTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM device_events WHERE at < now() - interval '365 days'`)
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
	days := s.settings().AuditRetentionDays
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
func cutMAC(id int64, hash []byte) []byte {
	m := hmac.New(sha256.New, auditKey)
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
	ctx := r.Context()
	id := r.PathValue("id")
	var host string
	var retired bool
	if err := s.db.QueryRow(ctx, `SELECT hostname, retired FROM devices WHERE id=$1`, id).Scan(&host, &retired); err != nil {
		http.NotFound(w, r)
		return
	}
	if !retired {
		s.errorPage(w, r, sess, http.StatusBadRequest, "retire the device before deleting it")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), host) {
		s.errorPage(w, r, sess, http.StatusBadRequest, "type the host name to confirm")
		return
	}
	err := s.retentionTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE id=$1 AND retired`, id); err != nil {
			return err
		}
		return audit(ctx, tx, sess.Email, "device.delete", id, "hostname="+host+"; device, events, metrics, commands, recovery keys and app requests deleted")
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}
