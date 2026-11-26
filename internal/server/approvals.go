package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Four eyes approval: with the setting on, wipe, lost mode, scripts and
// console role changes (and optionally recovery key views) are stored as a
// request; another admin approves or rejects it. The requester can never
// approve their own request, requests expire after a day, every step is
// audited. With the setting off nothing changes.

const (
	approvalTTL = 24 * time.Hour
	// viewWindow is how long an approved recovery key view stays usable.
	viewWindow = time.Hour
)

type approval struct {
	ID                          int64
	Action, Target              string
	Payload                     json.RawMessage
	Reason, RequestedBy, Status string
	DecidedBy                   *string
	DecidedAt                   *time.Time
	CreatedAt, ExpiresAt        time.Time
}

// commandApproval is the payload of a command request.
type commandApproval struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

// needsApproval: commands four eyes approval covers.
func (s *Server) needsApproval(typ string) bool {
	return s.settings().FourEyes && (typ == "wipe" || typ == "lost" || typ == "script")
}

// requestApproval stores a request and audits and announces it.
func (s *Server) requestApproval(ctx context.Context, sess session, action, target string, payload any, reason string) error {
	if len(reason) > 500 {
		return errors.New("reason: up to 500 characters")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var id int64
	err = s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		err := tx.QueryRow(ctx, `INSERT INTO approvals(action, target, payload, reason, requested_by, expires_at)
			VALUES ($1,$2,$3,$4,$5, now() + make_interval(secs => $6)) RETURNING id`,
			action, target, b, reason, sess.Email, approvalTTL.Seconds()).Scan(&id)
		return sess.Email, "approval.request", target, fmt.Sprintf("#%d %s %s reason=%q", id, action, truncate(string(b), 2000), reason), err
	})
	if err != nil {
		return err
	}
	s.notify(notice{Type: "approval.request", Severity: "warning", Title: "Approval requested: " + action + " " + target,
		Text: fmt.Sprintf("%s asks for %s on %s. Reason: %s. Another admin decides under Approvals within 24 hours.", sess.Email, action, target, firstNonEmpty(reason, "none given")),
		URL:  s.cfg.PublicURL + "/approvals"})
	return nil
}

func (s *Server) approvalsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderApprovals(w, r, sess, "")
}

func (s *Server) renderApprovals(w http.ResponseWriter, r *http.Request, sess session, errMsg string) {
	q := `SELECT id, action, target, payload, reason, requested_by, status, decided_by, decided_at, created_at, expires_at
		FROM approvals WHERE ($1 = '' OR requested_by = $1) ORDER BY status <> 'pending', id DESC LIMIT 200`
	own := ""
	if sess.Role == "helpdesk" { // sees the state of their own requests only
		own = sess.Email
	}
	rows, err := s.db.Query(r.Context(), q, own)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[approval])
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "approvals", map[string]any{"Approvals": list, "FourEyes": s.settings().FourEyes, "Error": errMsg})
}

// approvalDecide approves or rejects a pending request (admins only, never
// their own). An approved command or role change runs in the same
// transaction; an approved recovery key view opens for the requester.
func (s *Server) approvalDecide(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	op := r.PathValue("op")
	if err != nil || (op != "approve" && op != "reject") {
		http.NotFound(w, r)
		return
	}
	var notices []func()
	err = func() error {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		var a approval
		err = tx.QueryRow(ctx, `SELECT id, action, target, payload, reason, requested_by, status, decided_by, decided_at, created_at, expires_at
			FROM approvals WHERE id=$1 FOR UPDATE`, id).Scan(&a.ID, &a.Action, &a.Target, &a.Payload, &a.Reason, &a.RequestedBy, &a.Status,
			&a.DecidedBy, &a.DecidedAt, &a.CreatedAt, &a.ExpiresAt)
		if err != nil {
			return err
		}
		switch {
		case a.Status != "pending":
			return errApproval("this request was decided already")
		case time.Now().After(a.ExpiresAt):
			return errApproval("this request has expired")
		case a.RequestedBy == sess.Email:
			return errApproval("you cannot decide your own request")
		}
		status, expires := "rejected", a.ExpiresAt
		if op == "approve" {
			status = "approved"
			switch a.Action {
			case "command":
				var c commandApproval
				if err := json.Unmarshal(a.Payload, &c); err != nil {
					return err
				}
				var active bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND NOT retired)`, a.Target).Scan(&active); err != nil {
					return err
				}
				if !active {
					return errApproval("the device is retired or deleted")
				}
				cmdID, err := s.insertCommand(ctx, tx, a.Target, c.Type, c.Payload, a.RequestedBy)
				if err != nil {
					return err
				}
				if err := audit(ctx, tx, a.RequestedBy, "command."+c.Type, a.Target, fmt.Sprintf("command %d ", cmdID)+truncate(c.Payload, 2000)+fmt.Sprintf(" (approval #%d by %s)", a.ID, sess.Email)); err != nil {
					return err
				}
				notices = append(notices, func() { s.notifyCommand(a.RequestedBy, a.Target, c.Type) })
			case "user.update":
				var c userChange
				if err := json.Unmarshal(a.Payload, &c); err != nil {
					return err
				}
				old := s.currentRole(ctx, a.Target)
				if err := s.applyUserChange(ctx, tx, a.Target, c); err != nil {
					return errApproval(err.Error())
				}
				if err := audit(ctx, tx, a.RequestedBy, "user.update", a.Target, c.String()+fmt.Sprintf(" (approval #%d by %s)", a.ID, sess.Email)); err != nil {
					return err
				}
				notices = append(notices, func() { s.notifyRoleChange(a.RequestedBy, a.Target, old, c.Role, sess.Email) })
			case "recovery.view":
				expires = time.Now().Add(viewWindow) // the requester opens the key within the hour
			default:
				return fmt.Errorf("unknown approval action %q", a.Action)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE approvals SET status=$2, decided_by=$3, decided_at=now(), expires_at=$4 WHERE id=$1`,
			a.ID, status, sess.Email, expires); err != nil {
			return err
		}
		if err := audit(ctx, tx, sess.Email, "approval."+op, a.Target, fmt.Sprintf("#%d %s requested by %s", a.ID, a.Action, a.RequestedBy)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}()
	var ae errApproval
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		http.NotFound(w, r)
		return
	case errors.As(err, &ae):
		s.renderApprovals(w, r, sess, string(ae))
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	for _, n := range notices {
		n()
	}
	http.Redirect(w, r, "/approvals", http.StatusSeeOther)
}

// errApproval is a refusal shown to the deciding admin.
type errApproval string

func (e errApproval) Error() string { return string(e) }

// expireApprovals ends pending requests and unused recovery views past
// their time, with an audit entry each.
func (s *Server) expireApprovals(ctx context.Context) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `UPDATE approvals SET status='expired'
		WHERE (status = 'pending' OR status = 'approved' AND action = 'recovery.view') AND expires_at < now()
		RETURNING id, action, target, requested_by`)
	if err != nil {
		return err
	}
	type row struct {
		ID                  int64
		Action, Target, Req string
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
	if err != nil {
		return err
	}
	for _, a := range list {
		if err := audit(ctx, tx, "system", "approval.expire", a.Target, fmt.Sprintf("#%d %s requested by %s", a.ID, a.Action, a.Req)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
