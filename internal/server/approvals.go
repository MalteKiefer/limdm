package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Four eyes approval: with the setting on, wipe, lost mode, scripts,
// console role changes, root effective library items, required catalog apps
// or ones with a repository and admin API tokens (foureyes.go), and
// optionally recovery key views and remote shells, are stored as a request; another admin approves or rejects it. The requester can never
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

// requestApproval stores a request, audits and announces it, and returns its ID.
func (s *Server) requestApproval(ctx context.Context, sess session, action, target string, payload any, reason string) (int64, error) {
	if len(reason) > 500 {
		return 0, errors.New("reason: up to 500 characters")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var id, tenant int64
	err = s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		// the tenant that decides: the requester's, else the target device's or user's
		err := tx.QueryRow(ctx, `INSERT INTO approvals(action, target, payload, reason, requested_by, expires_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5, now() + make_interval(secs => $6), coalesce(nullif($7::bigint, 0), (SELECT tenant_id FROM devices WHERE id=$2),
				(SELECT tenant_id FROM console_users WHERE email=$2), (SELECT tenant_id FROM local_admins WHERE 'local:' || name = $2), 1)) RETURNING id,
				coalesce(nullif($7::bigint, 0), (SELECT tenant_id FROM devices WHERE id=$2), (SELECT tenant_id FROM console_users WHERE email=$2),
					(SELECT tenant_id FROM local_admins WHERE 'local:' || name = $2), 0)`,
			action, target, b, reason, sess.Email, approvalTTL.Seconds(), sess.Tenant).Scan(&id, &tenant)
		return sess.Email, "approval.request", target, fmt.Sprintf("#%d %s %s reason=%q", id, action, truncate(string(b), 2000), reason), err
	})
	if err != nil {
		return 0, err
	}
	s.notify(notice{Type: "approval.request", Severity: "warning", Title: "Approval requested: " + action + " " + target,
		Text: fmt.Sprintf("%s asks for %s on %s. Reason: %s. Another admin decides under Approvals within 24 hours.", sess.Email, action, target, firstNonEmpty(reason, "none given")),
		URL:  s.cfg.PublicURL + "/approvals", Tenant: tenant}) // the tenant's channels and the global ones; 0 for global accounts
	return id, nil
}

func (s *Server) approvalsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderApprovals(w, r, sess, "")
}

func (s *Server) renderApprovals(w http.ResponseWriter, r *http.Request, sess session, errMsg string) {
	s.renderApprovalsWith(w, r, sess, errMsg, "")
}

func (s *Server) renderApprovalsCreds(w http.ResponseWriter, r *http.Request, sess session, creds string) {
	s.renderApprovalsWith(w, r, sess, "", creds)
}

func (s *Server) renderApprovalsWith(w http.ResponseWriter, r *http.Request, sess session, errMsg, creds string) {
	tcond, targs := tenantCond(sess, "tenant_id", 1)
	q := `SELECT id, action, target, payload, reason, requested_by, status, decided_by, decided_at, created_at, expires_at
		FROM approvals WHERE ($1 = '' OR requested_by = $1) AND ` + tcond + ` ORDER BY status <> 'pending', id DESC LIMIT 200`
	own := ""
	if sess.Role == "helpdesk" { // sees the state of their own requests only
		own = sess.Email
	}
	rows, err := s.db.Query(r.Context(), q, append([]any{own}, targs...)...)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[approval])
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "approvals", map[string]any{"Approvals": list, "FourEyes": s.settings().FourEyes, "Error": errMsg, "Creds": creds})
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
	creds, notices, err := s.decideApproval(ctx, sess, id, op, "")
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
	if creds != "" {
		s.renderApprovalsCreds(w, r, sess, creds)
		return
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
		WHERE (status = 'pending' OR status = 'approved' AND action IN ('recovery.view', 'remote_shell')) AND expires_at < now()
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

// sameActor reports whether a request was made by the deciding admin:
// both sides are traced to the person behind them (an API token to its
// creator, a token made by a token to that one's creator, and so on).
func (s *Server) sameActor(ctx context.Context, tx pgx.Tx, requestedBy, email string) bool {
	if requestedBy == email {
		return true
	}
	a, ok1 := rootActor(ctx, tx, requestedBy)
	b, ok2 := rootActor(ctx, tx, email)
	// an actor we cannot resolve never passes as someone else
	return !ok1 || !ok2 || strings.EqualFold(a, b)
}

// rootActor returns the person behind an actor: "api:name#id" is replaced
// by the creator of token id until a person is reached.
func rootActor(ctx context.Context, q querier, actor string) (string, bool) {
	for range 10 {
		rest, ok := strings.CutPrefix(actor, "api:")
		if !ok {
			return actor, true
		}
		i := strings.LastIndexByte(rest, '#')
		if i < 0 {
			return "", false
		}
		id, err := strconv.ParseInt(rest[i+1:], 10, 64)
		if err != nil || q.QueryRow(ctx, `SELECT created_by FROM api_tokens WHERE id=$1`, id).Scan(&actor) != nil {
			return "", false
		}
	}
	return "", false
}

// globalRequest reports whether approving a acts beyond one tenant: the
// catalog, a global API token, a library item saved in the global view.
func globalRequest(a approval) bool {
	switch a.Action {
	case "catalog.save":
		return true
	case "token.add":
		var t tokenApproval
		return json.Unmarshal(a.Payload, &t) != nil || t.Tenant == nil
	case "library.save":
		var c itemApproval
		return json.Unmarshal(a.Payload, &c) != nil || c.Tenant == 0
	}
	return false
}

// decideApproval approves or rejects a pending request for the console and
// the admin API, with the decider's reason (may be empty). It returns new
// local credentials (shown once to the approver) and notifications to send
// after the commit.
func (s *Server) decideApproval(ctx context.Context, sess session, id int64, op, reason string) (creds string, notices []func(), err error) {
	if len(reason) > 500 {
		return "", nil, errApproval("reason: up to 500 characters")
	}
	err = func() error {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		var a approval
		tcond, targs := tenantCond(sess, "tenant_id", 1)
		err = tx.QueryRow(ctx, `SELECT id, action, target, payload, reason, requested_by, status, decided_by, decided_at, created_at, expires_at
			FROM approvals WHERE id=$1 AND `+tcond+` FOR UPDATE`, append([]any{id}, targs...)...).Scan(&a.ID, &a.Action, &a.Target, &a.Payload, &a.Reason, &a.RequestedBy, &a.Status,
			&a.DecidedBy, &a.DecidedAt, &a.CreatedAt, &a.ExpiresAt)
		if err != nil {
			return err
		}
		switch {
		case a.Status != "pending":
			return errApproval("this request was decided already")
		case time.Now().After(a.ExpiresAt):
			return errApproval("this request has expired")
		case s.sameActor(ctx, tx, a.RequestedBy, sess.Email):
			return errApproval("you cannot decide your own request")
		case sess.Tenant != 0 && globalRequest(a):
			// stored under tenant 1 (or the tenant its name matched), but
			// approving it acts for every tenant
			return errApproval("a global request is decided in the global view")
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
			case "user.add":
				var c userAddition
				if err := json.Unmarshal(a.Payload, &c); err != nil {
					return err
				}
				if creds, err = c.apply(ctx, tx); err != nil {
					return errApproval(err.Error())
				}
				if err := audit(ctx, tx, a.RequestedBy, "user.add", a.Target, c.Kind+" "+c.Role+fmt.Sprintf(" (approval #%d by %s)", a.ID, sess.Email)); err != nil {
					return err
				}
			case "user.reset":
				name := strings.TrimPrefix(a.Target, localPrefix)
				if creds, err = localReset(ctx, tx, name); err != nil {
					return errApproval(err.Error())
				}
				if err := audit(ctx, tx, a.RequestedBy, "user.reset", a.Target, fmt.Sprintf("new credentials and TOTP (approval #%d by %s)", a.ID, sess.Email)); err != nil {
					return err
				}
			case "library.save":
				if err := applyItemApproval(ctx, tx, a, sess.Email); err != nil {
					return err
				}
			case "catalog.save":
				if err := s.applyCatalogApproval(ctx, tx, a, sess.Email); err != nil {
					return err
				}
			case "token.add":
				if creds, err = applyTokenApproval(ctx, tx, a, sess.Email); err != nil {
					return err
				}
			case "artifact.upload": // the upload becomes installable (packages.go)
				var c struct {
					Tenant int64 `json:"tenant"`
				}
				if err := json.Unmarshal(a.Payload, &c); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE artifacts SET approved_by=$3 WHERE tenant_id=$1 AND sha256=$2 AND approved_by IS NULL`, c.Tenant, a.Target, sess.Email); err != nil {
					return err
				}
			case "recovery.view", "remote_shell":
				expires = time.Now().Add(viewWindow) // the requester opens the key or shell within the hour
			default:
				return fmt.Errorf("unknown approval action %q", a.Action)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE approvals SET status=$2, decided_by=$3, decided_at=now(), expires_at=$4, decision_reason=$5 WHERE id=$1`,
			a.ID, status, sess.Email, expires, reason); err != nil {
			return err
		}
		detail := fmt.Sprintf("#%d %s requested by %s", a.ID, a.Action, a.RequestedBy)
		if reason != "" {
			detail += fmt.Sprintf(" reason=%q", reason)
		}
		if err := audit(ctx, tx, sess.Email, "approval."+op, a.Target, detail); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}()
	return creds, notices, err
}
