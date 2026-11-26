package server

import (
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

	"github.com/maltekiefer/limdm/internal/api"
)

// Risk acceptance: an exception excludes a check (shown as excepted) or
// makes it advisory (reported, not counted), with reason, risk owner,
// approver and expiry. The server merges the active ones into the
// compliance declaration of each device, so an expired exception stops
// applying at the next check in and the agent needs no logic for it.

// activeExceptionSQL selects active exceptions of the alias x.
const activeExceptionSQL = `x.revoked_at IS NULL AND x.expires_at > now()`

type riskException struct {
	ID                                int64
	CheckID, Mode, Tag, Reason, Owner string
	Approver                          string
	Expires                           time.Time
	CreatedBy                         string
	Created                           time.Time
	Revoked                           *time.Time
}

// State is active, expired or revoked.
func (e riskException) State() string {
	switch {
	case e.Revoked != nil:
		return "revoked"
	case !time.Now().Before(e.Expires):
		return "expired"
	}
	return "active"
}

func (s *Server) riskExceptions(ctx context.Context) ([]riskException, error) {
	cond, args := tenantCond(session{Tenant: ctxTenant(ctx)}, "x.tenant_id", 0)
	rows, err := s.db.Query(ctx, `SELECT id, check_id, mode, tag, reason, owner, approver, expires_at, created_by, created_at, revoked_at
		FROM risk_exceptions x WHERE `+cond+` ORDER BY (`+activeExceptionSQL+`) DESC, expires_at`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[riskException])
}

// applyExceptions merges the active exceptions of a device into its
// compliance declaration (a device without one runs no checks).
func applyExceptions(ctx context.Context, q pgx.Tx, deviceID string, decls []api.Declaration) error {
	i := slices.IndexFunc(decls, func(d api.Declaration) bool { return d.Type == api.TypeCompliance })
	if i < 0 {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT check_id, mode FROM risk_exceptions x WHERE `+activeExceptionSQL+`
		AND x.tenant_id = (SELECT tenant_id FROM devices WHERE id=$1)
		AND (x.tag = '' OR x.tag = ANY(SELECT unnest(tags) FROM devices WHERE id=$1)) ORDER BY id`, deviceID)
	if err != nil {
		return err
	}
	type ex struct{ Check, Mode string }
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ex])
	if err != nil || len(list) == 0 {
		return err
	}
	var c api.Compliance
	if err := json.Unmarshal(decls[i].Payload, &c); err != nil {
		return err
	}
	for _, e := range list {
		if e.Mode == "exclude" && !slices.Contains(c.Exclude, e.Check) {
			c.Exclude = append(c.Exclude, e.Check)
		}
		if e.Mode == "advisory" && !slices.Contains(c.Advisory, e.Check) {
			c.Advisory = append(c.Advisory, e.Check)
		}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	decls[i].Payload = b
	decls[i].ServerToken = decls[i].Token()
	return nil
}

// checkException validates a risk exception for the console and the admin
// API; expires is the last day it applies (YYYY-MM-DD). With approver the
// approver named by the caller is checked too (four eyes: another person);
// a request leaves it to the admin who approves it. Validation errors are
// userErrors (400).
func (s *Server) checkException(ctx context.Context, sess session, e *riskException, expires string, approver bool) error {
	bad := func(msg string) error { return &userError{http.StatusBadRequest, msg} }
	e.CheckID, e.Reason, e.Owner, e.Approver, e.CreatedBy = strings.TrimSpace(e.CheckID), strings.TrimSpace(e.Reason),
		strings.TrimSpace(e.Owner), strings.TrimSpace(e.Approver), sess.Email
	tags, err := parseTags(e.Tag)
	if err != nil || len(tags) > 1 {
		return bad("tag: one tag or empty for every device")
	}
	e.Tag = ""
	if len(tags) == 1 {
		e.Tag = tags[0]
	}
	day, err := time.ParseInLocation("2006-01-02", expires, time.Local)
	e.Expires = day.AddDate(0, 0, 1) // valid through the given day
	switch {
	case !identOK(e.CheckID):
		return bad("check ID: letters, digits, dot, dash, underscore")
	case e.Mode != "exclude" && e.Mode != "advisory":
		return bad("mode: exclude or advisory")
	case e.Reason == "" || len(e.Reason) > 1000:
		return bad("reason: 1 to 1000 characters")
	case e.Owner == "" || len(e.Owner) > 200:
		return bad("risk owner and approver: 1 to 200 characters")
	case approver && (e.Approver == "" || len(e.Approver) > 200):
		return bad("risk owner and approver: 1 to 200 characters")
	case approver && s.settings().FourEyes && s.selfApprover(ctx, sess.Email, e.Approver):
		return bad("four eyes approval is on: the approver must be another person")
	case err != nil || !e.Expires.After(time.Now()) || e.Expires.After(time.Now().AddDate(3, 0, 1)):
		return bad("expiry: a date within the next three years")
	}
	return nil
}

// addException validates and stores a risk exception for the console and
// the admin API.
func (s *Server) addException(ctx context.Context, sess session, e riskException, expires string) (int64, error) {
	if err := s.checkException(ctx, sess, &e, expires, true); err != nil {
		return 0, err
	}
	var id int64
	err := s.auditAction(ctx, sess.Email, "exception.add", e.CheckID, fmt.Sprintf("mode=%s tag=%q owner=%q approver=%q expires=%s reason=%q",
		e.Mode, e.Tag, e.Owner, e.Approver, e.Expires.Format(time.DateOnly), e.Reason), func(tx pgx.Tx) error {
		var err error
		id, err = insertException(ctx, tx, e, ownerTenant(ctx))
		return err
	})
	return id, err
}

func insertException(ctx context.Context, tx pgx.Tx, e riskException, tenant int64) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO risk_exceptions(check_id, mode, tag, reason, owner, approver, expires_at, created_by, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, e.CheckID, e.Mode, e.Tag, e.Reason, e.Owner, e.Approver, e.Expires, e.CreatedBy, tenant).Scan(&id)
	return id, err
}

// exceptionApproval is the payload of a requested risk exception
// (approval action exception.add). The admin who approves it is recorded
// as its approver, the requester as its creator.
type exceptionApproval struct {
	CheckID string    `json:"check_id"`
	Mode    string    `json:"mode"`
	Tag     string    `json:"tag"`
	Reason  string    `json:"reason"`
	Owner   string    `json:"owner"`
	Expires time.Time `json:"expires_at"`
	Tenant  int64     `json:"tenant"`
}

// requestException stores a risk exception as a four eyes request: another
// admin approves it in the inbox (applyExceptionApproval).
func (s *Server) requestException(ctx context.Context, sess session, e riskException, expires string) (int64, error) {
	if err := s.checkException(ctx, sess, &e, expires, false); err != nil {
		return 0, err
	}
	return s.requestApproval(ctx, sess, "exception.add", e.CheckID, exceptionApproval{e.CheckID, e.Mode, e.Tag, e.Reason, e.Owner, e.Expires, ownerTenant(ctx)}, truncate(e.Reason, 500))
}

// addOrRequestException adds the exception directly, or with four eyes
// approval on stores it as a request (pending).
func (s *Server) addOrRequestException(ctx context.Context, sess session, e riskException, expires string) (id int64, pending bool, err error) {
	if s.settings().FourEyes {
		id, err = s.requestException(ctx, sess, e, expires)
		return id, true, err
	}
	id, err = s.addException(ctx, sess, e, expires)
	return id, false, err
}

func applyExceptionApproval(ctx context.Context, tx pgx.Tx, a approval, approver string) error {
	var c exceptionApproval
	if err := json.Unmarshal(a.Payload, &c); err != nil {
		return err
	}
	if !c.Expires.After(time.Now()) {
		return errApproval("the requested exception would have expired already")
	}
	e := riskException{CheckID: c.CheckID, Mode: c.Mode, Tag: c.Tag, Reason: c.Reason, Owner: c.Owner, Approver: approver, Expires: c.Expires, CreatedBy: a.RequestedBy}
	id, err := insertException(ctx, tx, e, c.Tenant)
	if err != nil {
		return err
	}
	return audit(ctx, tx, a.RequestedBy, "exception.add", c.CheckID, fmt.Sprintf("#%d mode=%s tag=%q owner=%q approver=%q expires=%s reason=%q (approval #%d by %s)",
		id, c.Mode, c.Tag, c.Owner, approver, c.Expires.Format(time.DateOnly), c.Reason, a.ID, approver))
}

// revokeException ends an exception of the session's tenant; revoking one
// that is revoked already is no error, errNotFound one of another tenant.
func (s *Server) revokeException(ctx context.Context, sess session, id int64) error {
	err := s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var check string
		tcond, targs := tenantCond(sess, "tenant_id", 1)
		err := tx.QueryRow(ctx, `UPDATE risk_exceptions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL AND `+tcond+` RETURNING check_id`, append([]any{id}, targs...)...).Scan(&check)
		return sess.Email, "exception.revoke", check, "#" + strconv.FormatInt(id, 10), err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if !s.tenantOwns(ctx, sess, "risk_exceptions", id, false) {
			return errNotFound
		}
		return nil
	}
	return err
}

// selfApprover reports whether the named approver is the person behind
// actor (an API token counts as its creator).
func (s *Server) selfApprover(ctx context.Context, actor, approver string) bool {
	who, ok := rootActor(ctx, s.db, actor)
	return !ok || strings.EqualFold(who, approver)
}
