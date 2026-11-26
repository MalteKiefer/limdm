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

func (s *Server) exceptionAdd(w http.ResponseWriter, r *http.Request, sess session) {
	e := riskException{CheckID: strings.TrimSpace(r.FormValue("check_id")), Mode: r.FormValue("mode"),
		Reason: strings.TrimSpace(r.FormValue("reason")), Owner: strings.TrimSpace(r.FormValue("owner")),
		Approver: strings.TrimSpace(r.FormValue("approver")), CreatedBy: sess.Email}
	tags, err := parseTags(r.FormValue("tag"))
	if err != nil || len(tags) > 1 {
		s.errorPage(w, r, sess, http.StatusBadRequest, "tag: one tag or empty for every device")
		return
	}
	if len(tags) == 1 {
		e.Tag = tags[0]
	}
	expires, err := time.ParseInLocation("2006-01-02", r.FormValue("expires"), time.Local)
	e.Expires = expires.AddDate(0, 0, 1) // valid through the given day
	switch {
	case !identOK(e.CheckID):
		s.errorPage(w, r, sess, http.StatusBadRequest, "check ID: letters, digits, dot, dash, underscore")
	case e.Mode != "exclude" && e.Mode != "advisory":
		s.errorPage(w, r, sess, http.StatusBadRequest, "mode: exclude or advisory")
	case e.Reason == "" || len(e.Reason) > 1000:
		s.errorPage(w, r, sess, http.StatusBadRequest, "reason: 1 to 1000 characters")
	case e.Owner == "" || len(e.Owner) > 200 || e.Approver == "" || len(e.Approver) > 200:
		s.errorPage(w, r, sess, http.StatusBadRequest, "risk owner and approver: 1 to 200 characters")
	case s.settings().FourEyes && strings.EqualFold(e.Approver, sess.Email):
		s.errorPage(w, r, sess, http.StatusBadRequest, "four eyes approval is on: the approver must be another person")
	case err != nil || !e.Expires.After(time.Now()) || e.Expires.After(time.Now().AddDate(3, 0, 1)):
		s.errorPage(w, r, sess, http.StatusBadRequest, "expiry: a date within the next three years")
	default:
		err := s.auditAction(r.Context(), sess.Email, "exception.add", e.CheckID, fmt.Sprintf("mode=%s tag=%q owner=%q approver=%q expires=%s reason=%q",
			e.Mode, e.Tag, e.Owner, e.Approver, e.Expires.Format(time.DateOnly), e.Reason), func(tx pgx.Tx) error {
			_, err := tx.Exec(r.Context(), `INSERT INTO risk_exceptions(check_id, mode, tag, reason, owner, approver, expires_at, created_by, tenant_id)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, e.CheckID, e.Mode, e.Tag, e.Reason, e.Owner, e.Approver, e.Expires, e.CreatedBy, ownerTenant(r.Context()))
			return err
		})
		if err != nil {
			s.fail(w, err)
			return
		}
		http.Redirect(w, r, "/compliance#exceptions", http.StatusSeeOther)
	}
}

func (s *Server) exceptionRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.auditActionFn(r.Context(), func(tx pgx.Tx) (string, string, string, string, error) {
		var check string
		tcond, targs := tenantCond(sess, "tenant_id", 1)
		err := tx.QueryRow(r.Context(), `UPDATE risk_exceptions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL AND `+tcond+` RETURNING check_id`, append([]any{id}, targs...)...).Scan(&check)
		return sess.Email, "exception.revoke", check, "#" + strconv.FormatInt(id, 10), err
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/compliance#exceptions", http.StatusSeeOther)
}
