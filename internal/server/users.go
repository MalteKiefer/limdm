package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Console users: OIDC identities (by email) and local accounts (password +
// TOTP). Roles: admin (everything), helpdesk (view, device commands except
// scripts) and auditor (read only).

var roles = []string{"admin", "helpdesk", "auditor"}

// seedConsoleUsers adds the bootstrap OIDC users from the environment and
// disables seeded users that were removed from it, so taking someone out of
// LIMDM_ADMINS revokes their access at the next start. Changes made in the
// console win: such users are no longer managed by the environment.
func (s *Server) seedConsoleUsers(ctx context.Context) error {
	listed := []string{}
	for role, list := range map[string][]string{"admin": s.cfg.Admins, "auditor": s.cfg.Auditors} {
		for _, email := range list {
			listed = append(listed, email)
			if _, err := s.db.Exec(ctx, `INSERT INTO console_users(email, role, from_env) VALUES ($1,$2,true)
				ON CONFLICT (email) DO NOTHING`, email, role); err != nil {
				return err
			}
		}
	}
	rows, err := s.db.Query(ctx, `UPDATE console_users SET disabled=true WHERE from_env AND NOT disabled AND email <> ALL($1) RETURNING email`, listed)
	if err != nil {
		return err
	}
	revoked, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, email := range revoked {
		s.log.Warn("console user removed from the environment, disabled", "email", email)
		if err := s.auditAction(ctx, "system", "user.update", email, "disabled: no longer in LIMDM_ADMINS or LIMDM_AUDITORS", func(pgx.Tx) error { return nil }); err != nil {
			return err
		}
	}
	return nil
}

// oidcRole returns the role of an enabled OIDC console user, or "".
func (s *Server) oidcRole(ctx context.Context, email string) string {
	var role string
	if err := s.db.QueryRow(ctx, `SELECT role FROM console_users WHERE email=$1 AND NOT disabled`, email).Scan(&role); err != nil {
		return ""
	}
	return role
}

type consoleUser struct {
	Login, Role string
	Disabled    bool
	LastLogin   *time.Time
	Local       bool
}

func (s *Server) consoleUsers(ctx context.Context) ([]consoleUser, error) {
	rows, err := s.db.Query(ctx, `SELECT email, role, disabled, last_login, false FROM console_users
		UNION ALL SELECT name, role, disabled, last_login, true FROM local_admins ORDER BY 5, 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[consoleUser])
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderUsers(w, r, sess, "", "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, sess session, creds, errMsg string) {
	users, err := s.consoleUsers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "users", map[string]any{"Users": users, "Roles": roles, "Creds": creds, "Error": errMsg,
		"LocalLogin": s.settings().LocalLogin, "OIDC": s.oidc() != nil})
}

// enabledAdminsExcept counts active admins other than login.
func enabledAdminsExcept(ctx context.Context, tx pgx.Tx, login string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM console_users WHERE role='admin' AND NOT disabled AND email<>$1)
		+ (SELECT count(*) FROM local_admins WHERE role='admin' AND NOT disabled AND 'local:' || name <> $1)`, login).Scan(&n)
	return n, err
}

func (s *Server) userAdd(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	kind, role := r.FormValue("kind"), r.FormValue("role")
	if !slices.Contains(roles, role) {
		s.renderUsers(w, r, sess, "", "unknown role")
		return
	}
	if kind == "oidc" {
		addr, err := mail.ParseAddress(strings.TrimSpace(r.FormValue("login")))
		if err != nil || addr.Name != "" {
			s.renderUsers(w, r, sess, "", "enter a plain email address")
			return
		}
		email := strings.ToLower(addr.Address)
		err = s.auditAction(ctx, sess.Email, "user.add", email, "oidc "+role, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `INSERT INTO console_users(email, role) VALUES ($1,$2) ON CONFLICT DO NOTHING`, email, role)
			if err == nil && tag.RowsAffected() == 0 {
				err = errors.New("user exists already")
			}
			return err
		})
		if err != nil {
			s.renderUsers(w, r, sess, "", err.Error())
			return
		}
		s.renderUsers(w, r, sess, "", "")
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("login")))
	if !localNameRe.MatchString(name) {
		s.renderUsers(w, r, sess, "", "local name: 2..32 lowercase letters, digits, dot, dash, underscore")
		return
	}
	var creds string
	err := s.auditAction(ctx, sess.Email, "user.add", localPrefix+name, "local "+role, func(tx pgx.Tx) error {
		var err error
		creds, err = localAdd(ctx, tx, name, role)
		return err
	})
	if err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	s.renderUsers(w, r, sess, creds, "")
}

// userUpdate changes role or enabled state; self lockout and losing the last admin are refused.
func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	login, role := r.FormValue("login"), r.FormValue("role")
	disable := r.FormValue("disabled") == "on"
	if !slices.Contains(roles, role) {
		s.renderUsers(w, r, sess, "", "unknown role")
		return
	}
	if login == sess.Email && (disable || role != sess.Role) {
		s.renderUsers(w, r, sess, "", "you cannot demote or disable your own account")
		return
	}
	err := s.auditAction(ctx, sess.Email, "user.update", login, fmt.Sprintf("role=%s disabled=%v", role, disable), func(tx pgx.Tx) error {
		if role != "admin" || disable {
			n, err := enabledAdminsExcept(ctx, tx, login)
			if err != nil {
				return err
			}
			if n == 0 {
				return errors.New("at least one active administrator must remain")
			}
		}
		var tag interface{ RowsAffected() int64 }
		var err error
		if name, ok := strings.CutPrefix(login, localPrefix); ok {
			tag, err = tx.Exec(ctx, `UPDATE local_admins SET role=$2, disabled=$3 WHERE name=$1`, name, role, disable)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE console_users SET role=$2, disabled=$3, from_env=false WHERE email=$1`, login, role, disable)
		}
		if err == nil && tag.RowsAffected() == 0 {
			err = errors.New("user not found")
		}
		return err
	})
	if err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	s.renderUsers(w, r, sess, "", "")
}

func (s *Server) userReset(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	name, ok := strings.CutPrefix(r.FormValue("login"), localPrefix)
	if !ok {
		s.renderUsers(w, r, sess, "", "only local accounts have credentials to reset")
		return
	}
	if localPrefix+name == sess.Email {
		s.renderUsers(w, r, sess, "", "change your own credentials in your profile")
		return
	}
	var creds string
	err := s.auditAction(ctx, sess.Email, "user.reset", localPrefix+name, "new password and TOTP", func(tx pgx.Tx) error {
		var err error
		creds, err = localReset(ctx, tx, name)
		return err
	})
	if err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	s.renderUsers(w, r, sess, creds, "")
}
