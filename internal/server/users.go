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
	"github.com/jackc/pgx/v5/pgconn"
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
	role, _ := s.account(ctx, email)
	return role
}

// account returns role and session generation of an enabled console account
// (OIDC email or local:<name>); role is "" when it is unknown or disabled.
func (s *Server) account(ctx context.Context, login string) (string, int64) {
	var role string
	var gen int64
	var fromGroup bool
	var claim []string
	q := `SELECT role, session_gen, from_group, oidc_groups FROM console_users WHERE email=$1 AND NOT disabled`
	key := login
	if name, ok := strings.CutPrefix(login, localPrefix); ok {
		q, key = `SELECT role, session_gen, false, '{}'::text[] FROM local_admins WHERE name=$1 AND NOT disabled`, name
	}
	if err := s.db.QueryRow(ctx, q, key).Scan(&role, &gen, &fromGroup, &claim); err != nil {
		return "", 0
	}
	if fromGroup { // follows the directory: leaving the group ends access
		role, _ = s.groupRole(ctx, login, claim)
	}
	return role, gen
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// revokeSessions ends every session of an account.
func (s *Server) revokeSessions(ctx context.Context, db execer, login string) error {
	if name, ok := strings.CutPrefix(login, localPrefix); ok {
		_, err := db.Exec(ctx, `UPDATE local_admins SET session_gen=session_gen+1 WHERE name=$1`, name)
		return err
	}
	_, err := db.Exec(ctx, `UPDATE console_users SET session_gen=session_gen+1 WHERE email=$1`, login)
	return err
}

// renewSession reissues the current session under the account's new
// generation after the user changed their own credentials.
func (s *Server) renewSession(w http.ResponseWriter, r *http.Request, sess session) {
	if role, gen := s.account(r.Context(), sess.Email); role != "" {
		sess.Gen = gen
		s.setCookie(w, sessionCookie, s.seal(sess), maxSession-time.Since(sess.IAT))
	}
}

type consoleUser struct {
	Login, Role string
	Disabled    bool
	LastLogin   *time.Time
	Local       bool
	Tags        []string // device scope (helpdesk, auditor)
	Groups      []string
	FromGroup   bool // role from a directory group mapping
}

func (s *Server) consoleUsers(ctx context.Context) ([]consoleUser, error) {
	rows, err := s.db.Query(ctx, `SELECT email, role, disabled, last_login, false, scope_tags, scope_groups, from_group FROM console_users
		UNION ALL SELECT name, role, disabled, last_login, true, scope_tags, scope_groups, false FROM local_admins ORDER BY 5, 1`)
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
		"LocalLogin": s.settings().LocalLogin, "OIDC": s.oidc() != nil, "FourEyes": s.settings().FourEyes})
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
	login := r.FormValue("login")
	c := userChange{Role: r.FormValue("role"), Disabled: r.FormValue("disabled") == "on"}
	if !slices.Contains(roles, c.Role) {
		s.renderUsers(w, r, sess, "", "unknown role")
		return
	}
	if login == sess.Email && (c.Disabled || c.Role != sess.Role) {
		s.renderUsers(w, r, sess, "", "you cannot demote or disable your own account")
		return
	}
	var err error
	if c.Tags, err = parseTags(r.FormValue("scope_tags")); err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	if c.Groups, err = parseScopeGroups(r.FormValue("scope_groups")); err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	if c.Role == "admin" {
		c.Tags, c.Groups = []string{}, []string{} // admins are never scoped
	}
	cur := s.currentRole(ctx, login)
	if cur == "" {
		s.renderUsers(w, r, sess, "", "user not found")
		return
	}
	if cur != c.Role && s.settings().FourEyes {
		if err := s.requestApproval(ctx, sess, "user.update", login, c, strings.TrimSpace(r.FormValue("reason"))); err != nil {
			s.renderUsers(w, r, sess, "", err.Error())
			return
		}
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}
	err = s.auditAction(ctx, sess.Email, "user.update", login, c.String(), func(tx pgx.Tx) error {
		return s.applyUserChange(ctx, tx, login, c)
	})
	if err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	if cur != c.Role {
		s.notifyRoleChange(sess.Email, login, cur, c.Role, "")
	}
	s.renderUsers(w, r, sess, "", "")
}

// userChange is the edit of a console account, applied directly or after
// a four eyes approval.
type userChange struct {
	Role     string   `json:"role"`
	Disabled bool     `json:"disabled"`
	Tags     []string `json:"tags"`
	Groups   []string `json:"groups"`
}

func (c userChange) String() string {
	return fmt.Sprintf("role=%s disabled=%v scope_tags=%v scope_groups=%q", c.Role, c.Disabled, c.Tags, c.Groups)
}

// currentRole is the stored role of an account, enabled or not ("" unknown).
func (s *Server) currentRole(ctx context.Context, login string) string {
	var role string
	q, key := `SELECT role FROM console_users WHERE email=$1`, login
	if name, ok := strings.CutPrefix(login, localPrefix); ok {
		q, key = `SELECT role FROM local_admins WHERE name=$1`, name
	}
	_ = s.db.QueryRow(ctx, q, key).Scan(&role)
	return role
}

// applyUserChange stores c; losing the last admin, or the second one while
// four eyes approval is on, is refused.
func (s *Server) applyUserChange(ctx context.Context, tx pgx.Tx, login string, c userChange) error {
	if c.Role != "admin" || c.Disabled {
		n, err := enabledAdminsExcept(ctx, tx, login)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("at least one active administrator must remain")
		}
		var isAdmin bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM console_users WHERE email=$1 AND role='admin' AND NOT disabled)
			OR EXISTS(SELECT 1 FROM local_admins WHERE 'local:' || name = $1 AND role='admin' AND NOT disabled)`, login).Scan(&isAdmin); err != nil {
			return err
		}
		if isAdmin && n < 2 && s.settings().FourEyes {
			return errors.New("four eyes approval is on: at least two active administrators must remain")
		}
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	if c.Groups == nil {
		c.Groups = []string{}
	}
	var tag interface{ RowsAffected() int64 }
	var err error
	if name, ok := strings.CutPrefix(login, localPrefix); ok {
		tag, err = tx.Exec(ctx, `UPDATE local_admins SET role=$2, disabled=$3, scope_tags=$4, scope_groups=$5, session_gen=session_gen+1 WHERE name=$1`,
			name, c.Role, c.Disabled, c.Tags, c.Groups)
	} else {
		tag, err = tx.Exec(ctx, `UPDATE console_users SET role=$2, disabled=$3, scope_tags=$4, scope_groups=$5, from_env=false, from_group=false,
			session_gen=session_gen+1 WHERE email=$1`, login, c.Role, c.Disabled, c.Tags, c.Groups)
	}
	if err == nil && tag.RowsAffected() == 0 {
		err = errors.New("user not found")
	}
	return err
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
