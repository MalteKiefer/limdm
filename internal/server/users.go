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
	FromGroup   bool   // role from a directory group mapping
	Tenant      string // tenant name, "" for global accounts
}

// consoleUsers lists the accounts of the tenant of sess (all in the global view).
func (s *Server) consoleUsers(ctx context.Context, sess session) ([]consoleUser, error) {
	cu, args := tenantCond(sess, "u.tenant_id", 0)
	la, _ := tenantCond(sess, "l.tenant_id", 0)
	rows, err := s.db.Query(ctx, `SELECT u.email, u.role, u.disabled, u.last_login, false, u.scope_tags, u.scope_groups, u.from_group, coalesce(t.name, '')
		FROM console_users u LEFT JOIN tenants t ON t.id=u.tenant_id WHERE `+cu+`
		UNION ALL SELECT l.name, l.role, l.disabled, l.last_login, true, l.scope_tags, l.scope_groups, false, coalesce(t.name, '')
		FROM local_admins l LEFT JOIN tenants t ON t.id=l.tenant_id WHERE `+la+` ORDER BY 5, 1`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[consoleUser])
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderUsers(w, r, sess, "", "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, sess session, creds, errMsg string) {
	users, err := s.consoleUsers(r.Context(), sess)
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
	creds, approval, err := s.addUser(r.Context(), sess, userAddition{Kind: r.FormValue("kind"), Login: r.FormValue("login"), Role: r.FormValue("role")}, r.FormValue("reason"))
	s.userDone(w, r, sess, creds, approval, err)
}

// userDone answers a console form of the users page: the error, the way
// to the approval, or the page with new credentials.
func (s *Server) userDone(w http.ResponseWriter, r *http.Request, sess session, creds string, approval int64, err error) {
	switch {
	case err != nil:
		s.renderUsers(w, r, sess, "", err.Error())
	case approval != 0:
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
	default:
		s.renderUsers(w, r, sess, creds, "")
	}
}

// addUser creates a console account in the tenant of sess and returns
// local credentials, or the approval it waits for (four eyes for admins).
// The console form and the admin API both call it.
func (s *Server) addUser(ctx context.Context, sess session, add userAddition, reason string) (creds string, approval int64, err error) {
	if !slices.Contains(roles, add.Role) {
		return "", 0, &userError{http.StatusUnprocessableEntity, "unknown role"}
	}
	if sess.Tenant != 0 { // accounts added in a tenant belong to it; NULL is global
		add.Tenant = &sess.Tenant
	}
	add.Login = strings.TrimSpace(add.Login)
	if add.Kind != "oidc" {
		add.Kind = "local"
	}
	if err := add.normalize(); err != nil {
		return "", 0, &userError{http.StatusUnprocessableEntity, err.Error()}
	}
	if add.Role == "admin" && s.settings().FourEyes {
		// a second admin decides; local credentials are shown to the approver,
		// so the requester never holds a second admin account
		id, err := s.requestApproval(ctx, sess, "user.add", add.target(), add, strings.TrimSpace(reason))
		return "", id, err
	}
	err = s.auditAction(ctx, sess.Email, "user.add", add.target(), add.Kind+" "+add.Role, func(tx pgx.Tx) error {
		var err error
		creds, err = add.apply(ctx, tx)
		return err
	})
	return creds, 0, err
}

// userUpdate changes role or enabled state; self lockout and losing the last admin are refused.
func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request, sess session) {
	c := userChange{Role: r.FormValue("role"), Disabled: r.FormValue("disabled") == "on"}
	var err error
	if c.Tags, err = parseTags(r.FormValue("scope_tags")); err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	if c.Groups, err = parseScopeGroups(r.FormValue("scope_groups")); err != nil {
		s.renderUsers(w, r, sess, "", err.Error())
		return
	}
	approval, err := s.updateUser(r.Context(), sess, r.FormValue("login"), c, r.FormValue("reason"))
	s.userDone(w, r, sess, "", approval, err)
}

// updateUser stores the role, state and scope of an account, or asks for
// approval when four eyes approval covers the change. The console form and
// the admin API both call it.
func (s *Server) updateUser(ctx context.Context, sess session, login string, c userChange, reason string) (int64, error) {
	if !slices.Contains(roles, c.Role) {
		return 0, &userError{http.StatusUnprocessableEntity, "unknown role"}
	}
	if !s.userInTenant(ctx, sess, login) {
		return 0, &userError{http.StatusNotFound, "user not found"}
	}
	if login == sess.Email && (c.Disabled || c.Role != sess.Role) {
		return 0, &userError{http.StatusUnprocessableEntity, "you cannot demote or disable your own account"}
	}
	if c.Role == "admin" {
		c.Tags, c.Groups = []string{}, []string{} // admins are never scoped
	}
	cur := s.currentRole(ctx, login)
	if cur == "" {
		return 0, &userError{http.StatusNotFound, "user not found"}
	}
	if (cur != c.Role || cur == "admin") && s.settings().FourEyes {
		return s.requestApproval(ctx, sess, "user.update", login, c, strings.TrimSpace(reason))
	}
	err := s.auditAction(ctx, sess.Email, "user.update", login, c.String(), func(tx pgx.Tx) error {
		return s.applyUserChange(ctx, tx, login, c)
	})
	if err == nil && cur != c.Role {
		s.notifyRoleChange(sess.Email, login, cur, c.Role, "")
	}
	return 0, err
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

// userInTenant reports whether the account belongs to the tenant of sess;
// in the global view every account does.
func (s *Server) userInTenant(ctx context.Context, sess session, login string) bool {
	if sess.Tenant == 0 {
		return true
	}
	q, key := `SELECT EXISTS(SELECT 1 FROM console_users WHERE email=$1 AND tenant_id=$2)`, login
	if name, ok := strings.CutPrefix(login, localPrefix); ok {
		q, key = `SELECT EXISTS(SELECT 1 FROM local_admins WHERE name=$1 AND tenant_id=$2)`, name
	}
	var ok bool
	err := s.db.QueryRow(ctx, q, key, sess.Tenant).Scan(&ok)
	return err == nil && ok
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
			return &userError{http.StatusUnprocessableEntity, "at least one active administrator must remain"}
		}
		var isAdmin bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM console_users WHERE email=$1 AND role='admin' AND NOT disabled)
			OR EXISTS(SELECT 1 FROM local_admins WHERE 'local:' || name = $1 AND role='admin' AND NOT disabled)`, login).Scan(&isAdmin); err != nil {
			return err
		}
		if isAdmin && n < 2 && s.settings().FourEyes {
			return &userError{http.StatusUnprocessableEntity, "four eyes approval is on: at least two active administrators must remain"}
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
		err = &userError{http.StatusNotFound, "user not found"}
	}
	return err
}

func (s *Server) userReset(w http.ResponseWriter, r *http.Request, sess session) {
	creds, approval, err := s.resetUser(r.Context(), sess, r.FormValue("login"), r.FormValue("reason"))
	s.userDone(w, r, sess, creds, approval, err)
}

// resetUser replaces password and TOTP of a local account and returns the
// new credentials, or the approval it waits for (four eyes for admins: the
// approver gets the credentials). The console form and the admin API both
// call it.
func (s *Server) resetUser(ctx context.Context, sess session, login, reason string) (creds string, approval int64, err error) {
	name, ok := strings.CutPrefix(login, localPrefix)
	if !ok {
		return "", 0, &userError{http.StatusUnprocessableEntity, "only local accounts have credentials to reset"}
	}
	if localPrefix+name == sess.Email {
		return "", 0, &userError{http.StatusUnprocessableEntity, "change your own credentials in your profile"}
	}
	if !s.userInTenant(ctx, sess, localPrefix+name) {
		return "", 0, &userError{http.StatusNotFound, "user not found"}
	}
	if s.currentRole(ctx, localPrefix+name) == "admin" && s.settings().FourEyes {
		// the new credentials are shown to the approving admin, not the requester
		id, err := s.requestApproval(ctx, sess, "user.reset", localPrefix+name, map[string]string{"login": localPrefix + name}, strings.TrimSpace(reason))
		return "", id, err
	}
	err = s.auditAction(ctx, sess.Email, "user.reset", localPrefix+name, "new password and TOTP", func(tx pgx.Tx) error {
		var err error
		creds, err = localReset(ctx, tx, name)
		return err
	})
	return creds, 0, err
}

// userAddition is a new console account waiting for four eyes approval.
type userAddition struct {
	Kind   string `json:"kind"` // oidc | local
	Login  string `json:"login"`
	Role   string `json:"role"`
	Tenant *int64 `json:"tenant,omitempty"`
}

func (a *userAddition) normalize() error {
	if a.Kind == "oidc" {
		addr, err := mail.ParseAddress(a.Login)
		if err != nil || addr.Name != "" {
			return errors.New("enter a plain email address")
		}
		a.Login = strings.ToLower(addr.Address)
		return nil
	}
	a.Kind, a.Login = "local", strings.ToLower(a.Login)
	if !localNameRe.MatchString(a.Login) {
		return errors.New("local name: 2..32 lowercase letters, digits, dot, dash, underscore")
	}
	return nil
}

// target is the login the account will have.
func (a userAddition) target() string {
	if a.Kind == "local" {
		return localPrefix + a.Login
	}
	return a.Login
}

// apply creates the account in tx and returns local credentials ("" for OIDC).
func (a userAddition) apply(ctx context.Context, tx pgx.Tx) (string, error) {
	if a.Kind == "oidc" {
		tag, err := tx.Exec(ctx, `INSERT INTO console_users(email, role, tenant_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, a.Login, a.Role, a.Tenant)
		if err == nil && tag.RowsAffected() == 0 {
			err = &userError{http.StatusConflict, "user exists already"}
		}
		return "", err
	}
	creds, err := localAdd(ctx, tx, a.Login, a.Role)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `UPDATE local_admins SET tenant_id=$2 WHERE name=$1`, a.Login, a.Tenant)
	return creds, err
}
