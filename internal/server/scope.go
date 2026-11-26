package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Role scopes: helpdesk and auditor accounts can be limited to device tags
// or directory groups (the primary user's groups). Every device listing,
// device page, command, export and recovery key path adds the scope
// condition, so a device outside the scope is not found (deny by default).
// Admins are never scoped.

// RoleGroup gives members of a directory group (Google, SCIM) or an OIDC
// group claim a console role, optionally limited to device tags.
type RoleGroup struct {
	Group string   `json:"group"`
	Role  string   `json:"role"`
	Tags  []string `json:"tags,omitempty"`
}

// parseRoleGroups reads one mapping per line: "group; role; tag,tag".
func parseRoleGroups(text string) ([]RoleGroup, error) {
	var out []RoleGroup
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, ";")
		if len(f) < 2 || len(f) > 3 {
			return nil, fmt.Errorf("role mapping %q: expected 'group; role; tags'", strings.TrimSpace(line))
		}
		g := RoleGroup{Group: strings.TrimSpace(f[0]), Role: strings.TrimSpace(f[1])}
		if g.Group == "" || len(g.Group) > 200 || !slices.Contains(roles, g.Role) {
			return nil, fmt.Errorf("role mapping %q: a group name and the role admin, helpdesk or auditor", strings.TrimSpace(line))
		}
		if len(f) == 3 {
			tags, err := parseTags(f[2])
			if err != nil {
				return nil, err
			}
			if g.Role == "admin" && len(tags) > 0 {
				return nil, fmt.Errorf("role mapping %q: admins cannot be limited to tags", strings.TrimSpace(line))
			}
			g.Tags = tags
		}
		out = append(out, g)
	}
	if len(out) > 100 {
		return nil, errors.New("at most 100 role mappings")
	}
	return out, nil
}

func roleGroupsText(list []RoleGroup) string {
	var b strings.Builder
	for _, g := range list {
		fmt.Fprintf(&b, "%s; %s", g.Group, g.Role)
		if len(g.Tags) > 0 {
			b.WriteString("; " + strings.Join(g.Tags, ","))
		}
		b.WriteString("\n")
	}
	return b.String()
}

var roleRank = map[string]int{"auditor": 1, "helpdesk": 2, "admin": 3}

// mapRole picks the strongest role the groups grant and the tags it is
// limited to; nil tags mean every device (one unlimited mapping is enough).
func mapRole(mappings []RoleGroup, groups []string) (string, []string) {
	role := ""
	for _, m := range mappings {
		if slices.Contains(groups, m.Group) && roleRank[m.Role] > roleRank[role] {
			role = m.Role
		}
	}
	if role == "" {
		return "", nil
	}
	var tags []string
	for _, m := range mappings {
		if m.Role != role || !slices.Contains(groups, m.Group) {
			continue
		}
		if len(m.Tags) == 0 {
			return role, nil
		}
		for _, t := range m.Tags {
			if !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
	}
	return role, tags
}

// memberGroups lists the directory groups of an active directory user plus
// extra names (OIDC group claim), and the names the user holds only through
// SCIM groups.
func (s *Server) memberGroups(ctx context.Context, email string, extra []string) ([]string, []string, error) {
	rows, err := s.db.Query(ctx, `SELECT g.name, g.source FROM dir_groups g JOIN dir_members m ON m.group_id=g.id
		JOIN dir_users u ON u.id=m.user_id WHERE lower(u.email)=$1 AND u.active`, email)
	if err != nil {
		return nil, nil, err
	}
	type member struct{ Name, Source string }
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[member])
	if err != nil {
		return nil, nil, err
	}
	names := append([]string{}, extra...)
	var scim []string
	for _, m := range list {
		names = append(names, m.Name)
		if m.Source == "scim" {
			scim = append(scim, m.Name)
		}
	}
	scimOnly := slices.DeleteFunc(scim, func(n string) bool {
		return slices.Contains(extra, n) || slices.ContainsFunc(list, func(m member) bool { return m.Name == n && m.Source != "scim" })
	})
	return names, scimOnly, nil
}

// adminMappings drops the mappings that must not grant the admin role:
// all of them while four eyes approval is on (an administrator needs an
// approved account), and those of groups the user holds only through SCIM,
// whose static token would otherwise create global administrators.
func adminMappings(m []RoleGroup, fourEyes bool, scimOnly []string) []RoleGroup {
	return slices.DeleteFunc(slices.Clone(m), func(g RoleGroup) bool {
		return g.Role == "admin" && (fourEyes || slices.Contains(scimOnly, g.Group))
	})
}

// groupRole derives the role of a console user created from a group mapping.
func (s *Server) groupRole(ctx context.Context, email string, claim []string) (string, []string) {
	m := s.settings().RoleGroups
	if len(m) == 0 {
		return "", nil
	}
	groups, scimOnly, err := s.memberGroups(ctx, email, claim)
	if err != nil {
		s.log.Error("directory groups", "err", err)
		return "", nil
	}
	return mapRole(adminMappings(m, s.settings().FourEyes, scimOnly), groups)
}

// syncGroupUser runs at OIDC sign in: a person without an explicit console
// account whose groups map to a role gets an account marked from_group,
// whose role is derived again on every request.
func (s *Server) syncGroupUser(ctx context.Context, email string, claim []string) error {
	if len(s.settings().RoleGroups) == 0 {
		return nil
	}
	if claim == nil {
		claim = []string{}
	}
	var fromGroup bool
	err := s.db.QueryRow(ctx, `SELECT from_group FROM console_users WHERE email=$1`, email).Scan(&fromGroup)
	switch {
	case err == nil && !fromGroup:
		return nil // explicit accounts win
	case err == nil:
		role, _ := s.groupRole(ctx, email, claim)
		if role == "" {
			role = "auditor" // the column needs a role; account() refuses the user anyway
		}
		_, err = s.db.Exec(ctx, `UPDATE console_users SET oidc_groups=$2, role=$3 WHERE email=$1 AND from_group`, email, claim, role)
		return err
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	role, tags := s.groupRole(ctx, email, claim)
	if role == "" {
		return nil
	}
	return s.auditAction(ctx, "system", "user.add", email, fmt.Sprintf("oidc %s from directory group, tags=%v", role, tags), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO console_users(email, role, from_group, oidc_groups) VALUES ($1,$2,true,$3) ON CONFLICT DO NOTHING`, email, role, claim)
		return err
	})
}

// claimGroups reads the optional "groups" claim leniently: providers that
// send it in another shape must not break sign in.
func claimGroups(raw json.RawMessage) []string {
	var g []string
	if len(raw) == 0 || json.Unmarshal(raw, &g) != nil {
		return nil
	}
	return g
}

// loadScope fills the scope of a non admin session.
func (s *Server) loadScope(ctx context.Context, sess *session) error {
	sess.Tags, sess.Groups = nil, nil
	if sess.Role == "admin" {
		return nil
	}
	var fromGroup bool
	var claim []string
	var err error
	if name, ok := strings.CutPrefix(sess.Email, localPrefix); ok {
		err = s.db.QueryRow(ctx, `SELECT scope_tags, scope_groups FROM local_admins WHERE name=$1`, name).Scan(&sess.Tags, &sess.Groups)
	} else {
		err = s.db.QueryRow(ctx, `SELECT scope_tags, scope_groups, from_group, oidc_groups FROM console_users WHERE email=$1`, sess.Email).
			Scan(&sess.Tags, &sess.Groups, &fromGroup, &claim)
	}
	if err != nil {
		return err
	}
	if fromGroup && len(sess.Tags) == 0 && len(sess.Groups) == 0 {
		_, sess.Tags = s.groupRole(ctx, sess.Email, claim)
	}
	return nil
}

// scoped reports whether sess sees only part of the fleet.
func (sess session) scoped() bool {
	return sess.Role != "admin" && (len(sess.Tags) > 0 || len(sess.Groups) > 0)
}

// scopeCond is a condition on devices d limiting sess to its tenant and
// its scope, with its arguments numbered after n existing ones. It is the
// one place that builds the device filter of a console session or token.
func scopeCond(sess session, n int) (string, []any) {
	tcond, targs := tenantCond(sess, "d.tenant_id", n)
	if !sess.scoped() {
		return tcond, targs
	}
	n += len(targs)
	tags, groups := sess.Tags, sess.Groups
	if tags == nil {
		tags = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	return tcond + fmt.Sprintf(` AND (d.tags && $%d::text[] OR d.primary_user_id IN (SELECT m.user_id FROM dir_members m
		JOIN dir_groups g ON g.id=m.group_id WHERE g.name = ANY($%d::text[])))`, n+1, n+2), append(targs, tags, groups)
}

// auditScope limits audit entries to the tenant of sess and, for scoped
// accounts, to those about devices in the scope.
func auditScope(sess session, n int) (string, []any) {
	tcond, targs := tenantCond(sess, "tenant_id", n)
	if !sess.scoped() {
		return tcond, targs
	}
	cond, args := scopeCond(sess, n+len(targs))
	return tcond + ` AND target IN (SELECT d.id FROM devices d WHERE ` + cond + `)`, append(targs, args...)
}

// inScope reports whether the device exists within the scope of sess.
func (s *Server) inScope(ctx context.Context, sess session, id string) bool {
	cond, args := scopeCond(sess, 1)
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices d WHERE d.id=$1 AND `+cond+`)`, append([]any{id}, args...)...).Scan(&ok)
	return err == nil && ok
}

// activeAdmins counts enabled admin accounts (OIDC and local); accounts from
// group mappings do not count, they lose the admin role while four eyes
// approval is on (adminMappings).
func (s *Server) activeAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM console_users WHERE role='admin' AND NOT disabled AND NOT from_group)
		+ (SELECT count(*) FROM local_admins WHERE role='admin' AND NOT disabled)`).Scan(&n)
	return n, err
}

// parseScopeGroups reads comma separated directory group names.
func parseScopeGroups(text string) ([]string, error) {
	out := []string{}
	for _, g := range strings.Split(text, ",") {
		g = strings.TrimSpace(g)
		if g == "" || slices.Contains(out, g) {
			continue
		}
		if len(g) > 200 {
			return nil, errors.New("group names: up to 200 characters")
		}
		out = append(out, g)
	}
	if len(out) > 50 {
		return nil, errors.New("at most 50 groups")
	}
	return out, nil
}
