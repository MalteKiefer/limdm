package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SCIM 2.0 (RFC 7643/7644) provisioning endpoint for users and groups.
// Covers what Okta, Microsoft Entra ID, authentik and JumpCloud send,
// including Entra's PATCH quirks (string booleans, filtered paths).

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimEnterprise  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	scimList        = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimError       = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatch       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

func (s *Server) scimRoutes(mux *http.ServeMux) {
	h := func(f http.HandlerFunc) http.HandlerFunc { return s.scimAuth(f) }
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", h(s.scimConfig))
	mux.HandleFunc("GET /scim/v2/ResourceTypes", h(s.scimResourceTypes))
	mux.HandleFunc("GET /scim/v2/Schemas", h(func(w http.ResponseWriter, r *http.Request) {
		scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimList}, "totalResults": 0, "Resources": []any{}})
	}))
	mux.HandleFunc("GET /scim/v2/Users", h(s.scimListUsers))
	mux.HandleFunc("POST /scim/v2/Users", h(s.scimCreateUser))
	mux.HandleFunc("GET /scim/v2/Users/{id}", h(s.scimGetUser))
	mux.HandleFunc("PUT /scim/v2/Users/{id}", h(s.scimReplaceUser))
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", h(s.scimPatchUser))
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", h(s.scimDeleteUser))
	mux.HandleFunc("GET /scim/v2/Groups", h(s.scimListGroups))
	mux.HandleFunc("POST /scim/v2/Groups", h(s.scimCreateGroup))
	mux.HandleFunc("GET /scim/v2/Groups/{id}", h(s.scimGetGroup))
	mux.HandleFunc("PUT /scim/v2/Groups/{id}", h(s.scimReplaceGroup))
	mux.HandleFunc("PATCH /scim/v2/Groups/{id}", h(s.scimPatchGroup))
	mux.HandleFunc("DELETE /scim/v2/Groups/{id}", h(s.scimDeleteGroup))
}

func scimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func scimErr(w http.ResponseWriter, status int, detail string) {
	scimJSON(w, status, map[string]any{"schemas": []string{scimError}, "status": strconv.Itoa(status), "detail": detail})
}

// scimAuth checks the bearer token against the stored hash.
func (s *Server) scimAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var raw []byte
		var stored struct {
			Hash string `json:"token_sha256"`
		}
		err := s.db.QueryRow(r.Context(), `SELECT value FROM settings WHERE key='scim'`).Scan(&raw)
		if err == nil {
			err = json.Unmarshal(raw, &stored)
		}
		if !ok || err != nil || stored.Hash == "" || subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%x", sha(tok))), []byte(stored.Hash)) != 1 {
			if !s.limit.allow("scim:"+clientIP(r), 20, 5*time.Minute) {
				scimErr(w, http.StatusTooManyRequests, "too many failed attempts")
				return
			}
			scimErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

func (s *Server) scimConfig(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "Token from the LiMDM directory page"}},
	})
}

func (s *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimList}, "totalResults": 2, "Resources": []map[string]any{
		{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema, "schemaExtensions": []map[string]any{{"schema": scimEnterprise, "required": false}}},
		{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema},
	}})
}

// ---- users ----

type scimName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimUser struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id,omitempty"`
	ExternalID  string           `json:"externalId,omitempty"`
	UserName    string           `json:"userName"`
	Name        *scimName        `json:"name,omitempty"`
	DisplayName string           `json:"displayName,omitempty"`
	Emails      []scimEmail      `json:"emails,omitempty"`
	Active      *bool            `json:"active,omitempty"`
	Title       string           `json:"title,omitempty"`
	Enterprise  *scimEntExt      `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta        map[string]any   `json:"meta,omitempty"`
	Groups      []map[string]any `json:"groups,omitempty"`
}

type scimEntExt struct {
	Department string `json:"department,omitempty"`
}

func (u scimUser) email() string {
	for _, e := range u.Emails {
		if e.Primary {
			return strings.ToLower(e.Value)
		}
	}
	if len(u.Emails) > 0 {
		return strings.ToLower(u.Emails[0].Value)
	}
	if strings.Contains(u.UserName, "@") {
		return strings.ToLower(u.UserName)
	}
	return ""
}

func (u scimUser) display() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name != nil {
		if u.Name.Formatted != "" {
			return u.Name.Formatted
		}
		return strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
	}
	return ""
}

func toSCIMUser(base string, u dirUser) scimUser {
	active := u.Active
	given, family, _ := strings.Cut(u.DisplayName, " ")
	out := scimUser{Schemas: []string{scimUserSchema, scimEnterprise}, ID: strconv.FormatInt(u.ID, 10), ExternalID: u.ExternalID,
		UserName: u.UserName, DisplayName: u.DisplayName, Name: &scimName{GivenName: given, FamilyName: family, Formatted: u.DisplayName},
		Emails: []scimEmail{{Value: u.Email, Type: "work", Primary: true}}, Active: &active, Title: u.Title,
		Enterprise: &scimEntExt{Department: u.Department},
		Meta:       map[string]any{"resourceType": "User", "location": base + "/Users/" + strconv.FormatInt(u.ID, 10)}}
	for _, g := range u.Groups {
		out.Groups = append(out.Groups, map[string]any{"display": g})
	}
	return out
}

const dirUserCols = `u.id, u.external_id, u.source, u.user_name, u.email, u.display_name, u.department, u.title, u.active,
	coalesce((SELECT array_agg(g.name ORDER BY g.name) FROM dir_members m JOIN dir_groups g ON g.id=m.group_id WHERE m.user_id=u.id), '{}')`

func (s *Server) scimBase() string { return s.cfg.PublicURL + "/scim/v2" }

func (s *Server) loadDirUser(ctx context.Context, id string) (dirUser, error) {
	rows, err := s.db.Query(ctx, `SELECT `+dirUserCols+` FROM dir_users u WHERE u.id::text=$1 AND u.source='scim'`, id)
	if err != nil {
		return dirUser{}, err
	}
	return pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[dirUser])
}

// filterRe accepts the equality filters identity providers send.
var filterRe = regexp.MustCompile(`(?i)^\s*(userName|externalId|displayName|emails\.value|emails\[type eq "work"\]\.value)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

func parseFilter(f string) (attr, value string, err error) {
	if strings.TrimSpace(f) == "" {
		return "", "", nil
	}
	m := filterRe.FindStringSubmatch(f)
	if m == nil {
		return "", "", errors.New("unsupported filter")
	}
	return strings.ToLower(m[1]), strings.ReplaceAll(m[2], `\"`, `"`), nil
}

func paging(r *http.Request) (start, count int) {
	start, _ = strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil {
		count = 100
	}
	return max(start, 1), min(max(count, 0), 200)
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	attr, val, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cond, args := "u.source='scim'", []any{}
	switch attr {
	case "username":
		cond, args = cond+" AND lower(u.user_name)=lower($1)", append(args, val)
	case "externalid":
		cond, args = cond+" AND u.external_id=$1", append(args, val)
	case "emails.value", `emails[type eq "work"].value`:
		cond, args = cond+" AND u.email=lower($1)", append(args, val)
	case "displayname":
		cond, args = cond+" AND u.display_name=$1", append(args, val)
	}
	start, count := paging(r)
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM dir_users u WHERE `+cond, args...).Scan(&total); err != nil {
		scimErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT `+dirUserCols+` FROM dir_users u WHERE `+cond+
		fmt.Sprintf(" ORDER BY u.id OFFSET %d LIMIT %d", start-1, count), args...)
	if err != nil {
		scimErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	users, err := pgx.CollectRows(rows, pgx.RowToStructByPos[dirUser])
	if err != nil {
		scimErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	res := make([]scimUser, 0, len(users))
	for _, u := range users {
		res = append(res, toSCIMUser(s.scimBase(), u))
	}
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimList}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(res), "Resources": res})
}

func (s *Server) writeUser(ctx context.Context, id string, u scimUser) (string, int, error) {
	email := u.email()
	if u.UserName == "" || email == "" || !strings.Contains(email, "@") {
		return "", http.StatusBadRequest, errors.New("userName and an email are required")
	}
	active := u.Active == nil || *u.Active
	dept := ""
	if u.Enterprise != nil {
		dept = u.Enterprise.Department
	}
	var newID int64
	var err error
	action := "directory.scim_user_create"
	if id == "" {
		err = s.db.QueryRow(ctx, `INSERT INTO dir_users(external_id, source, user_name, email, display_name, department, title, active)
			VALUES ($1,'scim',$2,$3,$4,$5,$6,$7) RETURNING id`, u.ExternalID, u.UserName, email, u.display(), dept, u.Title, active).Scan(&newID)
		if err != nil && strings.Contains(err.Error(), "duplicate key") {
			return "", http.StatusConflict, errors.New("user exists")
		}
	} else {
		action = "directory.scim_user_replace"
		err = s.db.QueryRow(ctx, `UPDATE dir_users SET external_id=$2, user_name=$3, email=$4, display_name=$5, department=$6, title=$7, active=$8, updated_at=now()
			WHERE id::text=$1 AND source='scim' RETURNING id`, id, u.ExternalID, u.UserName, email, u.display(), dept, u.Title, active).Scan(&newID)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", http.StatusNotFound, errors.New("user not found")
		}
	}
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	sid := strconv.FormatInt(newID, 10)
	s.auditSystem(ctx, "scim", action, sid, email+fmt.Sprintf(" active=%v", active))
	return sid, http.StatusOK, nil
}

// auditSystem records provisioning changes; failures are logged, not fatal.
func (s *Server) auditSystem(ctx context.Context, actor, action, target, detail string) {
	if err := s.auditAction(ctx, actor, action, target, detail, nil); err != nil {
		s.log.Error("audit", "action", action, "err", err)
	}
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var u scimUser
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, code, err := s.writeUser(r.Context(), "", u)
	if err != nil {
		scimErr(w, code, err.Error())
		return
	}
	s.respondUser(w, r.Context(), id, http.StatusCreated)
}

func (s *Server) respondUser(w http.ResponseWriter, ctx context.Context, id string, status int) {
	u, err := s.loadDirUser(ctx, id)
	if err != nil {
		scimErr(w, http.StatusNotFound, "user not found")
		return
	}
	scimJSON(w, status, toSCIMUser(s.scimBase(), u))
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	s.respondUser(w, r.Context(), r.PathValue("id"), http.StatusOK)
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request) {
	var u scimUser
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, code, err := s.writeUser(r.Context(), r.PathValue("id"), u)
	if err != nil {
		scimErr(w, code, err.Error())
		return
	}
	s.respondUser(w, r.Context(), id, http.StatusOK)
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// scimBool accepts true, "True" and "false" alike (Entra sends strings).
func scimBool(raw json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, err
	}
	return strconv.ParseBool(strings.ToLower(s))
}

func scimString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// applyUserPatch applies one operation to the user resource.
func applyUserPatch(u *scimUser, op patchOp) error {
	remove := strings.EqualFold(op.Op, "remove")
	path := strings.ToLower(op.Path)
	if path == "" { // value carries attributes
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &attrs); err != nil {
			return err
		}
		for k, v := range attrs {
			if err := applyUserPatch(u, patchOp{Op: op.Op, Path: k, Value: v}); err != nil {
				return err
			}
		}
		return nil
	}
	if u.Name == nil {
		u.Name = &scimName{}
	}
	if u.Enterprise == nil {
		u.Enterprise = &scimEntExt{}
	}
	str := func() string {
		if remove {
			return ""
		}
		return scimString(op.Value)
	}
	switch path {
	case "active":
		b, err := scimBool(op.Value)
		if err != nil {
			return errors.New("active must be a boolean")
		}
		u.Active = &b
	case "username":
		u.UserName = str()
	case "displayname":
		u.DisplayName = str()
	case "title":
		u.Title = str()
	case "externalid":
		u.ExternalID = str()
	case "name.givenname":
		u.Name.GivenName, u.DisplayName = str(), ""
	case "name.familyname":
		u.Name.FamilyName, u.DisplayName = str(), ""
	case "name.formatted":
		u.Name.Formatted = str()
	case `emails[type eq "work"].value`, "emails.value":
		u.Emails = []scimEmail{{Value: str(), Type: "work", Primary: true}}
	case "emails":
		var es []scimEmail
		if !remove {
			if err := json.Unmarshal(op.Value, &es); err != nil {
				return err
			}
		}
		u.Emails = es
	case strings.ToLower(scimEnterprise) + ":department", "department":
		u.Enterprise.Department = str()
	case strings.ToLower(scimEnterprise):
		var ext scimEntExt
		if err := json.Unmarshal(op.Value, &ext); err == nil {
			u.Enterprise.Department = ext.Department
		}
	}
	return nil // unknown attributes are ignored, as RFC 7644 allows for unsupported ones
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cur, err := s.loadDirUser(ctx, r.PathValue("id"))
	if err != nil {
		scimErr(w, http.StatusNotFound, "user not found")
		return
	}
	var body struct {
		Operations []patchOp `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u := toSCIMUser(s.scimBase(), cur)
	for _, op := range body.Operations {
		if err := applyUserPatch(&u, op); err != nil {
			scimErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	id, code, err := s.writeUser(ctx, r.PathValue("id"), u)
	if err != nil {
		scimErr(w, code, err.Error())
		return
	}
	s.respondUser(w, ctx, id, http.StatusOK)
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	tag, err := s.db.Exec(r.Context(), `DELETE FROM dir_users WHERE id::text=$1 AND source='scim'`, r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		scimErr(w, http.StatusNotFound, "user not found")
		return
	}
	s.auditSystem(r.Context(), "scim", "directory.scim_user_delete", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

// ---- groups ----

type scimGroup struct {
	Schemas     []string            `json:"schemas"`
	ID          string              `json:"id,omitempty"`
	ExternalID  string              `json:"externalId,omitempty"`
	DisplayName string              `json:"displayName"`
	Members     []map[string]string `json:"members,omitempty"`
	Meta        map[string]any      `json:"meta,omitempty"`
}

func (s *Server) loadGroup(ctx context.Context, id string) (scimGroup, error) {
	var g scimGroup
	var gid int64
	err := s.db.QueryRow(ctx, `SELECT id, external_id, name FROM dir_groups WHERE id::text=$1 AND source='scim'`, id).Scan(&gid, &g.ExternalID, &g.DisplayName)
	if err != nil {
		return g, err
	}
	rows, err := s.db.Query(ctx, `SELECT u.id::text, coalesce(nullif(u.display_name,''), u.email) FROM dir_members m JOIN dir_users u ON u.id=m.user_id WHERE m.group_id=$1 ORDER BY u.id`, gid)
	if err != nil {
		return g, err
	}
	defer rows.Close()
	for rows.Next() {
		var mid, disp string
		if err := rows.Scan(&mid, &disp); err != nil {
			return g, err
		}
		g.Members = append(g.Members, map[string]string{"value": mid, "display": disp, "$ref": s.scimBase() + "/Users/" + mid})
	}
	g.Schemas, g.ID = []string{scimGroupSchema}, strconv.FormatInt(gid, 10)
	g.Meta = map[string]any{"resourceType": "Group", "location": s.scimBase() + "/Groups/" + g.ID}
	return g, rows.Err()
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	attr, val, err := parseFilter(r.URL.Query().Get("filter"))
	if err != nil {
		scimErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cond, args := "source='scim'", []any{}
	switch attr {
	case "displayname":
		cond, args = cond+" AND name=$1", append(args, val)
	case "externalid":
		cond, args = cond+" AND external_id=$1", append(args, val)
	}
	start, count := paging(r)
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM dir_groups WHERE `+cond, args...).Scan(&total); err != nil {
		scimErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id::text FROM dir_groups WHERE `+cond+fmt.Sprintf(" ORDER BY id OFFSET %d LIMIT %d", start-1, count), args...)
	if err != nil {
		scimErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		scimErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	res := []scimGroup{}
	for _, id := range ids {
		g, err := s.loadGroup(r.Context(), id)
		if err != nil {
			scimErr(w, http.StatusInternalServerError, "query failed")
			return
		}
		if r.URL.Query().Get("excludedAttributes") == "members" {
			g.Members = nil
		}
		res = append(res, g)
	}
	scimJSON(w, http.StatusOK, map[string]any{"schemas": []string{scimList}, "totalResults": total, "startIndex": start, "itemsPerPage": len(res), "Resources": res})
}

// writeGroup creates or replaces a group and, when members != nil, its membership.
func (s *Server) writeGroup(ctx context.Context, id string, g scimGroup, members []string) (string, int, error) {
	if strings.TrimSpace(g.DisplayName) == "" {
		return "", http.StatusBadRequest, errors.New("displayName is required")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	defer tx.Rollback(ctx)
	var gid int64
	if id == "" {
		ext := g.ExternalID
		if ext == "" {
			ext = randToken(12)
		}
		err = tx.QueryRow(ctx, `INSERT INTO dir_groups(external_id, source, name) VALUES ($1,'scim',$2) RETURNING id`, ext, g.DisplayName).Scan(&gid)
		if err != nil && strings.Contains(err.Error(), "duplicate key") {
			return "", http.StatusConflict, errors.New("group exists")
		}
	} else {
		err = tx.QueryRow(ctx, `UPDATE dir_groups SET name=$2, updated_at=now() WHERE id::text=$1 AND source='scim' RETURNING id`, id, g.DisplayName).Scan(&gid)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", http.StatusNotFound, errors.New("group not found")
		}
	}
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	if members != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM dir_members WHERE group_id=$1`, gid); err != nil {
			return "", http.StatusInternalServerError, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dir_members(group_id, user_id) SELECT $1, id FROM dir_users WHERE id::text = ANY($2) ON CONFLICT DO NOTHING`, gid, members); err != nil {
			return "", http.StatusInternalServerError, err
		}
	}
	if err := audit(ctx, tx, "scim", "directory.scim_group_write", strconv.FormatInt(gid, 10), fmt.Sprintf("%s members=%d", g.DisplayName, len(members))); err != nil {
		return "", http.StatusInternalServerError, err
	}
	return strconv.FormatInt(gid, 10), http.StatusOK, tx.Commit(ctx)
}

func memberIDs(ms []map[string]string) []string {
	out := []string{}
	for _, m := range ms {
		if v := m["value"]; v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	var g scimGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, code, err := s.writeGroup(r.Context(), "", g, memberIDs(g.Members))
	if err != nil {
		scimErr(w, code, err.Error())
		return
	}
	s.respondGroup(w, r.Context(), id, http.StatusCreated)
}

func (s *Server) respondGroup(w http.ResponseWriter, ctx context.Context, id string, status int) {
	g, err := s.loadGroup(ctx, id)
	if err != nil {
		scimErr(w, http.StatusNotFound, "group not found")
		return
	}
	scimJSON(w, status, g)
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	s.respondGroup(w, r.Context(), r.PathValue("id"), http.StatusOK)
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request) {
	var g scimGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, code, err := s.writeGroup(r.Context(), r.PathValue("id"), g, memberIDs(g.Members))
	if err != nil {
		scimErr(w, code, err.Error())
		return
	}
	s.respondGroup(w, r.Context(), id, http.StatusOK)
}

var memberFilterRe = regexp.MustCompile(`(?i)^members\[value eq "([^"]+)"\]$`)

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, err := s.loadGroup(ctx, r.PathValue("id"))
	if err != nil {
		scimErr(w, http.StatusNotFound, "group not found")
		return
	}
	var body struct {
		Operations []patchOp `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		scimErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	members := memberIDs(g.Members)
	for _, op := range body.Operations {
		kind, path := strings.ToLower(op.Op), strings.ToLower(op.Path)
		var vals []map[string]string
		_ = json.Unmarshal(op.Value, &vals)
		switch {
		case path == "displayname" || (path == "" && kind != "remove"):
			if path == "" {
				var attrs struct {
					DisplayName string              `json:"displayName"`
					Members     []map[string]string `json:"members"`
				}
				if json.Unmarshal(op.Value, &attrs) == nil {
					if attrs.DisplayName != "" {
						g.DisplayName = attrs.DisplayName
					}
					if attrs.Members != nil {
						members = memberIDs(attrs.Members)
					}
				}
			} else {
				g.DisplayName = scimString(op.Value)
			}
		case path == "members" && kind == "add":
			for _, id := range memberIDs(vals) {
				if !containsStr(members, id) {
					members = append(members, id)
				}
			}
		case path == "members" && kind == "replace":
			members = memberIDs(vals)
		case path == "members" && kind == "remove":
			if len(vals) == 0 {
				members = []string{}
			}
			for _, id := range memberIDs(vals) {
				members = removeStr(members, id)
			}
		case memberFilterRe.MatchString(op.Path) && kind == "remove":
			members = removeStr(members, memberFilterRe.FindStringSubmatch(op.Path)[1])
		}
	}
	id, code, err := s.writeGroup(ctx, r.PathValue("id"), g, members)
	if err != nil {
		scimErr(w, code, err.Error())
		return
	}
	s.respondGroup(w, ctx, id, http.StatusOK)
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func removeStr(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	tag, err := s.db.Exec(r.Context(), `DELETE FROM dir_groups WHERE id::text=$1 AND source='scim'`, r.PathValue("id"))
	if err != nil || tag.RowsAffected() == 0 {
		scimErr(w, http.StatusNotFound, "group not found")
		return
	}
	s.auditSystem(r.Context(), "scim", "directory.scim_group_delete", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}
