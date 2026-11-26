package server

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// The admin REST API lives on the console listener under /api/v1/. Every
// action goes through the same functions the console uses, so rules,
// validation and audit entries stay identical. Callers authenticate with a
// bearer token created on the API tokens page; there are no cookies, so
// there is nothing for CSRF to abuse.

//go:embed openapi.json
var openAPIDoc []byte

// apiRoles are the roles a token can carry; metrics tokens only read /metrics.
var apiRoles = []string{"admin", "helpdesk", "auditor", "metrics"}

// apiFail answers an API request with the error's status, or 500.
func (s *Server) apiFail(w http.ResponseWriter, err error) {
	if code, msg := errStatus(err); code != 0 {
		problem(w, code, msg)
		return
	}
	if overloaded(err) {
		s.log.Warn("admin api request: database busy", "err", err, "request_id", requestID(w))
		retryLater(w, 30, "server busy, retry later")
		return
	}
	s.log.Error("admin api request failed", "err", err, "request_id", requestID(w))
	problem(w, http.StatusInternalServerError, "internal error")
}

// ---- tokens ----

type apiCaller struct {
	ID       int64
	Name     string
	Role     string
	ReadOnly bool
	Tags     []string // device scope of a helpdesk or auditor token; empty: every device
	Tenant   int64    // tenant of the token, 0 for global tokens (tenant.go)
	Scopes   []string // tokenScopes it is limited to; empty: all its role allows
}

// actor names the token in the audit log and as creator of commands.
func (c apiCaller) actor() string { return fmt.Sprintf("api:%s#%d", c.Name, c.ID) }

// sess is the session the shared console functions check roles against.
// It carries the token's device scope, so the W2 scope rules apply.
func (c apiCaller) sess() session {
	return session{Email: c.actor(), Role: c.Role, Tags: c.Tags, Tenant: c.Tenant, Super: c.Tenant == 0}
}

const apiCallerKey ctxKey = 2

// auditIP is the client address for audit entries: parsed, never raw header text.
func auditIP(r *http.Request) string {
	if a, err := netip.ParseAddr(clientIP(r)); err == nil {
		return a.String()
	}
	return "invalid"
}

// tokenFailures caps the audit entries of failed token checks: each takes
// the global audit lock, and anyone can send tokens.
var tokenFailures struct {
	sync.Mutex
	window time.Time
	n      int
}

// auditTokenFailure tells whether a failed token check may go to the audit
// log: at most 30 per minute; the process log gets every one.
func auditTokenFailure() bool {
	tokenFailures.Lock()
	defer tokenFailures.Unlock()
	if time.Since(tokenFailures.window) > time.Minute {
		tokenFailures.window, tokenFailures.n = time.Now(), 0
	}
	tokenFailures.n++
	return tokenFailures.n <= 30
}

// bearer checks the request's API token. Failed checks are limited per
// client and token (20 in five minutes, as for SCIM) and per client (200),
// so one script with a wrong token does not lock out valid tokens behind
// the same NAT. A presented but unknown, expired or revoked token is
// audited (at most 30 entries a minute). Valid tokens get 600 requests per
// minute.
func (s *Server) bearer(w http.ResponseWriter, r *http.Request) (apiCaller, bool) {
	ctx := r.Context()
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	th := sha(tok)
	src := "apifail:" + rateKey(r)
	key := src + ":" + hex.EncodeToString(th[:8])
	var c apiCaller
	if s.limit.over(key, 20, 5*time.Minute) || s.limit.over(src, 200, 5*time.Minute) {
		w.Header().Set("Retry-After", "300")
		problem(w, http.StatusTooManyRequests, "too many failed attempts")
		return c, false
	}
	reason := "bearer token required"
	if ok && tok != "" {
		var expires time.Time
		var revoked *time.Time
		var tenantOff bool
		err := s.db.QueryRow(ctx, `SELECT k.id, k.name, k.role, k.read_only, k.scope_tags, coalesce(k.tenant_id, 0), coalesce(t.disabled, false), k.expires_at, k.revoked_at, k.scopes
			FROM api_tokens k LEFT JOIN tenants t ON t.id=k.tenant_id WHERE k.token_hash=$1`, th).
			Scan(&c.ID, &c.Name, &c.Role, &c.ReadOnly, &c.Tags, &c.Tenant, &tenantOff, &expires, &revoked, &c.Scopes)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			reason = "unknown token"
		case err != nil:
			s.apiFail(w, err)
			return c, false
		case revoked != nil:
			reason = "revoked token"
		case time.Now().After(expires):
			reason = "expired token"
		case tenantOff:
			reason = "tenant disabled"
		default:
			reason = ""
		}
		if reason != "" {
			s.log.Warn("api token refused", "reason", reason, "remote", auditIP(r), "request_id", requestID(w))
		}
		if reason != "" && auditTokenFailure() {
			if err := s.auditAction(ctx, "api", "api.auth_failed", c.Name, reason+" from "+auditIP(r), nil); err != nil {
				s.log.Error("audit api.auth_failed", "err", err)
			}
		}
	}
	if reason != "" {
		s.limit.allow(key, 20, 5*time.Minute) // counts the failure
		s.limit.allow(src, 200, 5*time.Minute)
		w.Header().Set("WWW-Authenticate", `Bearer realm="limdm", error="invalid_token"`)
		problem(w, http.StatusUnauthorized, reason)
		return apiCaller{}, false
	}
	if !s.limit.allow("api:"+strconv.FormatInt(c.ID, 10), 600, time.Minute) {
		w.Header().Set("Retry-After", "60")
		problem(w, http.StatusTooManyRequests, "rate limit: 600 requests per minute and token")
		return c, false
	}
	if _, err := s.db.Exec(ctx, `UPDATE api_tokens SET last_used_at=now() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, c.ID); err != nil {
		s.log.Warn("api token last use", "err", err)
	}
	return c, true
}

// deny refuses a request the token's role does not allow, and audits it.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, c apiCaller, msg string) {
	if err := s.auditAction(r.Context(), c.actor(), "api.denied", r.Method+" "+r.URL.Path, "role="+c.Role+" read_only="+strconv.FormatBool(c.ReadOnly), nil); err != nil {
		s.log.Error("audit api.denied", "err", err)
	}
	problem(w, http.StatusForbidden, msg)
}

// routeScope is the token scope a route needs (tokenScopes).
func routeScope(r *http.Request, level string) string {
	path := strings.TrimPrefix(r.Pattern, r.Method+" ")
	switch {
	case strings.HasPrefix(path, "/api/v1/approvals"), strings.HasPrefix(path, "/api/v1/exceptions"),
		strings.HasPrefix(path, "/api/v1/tokens"), strings.HasPrefix(path, "/api/v1/tenants"):
		return "admin"
	case level == "audit":
		return "audit"
	case level == "helpdesk":
		return "commands"
	case level == "read":
		return "read"
	case strings.HasPrefix(path, "/api/v1/library-items"), strings.HasPrefix(path, "/api/v1/blueprints"), strings.HasPrefix(path, "/api/v1/devices"):
		return "library"
	}
	return "admin"
}

// auditRead tells whether a read through the API goes to the audit log
// (LIMDM_AUDIT_API_READS): all reads, none, or (default) the sensitive
// ones, which are the audit log and a single device with its inventory.
func (s *Server) auditRead(r *http.Request, level string) bool {
	if r.Method != http.MethodGet {
		return false // writes audit themselves
	}
	switch s.ops().AuditAPIReads {
	case "all":
		return true
	case "off":
		return false
	}
	return level == "audit" || r.Pattern == "GET /api/v1/devices/{id}"
}

type apiHandlerFunc func(w http.ResponseWriter, r *http.Request, c apiCaller)

// need guards an API handler. Levels: read (every API role), audit (admin
// and auditor, as the console's audit page), helpdesk (admin and helpdesk
// writes, as device commands), admin (admin writes).
func (s *Server) need(level string, h apiHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(apiCallerKey).(apiCaller)
		var ok bool
		switch level {
		case "read":
			ok = true
		case "audit":
			ok = c.Role == "admin" || c.Role == "auditor"
		case "helpdesk":
			ok = !c.ReadOnly && (c.Role == "admin" || c.Role == "helpdesk")
		case "admin":
			ok = !c.ReadOnly && c.Role == "admin"
		}
		if !ok {
			s.deny(w, r, c, "the token's role cannot do this")
			return
		}
		if sc := routeScope(r, level); len(c.Scopes) > 0 && !slices.Contains(c.Scopes, sc) {
			s.deny(w, r, c, "the token's scopes do not include "+sc)
			return
		}
		if c.Tenant != 0 {
			r = r.WithContext(withTenant(r.Context(), c.Tenant))
		}
		if s.auditRead(r, level) {
			if err := s.auditAction(r.Context(), c.actor(), "api.read", r.Method+" "+truncate(r.URL.Path, 200), truncate(r.URL.RawQuery, 500), nil); err != nil {
				s.apiFail(w, err)
				return
			}
		}
		h(w, r, c)
	}
}

// problemWriter turns plain text errors (unknown path, wrong method, body
// too large) into RFC 9457 problem details, so every API error is JSON.
type problemWriter struct {
	http.ResponseWriter
	swallow bool
}

func (p *problemWriter) WriteHeader(code int) {
	if code >= 400 && p.Header().Get("Content-Type") != "application/problem+json" {
		p.swallow = true
		problem(p.ResponseWriter, code, http.StatusText(code))
		return
	}
	p.ResponseWriter.WriteHeader(code)
}

func (p *problemWriter) Write(b []byte) (int, error) {
	if p.swallow {
		return len(b), nil
	}
	return p.ResponseWriter.Write(b)
}

func (p *problemWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// apiRoutes adds the token page, the admin API and the metrics endpoint
// to the console mux.
func (s *Server) apiRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings/api", s.page(s.adminOrAuditor(s.apiTokensPage)))
	mux.HandleFunc("POST /settings/api", s.page(s.apiTokenCreate))
	mux.HandleFunc("POST /settings/api/{id}/revoke", s.page(s.apiTokenRevoke))
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAPIDoc)
	})

	m := http.NewServeMux()
	m.HandleFunc("GET /api/v1/devices", s.need("read", s.apiDevices))
	m.HandleFunc("GET /api/v1/devices/{id}", s.need("read", s.apiDeviceGet))
	m.HandleFunc("PATCH /api/v1/devices/{id}", s.need("admin", s.apiDevicePatch))
	m.HandleFunc("GET /api/v1/devices/{id}/commands", s.need("read", s.apiDeviceCommands))
	m.HandleFunc("POST /api/v1/devices/{id}/commands", s.need("helpdesk", s.idempotent(s.apiCommandCreate)))
	m.HandleFunc("GET /api/v1/commands/{id}", s.need("read", s.apiCommandGet))
	m.HandleFunc("GET /api/v1/library-items", s.need("read", s.apiItems))
	m.HandleFunc("POST /api/v1/library-items", s.need("admin", s.apiItemSave))
	m.HandleFunc("GET /api/v1/library-items/{id}", s.need("read", s.apiItemGet))
	m.HandleFunc("PUT /api/v1/library-items/{id}", s.need("admin", s.apiItemSave))
	m.HandleFunc("DELETE /api/v1/library-items/{id}", s.need("admin", s.apiItemDelete))
	m.HandleFunc("GET /api/v1/blueprints", s.need("read", s.apiBlueprints))
	m.HandleFunc("POST /api/v1/blueprints", s.need("admin", s.apiBlueprintSave))
	m.HandleFunc("GET /api/v1/blueprints/{id}", s.need("read", s.apiBlueprintGet))
	m.HandleFunc("PUT /api/v1/blueprints/{id}", s.need("admin", s.apiBlueprintSave))
	m.HandleFunc("DELETE /api/v1/blueprints/{id}", s.need("admin", s.apiBlueprintDelete))
	m.HandleFunc("GET /api/v1/tags", s.need("read", s.apiTags))
	m.HandleFunc("GET /api/v1/audit", s.need("audit", s.apiAudit))
	s.apiAdminRoutes(mux, m)
	mux.Handle("/api/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pw := &problemWriter{ResponseWriter: w}
		c, ok := s.bearer(pw, r)
		if !ok {
			return
		}
		if c.Role == "metrics" {
			s.deny(pw, r, c, "metrics tokens only read /metrics")
			return
		}
		r.Body = http.MaxBytesReader(pw, r.Body, 1<<20)
		m.ServeHTTP(pw, r.WithContext(context.WithValue(r.Context(), apiCallerKey, c)))
	}))
}

// ---- console page ----

type apiTokenRow struct {
	ID                  int64
	Name, Prefix, Role  string
	ReadOnly            bool
	CreatedBy           string
	Created, Expires    time.Time
	LastUsed, RevokedAt *time.Time
	State               string // active | expired | revoked
	Scope               []string
	Scopes              []string
}

func (s *Server) apiTokensPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderAPITokens(w, r, sess, "")
}

func (s *Server) renderAPITokens(w http.ResponseWriter, r *http.Request, sess session, created string) {
	tcond, targs := tenantCond(sess, "tenant_id", 0)
	rows, err := s.db.Query(r.Context(), `SELECT id, name, prefix, role, read_only, created_by, created_at, expires_at, last_used_at, revoked_at, '', scope_tags, scopes
		FROM api_tokens WHERE `+tcond+` ORDER BY revoked_at IS NOT NULL, expires_at < now(), created_at DESC`, targs...)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[apiTokenRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	for i, t := range list {
		switch {
		case t.RevokedAt != nil:
			list[i].State = "revoked"
		case time.Now().After(t.Expires):
			list[i].State = "expired"
		default:
			list[i].State = "active"
		}
	}
	s.render(w, r, sess, "apitokens", map[string]any{"Tokens": list, "Created": created, "Roles": apiRoles, "Scopes": tokenScopes, "PublicURL": s.cfg.PublicURL})
}

func (s *Server) apiTokenCreate(w http.ResponseWriter, r *http.Request, sess session) {
	days, _ := strconv.Atoi(r.FormValue("days")) // 0 is refused
	scope, err := parseTags(r.FormValue("scope_tags"))
	if err != nil {
		s.errorPage(w, r, sess, http.StatusBadRequest, err.Error())
		return
	}
	token, _, err := s.createAPIToken(r.Context(), sess, tokenSpec{Name: r.FormValue("name"), Role: r.FormValue("role"), Days: days,
		ReadOnly: r.FormValue("read_only") == "on", ScopeTags: scope, Scopes: r.Form["scopes"]})
	var pending approvalPending
	if errors.As(err, &pending) {
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.failUser(w, r, sess, err)
		return
	}
	s.renderAPITokens(w, r, sess, token)
}

// tokenScopes are what a token may be limited to; no scopes is all its role
// allows. read: devices, commands, library items, blueprints and tags;
// commands: send device commands; library: change library items,
// blueprints and devices; audit: the audit log; admin: approvals,
// exceptions, tokens and tenants.
var tokenScopes = []string{"read", "commands", "library", "audit", "admin"}

// tokenSpec is a new API token, from the console form or the admin API.
type tokenSpec struct {
	Name      string   `json:"name"`
	Role      string   `json:"role"`
	Days      int      `json:"days"`
	ReadOnly  bool     `json:"read_only"`
	ScopeTags []string `json:"scope_tags"`
	Scopes    []string `json:"scopes"`
}

// createAPIToken validates and stores a token of the session's tenant and
// returns it (shown once) with its id. Validation errors are userErrors.
func (s *Server) createAPIToken(ctx context.Context, sess session, t tokenSpec) (string, int64, error) {
	bad := func(msg string) (string, int64, error) { return "", 0, &userError{http.StatusBadRequest, msg} }
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" || len(t.Name) > 100 || strings.ContainsFunc(t.Name, unicode.IsControl) || !slices.Contains(apiRoles, t.Role) || t.Days < 1 || t.Days > 365 {
		return bad("name up to 100 characters, a role, and 1..365 days")
	}
	readOnly := t.ReadOnly || t.Role == "auditor" || t.Role == "metrics"
	if len(t.ScopeTags) > 0 && t.Role != "helpdesk" && t.Role != "auditor" {
		return bad("a device scope applies to helpdesk and auditor tokens only")
	}
	if t.Role == "metrics" && sess.Tenant != 0 {
		return bad("metrics tokens are global: switch to the global view")
	}
	slices.Sort(t.Scopes)
	t.Scopes = slices.Compact(t.Scopes)
	for _, sc := range t.Scopes {
		if !slices.Contains(tokenScopes, sc) {
			return bad("scopes: " + strings.Join(tokenScopes, ", "))
		}
	}
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	if t.ScopeTags == nil {
		t.ScopeTags = []string{}
	}
	var tenantID *int64 // NULL: a global token
	if sess.Tenant != 0 {
		tenantID = &sess.Tenant
	}
	ta := tokenApproval{Name: t.Name, Role: t.Role, ReadOnly: readOnly, Days: t.Days, Scope: t.ScopeTags, Scopes: t.Scopes, Tenant: tenantID}
	if t.Role == "admin" && s.settings().FourEyes { // four eyes: the approver gets the token once (foureyes.go)
		aid, err := s.requestApproval(ctx, sess, "token.add", t.Name, ta, "")
		if err != nil {
			return bad(err.Error())
		}
		return "", 0, approvalPending(aid)
	}
	var token string
	var id int64
	err := s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var prefix string
		var err error
		token, prefix, id, err = insertToken(ctx, tx, ta, sess.Email)
		return sess.Email, "api_token.create", t.Name, fmt.Sprintf("role=%s read_only=%t days=%d prefix=%s scope_tags=%s scopes=%s",
			t.Role, readOnly, t.Days, prefix, strings.Join(t.ScopeTags, ","), strings.Join(t.Scopes, ",")), err
	})
	return token, id, err
}

func (s *Server) apiTokenRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.revokeAPIToken(r.Context(), sess, id)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/settings/api", http.StatusSeeOther)
}

// revokeAPIToken revokes an active token of the session's tenant;
// pgx.ErrNoRows when there is none.
func (s *Server) revokeAPIToken(ctx context.Context, sess session, id int64) error {
	return s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var name, prefix string
		tcond, targs := tenantCond(sess, "tenant_id", 1)
		err := tx.QueryRow(ctx, `UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL AND `+tcond+` RETURNING name, prefix`, append([]any{id}, targs...)...).Scan(&name, &prefix)
		return sess.Email, "api_token.revoke", name, "prefix=" + prefix, err
	})
}

// ---- helpers ----

// decodeJSON reads a JSON request body into v: application/json only,
// unknown fields refused.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		problem(w, http.StatusUnsupportedMediaType, "send application/json")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		problem(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		problem(w, http.StatusBadRequest, "invalid JSON: one value expected")
		return false
	}
	return true
}

// writeJSONStatus answers with a JSON document and a status.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// listPage is a page of a list; NextCursor continues it.
type listPage struct {
	Items      any    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// pageArgs reads limit (1..500, default 100) and the opaque cursor.
func pageArgs(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			problem(w, http.StatusBadRequest, "limit must be 1..500")
			return 0, "", false
		}
		limit = n
	}
	cur, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("cursor"))
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid cursor")
		return 0, "", false
	}
	return limit, string(cur), true
}

func cursor(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// idCursor reads a cursor holding a numeric id; empty is 0.
func idCursor(w http.ResponseWriter, cur string) (int64, bool) {
	if cur == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(cur, 10, 64)
	if err != nil || id < 0 {
		problem(w, http.StatusBadRequest, "invalid cursor")
		return 0, false
	}
	return id, true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		problem(w, http.StatusNotFound, "not found")
		return 0, false
	}
	return id, true
}

// ---- devices ----

type apiDevice struct {
	ID           string          `json:"id"`
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	AgentVersion string          `json:"agent_version"`
	Blueprint    string          `json:"blueprint"`
	Tags         []string        `json:"tags"`
	Status       string          `json:"status"`
	Failing      int             `json:"failing"`
	Checks       int             `json:"checks"`
	LastSeen     *time.Time      `json:"last_seen"`
	Retired      bool            `json:"retired"`
	BlueprintID  *int64          `json:"blueprint_id,omitempty"`
	EnrolledAt   *time.Time      `json:"enrolled_at,omitempty"`
	Inventory    json.RawMessage `json:"inventory,omitempty"`
}

func toAPIDevice(d deviceRow) apiDevice {
	if d.Tags == nil {
		d.Tags = []string{}
	}
	return apiDevice{ID: d.ID, Hostname: d.Hostname, OS: d.OS, AgentVersion: d.AgentVersion, Blueprint: d.Blueprints, Tags: d.Tags,
		Status: d.Status, Failing: d.Failing, Checks: d.Checks, LastSeen: d.LastSeen, Retired: d.Retired}
}

func (s *Server) apiDevices(w http.ResponseWriter, r *http.Request, c apiCaller) {
	dq, err := parseDeviceQuery(r.URL.Query(), s.staleAfter())
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	where := dq.where()
	scope, sargs := scopeCond(c.sess(), 0)
	where.add(scope, sargs...)
	if cur != "" {
		host, id, ok := strings.Cut(cur, "\x00")
		if !ok {
			problem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		where.add(`(d.hostname, d.id) > ($1, $2)`, host, id)
	}
	list, err := s.listDevicesQuery(r.Context(), where.sql(), fmt.Sprintf(" ORDER BY d.hostname, d.id LIMIT %d", limit+1), where.args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		page.NextCursor = cursor(list[limit-1].Hostname + "\x00" + list[limit-1].ID)
	}
	items := make([]apiDevice, len(list))
	for i, d := range list {
		items[i] = toAPIDevice(d)
	}
	page.Items = items
	writeJSON(w, page)
}

// apiDevice loads one device with its inventory; ErrNoRows when unknown.
func (s *Server) apiDevice(ctx context.Context, id string) (apiDevice, error) {
	list, err := s.listDevicesQuery(ctx, `d.id = $1`, "", id)
	if err != nil {
		return apiDevice{}, err
	}
	if len(list) == 0 {
		return apiDevice{}, pgx.ErrNoRows
	}
	d := toAPIDevice(list[0])
	var enrolled time.Time
	err = s.db.QueryRow(ctx, `SELECT blueprint_id, enrolled_at, inventory FROM devices WHERE id=$1`, id).Scan(&d.BlueprintID, &enrolled, &d.Inventory)
	d.EnrolledAt = &enrolled
	return d, err
}

func (s *Server) apiDeviceGet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	d, err := s.apiDevice(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !s.inScope(r.Context(), c.sess(), d.ID) {
		problem(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, d)
}

// apiDevicePatch changes a device's tags and explicit blueprint (null:
// default), with the console's tag rules and audit action.
func (s *Server) apiDevicePatch(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	id := r.PathValue("id")
	var body struct {
		Tags        *[]string       `json:"tags"`
		BlueprintID json.RawMessage `json:"blueprint_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	var tags []string
	if body.Tags != nil {
		for _, t := range *body.Tags {
			if strings.Contains(t, ",") {
				problem(w, http.StatusUnprocessableEntity, "invalid tag "+strconv.Quote(t))
				return
			}
		}
		var err error
		if tags, err = parseTags(strings.Join(*body.Tags, ",")); err != nil {
			problem(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	setBP := len(body.BlueprintID) > 0
	var bpID *int64
	if !s.inScope(ctx, c.sess(), id) {
		problem(w, http.StatusNotFound, "device not found")
		return
	}
	if setBP && string(body.BlueprintID) != "null" {
		if err := json.Unmarshal(body.BlueprintID, &bpID); err != nil {
			problem(w, http.StatusUnprocessableEntity, "blueprint_id must be a number or null")
			return
		}
		if !s.tenantOwns(ctx, c.sess(), "blueprints", *bpID, true) {
			problem(w, http.StatusUnprocessableEntity, "unknown blueprint")
			return
		}
		var ok bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM blueprints WHERE id=$1)`, *bpID).Scan(&ok); err != nil || !ok {
			problem(w, http.StatusUnprocessableEntity, "unknown blueprint")
			return
		}
	}
	detail := []string{}
	if body.Tags != nil {
		detail = append(detail, fmt.Sprintf("tags=%v", tags))
	}
	if setBP {
		detail = append(detail, "blueprint="+strings.Trim(string(body.BlueprintID), " "))
	}
	err := s.auditAction(ctx, c.actor(), "device.assign", id, strings.Join(detail, " "), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET tags = CASE WHEN $2 THEN $3::text[] ELSE tags END,
			blueprint_id = CASE WHEN $4 THEN $5::bigint ELSE blueprint_id END WHERE id=$1`, id, body.Tags != nil, tags, setBP, bpID)
		if err == nil && tag.RowsAffected() == 0 {
			err = &userError{http.StatusNotFound, "device not found"}
		}
		return err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	s.apiDeviceGet(w, r, c)
}

// ---- commands ----

type apiCommand struct {
	ID        int64     `json:"id"`
	DeviceID  string    `json:"device_id"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Output    string    `json:"output"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// the payload is never returned: it can hold a new user's password
const apiCommandCols = `id, device_id, type, status, output, created_by, created_at, updated_at`

// apiCommandCreate queues a console command. Parameters are the console
// form fields (minutes, confirm, message, title, text, username, ...),
// checked by the same commandPayload with the token's role.
func (s *Server) apiCommandCreate(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	id := r.PathValue("id")
	var body struct {
		Type   string         `json:"type"`
		Params map[string]any `json:"params"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	form := url.Values{}
	for k, v := range body.Params {
		switch x := v.(type) {
		case string:
			form.Set(k, x)
		case bool:
			if x {
				form.Set(k, "on")
			}
		case float64:
			form.Set(k, strconv.FormatFloat(x, 'f', -1, 64))
		default:
			problem(w, http.StatusUnprocessableEntity, "params: strings, numbers and booleans only")
			return
		}
	}
	var retired bool
	err := s.db.QueryRow(ctx, `SELECT retired FROM devices WHERE id=$1`, id).Scan(&retired)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !s.inScope(ctx, c.sess(), id) {
		problem(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if retired {
		problem(w, http.StatusConflict, "the device is retired")
		return
	}
	fr := r.Clone(ctx)
	fr.Form, fr.PostForm = form, form
	payload, code, msg := s.commandPayload(fr, c.sess(), id, body.Type)
	switch code {
	case 0:
	case http.StatusForbidden:
		s.deny(w, r, c, msg)
		return
	default:
		problem(w, http.StatusUnprocessableEntity, msg)
		return
	}
	if s.needsApproval(body.Type) { // four eyes: an admin decides in the console
		aid, err := s.requestApproval(ctx, c.sess(), "command", id, commandApproval{Type: body.Type, Payload: payload}, strings.TrimSpace(form.Get("reason")))
		if err != nil {
			problem(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		w.Header().Set("Location", "/api/v1/approvals/"+strconv.FormatInt(aid, 10))
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": aid, "status": "pending"})
		return
	}
	cid, err := s.queueCommandID(ctx, c.actor(), id, body.Type, payload)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	s.notifyCommand(c.actor(), id, body.Type)
	cmd, err := collectOne(ctx, s.db, pgx.RowToStructByPos[apiCommand], `SELECT `+apiCommandCols+` FROM commands WHERE id=$1`, cid)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/commands/"+strconv.FormatInt(cid, 10))
	writeJSONStatus(w, http.StatusAccepted, cmd)
}

// collect runs a query and collects its rows.
func collect[T any](ctx context.Context, db *pgxpool.Pool, fn pgx.RowToFunc[T], sql string, args ...any) ([]T, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, fn)
}

// collectOne is collect for exactly one row; pgx.ErrNoRows when there is none.
func collectOne[T any](ctx context.Context, db *pgxpool.Pool, fn pgx.RowToFunc[T], sql string, args ...any) (T, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		var zero T
		return zero, err
	}
	return pgx.CollectExactlyOneRow(rows, fn)
}

func (s *Server) apiCommandGet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cmd, err := collectOne(r.Context(), s.db, pgx.RowToStructByPos[apiCommand], `SELECT `+apiCommandCols+` FROM commands WHERE id=$1`, id)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !s.inScope(r.Context(), c.sess(), cmd.DeviceID) {
		problem(w, http.StatusNotFound, "command not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, cmd)
}

// apiDeviceCommands lists a device's commands, newest first.
func (s *Server) apiDeviceCommands(w http.ResponseWriter, r *http.Request, c apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	if !s.inScope(r.Context(), c.sess(), r.PathValue("id")) {
		problem(w, http.StatusNotFound, "device not found")
		return
	}
	before, ok := idCursor(w, cur)
	if !ok {
		return
	}
	if before == 0 {
		before = 1<<63 - 1
	}
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[apiCommand], `SELECT `+apiCommandCols+` FROM commands WHERE device_id=$1 AND id < $2 ORDER BY id DESC LIMIT $3`,
		r.PathValue("id"), before, limit+1)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		page.NextCursor = cursor(strconv.FormatInt(list[limit-1].ID, 10))
	}
	page.Items = list
	writeJSON(w, page)
}

// ---- library items ----

func (s *Server) apiItems(w http.ResponseWriter, r *http.Request, c apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	after, ok := idCursor(w, cur)
	if !ok {
		return
	}
	cond, args := sharedCond(c.sess(), "i", 2)
	list, err := collect(r.Context(), s.db, scanItem, `SELECT id, name, type, description, payload FROM library_items i WHERE id > $1 AND `+cond+` ORDER BY id LIMIT $2`, append([]any{after, limit + 1}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		page.NextCursor = cursor(strconv.FormatInt(list[limit-1].ID, 10))
	}
	for i := range list {
		maskItem(&list[i])
	}
	page.Items = list
	writeJSON(w, page)
}

// maskItem hides network secrets in API answers, as the console editor
// does; a PUT that sends the mask back keeps the stored value.
func maskItem(it *api.LibraryItem) {
	if it.Type == api.TypeNetwork {
		it.Payload = api.MaskNetworkSecrets(it.Payload)
	}
}

func (s *Server) apiItemGet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !s.tenantOwns(r.Context(), c.sess(), "library_items", id, true) {
		problem(w, http.StatusNotFound, "library item not found")
		return
	}
	it, err := collectOne(r.Context(), s.db, scanItem, `SELECT id, name, type, description, payload FROM library_items WHERE id=$1`, id)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "library item not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	maskItem(&it)
	s.setETag(r.Context(), w, "library_items", id)
	writeJSON(w, it)
}

// apiItemSave creates (POST) or replaces (PUT) a library item through the
// console's saveLibraryItem.
func (s *Server) apiItemSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var id int64
	if r.Method == http.MethodPut {
		var ok bool
		if id, ok = pathID(w, r); !ok {
			return
		}
	}
	var it api.LibraryItem
	if !decodeJSON(w, r, &it) {
		return
	}
	it.ID = id
	it.Name, it.Description = strings.TrimSpace(it.Name), strings.TrimSpace(it.Description)
	if id != 0 && s.itemNeedsApproval(it) { // a request is no save: compare before it is queued
		if err := pgx.BeginFunc(r.Context(), s.db, func(tx pgx.Tx) error { return checkIfMatch(withIfMatch(r), tx, "library_items", id) }); err != nil {
			s.preconditionFail(w, r, "library_items", id, err)
			return
		}
	}
	if err := s.saveLibraryItem(withIfMatch(r), c.actor(), &it); err != nil {
		if aid, ok := pendingApproval(err); ok { // four eyes: an admin decides in the console
			w.Header().Set("Location", "/approvals")
			writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": aid, "status": "pending"})
			return
		}
		s.preconditionFail(w, r, "library_items", id, err)
		return
	}
	status := http.StatusOK
	if id == 0 {
		status = http.StatusCreated
		w.Header().Set("Location", "/api/v1/library-items/"+strconv.FormatInt(it.ID, 10))
	}
	maskItem(&it)
	s.setETag(r.Context(), w, "library_items", it.ID)
	writeJSONStatus(w, status, it)
}

func (s *Server) apiItemDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.deleteLibraryItem(r.Context(), c.actor(), id); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- blueprints ----

type apiBlueprint struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	ParentID    *int64     `json:"parent_id"`
	Tree        []api.Node `json:"tree"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func toAPIBlueprint(b blueprintRec) apiBlueprint {
	if b.Tree == nil {
		b.Tree = []api.Node{}
	}
	return apiBlueprint{ID: b.ID, Name: b.Name, Description: b.Desc, ParentID: b.Parent, Tree: b.Tree, UpdatedAt: b.Updated}
}

func (s *Server) apiBlueprints(w http.ResponseWriter, r *http.Request, c apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	after, ok := idCursor(w, cur)
	if !ok {
		return
	}
	bcond, bargs := sharedCond(c.sess(), "b", 2)
	list, err := collect(r.Context(), s.db, func(row pgx.CollectableRow) (apiBlueprint, error) {
		b, err := scanBlueprint(row)
		return toAPIBlueprint(b), err
	}, `SELECT `+blueprintCols+` FROM blueprints b WHERE id > $1 AND `+bcond+` ORDER BY id LIMIT $2`, append([]any{after, limit + 1}, bargs...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		page.NextCursor = cursor(strconv.FormatInt(list[limit-1].ID, 10))
	}
	page.Items = list
	writeJSON(w, page)
}

func (s *Server) apiBlueprintGet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !s.tenantOwns(r.Context(), c.sess(), "blueprints", id, true) {
		problem(w, http.StatusNotFound, "blueprint not found")
		return
	}
	b, err := scanBlueprint(s.db.QueryRow(r.Context(), `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "blueprint not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.Header().Set("ETag", etagOf(b.Updated))
	writeJSON(w, toAPIBlueprint(b))
}

// apiBlueprintSave creates (POST) or replaces (PUT) a blueprint through the
// console's saveBlueprint.
func (s *Server) apiBlueprintSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var id int64
	if r.Method == http.MethodPut {
		var ok bool
		if id, ok = pathID(w, r); !ok {
			return
		}
	}
	var body struct {
		Name        string     `json:"name"`
		Description string     `json:"description"`
		ParentID    *int64     `json:"parent_id"`
		Tree        []api.Node `json:"tree"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.ParentID != nil && *body.ParentID <= 0 {
		body.ParentID = nil
	}
	bp := blueprintRec{ID: id, Name: strings.TrimSpace(body.Name), Desc: strings.TrimSpace(body.Description), Parent: body.ParentID, Tree: body.Tree}
	if err := s.saveBlueprint(withIfMatch(r), c.actor(), &bp); err != nil {
		s.preconditionFail(w, r, "blueprints", id, err)
		return
	}
	saved, err := scanBlueprint(s.db.QueryRow(r.Context(), `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, bp.ID))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	status := http.StatusOK
	if id == 0 {
		status = http.StatusCreated
		w.Header().Set("Location", "/api/v1/blueprints/"+strconv.FormatInt(bp.ID, 10))
	}
	w.Header().Set("ETag", etagOf(saved.Updated))
	writeJSONStatus(w, status, toAPIBlueprint(saved))
}

func (s *Server) apiBlueprintDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.deleteBlueprint(r.Context(), c.actor(), id); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- tags and audit ----

// apiTags lists the tags of active devices with their device counts. The
// list is short, so it is not paged.
func (s *Server) apiTags(w http.ResponseWriter, r *http.Request, c apiCaller) {
	type tag struct {
		Name    string `json:"name"`
		Devices int    `json:"devices"`
	}
	cond, args := scopeCond(c.sess(), 0)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[tag], `SELECT t, count(*)::int FROM devices d, unnest(d.tags) t WHERE NOT d.retired AND `+cond+` GROUP BY t ORDER BY t`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if list == nil {
		list = []tag{}
	}
	writeJSON(w, listPage{Items: list})
}

type apiAuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
	Tenant *int64    `json:"tenant_id,omitempty"`
}

// apiAudit reads the audit log newest first with the console's filters.
func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request, c apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	before, ok := idCursor(w, cur)
	if !ok {
		return
	}
	_, where, args := auditFilter(r.URL.Query(), c.sess())
	if before > 0 {
		args = append(args, before)
		where += " AND id < $" + strconv.Itoa(len(args))
	}
	args = append(args, limit+1)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[auditRow], `SELECT id, at, actor, action, target, detail, prev, hash, tenant_id FROM audit_log WHERE `+
		where+` ORDER BY id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		page.NextCursor = cursor(strconv.FormatInt(list[limit-1].ID, 10))
	}
	items := make([]apiAuditEntry, len(list))
	for i, a := range list {
		items[i] = apiAuditEntry{a.ID, a.At, a.Actor, a.Action, a.Target, a.Detail, hex.EncodeToString(a.Prev), hex.EncodeToString(a.Hash), a.Tenant}
	}
	page.Items = items
	writeJSON(w, page)
}
