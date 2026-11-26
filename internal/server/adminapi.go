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
	s.log.Error("admin api request failed", "err", err)
	problem(w, http.StatusInternalServerError, "internal error")
}

// ---- tokens ----

type apiCaller struct {
	ID       int64
	Name     string
	Role     string
	ReadOnly bool
}

// actor names the token in the audit log and as creator of commands.
func (c apiCaller) actor() string { return fmt.Sprintf("api:%s#%d", c.Name, c.ID) }

// sess is the session the shared console functions check roles against.
func (c apiCaller) sess() session { return session{Email: c.actor(), Role: c.Role} }

const apiCallerKey ctxKey = 2

// auditIP is the client address for audit entries: parsed, never raw header text.
func auditIP(r *http.Request) string {
	if a, err := netip.ParseAddr(clientIP(r)); err == nil {
		return a.String()
	}
	return "invalid"
}

// bearer checks the request's API token. Failed checks are limited per
// client (20 in five minutes, as for SCIM) and a presented but unknown,
// expired or revoked token is audited. Valid tokens get 600 requests per
// minute.
func (s *Server) bearer(w http.ResponseWriter, r *http.Request) (apiCaller, bool) {
	ctx := r.Context()
	key := "apifail:" + rateKey(r)
	var c apiCaller
	if s.limit.over(key, 20, 5*time.Minute) {
		w.Header().Set("Retry-After", "300")
		problem(w, http.StatusTooManyRequests, "too many failed attempts")
		return c, false
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	reason := "bearer token required"
	if ok && tok != "" {
		var expires time.Time
		var revoked *time.Time
		err := s.db.QueryRow(ctx, `SELECT id, name, role, read_only, expires_at, revoked_at FROM api_tokens WHERE token_hash=$1`, sha(tok)).
			Scan(&c.ID, &c.Name, &c.Role, &c.ReadOnly, &expires, &revoked)
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
		default:
			reason = ""
		}
		if reason != "" {
			if err := s.auditAction(ctx, "api", "api.auth_failed", c.Name, reason+" from "+auditIP(r), nil); err != nil {
				s.log.Error("audit api.auth_failed", "err", err)
			}
		}
	}
	if reason != "" {
		s.limit.allow(key, 20, 5*time.Minute) // counts the failure
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
	m.HandleFunc("POST /api/v1/devices/{id}/commands", s.need("helpdesk", s.apiCommandCreate))
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
}

func (s *Server) apiTokensPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderAPITokens(w, r, sess, "")
}

func (s *Server) renderAPITokens(w http.ResponseWriter, r *http.Request, sess session, created string) {
	rows, err := s.db.Query(r.Context(), `SELECT id, name, prefix, role, read_only, created_by, created_at, expires_at, last_used_at, revoked_at, ''
		FROM api_tokens ORDER BY revoked_at IS NOT NULL, expires_at < now(), created_at DESC`)
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
	s.render(w, r, sess, "apitokens", map[string]any{"Tokens": list, "Created": created, "Roles": apiRoles, "PublicURL": s.cfg.PublicURL})
}

func (s *Server) apiTokenCreate(w http.ResponseWriter, r *http.Request, sess session) {
	name := strings.TrimSpace(r.FormValue("name"))
	role := r.FormValue("role")
	days, err := strconv.Atoi(r.FormValue("days"))
	if name == "" || len(name) > 100 || strings.ContainsFunc(name, unicode.IsControl) || !slices.Contains(apiRoles, role) || err != nil || days < 1 || days > 365 {
		http.Error(w, "name up to 100 characters, a role, and 1..365 days", http.StatusBadRequest)
		return
	}
	readOnly := r.FormValue("read_only") == "on" || role == "auditor" || role == "metrics"
	token := "lma_" + randToken(32)
	prefix := token[:12]
	err = s.auditAction(r.Context(), sess.Email, "api_token.create", name, fmt.Sprintf("role=%s read_only=%t days=%d prefix=%s", role, readOnly, days, prefix), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO api_tokens(name, prefix, token_hash, role, read_only, created_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6, now() + make_interval(days => $7))`, name, prefix, sha(token), role, readOnly, sess.Email, days)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderAPITokens(w, r, sess, token)
}

func (s *Server) apiTokenRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.auditActionFn(r.Context(), func(tx pgx.Tx) (string, string, string, string, error) {
		var name, prefix string
		err := tx.QueryRow(r.Context(), `UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL RETURNING name, prefix`, id).Scan(&name, &prefix)
		return sess.Email, "api_token.revoke", name, "prefix=" + prefix, err
	})
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

func (s *Server) apiDevices(w http.ResponseWriter, r *http.Request, _ apiCaller) {
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

func (s *Server) apiDeviceGet(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	d, err := s.apiDevice(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
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
	if setBP && string(body.BlueprintID) != "null" {
		if err := json.Unmarshal(body.BlueprintID, &bpID); err != nil {
			problem(w, http.StatusUnprocessableEntity, "blueprint_id must be a number or null")
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
	if errors.Is(err, pgx.ErrNoRows) {
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
	cid, err := s.queueCommandID(ctx, c.actor(), id, body.Type, payload)
	if err != nil {
		s.apiFail(w, err)
		return
	}
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

func (s *Server) apiCommandGet(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	cmd, err := collectOne(r.Context(), s.db, pgx.RowToStructByPos[apiCommand], `SELECT `+apiCommandCols+` FROM commands WHERE id=$1`, id)
	if errors.Is(err, pgx.ErrNoRows) {
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
func (s *Server) apiDeviceCommands(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
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

func (s *Server) apiItems(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	after, ok := idCursor(w, cur)
	if !ok {
		return
	}
	list, err := collect(r.Context(), s.db, scanItem, `SELECT id, name, type, description, payload FROM library_items WHERE id > $1 ORDER BY id LIMIT $2`, after, limit+1)
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

func (s *Server) apiItemGet(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
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
	if err := s.saveLibraryItem(r.Context(), c.actor(), &it); err != nil {
		s.apiFail(w, err)
		return
	}
	status := http.StatusOK
	if id == 0 {
		status = http.StatusCreated
		w.Header().Set("Location", "/api/v1/library-items/"+strconv.FormatInt(it.ID, 10))
	}
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

func (s *Server) apiBlueprints(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	after, ok := idCursor(w, cur)
	if !ok {
		return
	}
	list, err := collect(r.Context(), s.db, func(row pgx.CollectableRow) (apiBlueprint, error) {
		b, err := scanBlueprint(row)
		return toAPIBlueprint(b), err
	}, `SELECT `+blueprintCols+` FROM blueprints WHERE id > $1 ORDER BY id LIMIT $2`, after, limit+1)
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

func (s *Server) apiBlueprintGet(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
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
	if err := s.saveBlueprint(r.Context(), c.actor(), &bp); err != nil {
		s.apiFail(w, err)
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
func (s *Server) apiTags(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	type tag struct {
		Name    string `json:"name"`
		Devices int    `json:"devices"`
	}
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[tag], `SELECT t, count(*)::int FROM devices, unnest(tags) t WHERE NOT retired GROUP BY t ORDER BY t`)
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
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[auditRow], `SELECT id, at, actor, action, target, detail, prev, hash FROM audit_log WHERE `+
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
		items[i] = apiAuditEntry{a.ID, a.At, a.Actor, a.Action, a.Target, a.Detail, hex.EncodeToString(a.Prev), hex.EncodeToString(a.Hash)}
	}
	page.Items = items
	writeJSON(w, page)
}
