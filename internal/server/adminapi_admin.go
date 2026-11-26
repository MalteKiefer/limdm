package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Admin API for what the console manages besides devices and the library:
// approvals, risk exceptions, API tokens and tenants; plus idempotent
// command requests, optimistic locking of library items and blueprints and
// the API reference page. Every handler calls the function the console
// uses, so validation, tenant rules and audit entries are the same.

func (s *Server) apiAdminRoutes(mux, m *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/docs", s.apiReference)
	m.HandleFunc("GET /api/v1/approvals", s.need("read", s.apiApprovals))
	m.HandleFunc("GET /api/v1/approvals/{id}", s.need("read", s.apiApprovalGet))
	m.HandleFunc("POST /api/v1/approvals/{id}/approve", s.need("admin", s.apiApprovalDecide))
	m.HandleFunc("POST /api/v1/approvals/{id}/reject", s.need("admin", s.apiApprovalDecide))
	m.HandleFunc("GET /api/v1/exceptions", s.need("read", s.apiExceptions))
	m.HandleFunc("POST /api/v1/exceptions", s.need("admin", s.apiExceptionAdd))
	m.HandleFunc("DELETE /api/v1/exceptions/{id}", s.need("admin", s.apiExceptionRevoke))
	m.HandleFunc("GET /api/v1/tokens", s.need("audit", s.apiTokens))
	m.HandleFunc("POST /api/v1/tokens", s.need("admin", s.apiTokenAdd))
	m.HandleFunc("DELETE /api/v1/tokens/{id}", s.need("admin", s.apiTokenDelete))
	m.HandleFunc("GET /api/v1/tenants", s.need("admin", s.superAPI(s.apiTenants)))
	m.HandleFunc("POST /api/v1/tenants", s.need("admin", s.superAPI(s.apiTenantAdd)))
}

// ---- approvals ----

type apiApproval struct {
	ID          int64           `json:"id"`
	Action      string          `json:"action"`
	Target      string          `json:"target"`
	Payload     json.RawMessage `json:"payload"`
	Reason      string          `json:"reason"`
	RequestedBy string          `json:"requested_by"`
	Status      string          `json:"status"`
	DecidedBy   *string         `json:"decided_by"`
	DecidedAt   *time.Time      `json:"decided_at"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	// Credentials are new local credentials an approved user.add or
	// user.reset created; only in the answer of the decision.
	Credentials string `json:"credentials,omitempty"`
}

const apiApprovalCols = `id, action, target, payload, reason, requested_by, status, decided_by, decided_at, created_at, expires_at, ''`

// approvalCond limits approvals to the caller's tenant; helpdesk tokens see
// their own requests only, as in the console.
func approvalCond(c apiCaller, n int) (string, []any) {
	cond, args := tenantCond(c.sess(), "tenant_id", n)
	if c.Role == "helpdesk" {
		cond += " AND requested_by = $" + strconv.Itoa(n+len(args)+1)
		args = append(args, c.actor())
	}
	return cond, args
}

func (s *Server) apiApprovals(w http.ResponseWriter, r *http.Request, c apiCaller) {
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
	status := r.URL.Query().Get("status")
	if status != "" && !slices.Contains([]string{"pending", "approved", "rejected", "expired", "used"}, status) {
		problem(w, http.StatusBadRequest, "status: pending, approved, rejected, expired or used")
		return
	}
	cond, args := approvalCond(c, 3)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[apiApproval], `SELECT `+apiApprovalCols+` FROM approvals
		WHERE id < $1 AND ($2 = '' OR status = $2) AND `+cond+` ORDER BY id DESC LIMIT `+strconv.Itoa(limit+1), append([]any{before, status}, args...)...)
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

func (s *Server) apiApproval(ctx context.Context, c apiCaller, id int64) (apiApproval, error) {
	cond, args := approvalCond(c, 1)
	return collectOne(ctx, s.db, pgx.RowToStructByPos[apiApproval], `SELECT `+apiApprovalCols+` FROM approvals WHERE id=$1 AND `+cond, append([]any{id}, args...)...)
}

func (s *Server) apiApprovalGet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a, err := s.apiApproval(r.Context(), c, id)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "approval not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, a)
}

// apiApprovalDecide approves or rejects a request like the console: never
// one the token (or the person who created it) requested.
func (s *Server) apiApprovalDecide(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	op := "approve"
	if strings.HasSuffix(r.URL.Path, "/reject") {
		op = "reject"
	}
	creds, notices, err := s.decideApproval(r.Context(), c.sess(), id, op)
	var ae errApproval
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		problem(w, http.StatusNotFound, "approval not found")
		return
	case errors.As(err, &ae):
		problem(w, http.StatusConflict, string(ae))
		return
	case err != nil:
		s.apiFail(w, err)
		return
	}
	for _, n := range notices {
		n()
	}
	a, err := s.apiApproval(r.Context(), c, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	a.Credentials = creds
	writeJSON(w, a)
}

// ---- risk exceptions ----

type apiException struct {
	ID        int64      `json:"id"`
	CheckID   string     `json:"check_id"`
	Mode      string     `json:"mode"`
	Tag       string     `json:"tag"`
	Reason    string     `json:"reason"`
	Owner     string     `json:"owner"`
	Approver  string     `json:"approver"`
	Expires   time.Time  `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	Created   time.Time  `json:"created_at"`
	Revoked   *time.Time `json:"revoked_at"`
	State     string     `json:"state"`
}

func apiExceptionsOf(list []riskException) []apiException {
	out := make([]apiException, len(list))
	for i, e := range list {
		out[i] = apiException{e.ID, e.CheckID, e.Mode, e.Tag, e.Reason, e.Owner, e.Approver, e.Expires, e.CreatedBy, e.Created, e.Revoked, e.State()}
	}
	return out
}

func (s *Server) apiExceptions(w http.ResponseWriter, r *http.Request, c apiCaller) {
	list, err := s.riskExceptions(r.Context())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: apiExceptionsOf(list)})
}

func (s *Server) apiExceptionAdd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		CheckID  string `json:"check_id"`
		Mode     string `json:"mode"`
		Tag      string `json:"tag"`
		Reason   string `json:"reason"`
		Owner    string `json:"owner"`
		Approver string `json:"approver"`
		Expires  string `json:"expires"` // last day it applies, YYYY-MM-DD
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id, pending, err := s.addOrRequestException(r.Context(), c.sess(), riskException{CheckID: body.CheckID, Mode: body.Mode, Tag: body.Tag, Reason: body.Reason,
		Owner: body.Owner, Approver: body.Approver}, body.Expires)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if pending { // four eyes: another admin approves it and is recorded as approver
		w.Header().Set("Location", "/api/v1/approvals/"+strconv.FormatInt(id, 10))
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": id, "status": "pending"})
		return
	}
	w.Header().Set("Location", "/api/v1/exceptions/"+strconv.FormatInt(id, 10))
	writeJSONStatus(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) apiExceptionRevoke(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := s.revokeException(r.Context(), c.sess(), id)
	if errors.Is(err, errNotFound) {
		problem(w, http.StatusNotFound, "exception not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- API tokens ----

type apiTokenOut struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Role      string     `json:"role"`
	ReadOnly  bool       `json:"read_only"`
	CreatedBy string     `json:"created_by"`
	Created   time.Time  `json:"created_at"`
	Expires   time.Time  `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used_at"`
	Revoked   *time.Time `json:"revoked_at"`
	ScopeTags []string   `json:"scope_tags"`
	Scopes    []string   `json:"scopes"`
	// Token is the secret, only in the answer that created it.
	Token string `json:"token,omitempty"`
}

const apiTokenCols = `id, name, prefix, role, read_only, created_by, created_at, expires_at, last_used_at, revoked_at, scope_tags, scopes, ''` //nolint:gosec // column names, no credentials

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request, c apiCaller) {
	cond, args := tenantCond(c.sess(), "tenant_id", 0)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[apiTokenOut], `SELECT `+apiTokenCols+` FROM api_tokens WHERE `+cond+` ORDER BY id`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: list})
}

// apiTokenAdd creates a token of the caller's tenant; rotating a token is
// creating its successor and deleting it.
func (s *Server) apiTokenAdd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var t tokenSpec
	if !decodeJSON(w, r, &t) {
		return
	}
	tags, err := parseTags(strings.Join(t.ScopeTags, ","))
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	t.ScopeTags = tags
	// a scoped token cannot mint a token with scopes it does not have
	if len(c.Scopes) > 0 && (len(t.Scopes) == 0 || slices.ContainsFunc(t.Scopes, func(sc string) bool { return !slices.Contains(c.Scopes, sc) })) {
		problem(w, http.StatusForbidden, "scopes: a subset of this token's scopes ("+strings.Join(c.Scopes, ", ")+")")
		return
	}
	tok, id, err := s.createAPIToken(r.Context(), c.sess(), t)
	var pending approvalPending
	if errors.As(err, &pending) {
		w.Header().Set("Location", "/api/v1/approvals/"+strconv.FormatInt(int64(pending), 10))
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": int64(pending), "status": "pending"})
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out, err := collectOne(r.Context(), s.db, pgx.RowToStructByPos[apiTokenOut], `SELECT `+apiTokenCols+` FROM api_tokens WHERE id=$1`, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out.Token = tok
	w.Header().Set("Location", "/api/v1/tokens")
	writeJSONStatus(w, http.StatusCreated, out)
}

func (s *Server) apiTokenDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := s.revokeAPIToken(r.Context(), c.sess(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "token not found or revoked already")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- tenants ----

// superAPI limits a route to global tokens while multi tenancy is on, as
// superOnly does for console pages (a super admin's session keeps the
// right while it looks at one tenant).
func (s *Server) superAPI(h apiHandlerFunc) apiHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c apiCaller) {
		if !s.cfg.MultiTenant {
			problem(w, http.StatusNotFound, "multi tenancy is off")
			return
		}
		if c.Tenant != 0 && (c.Sess == nil || !c.Sess.Super) {
			s.deny(w, r, c, "only global tokens manage tenants")
			return
		}
		h(w, r, c)
	}
}

type apiTenant struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Disabled    bool      `json:"disabled"`
	CompanyName string    `json:"company_name"`
	Devices     int       `json:"devices"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) apiTenants(w http.ResponseWriter, r *http.Request, c apiCaller) {
	list, err := s.tenantList(r.Context())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := make([]apiTenant, len(list))
	for i, t := range list {
		out[i] = apiTenant{t.ID, t.Name, t.Disabled, t.CompanyName, t.Devices, t.CreatedAt}
	}
	writeJSON(w, listPage{Items: out})
}

func (s *Server) apiTenantAdd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id, err := s.createTenant(r.Context(), c.sess(), body.Name)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/tenants")
	writeJSONStatus(w, http.StatusCreated, map[string]int64{"id": id})
}

// ---- idempotent command requests ----

// captureWriter keeps the status and body a handler writes.
type captureWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.body.Len() < 1<<20 {
		c.body.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

// idempotent makes a POST repeatable: with an Idempotency-Key header, the
// first answer is stored for 24 hours per token and key, and a repetition
// with the same request gets that answer again (Idempotent-Replayed: true)
// instead of queuing a second command. The same key with another request
// is refused (422), one still running answers 409.
func (s *Server) idempotent(h apiHandlerFunc) apiHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c apiCaller) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			h(w, r, c)
			return
		}
		if len(key) > 255 || strings.ContainsFunc(key, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
			problem(w, http.StatusBadRequest, "Idempotency-Key: 1 to 255 printable ASCII characters")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			problem(w, http.StatusBadRequest, "request body too large or unreadable")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		sum := sha256.Sum256(append([]byte(r.Method+" "+r.URL.Path+"\n"), body...))
		hash := hex.EncodeToString(sum[:])
		ctx := r.Context()
		if _, err := s.db.Exec(ctx, `DELETE FROM api_idempotency WHERE created_at < now() - interval '24 hours'`); err != nil {
			s.apiFail(w, err)
			return
		}
		tag, err := s.db.Exec(ctx, `INSERT INTO api_idempotency(token_id, key, request_hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, c.ID, key, hash)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		if tag.RowsAffected() == 0 {
			var prevHash, location string
			var status int
			var prev []byte
			if err := s.db.QueryRow(ctx, `SELECT request_hash, status, location, body FROM api_idempotency WHERE token_id=$1 AND key=$2`, c.ID, key).
				Scan(&prevHash, &status, &location, &prev); err != nil {
				s.apiFail(w, err)
				return
			}
			switch {
			case prevHash != hash:
				problemField(w, http.StatusUnprocessableEntity, "Idempotency-Key", "this Idempotency-Key was used for another request")
			case status == 0:
				w.Header().Set("Retry-After", "1")
				problem(w, http.StatusConflict, "a request with this Idempotency-Key is still running")
			default:
				if location != "" {
					w.Header().Set("Location", location)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Idempotent-Replayed", "true")
				w.WriteHeader(status)
				w.Write(prev)
			}
			return
		}
		rec := &captureWriter{ResponseWriter: w}
		h(rec, r, c)
		if rec.status == 0 || rec.status >= 500 { // failed: a retry with the key runs again
			_, err = s.db.Exec(context.WithoutCancel(ctx), `DELETE FROM api_idempotency WHERE token_id=$1 AND key=$2`, c.ID, key)
		} else {
			_, err = s.db.Exec(context.WithoutCancel(ctx), `UPDATE api_idempotency SET status=$3, location=$4, body=$5 WHERE token_id=$1 AND key=$2`,
				c.ID, key, rec.status, w.Header().Get("Location"), rec.body.Bytes())
		}
		if err != nil {
			s.log.Error("idempotency record", "err", err, "request_id", requestID(w))
		}
	}
}

// ---- optimistic locking ----

// etagOf is the entity tag of a library item or blueprint: its last change.
func etagOf(t time.Time) string { return `"` + strconv.FormatInt(t.UnixMicro(), 36) + `"` }

// setETag sends the entity tag of the row id of table (library_items or
// blueprints).
func (s *Server) setETag(ctx context.Context, w http.ResponseWriter, table string, id int64) {
	var at time.Time
	if err := s.db.QueryRow(ctx, `SELECT updated_at FROM `+table+` WHERE id=$1`, id).Scan(&at); err == nil {
		w.Header().Set("ETag", etagOf(at))
	}
}

// ifMatchKey carries the If-Match header of a PUT to the save (withIfMatch).
type ifMatchKey struct{}

func withIfMatch(r *http.Request) context.Context {
	return context.WithValue(r.Context(), ifMatchKey{}, r.Header.Get("If-Match"))
}

// checkIfMatch compares the If-Match of the request in ctx with the entity
// tag of row id of table, locked in tx: the check and the save are one
// transaction, so a change committed in between cannot be overwritten.
// Without If-Match (or *) the save goes ahead, as before.
func checkIfMatch(ctx context.Context, tx pgx.Tx, table string, id int64) error {
	want, _ := ctx.Value(ifMatchKey{}).(string)
	if want == "" || want == "*" {
		return nil
	}
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT updated_at FROM `+table+` WHERE id=$1 FOR UPDATE`, id).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // the save answers 404
	}
	if err != nil {
		return err
	}
	for _, tag := range strings.Split(want, ",") {
		if strings.TrimSpace(tag) == etagOf(at) {
			return nil
		}
	}
	return errPrecondition
}

var errPrecondition = &userError{http.StatusPreconditionFailed, "changed since it was read: get it again and repeat the change"}

// ---- API reference ----

// apiReference renders openapi.json as a page on the console origin, with
// the console's stylesheet and no scripts, so the CSP needs no exception.
func (s *Server) apiReference(w http.ResponseWriter, r *http.Request) {
	var doc struct {
		Info struct {
			Title, Version, Description string
		}
		Paths map[string]map[string]json.RawMessage
	}
	type operation struct {
		Summary, Description string
		Parameters           []struct {
			Ref         string `json:"$ref"`
			Name, In    string
			Required    bool
			Description string
		}
		Responses map[string]json.RawMessage
	}
	if err := json.Unmarshal(openAPIDoc, &doc); err != nil {
		http.Error(w, "invalid openapi.json", http.StatusInternalServerError)
		return
	}
	type param struct{ Name, In, Description string }
	type op struct {
		ID, Method, Path, Summary, Description string
		Params                                 []param
		Codes                                  []string
	}
	var ops []op
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			var o operation
			if method == "parameters" || json.Unmarshal(raw, &o) != nil {
				continue // path level parameters are repeated by the operations
			}
			x := op{Method: strings.ToUpper(method), Path: path, Summary: o.Summary, Description: o.Description}
			x.ID = strings.NewReplacer("/", "-", "{", "", "}", "").Replace(strings.ToLower(x.Method) + path)
			for _, p := range o.Parameters {
				if p.Ref != "" {
					p.Name, p.In = strings.TrimPrefix(p.Ref, "#/components/parameters/"), "query"
				}
				if p.Required {
					p.Description = strings.TrimSpace("required. " + p.Description)
				}
				x.Params = append(x.Params, param{p.Name, p.In, p.Description})
			}
			for code := range o.Responses {
				x.Codes = append(x.Codes, code)
			}
			sort.Strings(x.Codes)
			ops = append(ops, x)
		}
	}
	order := map[string]int{"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Path != ops[j].Path {
			return ops[i].Path < ops[j].Path
		}
		return order[ops[i].Method] < order[ops[j].Method]
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := apiReferenceTpl.Execute(w, map[string]any{"Info": doc.Info, "Ops": ops}); err != nil {
		s.log.Error("api reference", "err", err)
	}
}

var apiReferenceTpl = template.Must(template.New("ref").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Info.Title}} reference</title><link rel="stylesheet" href="/static/app.css"></head>
<body><main class="content">
<h1>{{.Info.Title}} <span class="muted">version {{.Info.Version}}</span></h1>
<p>Machine readable: <a href="/api/v1/openapi.json">/api/v1/openapi.json</a> (OpenAPI 3.1). Every endpoint takes <code>Authorization: Bearer &lt;token&gt;</code>.</p>
<nav class="card"><ul>{{range .Ops}}<li><a href="#{{.ID}}"><code>{{.Method}} {{.Path}}</code></a> {{.Summary}}</li>{{end}}</ul></nav>
{{range .Ops}}<section class="card" id="{{.ID}}">
<h2><code>{{.Method}} {{.Path}}</code></h2>
<p><strong>{{.Summary}}</strong></p>{{if .Description}}<p>{{.Description}}</p>{{end}}
{{if .Params}}<table><thead><tr><th>Parameter</th><th>In</th><th>Description</th></tr></thead><tbody>
{{range .Params}}<tr><td><code>{{.Name}}</code></td><td>{{.In}}</td><td>{{.Description}}</td></tr>{{end}}</tbody></table>{{end}}
<p class="muted">Answers: {{range $i, $c := .Codes}}{{if $i}}, {{end}}{{$c}}{{end}}</p>
</section>{{end}}
</main></body></html>
`))

// preconditionFail answers err; a failed If-Match carries the current ETag.
func (s *Server) preconditionFail(w http.ResponseWriter, r *http.Request, table string, id int64, err error) {
	if errors.Is(err, errPrecondition) {
		s.setETag(r.Context(), w, table, id)
	}
	s.apiFail(w, err)
}
