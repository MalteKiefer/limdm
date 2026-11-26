package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// API endpoints of the console app (/app/, webapp.go). They live in the
// admin API, so tokens can use them too; the app itself authenticates with
// the console session (sessionCaller).

// appAPIRoutes adds the console app endpoints to the admin API mux.
func (s *Server) appAPIRoutes(m *http.ServeMux) {
	s.appDevicesRoutes(m)
	m.HandleFunc("GET /api/v1/me", s.need("read", s.apiMe))
	m.HandleFunc("GET /api/v1/events/stream", s.need("read", s.apiEventStream))
	m.HandleFunc("GET /api/v1/devices/facets", s.need("read", s.apiDeviceFacets))
	m.HandleFunc("GET /api/v1/schemas", s.need("read", s.apiSchemas))
	m.HandleFunc("GET /api/v1/schemas/{type}", s.need("read", s.apiSchema))
	m.HandleFunc("GET /api/v1/views", s.need("read", s.apiViews))
	m.HandleFunc("POST /api/v1/views", s.need("self", s.apiViewSave))
	m.HandleFunc("PUT /api/v1/views/{id}", s.need("self", s.apiViewSave))
	m.HandleFunc("DELETE /api/v1/views/{id}", s.need("self", s.apiViewDelete))
	m.HandleFunc("GET /api/v1/stats/fleet", s.need("read", s.apiStatsFleet))
	m.HandleFunc("GET /api/v1/stats/compliance", s.need("read", s.apiStatsCompliance))
	m.HandleFunc("GET /api/v1/stats/attention", s.need("read", s.apiStatsAttention))
	s.appComplianceRoutes(m)
	s.appHomeRoutes(m)
	s.appInboxRoutes(m)
	s.appActivityRoutes(m)
	s.appReportsRoutes(m)
	s.appConfigRoutes(m)   // configuration area (app_config.go)
	s.appSettingsRoutes(m) // app_settings.go
}

// csrfHeader carries the session's CSRF token on every state changing
// request of the console app.
const csrfHeader = "X-CSRF-Token"

// sessionCaller authenticates a console app request by the session cookie.
// Every request must come from the console's own origin (Sec-Fetch-Site,
// Origin); every state change must also carry the session's CSRF token in
// the X-CSRF-Token header, which only a page of our origin can read (from
// /api/v1/me). The session gets the token limits: 600 requests a minute.
func (s *Server) sessionCaller(w http.ResponseWriter, r *http.Request) (apiCaller, bool) {
	sess, ok := s.session(w, r)
	if !ok {
		problem(w, http.StatusUnauthorized, "session expired: sign in again")
		return apiCaller{}, false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		problem(w, http.StatusForbidden, "cross site request refused")
		return apiCaller{}, false
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.cfg.PublicURL {
		problem(w, http.StatusForbidden, "origin check failed")
		return apiCaller{}, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if !s.macOK(fmt.Sprintf("csrf|%s|%d", sess.Email, sess.IAT.UnixNano()), r.Header.Get(csrfHeader)) {
			problem(w, http.StatusForbidden, "csrf check failed")
			return apiCaller{}, false
		}
	}
	if !s.limit.allow("apisess:"+sess.Email, 600, time.Minute) {
		w.Header().Set("Retry-After", "60")
		problem(w, http.StatusTooManyRequests, "rate limit: 600 requests per minute")
		return apiCaller{}, false
	}
	return apiCaller{Name: sess.Email, Role: sess.Role, Tags: sess.Tags, Tenant: sess.Tenant, Sess: &sess}, true
}

type apiMeTenant struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// apiMeInfo is the current user as the console app needs it.
type apiMeInfo struct {
	Login       string       `json:"login"`
	Role        string       `json:"role"`
	Tenant      *apiMeTenant `json:"tenant"` // nil: the global view
	Super       bool         `json:"super"`  // may see every tenant and switch between them
	MultiTenant bool         `json:"multi_tenant"`
	ScopeTags   []string     `json:"scope_tags"`
	ScopeGroups []string     `json:"scope_groups"`
	Scopes      []string     `json:"scopes"`
	Permissions []string     `json:"permissions"`
	FourEyes    bool         `json:"four_eyes"`
	Locale      string       `json:"locale"`
	DateFormat  string       `json:"date_format"`
	StaleHours  int          `json:"stale_hours"`
	Version     string       `json:"version"`
	CompanyName string       `json:"company_name"` // branding of the tenant or the installation
	Accent      string       `json:"accent"`       // tenant color (#rrggbb) or empty; the app guards its contrast
	CSRFToken   string       `json:"csrf_token,omitempty"`
}

// permissionLevels map the permission names of /api/v1/me to access levels.
var permissionLevels = []struct{ Name, Level string }{
	{"read", "read"}, {"audit", "audit"}, {"commands", "helpdesk"}, {"admin", "admin"},
}

// permissions lists what the caller may do, by role and token scopes (can).
func (c apiCaller) permissions(multiTenant bool) []string {
	out := []string{}
	for _, p := range permissionLevels {
		if c.can(p.Level) {
			out = append(out, p.Name)
		}
	}
	if multiTenant && c.can("admin") && (c.Tenant == 0 || c.Sess != nil && c.Sess.Super) {
		out = append(out, "tenants")
	}
	return out
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request, c apiCaller) {
	sess := c.sess()
	me := apiMeInfo{Login: c.actor(), Role: c.Role, Super: sess.Super, MultiTenant: s.cfg.MultiTenant,
		ScopeTags: nonNil(sess.Tags), ScopeGroups: nonNil(sess.Groups), Scopes: nonNil(c.Scopes),
		Permissions: c.permissions(s.cfg.MultiTenant), FourEyes: s.settings().FourEyes, Locale: requestLang(r),
		DateFormat: requestDateFormat(r), StaleHours: s.settings().StaleHours, Version: Version}
	if c.Sess != nil {
		me.CSRFToken = s.csrfToken(*c.Sess)
	}
	b, color := s.tenantBrand(r.Context(), s.db, sess.Tenant)
	me.CompanyName = b.Name
	if colorRe.MatchString(color) {
		me.Accent = color
	}
	if sess.Tenant != 0 {
		t := apiMeTenant{ID: sess.Tenant}
		if err := s.db.QueryRow(r.Context(), `SELECT name FROM tenants WHERE id=$1`, sess.Tenant).Scan(&t.Name); err != nil {
			s.apiFail(w, err)
			return
		}
		me.Tenant = &t
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, me)
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// apiSchemas lists the declaration types that have a payload schema.
func (s *Server) apiSchemas(w http.ResponseWriter, r *http.Request, c apiCaller) {
	type item struct {
		Type        string `json:"type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Doc         string `json:"doc"`
		FourEyes    bool   `json:"four_eyes"` // root effective: saves need four eyes approval while it is on
	}
	lang := schemaLang(r)
	out := []item{}
	for _, t := range api.PayloadTypes() {
		out = append(out, item{t, translate(lang, firstNonEmpty(typeLabels[t], t)), translate(lang, typeInfo[t].Desc),
			docsURL + "declarations.md#" + typeInfo[t].Anchor, rootTypes[t]})
	}
	writeJSON(w, listPage{Items: out})
}

// apiSchema serves the JSON Schema of one declaration type's payload.
func (s *Server) apiSchema(w http.ResponseWriter, r *http.Request, c apiCaller) {
	typ := r.PathValue("type")
	sch, ok := api.PayloadSchema(typ)
	if !ok {
		problem(w, http.StatusNotFound, "unknown declaration type")
		return
	}
	sch["$id"] = "/api/v1/schemas/" + typ
	lang := schemaLang(r)
	sch["title"] = translate(lang, firstNonEmpty(typeLabels[typ], typ))
	sch["description"] = translate(lang, typeInfo[typ].Desc)
	annotateSchema(sch, typ, lang) // titles, help, choices and widgets (app_config_schema.go)
	w.Header().Set("Cache-Control", "private, max-age=300")
	writeJSON(w, sch)
}
