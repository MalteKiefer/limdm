package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Multi tenancy (Mandanten): an MSP or a group of companies runs one server
// for several companies. Every device, enrollment token, library item,
// blueprint, risk exception and approval belongs to one tenant; tenant 1
// ("Default") owns everything from before tenants existed. Console users,
// API tokens and notification channels belong to one tenant or are global
// (tenant NULL): global admins are super admins.
//
// Isolation is deny by default on two levels: a session bound to a tenant
// reaches only the routes in tenantRoutes (every other route answers 403),
// and those handlers filter by tenant through scopeCond (devices, the same
// central filter as the device scopes) or tenantCond and tenantOwns (the
// other tables).

const defaultTenant int64 = 1

type tenantKey struct{}

// withTenant records the tenant a request acts for (audit entries, new objects).
func withTenant(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, tenantKey{}, id)
}

// ctxTenant is the tenant a request acts for, 0 for global requests.
func ctxTenant(ctx context.Context) int64 {
	id, _ := ctx.Value(tenantKey{}).(int64)
	return id
}

// ownerTenant is the tenant new objects of a request belong to: its tenant,
// or the default tenant for global requests.
func ownerTenant(ctx context.Context) int64 {
	if id := ctxTenant(ctx); id != 0 {
		return id
	}
	return defaultTenant
}

// tenantCond limits rows to the tenant of sess (col is the tenant column),
// with its argument numbered after n existing ones.
func tenantCond(sess session, col string, n int) (string, []any) {
	if sess.Tenant == 0 {
		return "TRUE", nil
	}
	return col + " = $" + strconv.Itoa(n+1), []any{sess.Tenant}
}

// sharedCond is tenantCond plus the rows of the default tenant marked
// shared (library items, blueprints): readable by every tenant, never
// writable by one.
func sharedCond(sess session, alias string, n int) (string, []any) {
	if sess.Tenant == 0 {
		return "TRUE", nil
	}
	return fmt.Sprintf("(%[1]s.tenant_id = $%[2]d OR %[1]s.tenant_id = 1 AND %[1]s.shared)", alias, n+1), []any{sess.Tenant}
}

// tenantTables are the tables tenantOwns may look into, with their key column.
var tenantTables = map[string]string{
	"library_items": "id", "blueprints": "id", "risk_exceptions": "id", "approvals": "id",
	"notification_channels": "id", "api_tokens": "id", "enroll_tokens": "token_hash", "devices": "id",
}

// tenantOwns reports whether the row of table with the key id belongs to
// the tenant of sess; with shared, shared rows of the default tenant count
// too (read only use). Global sessions own every row. Unknown rows are
// not owned, so callers answer 404 either way.
func (s *Server) tenantOwns(ctx context.Context, sess session, table string, id any, shared bool) bool {
	if sess.Tenant == 0 {
		return true
	}
	key, ok := tenantTables[table]
	if !ok {
		return false
	}
	q := `SELECT EXISTS(SELECT 1 FROM ` + table + ` t WHERE t.` + key + `=$1 AND (t.tenant_id=$2`
	if shared {
		q += ` OR t.tenant_id=1 AND t.shared`
	}
	var owned bool
	err := s.db.QueryRow(ctx, q+`))`, id, sess.Tenant).Scan(&owned)
	return err == nil && owned
}

// loadTenant sets the tenant of a session on every request: tenant accounts
// get their tenant (a disabled tenant ends the session), global accounts are
// super admins and keep the tenant they switched to while it is active.
func (s *Server) loadTenant(ctx context.Context, sess *session) error {
	q, key := `SELECT tenant_id FROM console_users WHERE email=$1`, sess.Email
	if name, ok := strings.CutPrefix(sess.Email, localPrefix); ok {
		q, key = `SELECT tenant_id FROM local_admins WHERE name=$1`, name
	}
	var t *int64
	if err := s.db.QueryRow(ctx, q, key).Scan(&t); err != nil {
		return err
	}
	sess.Super = t == nil
	if t != nil {
		sess.Tenant = *t
	}
	if sess.Tenant == 0 {
		return nil
	}
	var disabled bool
	err := s.db.QueryRow(ctx, `SELECT disabled FROM tenants WHERE id=$1`, sess.Tenant).Scan(&disabled)
	switch {
	case sess.Super && (err != nil || disabled):
		sess.Tenant = 0 // back to the global view
		return nil
	case err != nil:
		return err
	case disabled:
		return errors.New("tenant disabled")
	}
	return nil
}

// tenantRoutes are the console routes open to accounts bound to a tenant.
// Each handler filters what it reads and writes by the session tenant;
// every route missing here is global and answers 403 to them.
var tenantRoutes = map[string]bool{
	"GET /{$}": true, "GET /help": true, "POST /onboarding/dismiss": true,
	"GET /devices": true, "GET /devices/{id}": true, "POST /devices/bulk": true, "POST /devices/{id}/command": true,
	"GET /devices/{id}/diagnostics/{cid}": true, "POST /devices/{id}/agent-update": true, "POST /devices/{id}/recovery": true,
	"POST /devices/{id}/assign": true, "POST /devices/{id}/retire": true, "POST /devices/{id}/delete": true,
	"GET /devices/{id}/shell": true, "POST /devices/{id}/shell": true, "GET /shell/{sid}": true, "POST /shell/{sid}/end": true,
	"GET /users": true, "POST /users": true, "POST /users/update": true, "POST /users/reset": true,
	"GET /profile": true, "POST /profile/password": true, "POST /profile/totp": true, "POST /profile/recovery": true,
	"GET /blueprints": true, "GET /blueprints/{id}": true, "POST /blueprints": true, "POST /blueprints/{id}/delete": true,
	"GET /blueprints/{id}/history": true, "POST /blueprints/{id}/rollback": true,
	"GET /library": true, "GET /library/{id}": true, "POST /library": true, "POST /library/{id}/delete": true,
	"GET /library/{id}/history": true, "POST /library/{id}/rollback": true,
	"GET /tokens": true, "POST /tokens": true, "POST /tokens/{id}/revoke": true,
	"GET /compliance": true, "GET /compliance/history": true, "POST /compliance/exceptions": true, "POST /compliance/exceptions/{id}/revoke": true,
	"GET /audit": true, "GET /export/{kind}": true,
	"GET /approvals": true, "POST /approvals/{id}/{op}": true,
	"GET /settings": true, "POST /settings/notifications": true, "POST /settings/notifications/{id}/{op}": true,
	"GET /settings/api": true, "POST /settings/api": true, "POST /settings/api/{id}/revoke": true,
	"GET /network": true, "GET /network/ca.pem": true,
	"GET /tenants/{id}": true, "POST /tenants/{id}": true, "GET /tenants/{id}/logo.png": true, "GET /branding/tenant.css": true,
}

// tenantAllowed is the route gate of pageFor.
func tenantAllowed(sess session, pattern string) bool {
	return sess.Super || sess.Tenant == 0 || tenantRoutes[pattern]
}

// TenantOnly reports whether sess is bound to a tenant (not a super admin).
func (sess session) TenantOnly() bool { return !sess.Super && sess.Tenant != 0 }

type tenant struct {
	ID          int64
	Name        string
	Disabled    bool
	CompanyName string
	HasLogo     bool
	Color       string
	Devices     int
	CreatedAt   time.Time
}

func (s *Server) tenantPages(mux *http.ServeMux) {
	mux.HandleFunc("GET /tenants", s.page(s.superOnly(s.tenantsPage)))
	mux.HandleFunc("POST /tenants", s.page(s.superOnly(s.tenantCreate)))
	mux.HandleFunc("POST /tenants/switch", s.page(s.superOnly(s.tenantSwitch)))
	mux.HandleFunc("POST /tenants/shared", s.page(s.superOnly(s.tenantShared)))
	mux.HandleFunc("GET /tenants/{id}", s.page(s.tenantEdit))
	mux.HandleFunc("POST /tenants/{id}", s.page(s.tenantSave))
	mux.HandleFunc("GET /tenants/{id}/logo.png", s.page(s.tenantLogo))
	mux.HandleFunc("GET /branding/tenant.css", s.page(s.tenantCSS))
}

// superOnly limits a page to global accounts while multi tenancy is on.
func (s *Server) superOnly(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		if !s.cfg.MultiTenant {
			s.notFound(w, r, sess)
			return
		}
		if !sess.Super {
			s.errorPage(w, r, sess, http.StatusForbidden, "only global administrators manage tenants")
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) tenantList(ctx context.Context) ([]tenant, error) {
	rows, err := s.db.Query(ctx, `SELECT t.id, t.name, t.disabled, t.company_name, length(t.logo) > 0, t.color,
		(SELECT count(*) FROM devices d WHERE d.tenant_id=t.id AND NOT d.retired)::int, t.created_at FROM tenants t ORDER BY t.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[tenant])
}

func (s *Server) tenantsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderTenants(w, r, sess, "")
}

func (s *Server) renderTenants(w http.ResponseWriter, r *http.Request, sess session, errMsg string) {
	ctx := r.Context()
	list, err := s.tenantList(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	type obj struct {
		ID         int64
		Name, Type string
		Shared     bool
	}
	objs := func(q string) ([]obj, error) {
		rows, err := s.db.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, pgx.RowToStructByPos[obj])
	}
	bps, err := objs(`SELECT id, name, '', shared FROM blueprints WHERE tenant_id=1 ORDER BY name`)
	if err != nil {
		s.fail(w, err)
		return
	}
	items, err := objs(`SELECT id, name, type, shared FROM library_items WHERE tenant_id=1 ORDER BY type, name`)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "tenants", map[string]any{"Tenants": list, "Error": errMsg, "Blueprints": bps, "Items": items})
}

// tenantShared sets which library items and blueprints of the default
// tenant every tenant may read and use.
func (s *Server) tenantShared(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, sess, http.StatusBadRequest, "bad form")
		return
	}
	ids := func(key string) []int64 {
		out := []int64{}
		for _, v := range r.Form[key] {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				out = append(out, id)
			}
		}
		return out
	}
	bps, items := ids("blueprint"), ids("item")
	err := s.auditAction(ctx, sess.Email, "tenant.shared", "", fmt.Sprintf("blueprints=%v items=%v", bps, items), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE blueprints SET shared = (id = ANY($1)) WHERE tenant_id=1`, bps); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE library_items SET shared = (id = ANY($1)) WHERE tenant_id=1`, items)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/tenants", http.StatusSeeOther)
}

// tenantName checks a tenant name: 1 to 100 characters, no control characters.
func tenantName(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || utf8.RuneCountInString(v) > 100 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("tenant name: 1 to 100 characters")
	}
	return v, nil
}

func (s *Server) tenantCreate(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := s.createTenant(r.Context(), sess, r.FormValue("name"))
	var ue *userError
	switch {
	case errors.As(err, &ue) && ue.Status == http.StatusConflict:
		s.renderTenants(w, r, sess, "A tenant with this name exists already.")
		return
	case errors.As(err, &ue):
		s.renderTenants(w, r, sess, ue.Msg)
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/tenants/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// createTenant adds a tenant (console and admin API); a bad or taken name
// is a userError.
func (s *Server) createTenant(ctx context.Context, sess session, name string) (int64, error) {
	name, err := tenantName(name)
	if err != nil {
		return 0, &userError{http.StatusBadRequest, err.Error()}
	}
	var id int64
	err = s.auditAction(ctx, sess.Email, "tenant.add", name, "", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ($1) RETURNING id`, name).Scan(&id)
	})
	if isUnique(err) {
		return 0, &userError{http.StatusConflict, "a tenant with this name exists already"}
	}
	return id, err
}

// tenantSwitch sets the tenant context of a super admin (0: global view).
// The choice lives in the signed session cookie and is checked on every
// request (loadTenant).
func (s *Server) tenantSwitch(w http.ResponseWriter, r *http.Request, sess session) {
	id, _ := strconv.ParseInt(r.FormValue("tenant"), 10, 64)
	if id != 0 {
		var ok bool
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1 AND NOT disabled)`, id).Scan(&ok); err != nil || !ok {
			s.notFound(w, r, sess)
			return
		}
	}
	sess.Tenant = id
	s.setCookie(w, sessionCookie, s.seal(sess), maxSession-time.Since(sess.IAT))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// editableTenant parses {id}: super admins edit every tenant, tenant
// admins only their own (branding).
func (s *Server) editableTenant(w http.ResponseWriter, r *http.Request, sess session) (tenant, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || !s.cfg.MultiTenant || sess.TenantOnly() && id != sess.Tenant {
		s.notFound(w, r, sess)
		return tenant{}, false
	}
	var t tenant
	err = s.db.QueryRow(r.Context(), `SELECT id, name, disabled, company_name, length(logo) > 0, color, 0, created_at FROM tenants WHERE id=$1`, id).
		Scan(&t.ID, &t.Name, &t.Disabled, &t.CompanyName, &t.HasLogo, &t.Color, &t.Devices, &t.CreatedAt)
	if err != nil {
		s.notFound(w, r, sess)
		return tenant{}, false
	}
	return t, true
}

func (s *Server) tenantEdit(w http.ResponseWriter, r *http.Request, sess session) {
	if t, ok := s.editableTenant(w, r, sess); ok {
		s.render(w, r, sess, "tenant", map[string]any{"T": t})
	}
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// tenantSave stores name and state (super admins) and the branding.
func (s *Server) tenantSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	t, ok := s.editableTenant(w, r, sess)
	if !ok {
		return
	}
	fail := func(msg string) { s.render(w, r, sess, "tenant", map[string]any{"T": t, "Error": msg}) }
	if sess.Super {
		name, err := tenantName(r.FormValue("name"))
		if err != nil {
			fail(err.Error())
			return
		}
		t.Name = name
		t.Disabled = r.FormValue("disabled") == "on" && t.ID != defaultTenant
	}
	t.CompanyName = strings.TrimSpace(r.FormValue("company_name"))
	t.Color = strings.ToLower(strings.TrimSpace(r.FormValue("color")))
	if t.Color == "#0f6e6e" { // the color picker's default: keep the console colors
		t.Color = ""
	}
	if utf8.RuneCountInString(t.CompanyName) > 100 {
		fail("company name: up to 100 characters")
		return
	}
	if t.Color != "" && !colorRe.MatchString(t.Color) {
		fail("color: #rrggbb")
		return
	}
	var logo []byte
	keepLogo := r.FormValue("remove_logo") != "on"
	if f, _, err := r.FormFile("logo"); err == nil {
		logo, err = io.ReadAll(io.LimitReader(f, maxLogo+1))
		f.Close()
		if err != nil {
			s.fail(w, err)
			return
		}
		if err := validLogo(logo); err != nil {
			fail(err.Error())
			return
		}
		keepLogo = false
	}
	detail := fmt.Sprintf("name=%q disabled=%v company=%q color=%q logo_bytes=%d keep_logo=%v", t.Name, t.Disabled, t.CompanyName, t.Color, len(logo), keepLogo)
	err := s.auditAction(ctx, sess.Email, "tenant.update", strconv.FormatInt(t.ID, 10), detail, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE tenants SET name=$2, disabled=$3, company_name=$4, color=$5, logo=CASE WHEN $7 THEN logo ELSE $6 END WHERE id=$1`,
			t.ID, t.Name, t.Disabled, t.CompanyName, t.Color, logo, keepLogo)
		return err
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			fail("A tenant with this name exists already.")
			return
		}
		s.fail(w, err)
		return
	}
	s.brands.Delete(t.ID)
	http.Redirect(w, r, "/tenants/"+strconv.FormatInt(t.ID, 10), http.StatusSeeOther)
}

func (s *Server) tenantLogo(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || sess.TenantOnly() && id != sess.Tenant {
		s.notFound(w, r, sess)
		return
	}
	b, _ := s.tenantBrand(r.Context(), s.db, id)
	if len(b.Logo) == 0 {
		s.notFound(w, r, sess)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Write(b.Logo)
}

// tenantCSS overrides the accent color with the tenant's color (a file, so
// the CSP needs no inline styles).
func (s *Server) tenantCSS(w http.ResponseWriter, r *http.Request, sess session) {
	_, color := s.tenantBrand(r.Context(), s.db, sess.Tenant)
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=300")
	if colorRe.MatchString(color) {
		fmt.Fprintf(w, ":root, :root:not([data-theme=\"light\"]), :root[data-theme=\"dark\"] { --accent: %s; }\n", color)
	}
}

type brandEntry struct {
	b     api.Branding
	color string
	at    time.Time
}

// tenantBrand is the branding of a tenant with the global branding as
// fallback for name and logo; tenant 0 is the global branding. Cached for
// a minute: devices ask on every check in.
func (s *Server) tenantBrand(ctx context.Context, q rowQuerier, id int64) (api.Branding, string) {
	global := s.branding()
	if id == 0 {
		return global, ""
	}
	if v, ok := s.brands.Load(id); ok && time.Since(v.(brandEntry).at) < time.Minute {
		e := v.(brandEntry)
		return e.b, e.color
	}
	var name, color string
	var logo []byte
	if err := q.QueryRow(ctx, `SELECT company_name, logo, color FROM tenants WHERE id=$1`, id).Scan(&name, &logo, &color); err != nil {
		return global, ""
	}
	if name == "" && len(logo) == 0 {
		s.brands.Store(id, brandEntry{global, color, time.Now()})
		return global, color
	}
	if name == "" {
		name = global.Name
	}
	if len(logo) == 0 {
		logo = global.Logo
	}
	h := sha256.Sum256(bytes.Join([][]byte{[]byte(name), logo}, []byte{0}))
	b := api.Branding{Name: name, Logo: logo, Hash: hex.EncodeToString(h[:])[:16]}
	s.brands.Store(id, brandEntry{b, color, time.Now()})
	return b, color
}

// deviceBranding is what a device receives: the branding of its tenant.
func (s *Server) deviceBranding(ctx context.Context, q rowQuerier, deviceID string) api.Branding {
	var id int64
	if err := q.QueryRow(ctx, `SELECT tenant_id FROM devices WHERE id=$1`, deviceID).Scan(&id); err != nil {
		return s.branding()
	}
	b, _ := s.tenantBrand(ctx, q, id)
	return b
}

// consoleBrand fills the layout's branding and tenant switcher.
func (s *Server) consoleBrand(ctx context.Context, sess session, data map[string]any) {
	b, color := s.tenantBrand(ctx, s.db, sess.Tenant)
	logo := ""
	if len(b.Logo) > 0 {
		logo = "/branding/logo.png?v=" + b.Hash
		if sess.Tenant != 0 && b.Hash != s.branding().Hash {
			logo = fmt.Sprintf("/tenants/%d/logo.png?v=%s", sess.Tenant, b.Hash)
		}
	}
	data["Brand"] = map[string]any{"Name": b.Name, "Logo": logo != "", "LogoURL": logo, "V": b.Hash, "Color": color != ""}
	if sess.Email == "" || !s.cfg.MultiTenant {
		return
	}
	data["MultiTenant"] = true
	if sess.Super {
		if list, err := s.tenantList(ctx); err == nil {
			data["TenantList"] = list
		}
	}
	if sess.Tenant != 0 {
		var name string
		_ = s.db.QueryRow(ctx, `SELECT name FROM tenants WHERE id=$1`, sess.Tenant).Scan(&name)
		data["TenantName"] = name
	}
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// tenantGuard refuses, as not found, a row of table that does not belong to
// the tenant the request acts for (ctxTenant); global requests pass. The
// shared save and delete functions of the console and the admin API call it.
func tenantGuard(ctx context.Context, q rowQuerier, table string, id any) error {
	t := ctxTenant(ctx)
	if t == 0 {
		return nil
	}
	key, ok := tenantTables[table]
	if !ok {
		return errors.New("tenantGuard: unknown table " + table)
	}
	var owned bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE `+key+`=$1 AND tenant_id=$2)`, id, t).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return &userError{http.StatusNotFound, "not found"}
	}
	return nil
}

// visibleCond is sharedCond for the tenant a request acts for.
func visibleCond(ctx context.Context, alias string, n int) (string, []any) {
	return sharedCond(session{Tenant: ctxTenant(ctx)}, alias, n)
}

// tenantDevices limits devices d to the tenant a request acts for.
func tenantDevices(ctx context.Context, n int) (string, []any) {
	return tenantCond(session{Tenant: ctxTenant(ctx)}, "d.tenant_id", n)
}
