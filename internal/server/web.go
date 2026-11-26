package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

//go:embed web/*.html web/static
var webFS embed.FS

var staticFS, _ = fs.Sub(webFS, "web")

// dateFormats are the date and time notations a user can pick in the profile.
var dateFormats = map[string]string{
	"iso": "2006-01-02 15:04",
	"de":  "02.01.2006 15:04",
	"uk":  "02/01/2006 15:04",
	"us":  "01/02/2006 3:04 PM",
}

// pages holds the parsed templates (sign in and error page) per language.
var pages = map[string]map[string]*template.Template{"en": parsePages("en"), "de": parsePages("de")}

func parsePages(lang string) map[string]*template.Template {
	funcs := template.FuncMap{
		"t":       func(s string) string { return translate(lang, s) },
		"errmsg":  func(msg string) friendlyMsg { return friendlyError(lang, msg) },
		"lang":    func() string { return lang },
		"version": func() string { return Version },
	}
	m := map[string]*template.Template{}
	names, _ := fs.Glob(webFS, "web/*.html")
	for _, n := range names {
		if n == "web/layout.html" {
			continue
		}
		key := strings.TrimSuffix(strings.TrimPrefix(n, "web/"), ".html")
		m[key] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(webFS, "web/layout.html", n))
	}
	return m
}

type handler func(w http.ResponseWriter, r *http.Request, sess session)

// page enforces login, admin role for every state change, and CSRF.
func (s *Server) page(h handler) http.HandlerFunc { return s.pageFor(h, "admin") }

// adminOrAuditor hides administration pages from the helpdesk role.
func (s *Server) adminOrAuditor(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		if sess.Role == "helpdesk" {
			s.errorPage(w, r, sess, http.StatusForbidden, "not available for the helpdesk role")
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) pageFor(h handler, postRole string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(w, r)
		if !ok {
			toLogin(w, r)
			return
		}
		if !tenantAllowed(sess, r.Pattern) { // deny by default (tenant.go)
			s.errorPage(w, r, sess, http.StatusForbidden, "not available for tenant accounts")
			return
		}
		if sess.Tenant != 0 && tenantRoutes[r.Pattern] {
			r = r.WithContext(withTenant(r.Context(), sess.Tenant))
		}
		// every device route checks the device against tenant and scope here,
		// so a handler cannot forget it
		if strings.Contains(r.Pattern, "/devices/{id}") && (sess.Tenant != 0 || sess.scoped()) && !s.inScope(r.Context(), sess, r.PathValue("id")) {
			s.notFound(w, r, sess)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, s.bodyLimit(w, r)) // 1 MiB, uploads more (packages.go)
			if sess.Role != "admin" && postRole != "self" && (postRole != "helpdesk" || sess.Role != "helpdesk") {
				s.errorPage(w, r, sess, http.StatusForbidden, "your role cannot change this")
				return
			}
			if !s.csrfOK(r, sess) {
				s.errorPage(w, r, sess, http.StatusForbidden, "csrf check failed")
				return
			}
		}
		h(w, r, sess)
	}
}

var typeLabels = map[string]string{
	api.TypeAgent: "Agent", api.TypeCompliance: "Compliance", api.TypeUpdates: "Software updates",
	api.TypePackages: "Packages", api.TypeServices: "Services", api.TypeFiles: "Files", api.TypeFirewall: "Firewall",
	api.TypeOSVersion: "OS versions", api.TypeScreenLock: "Screen lock", api.TypeLogin: "Desktop login (OIDC)",
	api.TypePrivacy: "Privacy", api.TypeRepositories: "Package sources", api.TypeCertificates: "CA certificates",
	api.TypeSysctl: "Kernel parameters", api.TypeKernelModules: "Blocked kernel modules", api.TypeSSH: "SSH server options",
	api.TypeBanner: "Login banner", api.TypeDNS: "DNS", api.TypeNTP: "Time servers", api.TypeProxy: "Proxy",
	api.TypeFlatpak: "Flatpak apps", api.TypeScripts: "Recurring scripts",
	api.TypeDiskEncryption: "Disk encryption recovery", api.TypePolkit: "polkit rules", api.TypeSudo: "sudo rules",
	api.TypeBootloader: "Boot loader password", api.TypeSoftwareStore: "Software store policy",
	api.TypePrinters: "Printers",
	api.TypeDconf:    "GNOME settings (dconf)", api.TypeLocalUsers: "Local accounts",
	api.TypeCustomChecks: "Custom compliance checks",
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sess session, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Sess"] = sess
	data["CSRF"] = s.csrfToken(sess)
	data["Page"] = name
	s.consoleBrand(r.Context(), sess, data)
	var buf bytes.Buffer
	if err := pages[requestLang(r)][name].Execute(&buf, data); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// classicPaths maps the pages of the former server rendered console to the
// matching console app page, so bookmarks keep working; {id} carries over.
var classicPaths = map[string]string{ //nolint:gosec // page paths, no credentials
	"/classic": "/app/", "/help": "/app/help", "/profile": "/app/profile",
	"/devices": "/app/devices", "/devices/{id}": "/app/devices/{id}", "/devices/{id}/shell": "/app/devices/{id}",
	"/compliance": "/app/compliance", "/compliance/history": "/app/compliance/history",
	"/blueprints": "/app/config", "/blueprints/{id}": "/app/config/blueprints/{id}", "/blueprints/{id}/history": "/app/config/blueprints/{id}",
	"/library": "/app/config?tab=library", "/library/{id}": "/app/config/library/{id}", "/library/{id}/history": "/app/config/library/{id}",
	"/software": "/app/config?tab=software", "/software/new": "/app/config/software/new", "/software/apps/{id}": "/app/config/software/{id}",
	"/software/packages": "/app/config?tab=packages", "/tokens": "/app/devices/enroll",
	"/audit": "/app/activity", "/approvals": "/app/inbox", "/export/{kind}": "/app/reports",
	"/settings": "/app/settings", "/settings/api": "/app/settings?s=tokens", "/settings/backup": "/app/settings?s=backup",
	"/users": "/app/settings?s=users", "/directory": "/app/settings?s=directory", "/agents": "/app/settings?s=agents",
	"/network": "/app/settings?s=network", "/tenants": "/app/settings?s=tenants", "/tenants/{id}": "/app/settings?s=tenants",
	"/shell/{sid}": "/app/",
}

func (s *Server) webRoutes(mux *http.ServeMux) {
	s.networkRoutes(mux)
	s.shellRoutes(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/app/", http.StatusFound) })
	for from, to := range classicPaths {
		mux.HandleFunc("GET "+from, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, strings.ReplaceAll(to, "{id}", url.PathEscape(r.PathValue("id"))), http.StatusFound)
		})
	}
	// files the console app links to
	mux.HandleFunc("GET /software/icons/{id}", s.page(func(w http.ResponseWriter, r *http.Request, _ session) { s.catalogIcon(w, r) }))
	mux.HandleFunc("GET /software/flathub/icon", s.page(s.adminOrAuditor(func(w http.ResponseWriter, r *http.Request, _ session) { s.flathubIcon(w, r) })))
	mux.HandleFunc("GET /tenants/{id}/logo.png", s.page(s.tenantLogo))
}

// ---- devices ----

type deviceRow struct {
	ID, Hostname, OS, AgentVersion, Blueprints string
	Tags                                       []string
	Desktop                                    string
	MemoryMB                                   uint64
	GraceUntil                                 *time.Time
	AutoLocked                                 bool
	UpdateState, UpdateVersion                 string
	UpdateRequested                            bool
	ExternalIP                                 string
	Geo                                        *Geo
	Failing                                    int
	Checks                                     int
	LastSeen                                   *time.Time
	Retired                                    bool
	Status, Class                              string
}

func (s *Server) status(d *deviceRow) {
	switch {
	case d.Retired:
		d.Status, d.Class = "retired", "na"
	case d.LastSeen == nil || d.Checks == 0:
		d.Status, d.Class = "pending", "warn"
	case time.Since(*d.LastSeen) > s.staleAfter():
		d.Status, d.Class = "stale", "warn"
	case d.Failing > 0 && d.GraceUntil != nil && time.Now().Before(*d.GraceUntil):
		d.Status, d.Class = "in grace", "warn"
	case d.Failing > 0:
		d.Status, d.Class = "non-compliant", "bad"
	default:
		d.Status, d.Class = "compliant", "ok"
	}
}

func (s *Server) listDevices(ctx context.Context) ([]deviceRow, error) {
	return s.listDevicesWhere(ctx, "TRUE")
}

// listDevicesWhere lists devices matching a condition on d (devices).
func (s *Server) listDevicesWhere(ctx context.Context, where string, args ...any) ([]deviceRow, error) {
	return s.listDevicesQuery(ctx, where, ` ORDER BY d.retired, d.hostname`, args...)
}

// listDevicesQuery lists devices matching a condition on d; tail orders
// and pages the result.
func (s *Server) listDevicesQuery(ctx context.Context, where, tail string, args ...any) ([]deviceRow, error) {
	rows, err := s.db.Query(ctx, `SELECT d.id, d.hostname, d.os_name, d.agent_version,
		coalesce(b.name, 'default'), d.tags,
		d.desktop, d.memory_mb, d.failing, d.checks_count, d.last_seen, d.retired, d.grace_until, d.auto_locked`+
		deviceFrom+` WHERE `+where+tail, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (deviceRow, error) {
		var d deviceRow
		err := row.Scan(&d.ID, &d.Hostname, &d.OS, &d.AgentVersion, &d.Blueprints, &d.Tags, &d.Desktop, &d.MemoryMB, &d.Failing, &d.Checks, &d.LastSeen, &d.Retired, &d.GraceUntil, &d.AutoLocked)
		s.status(&d)
		return d, err
	})
}

// deviceFilters are the device list filters other pages link to; each is
// a condition on d with the value as $1. Containment (@>) instead of
// expanding the arrays: the GIN indexes in schema.sql answer it.
var deviceFilters = []struct{ Key, Label, Where string }{
	{"tag", "Tag", `d.tags @> ARRAY[$1::text]`},
	{"app", "Catalog app installed", `d.inventory->'apps' @> jsonb_build_array(jsonb_build_object('id', $1::text, 'installed', true))`},
	{"flatpak", "Flatpak installed", `d.inventory->'flatpaks' @> jsonb_build_array(jsonb_build_object('id', $1::text))`},
	{"remote", "Flatpak remote", `d.inventory->'flatpak_remotes' @> jsonb_build_array(jsonb_build_object('name', $1::text))`},
	{"blueprint", "Blueprint", `(SELECT name FROM blueprints WHERE id = ` + effectiveBlueprintSQL + `) = $1`},
	{"agent", "Agent version", `d.agent_version = $1`},
	{"failing", "Failing check", `d.checks @> jsonb_build_array(jsonb_build_object('id', $1::text, 'status', 'fail'))`},
}

// bulkAction runs one action ("command:<type>", "agent-update", "tag-add",
// "tag-remove") on 1 to 1000 devices of the caller's scope, with the form
// fields of r as parameters (tag, payload, reason, ...). Commands that need
// four eyes become one approval request per device; their count is
// returned. Refusals are userErrors. The console list and the admin API
// share it.
func (s *Server) bulkAction(r *http.Request, sess session, ids []string, action string) (int, error) {
	ctx := r.Context()
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	if len(ids) == 0 || len(ids) > 1000 {
		return 0, &userError{http.StatusBadRequest, "select 1 to 1000 devices"}
	}
	var known int
	cond, sargs := scopeCond(sess, 1)
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM devices d WHERE d.id = ANY($1) AND NOT d.retired AND `+cond, append([]any{ids}, sargs...)...).Scan(&known); err != nil || known != len(ids) {
		return 0, &userError{http.StatusBadRequest, "unknown or retired device selected"}
	}
	op, typ, _ := strings.Cut(action, ":")
	switch op {
	case "tag-add", "tag-remove":
		if sess.Role != "admin" {
			return 0, &userError{http.StatusForbidden, "this action requires the admin role"}
		}
		tags, err := parseTags(r.FormValue("tag"))
		if err != nil || len(tags) != 1 {
			return 0, &userError{http.StatusBadRequest, "one tag: up to 32 letters, digits, dot, dash, underscore"}
		}
		sql := `UPDATE devices SET tags = array_append(tags, $2) WHERE id = $1 AND NOT $2 = ANY(tags)`
		if op == "tag-remove" {
			sql = `UPDATE devices SET tags = array_remove(tags, $2) WHERE id = $1`
		}
		for _, id := range ids {
			if err := s.auditAction(ctx, sess.Email, "device."+op, id, tags[0], func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, sql, id, tags[0])
				return err
			}); err != nil {
				return 0, err
			}
		}
	case "agent-update":
		if sess.Role != "admin" {
			return 0, &userError{http.StatusForbidden, "this action requires the admin role"}
		}
		for _, id := range ids {
			if err := s.auditAction(ctx, sess.Email, "agent_update.request", id, "", func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE devices SET update_requested=true, update_target='' WHERE id=$1`, id)
				return err
			}); err != nil {
				return 0, err
			}
		}
	case "command":
		if typ == "lost" || typ == "wipe" {
			return 0, &userError{http.StatusBadRequest, "lost mode and wipe are sent to one device at a time"}
		}
		payload, code, msg := s.commandPayload(r, sess, ids[0], typ)
		if code != 0 {
			return 0, &userError{code, msg}
		}
		if s.needsApproval(typ) { // bulk scripts: one four eyes request per device
			for _, id := range ids {
				if _, err := s.requestApproval(ctx, sess, "command", id, commandApproval{Type: typ, Payload: payload}, strings.TrimSpace(r.FormValue("reason"))); err != nil {
					return 0, err
				}
			}
			return len(ids), nil
		}
		for _, id := range ids {
			if err := s.queueCommand(ctx, sess.Email, id, typ, payload); err != nil {
				return 0, err
			}
			s.notifyCommand(sess.Email, id, typ)
		}
	default:
		return 0, &userError{http.StatusBadRequest, "unknown action"}
	}
	return 0, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// protective is the latest protective action of one kind on a device.
type protective struct {
	Type   string    `json:"type"`
	Status string    `json:"status"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// protectiveActions lists the latest protective action per kind (lock, lost
// mode, wipe, uninstall release); it stays visible on the device page until
// the next one of its kind replaces it, the release for two hours.
func (s *Server) protectiveActions(ctx context.Context, id string) ([]protective, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (k) type, status, created_by, created_at FROM (
		SELECT *, CASE type WHEN 'unlock' THEN 'lock' WHEN 'found' THEN 'lost' ELSE type END AS k FROM commands
		WHERE device_id=$1 AND type IN ('lock','unlock','lost','found','wipe','allow_uninstall')) c
		ORDER BY k, id DESC`, id)
	if err != nil {
		return nil, err
	}
	protect, err := pgx.CollectRows(rows, pgx.RowToStructByPos[protective])
	return slices.DeleteFunc(protect, func(p protective) bool {
		return p.Type == "allow_uninstall" && time.Since(p.At) > 2*time.Hour
	}), err
}

// declRow is the state of one expected declaration on a device.
type declRow struct {
	Identifier string   `json:"identifier"`
	Type       string   `json:"type"`
	State      string   `json:"state"` // pending | invalid | not achieved | active
	Class      string   `json:"-"`
	Reasons    []string `json:"reasons"`
}

// declarationRows compares the declarations a device should have with what
// it reported.
func declarationRows(want []api.Declaration, got []api.DeclarationStatus) []declRow {
	reported := map[string]api.DeclarationStatus{}
	for _, st := range got {
		reported[st.Identifier] = st
	}
	out := []declRow{}
	for _, dcl := range want {
		row := declRow{Identifier: dcl.Identifier, Type: dcl.Type, Reasons: []string{}}
		st, ok := reported[dcl.Identifier]
		switch {
		case !ok || st.ServerToken != dcl.ServerToken:
			row.State, row.Class = "pending", "warn"
		case !st.Valid:
			row.State, row.Class, row.Reasons = "invalid", "bad", st.Reasons
		case !st.Active:
			row.State, row.Class, row.Reasons = "not achieved", "bad", st.Reasons
		default:
			row.State, row.Class = "active", "ok"
		}
		out = append(out, row)
	}
	return out
}

// queueCommand stores a command for a device and audits it. The entry names
// the command ID, like the command.result entry of the device later does.
func (s *Server) queueCommand(ctx context.Context, actor, id, typ, payload string) error {
	_, err := s.queueCommandID(ctx, actor, id, typ, payload)
	return err
}

// queueCommandID is queueCommand returning the new command's id.
func (s *Server) queueCommandID(ctx context.Context, actor, id, typ, payload string) (int64, error) {
	detail := payload
	var u api.UserCommand
	if strings.HasPrefix(typ, "user_") && json.Unmarshal([]byte(payload), &u) == nil {
		u.Password = ""         // never in the audit log
		b, _ := json.Marshal(u) //nolint:gosec // the password was cleared just above
		detail = string(b)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	cmdID, err := s.insertCommand(ctx, tx, id, typ, payload, actor)
	if err != nil {
		return 0, err
	}
	if typ == "unlock" || typ == "lock" { // a manual action takes over from the compliance policy
		if _, err := tx.Exec(ctx, `UPDATE devices SET auto_locked=false WHERE id=$1`, id); err != nil {
			return 0, err
		}
	}
	if err := audit(ctx, tx, actor, "command."+typ, id, truncate(fmt.Sprintf("command %d %s", cmdID, detail), 2000)); err != nil {
		return 0, err
	}
	return cmdID, tx.Commit(ctx)
}

// commandPayload checks a command from the form and builds its payload; a
// non zero status rejects it with msg.
func (s *Server) commandPayload(r *http.Request, sess session, id, typ string) (string, int, string) {
	payload := r.FormValue("payload")
	if !slices.Contains(api.CommandTypes, typ) || len(payload) > 64<<10 {
		return "", http.StatusBadRequest, "invalid command"
	}
	if sess.Role != "admin" && !slices.Contains(helpdeskCommands, typ) {
		return "", http.StatusForbidden, "this action requires the admin role"
	}
	switch {
	case typ == "reboot" || typ == "shutdown":
		// payload is the delay in minutes, 0 = now
		v := strings.TrimSpace(r.FormValue("minutes"))
		if v == "" {
			v = "1"
		}
		m, err := strconv.Atoi(v)
		if err != nil || m < 0 || m > 1440 {
			return "", http.StatusBadRequest, "delay must be 0..1440 minutes"
		}
		payload = strconv.Itoa(m)
	case typ == "lost" || typ == "wipe" || typ == "found" || typ == "allow_uninstall":
		// protective actions (admins only, see helpdeskCommands), lost and
		// wipe confirmed by typing the host name
		if typ == "lost" || typ == "wipe" {
			var host string
			if err := s.db.QueryRow(r.Context(), `SELECT hostname FROM devices WHERE id=$1`, id).Scan(&host); err != nil ||
				!strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), host) {
				return "", http.StatusBadRequest, "type the host name to confirm"
			}
		}
		payload = ""
		if typ == "lost" {
			msg := strings.TrimSpace(r.FormValue("message"))
			if len(msg) > 500 || strings.ContainsAny(msg, "\x00\r") {
				return "", http.StatusBadRequest, "message: up to 500 characters"
			}
			b, _ := json.Marshal(api.LostMode{Message: msg})
			payload = string(b)
		}
	case typ == "message":
		title, text := strings.TrimSpace(r.FormValue("title")), strings.TrimSpace(r.FormValue("text"))
		if text == "" || len(text) > 1000 || len(title) > 100 || strings.ContainsAny(title+text, "\x00\r") {
			return "", http.StatusBadRequest, "message: text up to 1000 characters, title up to 100"
		}
		b, _ := json.Marshal(api.Message{Title: title, Text: text})
		payload = string(b)
	case strings.HasPrefix(typ, "user_"):
		u := api.UserCommand{Username: strings.TrimSpace(r.FormValue("username")), FullName: strings.TrimSpace(r.FormValue("full_name")),
			Password: r.FormValue("password"), Admin: r.FormValue("admin") == "on" || r.FormValue("admin") == "1", KeepHome: r.FormValue("keep_home") == "on"}
		if err := u.Validate(typ); err != nil {
			return "", http.StatusBadRequest, err.Error()
		}
		if sess.Role != "admin" { // signed with the command; the agent refuses admin accounts
			u.NoAdmin = true
			if s.accountPrivileged(r.Context(), id, u.Username) {
				return "", http.StatusForbidden, helpdeskAdminAccount
			}
		}
		if typ == "user_create" || typ == "user_password" {
			if r.Form.Has("password2") && r.FormValue("password2") != u.Password { // the repeat field of the console form
				return "", http.StatusBadRequest, passwordMismatch
			}
			if msg := s.settings().Rules.Check(u.Password, u.Username); msg != "" {
				return "", http.StatusBadRequest, msg
			}
		}
		b, _ := json.Marshal(u) //nolint:gosec // signed command payload over mTLS, cleared from the database once applied
		payload = string(b)
	case typ == "software_remove":
		sr := api.SoftwareRemove{Kind: r.FormValue("kind"), Name: r.FormValue("name"), Installation: r.FormValue("installation")}
		if err := sr.Validate(); err != nil {
			return "", http.StatusBadRequest, err.Error()
		}
		b, _ := json.Marshal(sr)
		payload = string(b)
	case typ == "app_install" || typ == "app_remove":
		var ok bool
		app := r.FormValue("app")
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM catalog_apps WHERE slug=$1)`, app).Scan(&ok); err != nil || !ok {
			return "", http.StatusBadRequest, "unknown catalog app"
		}
		payload = app
	case typ != "script":
		payload = ""
	default:
		var err error
		if payload, err = scriptCommandPayload(r); err != nil {
			return "", http.StatusBadRequest, err.Error()
		}
	}
	return payload, 0, ""
}

// parseTags accepts a comma separated list of short labels.
func parseTags(text string) ([]string, error) {
	tags := []string{}
	for _, t := range strings.Split(text, ",") {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || slices.Contains(tags, t) {
			continue
		}
		if !identOK(t) || len(t) > 32 {
			return nil, fmt.Errorf("invalid tag %q: up to 32 letters, digits, dot, dash, underscore", t)
		}
		tags = append(tags, t)
	}
	return tags, nil
}

// retireDevice ends the management of a device: its client certificate and
// network certificates are revoked, its history stays.
func (s *Server) retireDevice(ctx context.Context, actor, id string) error {
	return s.auditAction(ctx, actor, "device.retire", id, "client certificate revoked", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET retired=true, cert_serial='', pending_serial=NULL WHERE id=$1`, id); err != nil {
			return err
		}
		return revokeNetworkCerts(ctx, tx, id, "retired")
	})
}

// ---- enrollment tokens ----

// createEnrollToken creates an enrollment token for 1..10000 uses and
// 1..90 days, optionally binding new devices to a blueprint (0: default),
// and returns it; it is shown only once.
func (s *Server) createEnrollToken(ctx context.Context, sess session, note string, blueprintID int64, uses, days int) (string, error) {
	if uses < 1 || uses > 10000 || days < 1 || days > 90 {
		return "", &userError{http.StatusBadRequest, "uses 1..10000, days 1..90"}
	}
	var bpID *int64
	if blueprintID > 0 {
		if !s.tenantOwns(ctx, sess, "blueprints", blueprintID, true) {
			return "", &userError{http.StatusBadRequest, "unknown blueprint"}
		}
		bpID = &blueprintID
	}
	token := "lmt_" + randToken(24)
	note = truncate(note, 200)
	err := s.auditAction(ctx, sess.Email, "token.create", note, fmt.Sprintf("uses=%d days=%d blueprint=%d", uses, days, blueprintID), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO enroll_tokens(token_hash, note, blueprint_id, uses_left, expires_at, created_by, tenant_id)
			VALUES ($1,$2,$3,$4, now() + make_interval(days => $5), $6, $7)`, sha(token), note, bpID, uses, days, sess.Email, ownerTenant(ctx))
		return err
	})
	return token, err
}

// revokeEnrollToken deletes an enrollment token of the caller's tenant;
// pgx.ErrNoRows when there is none.
func (s *Server) revokeEnrollToken(ctx context.Context, sess session, hash []byte) error {
	return s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var note string
		tcond, targs := tenantCond(sess, "tenant_id", 1)
		err := tx.QueryRow(ctx, `DELETE FROM enroll_tokens WHERE token_hash=$1 AND `+tcond+` RETURNING note`, append([]any{hash}, targs...)...).Scan(&note)
		return sess.Email, "token.revoke", hex.EncodeToString(hash)[:12], note, err
	})
}

// ---- compliance reporting ----

type checkAgg struct {
	ID, Title, Severity      string
	Level                    int
	Refs                     api.Refs
	Pass, Fail, NA, Excepted int
	FailingHosts             []string
}

type controlAgg struct {
	Framework, Control string
	Checks             []string
	Pass, Fail         int
}

type fleetStats struct {
	Checks                                     []*checkAgg
	Controls                                   []*controlAgg
	Total, Compliant, Stale, Pending, Noncompl int
}

// fleetCompliance aggregates the latest check results of all active devices.
const maxListedHosts = 20

type fleetCache struct {
	at time.Time
	fs fleetStats
}

// fleetComplianceCached serves the fleet aggregation for a minute; it reads
// and decodes the check results of every device.
func (s *Server) fleetComplianceCached(ctx context.Context) (fleetStats, error) {
	if c := s.fleet.Load(); c != nil && time.Since(c.at) < time.Minute {
		return c.fs, nil
	}
	fs, err := s.fleetCompliance(ctx, "TRUE")
	if err == nil {
		s.fleet.Store(&fleetCache{at: time.Now(), fs: fs})
	}
	return fs, err
}

// fleetComplianceFor aggregates the devices within the scope of sess
// (scoped accounts bypass the fleet wide cache).
func (s *Server) fleetComplianceFor(ctx context.Context, sess session) (fleetStats, error) {
	if !sess.scoped() && sess.Tenant == 0 {
		return s.fleetComplianceCached(ctx)
	}
	cond, args := scopeCond(sess, 0)
	return s.fleetCompliance(ctx, cond, args...)
}

func (s *Server) fleetCompliance(ctx context.Context, where string, args ...any) (fleetStats, error) {
	var fs fleetStats
	rows, err := s.db.Query(ctx, `SELECT hostname, checks, last_seen, failing FROM devices d WHERE NOT retired AND `+where, args...)
	if err != nil {
		return fs, err
	}
	defer rows.Close()
	checks := map[string]*checkAgg{}
	var total, compliant, stale, pending int
	for rows.Next() {
		var host string
		var raw []byte
		var seen *time.Time
		var failing int
		if err := rows.Scan(&host, &raw, &seen, &failing); err != nil {
			return fs, err
		}
		total++
		switch {
		case seen == nil || len(raw) <= 2:
			pending++
		case time.Since(*seen) > s.staleAfter():
			stale++
		case failing == 0:
			compliant++
		}
		var res []api.CheckResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return fs, err
		}
		for _, c := range res {
			a := checks[c.ID]
			if a == nil {
				a = &checkAgg{ID: c.ID, Title: c.Title, Severity: c.Severity, Level: c.Level, Refs: c.Refs}
				checks[c.ID] = a
			}
			switch c.Status {
			case "pass":
				a.Pass++
			case "fail":
				a.Fail++
				if len(a.FailingHosts) < maxListedHosts { // the count is in Fail; long lists help nobody
					a.FailingHosts = append(a.FailingHosts, host)
				}
			case "excepted":
				a.Excepted++
			default:
				a.NA++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fs, err
	}
	var list []*checkAgg
	controls := map[string]*controlAgg{}
	for _, a := range checks {
		list = append(list, a)
		for fw, refs := range map[string][]string{"BSI IT-Grundschutz": a.Refs.BSI, "CIS Benchmark": a.Refs.CIS, "ISO/IEC 27001:2022": a.Refs.ISO} {
			for _, ref := range refs {
				k := fw + "|" + ref
				c := controls[k]
				if c == nil {
					c = &controlAgg{Framework: fw, Control: ref}
					controls[k] = c
				}
				c.Checks = append(c.Checks, a.ID)
				c.Pass += a.Pass
				c.Fail += a.Fail
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	var ctl []*controlAgg
	for _, c := range controls {
		sort.Strings(c.Checks)
		ctl = append(ctl, c)
	}
	sort.Slice(ctl, func(i, j int) bool {
		if ctl[i].Framework != ctl[j].Framework {
			return ctl[i].Framework < ctl[j].Framework
		}
		return ctl[i].Control < ctl[j].Control
	})
	return fleetStats{Checks: list, Controls: ctl, Total: total, Compliant: compliant, Stale: stale, Pending: pending,
		Noncompl: total - compliant - stale - pending}, nil
}

// ---- audit ----

type auditRow struct {
	ID                            int64
	At                            time.Time
	Actor, Action, Target, Detail string
	Prev, Hash                    []byte
	Tenant                        *int64 // nil: a global entry
}

// verifyAudit checks the hash chain and returns the first broken entry (0 =
// intact). The audit page verifies incrementally from the last checkpoint;
// the daily background run and the "verify whole chain" action verify
// everything from the start.
func (s *Server) verifyAudit(ctx context.Context) (int64, error) { return s.verifyAuditFrom(ctx, true) }

func (s *Server) verifyAuditFrom(ctx context.Context, incremental bool) (int64, error) {
	from, prev, err := s.auditStart(ctx) // behind the last retention cut (retention.go)
	if err != nil {
		return 0, err
	}
	if incremental {
		var id int64
		var hash []byte
		err := s.db.QueryRow(ctx, `SELECT last_id, last_hash FROM audit_checkpoint`).Scan(&id, &hash)
		switch {
		case err == nil && id > from:
			from, prev = id, hash
		case err != nil && !errors.Is(err, pgx.ErrNoRows):
			return 0, err
		}
	}
	rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash, tenant_id FROM audit_log WHERE id > $1 ORDER BY id`, from)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	last := from
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.Prev, &a.Hash, &a.Tenant); err != nil {
			return 0, err
		}
		if !auditEntryOK(auditKeys, prev, a) {
			return a.ID, nil
		}
		prev, last = a.Hash, a.ID
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if last > from {
		_, err = s.db.Exec(ctx, `INSERT INTO audit_checkpoint(one, last_id, last_hash, verified_at) VALUES (true, $1, $2, now())
			ON CONFLICT (one) DO UPDATE SET last_id=EXCLUDED.last_id, last_hash=EXCLUDED.last_hash, verified_at=now()`, last, prev)
	}
	return 0, err
}

// ---- CSV exports (audit evidence) ----

// csvSafe neutralises spreadsheet formula injection from device supplied data.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) export(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	kind := r.PathValue("kind")
	var q string
	var args []any
	var header []string
	cond, args := scopeCond(sess, 0)
	switch kind {
	case "compliance.csv":
		header = []string{"device_id", "hostname", "last_seen", "agent_version", "catalog_version", "check_id", "level", "status", "detail",
			"bsi", "cis", "cis_benchmark", "iso", "exception_reason", "exception_owner", "exception_approver", "exception_expires", "generated_at"}
		q = `SELECT d.id, d.hostname, coalesce(d.last_seen::text,''), d.agent_version, d.catalog_version, c->>'id', coalesce(c->>'level',''), c->>'status', coalesce(c->>'detail',''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'bsi') x),''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'cis') x),''),
			coalesce(c->'refs'->>'cis_benchmark',''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'iso') x),''),
			coalesce(e.reason,''), coalesce(e.owner,''), coalesce(e.approver,''), coalesce(e.expires_at::date::text,''), $` + strconv.Itoa(len(args)+1) + `::text
			FROM devices d CROSS JOIN LATERAL jsonb_array_elements(d.checks) c
			LEFT JOIN LATERAL (SELECT reason, owner, approver, expires_at FROM risk_exceptions x WHERE x.check_id = c->>'id' AND ` + activeExceptionSQL + `
				AND x.tenant_id = d.tenant_id AND (x.tag = '' OR x.tag = ANY(d.tags)) ORDER BY x.expires_at DESC LIMIT 1) e ON true
			WHERE NOT d.retired AND ` + cond + ` ORDER BY d.hostname, c->>'id'`
		args = append(args, time.Now().UTC().Format(time.RFC3339))
	case "compliance-history.csv":
		at, device, ok := historyParams(r.URL.Query())
		if !ok {
			s.errorPage(w, r, sess, http.StatusBadRequest, "at must be a date (YYYY-MM-DD)")
			return
		}
		hcond, hargs := scopeCond(sess, 4)
		header = []string{"state_at", "device_id", "hostname", "check_id", "status", "detail", "since", "catalog_version", "generated_at"}
		q = `SELECT $4::text, h.device_id, d.hostname, h.check_id, h.status, h.detail, h.at::text, h.catalog_version, $3::text
			FROM (` + historyStateSQL + `) h JOIN devices d ON d.id = h.device_id WHERE ` + hcond + ` ORDER BY d.hostname, h.check_id`
		args = append([]any{at, device, time.Now().UTC().Format(time.RFC3339), at.AddDate(0, 0, -1).Format("2006-01-02")}, hargs...)
	case "inventory.csv":
		header = []string{"device_id", "hostname", "os", "kernel", "agent", "serial", "vendor", "model", "cpu", "memory_mb", "disk_gb", "last_seen", "enrolled_at", "retired"}
		q = `SELECT id, hostname, coalesce(inventory->>'os_name',''), coalesce(inventory->>'kernel',''), agent_version,
			coalesce(inventory->>'serial',''), coalesce(inventory->>'vendor',''), coalesce(inventory->>'model',''), coalesce(inventory->>'cpu',''),
			coalesce(inventory->>'memory_mb',''), coalesce(inventory->>'disk_gb',''), coalesce(last_seen::text,''), enrolled_at::text, retired::text
			FROM devices d WHERE ` + cond + ` ORDER BY hostname`
	case "packages.csv":
		header = []string{"device_id", "hostname", "package", "version", "arch"}
		q = `SELECT d.id, d.hostname, p.name, p.version, p.arch
			FROM devices d JOIN device_packages p ON p.device_id = d.id
			WHERE NOT d.retired AND ` + cond + ` ORDER BY d.hostname, d.id, p.name, p.arch, p.version`
	case "audit.csv":
		var where string
		where, args = auditFilter(r.URL.Query(), sess)
		header = []string{"id", "at", "actor", "action", "target", "detail", "prev", "hash", "tenant_id"}
		q = `SELECT id::text, at::text, actor, action, target, detail, encode(prev,'hex'), encode(hash,'hex'), coalesce(tenant_id::text, '') FROM audit_log WHERE ` + where + ` ORDER BY id`
	case "audit.jsonl":
		s.auditExportJSONL(w, r, sess)
		return
	case "evidence.json", "evidence.pdf":
		s.evidenceExport(w, r, sess, kind)
		return
	case "exceptions.csv":
		header = []string{"id", "check_id", "mode", "tag", "reason", "owner", "approver", "expires_at", "created_by", "created_at", "state"}
		var xcond string
		xcond, args = tenantCond(sess, "x.tenant_id", 0)
		q = `SELECT id::text, check_id, mode, tag, reason, owner, approver, expires_at::text, created_by, created_at::text,
			CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at <= now() THEN 'expired' ELSE 'active' END
			FROM risk_exceptions x WHERE ` + xcond + ` ORDER BY id`
	default:
		s.notFound(w, r, sess)
		return
	}
	s.streamExport(w, r, sess, kind, "text/csv; charset=utf-8", func(tx pgx.Tx, out io.Writer) (int, error) {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		cw := csv.NewWriter(out)
		cw.Write(header)
		vals := make([]string, len(header))
		ptrs := make([]any, len(header))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		n := 0
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				return n, err
			}
			out := make([]string, len(vals))
			for i, v := range vals {
				out[i] = csvSafe(v)
			}
			cw.Write(out)
			n++
		}
		cw.Flush()
		if err := rows.Err(); err != nil {
			return n, err
		}
		return n, cw.Error()
	})
}

// streamExport sends an export from one transaction and audits it twice:
// before (who, what, which filter) and after, with the row count and the
// SHA-256 of exactly the bytes sent, so a file handed to an auditor can be
// matched to its audit entry.
func (s *Server) streamExport(w http.ResponseWriter, r *http.Request, sess session, kind, ctype string, write func(pgx.Tx, io.Writer) (int, error)) {
	ctx := r.Context()
	filter := truncate(r.URL.RawQuery, 500)
	if err := s.auditAction(ctx, sess.Email, "export", kind, filter, nil); err != nil {
		s.fail(w, err)
		return
	}
	// one connection for the whole stream; a slow download must not run into
	// the pool's 30 second statement timeout and silently cut the evidence
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '15min'`); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="limdm-%s-%s"`, time.Now().Format("20060102"), kind))
	h := sha256.New()
	n, err := write(tx, io.MultiWriter(w, h))
	detail := fmt.Sprintf("rows=%d sha256=%s", n, hex.EncodeToString(h.Sum(nil)))
	if err != nil {
		// the header is sent already: mark the file as incomplete instead of
		// handing out a truncated export that looks complete
		s.log.Error("export incomplete", "kind", kind, "err", err)
		_, _ = io.WriteString(w, "\nERROR: export incomplete, run it again\n")
		detail += " incomplete"
	}
	_ = tx.Rollback(ctx) // the audit entry takes a connection of its own
	if err := s.auditAction(context.WithoutCancel(ctx), sess.Email, "export.done", kind, detail, nil); err != nil {
		s.log.Error("audit export.done", "err", err)
	}
}

// helpdeskCommands are the device commands the helpdesk role may send, as
// its role description promises: routine and reversible actions. Scripts,
// lost mode, wipe, software and account creation, deletion and admin rights
// stay with admins. Diagnostics (redacted logs) are for the helpdesk too;
// the remote shell is no command here, its own setting decides (shell.go).
var helpdeskCommands = []string{"sync", "update", "reboot", "shutdown", "lock", "unlock", "message",
	"user_password", "user_lock", "user_unlock", "diagnostics"}

// appNote is the outcome of an install or removal sent from the console.
type appNote struct {
	App, Type, Error string
	OK               bool
	At               time.Time
}

// appProgress follows installs and removals sent in the last hour: an app is
// busy until the device reports the new state (the command only starts the
// job), then a note says whether it worked.
func (s *Server) appProgress(ctx context.Context, id string, states []api.AppState, names map[string]string) (map[string]string, []appNote, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (payload) payload, type, status, output, created_at FROM commands
		WHERE device_id=$1 AND type IN ('app_install','app_remove') AND created_at > now() - interval '1 hour'
		ORDER BY payload, id DESC`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	state := map[string]api.AppState{}
	for _, a := range states {
		state[a.ID] = a
	}
	busy := map[string]string{}
	var notes []appNote
	for rows.Next() {
		var app, typ, status, output string
		var at time.Time
		if err := rows.Scan(&app, &typ, &status, &output, &at); err != nil {
			return nil, nil, err
		}
		op := strings.TrimPrefix(typ, "app_")
		st := state[app]
		name := firstNonEmpty(names[app], app)
		done := (op == "install" && st.Installed) || (op == "remove" && !st.Installed)
		switch {
		case status == "failed" || status == "expired":
			notes = append(notes, appNote{App: name, Type: op, Error: lastLine(output), At: at})
		case status == "ok" && done:
			notes = append(notes, appNote{App: name, Type: op, OK: true, At: at})
		case status == "ok" && st.Error != "":
			notes = append(notes, appNote{App: name, Type: op, Error: st.Error, At: at})
		default: // waiting for the device, or its job still runs
			busy[app] = op
		}
	}
	return busy, notes, rows.Err()
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
