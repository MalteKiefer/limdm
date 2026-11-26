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

// pages holds the parsed templates per language and date format ("de/iso").
var pages = func() map[string]map[string]*template.Template {
	m := map[string]map[string]*template.Template{}
	for _, lang := range []string{"en", "de"} {
		for f, layout := range dateFormats {
			m[lang+"/"+f] = parsePages(lang, layout)
		}
	}
	return m
}()

func parsePages(lang, layout string) map[string]*template.Template {
	T := func(s string) string { return translate(lang, s) }
	actionLabel := func(a string) string {
		return T(map[string]string{"sync": "Sync now", "update": "Install all updates", "reboot": "Reboot",
			"shutdown": "Shut down", "lock": "Lock device", "unlock": "Unlock device", "script": "Run script",
			"lost": "Lost mode", "found": "End lost mode", "wipe": "Wipe device", "allow_uninstall": "Allow uninstall for 1 hour", "message": "Message",
			"app_install": "Install app", "app_remove": "Remove app",
			"user_create": "Create user", "user_admin": "Change admin rights", "user_lock": "Lock user", "user_unlock": "Unlock user",
			"user_password": "Reset password", "user_delete": "Delete user", "software_remove": "Remove software", "diagnostics": "Collect logs", "shell": "Remote shell"}[a])
	}
	funcs := template.FuncMap{
		"dict": func(kv ...any) map[string]any { // arguments for shared partials
			m := make(map[string]any, len(kv)/2)
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
		"t":       T,
		"errmsg":  func(msg string) friendlyMsg { return friendlyError(lang, msg) },
		"lang":    func() string { return lang },
		"version": func() string { return Version },
		"ago": func(t *time.Time) string {
			if t == nil {
				return T("never")
			}
			switch d := time.Since(*t); {
			case d < time.Minute:
				return T("just now")
			case d < time.Hour:
				return fmt.Sprintf(T("%d min ago"), int(d.Minutes()))
			case d < 48*time.Hour:
				return fmt.Sprintf(T("%d h ago"), int(d.Hours()))
			default:
				return fmt.Sprintf(T("%d d ago"), int(d.Hours()/24))
			}
		},
		"frac":       func(v uint64, pct uint64) uint64 { return v * pct / 100 },
		"add":        func(a, b int) int { return a + b },
		"inc":        func(n int) int { return n + 1 },
		"sub":        func(a, b int) int { return a - b },
		"dec":        func(n int) int { return n - 1 },
		"list":       func(v ...string) []string { return v },
		"deref":      func(p *int64) int64 { return *p },
		"derefStr":   func(p *string) string { return *p },
		"appSources": appSourcesText,
		"hasID":      func(ids []int64, id int64) bool { return slices.Contains(ids, id) },
		"derefTime":  func(p *time.Time) time.Time { return *p },
		"derefBool":  func(p *bool) bool { return p != nil && *p },
		"deref2":     func(p *string) string { return *p },
		"typeLabel": func(t string) string {
			if l, ok := typeLabels[t]; ok {
				return T(l)
			}
			return t
		},
		"actionLabel": actionLabel,
		"auditLabel":  func(a string) string { return auditLabel(lang, a, actionLabel) },
		"statusHelp":  func(st string) string { return T(statusHelp[st]) },
		"checkDetail": func(d string) string { return checkDetail(lang, d) },
		"itemMeta":    func() map[string]typeMeta { return itemMeta(lang) },
		"typeDesc":    func(t string) string { return T(typeInfo[t].Desc) },
		"docs":        func(p string) string { return docsURL + p },
		"join":        strings.Join,
		"hasPrefix":   strings.HasPrefix,
		"fmtTime":     func(t time.Time) string { return t.Local().Format(layout) },
		"gib": func(mb uint64) string {
			if mb == 0 {
				return T("n/a")
			}
			return fmt.Sprintf("%.1f GiB", float64(mb)/1024)
		},
		"unix": func(sec int64) time.Time { return time.Unix(sec, 0) },
		"used": func(size, free uint64) uint64 { return size - min(free, size) },
		"pct": func(part, total int) int {
			if total == 0 {
				return 0
			}
			return part * 100 / total
		},
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

// helpdeskPage additionally lets the helpdesk role post (device commands).
func (s *Server) helpdeskPage(h handler) http.HandlerFunc { return s.pageFor(h, "helpdesk") }

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
			http.Redirect(w, r, "/login", http.StatusFound)
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
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
	if err := pages[requestLang(r)+"/"+requestDateFormat(r)][name].Execute(&buf, data); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (s *Server) webRoutes(mux *http.ServeMux) {
	s.networkRoutes(mux)
	s.tenantPages(mux)
	s.shellRoutes(mux)
	mux.HandleFunc("GET /{$}", s.page(s.overview))
	mux.HandleFunc("GET /help", s.page(s.helpPage))
	mux.HandleFunc("POST /onboarding/dismiss", s.page(s.onboardingDismiss))
	mux.HandleFunc("GET /devices", s.page(s.devices))
	mux.HandleFunc("GET /devices/{id}", s.page(s.device))
	mux.HandleFunc("POST /devices/bulk", s.helpdeskPage(s.devicesBulk))
	mux.HandleFunc("POST /devices/{id}/command", s.helpdeskPage(s.deviceCommand))
	mux.HandleFunc("GET /devices/{id}/diagnostics/{cid}", s.page(s.diagnosticsDownload))
	mux.HandleFunc("POST /devices/{id}/agent-update", s.page(s.deviceAgentUpdate))
	mux.HandleFunc("POST /devices/{id}/recovery", s.helpdeskPage(s.recoveryView))
	mux.HandleFunc("GET /directory", s.page(s.adminOrAuditor(s.unscoped(s.directoryPage))))
	mux.HandleFunc("POST /directory/groups", s.page(s.groupAssign))
	mux.HandleFunc("POST /directory/scim-token", s.page(s.scimToken))
	mux.HandleFunc("POST /directory/google", s.page(s.googleConfigure))
	mux.HandleFunc("POST /directory/google/sync", s.page(s.googleSyncNow))
	mux.HandleFunc("GET /users", s.page(s.adminOrAuditor(s.usersPage)))
	mux.HandleFunc("GET /agents", s.page(s.adminOrAuditor(s.unscoped(s.agentsPage))))
	mux.HandleFunc("GET /software", s.page(s.adminOrAuditor(s.unscoped(s.softwarePage))))
	mux.HandleFunc("GET /software/new", s.page(s.adminOrAuditor(s.appEdit)))
	mux.HandleFunc("GET /software/apps/{id}", s.page(s.adminOrAuditor(s.appEdit)))
	mux.HandleFunc("GET /software/icons/{id}", s.page(func(w http.ResponseWriter, r *http.Request, _ session) { s.catalogIcon(w, r) }))
	mux.HandleFunc("POST /software/apps", s.page(s.appSave))
	mux.HandleFunc("POST /software/import", s.page(s.appImport))
	mux.HandleFunc("POST /software/flathub", s.page(s.flathubAdd))
	mux.HandleFunc("GET /software/flathub/search", s.page(s.adminOrAuditor(func(w http.ResponseWriter, r *http.Request, _ session) { s.flathubSearchJSON(w, r) })))
	mux.HandleFunc("GET /software/flathub/icon", s.page(s.adminOrAuditor(func(w http.ResponseWriter, r *http.Request, _ session) { s.flathubIcon(w, r) })))
	mux.HandleFunc("POST /software/remotes", s.page(s.remoteSave))
	mux.HandleFunc("POST /software/remotes/{name}/{op}", s.page(s.remoteOp))
	mux.HandleFunc("POST /software/apps/{id}/delete", s.page(s.appDelete))
	mux.HandleFunc("POST /software/requests/{id}/{op}", s.page(s.requestDecide))
	mux.HandleFunc("POST /software/settings", s.page(s.softwareSettingsSave))
	mux.HandleFunc("POST /agents/policy", s.page(s.agentsPolicy))
	mux.HandleFunc("POST /agents/fetch", s.page(s.agentsFetch))
	mux.HandleFunc("POST /agents/{version}/{op}", s.page(s.agentsRelease))
	mux.HandleFunc("GET /profile", s.selfPage(s.profile))
	mux.HandleFunc("POST /profile/password", s.selfPage(s.profilePassword))
	mux.HandleFunc("POST /profile/totp", s.selfPage(s.profileTOTP))
	mux.HandleFunc("POST /profile/recovery", s.selfPage(s.profileRecovery))
	mux.HandleFunc("POST /users", s.page(s.userAdd))
	mux.HandleFunc("POST /users/update", s.page(s.userUpdate))
	mux.HandleFunc("POST /users/reset", s.page(s.userReset))
	mux.HandleFunc("GET /settings", s.page(s.adminOrAuditor(s.settingsPage)))
	mux.HandleFunc("POST /settings/notifications", s.page(s.channelSave))
	mux.HandleFunc("POST /settings/notifications/{id}/{op}", s.page(s.channelOp))
	mux.HandleFunc("POST /settings", s.page(s.settingsSave))
	mux.HandleFunc("POST /settings/keys/{op}/{kind}", s.page(s.unscoped(s.keysAction))) // keys.go
	mux.HandleFunc("POST /devices/{id}/assign", s.page(s.deviceAssign))
	mux.HandleFunc("POST /devices/{id}/retire", s.page(s.deviceRetire))
	mux.HandleFunc("GET /blueprints", s.page(s.blueprints))
	mux.HandleFunc("GET /blueprints/{id}", s.page(s.blueprintEdit))
	mux.HandleFunc("POST /blueprints", s.page(s.blueprintSave))
	mux.HandleFunc("POST /blueprints/{id}/delete", s.page(s.blueprintDelete))
	mux.HandleFunc("GET /blueprints/{id}/history", s.page(s.unscoped(s.blueprintHistory)))
	mux.HandleFunc("POST /blueprints/{id}/rollback", s.page(s.blueprintRollback))
	mux.HandleFunc("GET /library", s.page(s.library))
	mux.HandleFunc("GET /library/{id}", s.page(s.libraryEdit))
	mux.HandleFunc("POST /library", s.page(s.librarySave))
	mux.HandleFunc("POST /library/{id}/delete", s.page(s.libraryDelete))
	mux.HandleFunc("GET /library/{id}/history", s.page(s.unscoped(s.libraryHistory)))
	mux.HandleFunc("POST /library/{id}/rollback", s.page(s.libraryRollback))
	mux.HandleFunc("GET /tokens", s.page(s.tokens))
	mux.HandleFunc("POST /tokens", s.page(s.tokenCreate))
	mux.HandleFunc("POST /tokens/{id}/revoke", s.page(s.tokenRevoke))
	mux.HandleFunc("GET /compliance", s.page(s.compliance))
	mux.HandleFunc("GET /audit", s.page(s.adminOrAuditor(s.auditPage)))
	mux.HandleFunc("POST /audit/verify", s.selfPage(s.adminOrAuditor(s.auditVerify)))
	mux.HandleFunc("GET /compliance/history", s.page(s.complianceHistory))
	mux.HandleFunc("GET /export/{kind}", s.page(s.adminOrAuditor(s.export)))
	// W2 governance
	mux.HandleFunc("GET /approvals", s.page(s.approvalsPage))
	mux.HandleFunc("POST /approvals/{id}/{op}", s.page(s.approvalDecide))
	mux.HandleFunc("POST /devices/{id}/delete", s.page(s.deviceDelete))
	mux.HandleFunc("POST /compliance/exceptions", s.page(s.exceptionAdd))
	mux.HandleFunc("POST /compliance/exceptions/{id}/revoke", s.page(s.exceptionRevoke))
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

// devicesPageSize is the number of devices per page of the device list.
const devicesPageSize = 200

func (s *Server) devices(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	dq, err := parseDeviceQuery(r.URL.Query(), s.staleAfter())
	if err != nil {
		s.errorPage(w, r, sess, http.StatusBadRequest, err.Error())
		return
	}
	cond, sargs := scopeCond(sess, 0)
	dq.filters.add(cond, sargs...)
	counts, total, err := s.deviceCounts(ctx, dq)
	if err != nil {
		s.fail(w, err)
		return
	}
	matching := total
	if dq.Status != "" {
		matching = counts[dq.Status]
	}
	pages := max(1, (matching+devicesPageSize-1)/devicesPageSize)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = min(max(page, 1), pages)
	where := dq.where()
	shown, err := s.listDevicesQuery(ctx, where.sql(), fmt.Sprintf(" ORDER BY d.retired, d.hostname, d.id LIMIT %d OFFSET %d", devicesPageSize, (page-1)*devicesPageSize), where.args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	var tags []string
	cond, sargs = scopeCond(sess, 0)
	if err := s.db.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT t ORDER BY t), '{}') FROM devices d, unnest(d.tags) t WHERE NOT d.retired AND `+cond, sargs...).Scan(&tags); err != nil {
		s.fail(w, err)
		return
	}
	apps, err := s.catalogApps(ctx, s.db, `WHERE enabled`)
	if err != nil {
		s.fail(w, err)
		return
	}
	keepURL := template.URL(dq.Keep.Encode()) //nolint:gosec // url.Values.Encode escapes every key and value
	pageKeep := dq.Keep.Encode()
	if dq.Status != "" {
		pageKeep = url.Values{"status": {dq.Status}}.Encode() + "&" + pageKeep
	}
	s.render(w, r, sess, "devices", map[string]any{"Devices": shown, "Total": total, "Counts": counts, "Q": dq.Q, "Status": dq.Status,
		"Statuses": deviceStatuses, "Chips": dq.Chips, "Tag": dq.Keep.Get("tag"), "Pkg": dq.Keep.Get("pkg"), "Keep": keepURL, "Tags": tags, "Apps": apps,
		"Page": page, "Pages": pages, "PageKeep": template.URL(pageKeep), //nolint:gosec // url.Values.Encode escapes every key and value
		"Back": r.URL.RequestURI()})
}

// devicesBulk runs one action on the selected devices: a command, an
// agent update, or adding and removing a tag. Destructive commands (lost
// mode, wipe) stay single device actions; scripts need the admin role
// (commandPayload).
func (s *Server) devicesBulk(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, r, sess, http.StatusBadRequest, "bad form")
		return
	}
	ids := slices.Compact(slices.Sorted(slices.Values(r.Form["id"])))
	if len(ids) == 0 || len(ids) > 1000 {
		s.errorPage(w, r, sess, http.StatusBadRequest, "select 1 to 1000 devices")
		return
	}
	var known int
	cond, sargs := scopeCond(sess, 1)
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM devices d WHERE d.id = ANY($1) AND NOT d.retired AND `+cond, append([]any{ids}, sargs...)...).Scan(&known); err != nil || known != len(ids) {
		s.errorPage(w, r, sess, http.StatusBadRequest, "unknown or retired device selected")
		return
	}
	op, typ, _ := strings.Cut(r.FormValue("action"), ":")
	switch op {
	case "tag-add", "tag-remove":
		if sess.Role != "admin" {
			s.errorPage(w, r, sess, http.StatusForbidden, "this action requires the admin role")
			return
		}
		tags, err := parseTags(r.FormValue("tag"))
		if err != nil || len(tags) != 1 {
			s.errorPage(w, r, sess, http.StatusBadRequest, "one tag: up to 32 letters, digits, dot, dash, underscore")
			return
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
				s.fail(w, err)
				return
			}
		}
	case "agent-update":
		if sess.Role != "admin" {
			s.errorPage(w, r, sess, http.StatusForbidden, "this action requires the admin role")
			return
		}
		for _, id := range ids {
			if err := s.auditAction(ctx, sess.Email, "agent_update.request", id, "", func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE devices SET update_requested=true, update_target='' WHERE id=$1`, id)
				return err
			}); err != nil {
				s.fail(w, err)
				return
			}
		}
	case "command":
		if typ == "lost" || typ == "wipe" {
			s.errorPage(w, r, sess, http.StatusBadRequest, "lost mode and wipe are sent to one device at a time")
			return
		}
		payload, code, msg := s.commandPayload(r, sess, ids[0], typ)
		if code != 0 {
			s.errorPage(w, r, sess, code, msg)
			return
		}
		if s.needsApproval(typ) { // bulk scripts: one four eyes request per device
			for _, id := range ids {
				if _, err := s.requestApproval(ctx, sess, "command", id, commandApproval{Type: typ, Payload: payload}, strings.TrimSpace(r.FormValue("reason"))); err != nil {
					s.fail(w, err)
					return
				}
			}
			http.Redirect(w, r, "/approvals", http.StatusSeeOther)
			return
		}
		for _, id := range ids {
			if err := s.queueCommand(ctx, sess.Email, id, typ, payload); err != nil {
				s.fail(w, err)
				return
			}
			s.notifyCommand(sess.Email, id, typ)
		}
	default:
		s.errorPage(w, r, sess, http.StatusBadRequest, "unknown action")
		return
	}
	// back to the list with its filters; only the query is taken over
	back := "/devices"
	if u, err := url.Parse(r.FormValue("back")); err == nil && u.Path == "/devices" && len(u.Query()) > 0 {
		back += "?" + u.Query().Encode()
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// overview is the landing page: fleet state, OS mix, weakest controls, recent activity.
func (s *Server) overview(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	cond, sargs := scopeCond(sess, 0)
	list, err := s.listDevicesWhere(ctx, cond, sargs...)
	if err != nil {
		s.fail(w, err)
		return
	}
	counts, osMix := map[string]int{}, map[string]int{}
	active := 0
	for _, d := range list {
		counts[d.Status]++
		if !d.Retired {
			active++
			osMix[firstNonEmpty(d.OS, "unknown")]++
		}
	}
	type share struct {
		Name  string
		Count int
	}
	var oses []share
	for n, c := range osMix {
		oses = append(oses, share{n, c})
	}
	sort.Slice(oses, func(i, j int) bool {
		return oses[i].Count > oses[j].Count || oses[i].Count == oses[j].Count && oses[i].Name < oses[j].Name
	})
	fc, err := s.fleetComplianceFor(ctx, sess)
	if err != nil {
		s.fail(w, err)
		return
	}
	var failing []*checkAgg
	for _, c := range fc.Checks {
		if c.Fail > 0 {
			failing = append(failing, c)
		}
	}
	sort.SliceStable(failing, func(i, j int) bool { return failing[i].Fail > failing[j].Fail })
	if len(failing) > 6 {
		failing = failing[:6]
	}
	var recent []auditRow
	if sess.Role != "helpdesk" { // the audit log (script bodies included) is not theirs to read
		acond, aargs := auditScope(sess, 0)
		rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash, tenant_id FROM audit_log WHERE `+acond+` ORDER BY id DESC LIMIT 8`, aargs...)
		if err != nil {
			s.fail(w, err)
			return
		}
		if recent, err = pgx.CollectRows(rows, pgx.RowToStructByPos[auditRow]); err != nil {
			s.fail(w, err)
			return
		}
	}
	donut := donutChart([]donutPart{{"compliant", counts["compliant"], "ok"}, {"non-compliant", counts["non-compliant"], "bad"},
		{"in grace", counts["in grace"], "warn"}, {"stale", counts["stale"], "warn"}, {"pending", counts["pending"], "na"}})
	var trend template.HTML
	var steps []onboardingStep
	if sess.Tenant == 0 { // fleet history and first steps are installation wide
		if trend, err = s.fleetChart(ctx); err != nil {
			s.fail(w, err)
			return
		}
		if steps, err = s.onboarding(ctx, r, sess); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.render(w, r, sess, "overview", map[string]any{"Steps": steps, "Trend": trend, "Active": active, "Counts": counts, "OSes": oses, "Failing": failing, "Donut": donut,
		"Recent": recent, "StaleHours": s.settings().StaleHours})
}

type donutPart struct {
	Label string
	Value int
	Class string
}

// donutChart renders a ring chart as inline SVG. Only numbers and fixed class
// names go into the markup, so returning template.HTML is safe; colours come
// from CSS classes because the CSP forbids inline styles.
func donutChart(parts []donutPart) template.HTML {
	total := 0
	for _, p := range parts {
		total += p.Value
	}
	const r, c = 15.915494, 100.0 // circumference 100 makes dash lengths percentages
	var b strings.Builder
	b.WriteString(`<svg class="donut" viewBox="0 0 42 42" role="img" aria-label="Device status distribution">`)
	fmt.Fprintf(&b, `<circle class="track" cx="21" cy="21" r="%.6f"/>`, r)
	offset := 25.0 // start at 12 o'clock
	for _, p := range parts {
		if p.Value == 0 || total == 0 {
			continue
		}
		pct := float64(p.Value) * c / float64(total)
		fmt.Fprintf(&b, `<circle class="seg %s" cx="21" cy="21" r="%.6f" stroke-dasharray="%.3f %.3f" stroke-dashoffset="%.3f"/>`,
			p.Class, r, pct, c-pct, offset)
		offset -= pct
	}
	fmt.Fprintf(&b, `<text x="21" y="22.5" class="donut-total">%d</text></svg>`, total)
	return template.HTML(b.String()) //nolint:gosec // numbers and constant class names only
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (s *Server) device(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id := r.PathValue("id")
	if !s.inScope(ctx, sess, id) {
		http.NotFound(w, r)
		return
	}
	var d deviceRow
	var inv, checks, decl, users, pkgs []byte
	var enrolled, certExp time.Time
	var since *time.Time
	err := s.db.QueryRow(ctx, `SELECT id, hostname, agent_version, failing, jsonb_array_length(checks), last_seen, retired,
		inventory, checks, decl_status, users, packages, enrolled_at, cert_not_after, grace_until, auto_locked, noncompliant_since,
		update_state, update_version, update_requested, external_ip, geo FROM devices WHERE id=$1`, id).
		Scan(&d.ID, &d.Hostname, &d.AgentVersion, &d.Failing, &d.Checks, &d.LastSeen, &d.Retired, &inv, &checks, &decl, &users, &pkgs, &enrolled, &certExp, &d.GraceUntil, &d.AutoLocked, &since,
			&d.UpdateState, &d.UpdateVersion, &d.UpdateRequested, &d.ExternalIP, &d.Geo)
	if err != nil {
		s.notFound(w, r, sess)
		return
	}
	s.status(&d)
	var data struct {
		Inv      api.Inventory
		Checks   []api.CheckResult
		Decl     []api.DeclarationStatus
		Users    []api.User
		Packages []api.Package
	}
	if err := errors.Join(json.Unmarshal(inv, &data.Inv), json.Unmarshal(checks, &data.Checks), json.Unmarshal(decl, &data.Decl),
		json.Unmarshal(users, &data.Users), json.Unmarshal(pkgs, &data.Packages)); err != nil {
		s.fail(w, err)
		return
	}
	sort.SliceStable(data.Checks, func(i, j int) bool { return data.Checks[i].Status == "fail" && data.Checks[j].Status != "fail" })
	var userLines []string
	for _, u := range data.Users {
		l := u.Username + " " + u.Email
		if u.Admin {
			l += " admin"
		}
		userLines = append(userLines, l)
	}
	tab := r.URL.Query().Get("tab")
	type cmd struct {
		ID                       int64
		Type, Status, Output, By string
		At                       time.Time
	}
	var cmds []cmd
	var scripts []scriptRow
	var diags []diagRow
	if tab == "commands" { // outputs can be large; only the commands tab shows them
		var err error
		if scripts, err = s.scriptResults(ctx, id); err != nil {
			s.fail(w, err)
			return
		}
		if sess.Role == "admin" || sess.Role == "helpdesk" {
			if diags, err = s.diagnosticsList(ctx, id); err != nil {
				s.fail(w, err)
				return
			}
		}
		rows, err := s.db.Query(ctx, `SELECT id, type, status, output, created_by, created_at FROM commands WHERE device_id=$1 ORDER BY id DESC LIMIT 50`, id)
		if err == nil {
			cmds, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (cmd, error) {
				var c cmd
				return c, row.Scan(&c.ID, &c.Type, &c.Status, &c.Output, &c.By, &c.At)
			})
		}
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	bps, err := s.allBlueprints(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	var charts []template.HTML
	if tab == "" || tab == "overview" {
		if charts, err = s.deviceCharts(ctx, id); err != nil {
			s.fail(w, err)
			return
		}
	}
	recovery, err := s.recoveryKeys(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	type deviceEvent struct {
		At     time.Time
		Detail string
	}
	var events []deviceEvent
	const evSize = 50
	evPage, evTotal := 1, 0
	if r.URL.Query().Get("tab") == "commands" {
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM device_events WHERE device_id=$1`, id).Scan(&evTotal); err != nil {
			s.fail(w, err)
			return
		}
		if n, err := strconv.Atoi(r.URL.Query().Get("evpage")); err == nil && n > 1 {
			evPage = min(n, max(1, (evTotal+evSize-1)/evSize))
		}
		rows, err := s.db.Query(ctx, `SELECT at, detail FROM device_events WHERE device_id=$1 ORDER BY id DESC LIMIT $2 OFFSET $3`, id, evSize, (evPage-1)*evSize)
		if err == nil {
			events, err = pgx.CollectRows(rows, pgx.RowToStructByPos[deviceEvent])
		}
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	evPages := max(1, (evTotal+evSize-1)/evSize)
	// the latest protective action per kind (lock, lost mode, wipe, uninstall
	// release) stays visible on the device page until the next one replaces it
	type protective struct {
		Type, Status, By string
		At               time.Time
	}
	var protect []protective
	if rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (k) type, status, created_by, created_at FROM (
		SELECT *, CASE type WHEN 'unlock' THEN 'lock' WHEN 'found' THEN 'lost' ELSE type END AS k FROM commands
		WHERE device_id=$1 AND type IN ('lock','unlock','lost','found','wipe','allow_uninstall')) c
		ORDER BY k, id DESC`, id); err == nil {
		protect, err = pgx.CollectRows(rows, pgx.RowToStructByPos[protective])
		if err != nil {
			s.fail(w, err)
			return
		}
		protect = slices.DeleteFunc(protect, func(p protective) bool { // the release ends after an hour
			return p.Type == "allow_uninstall" && time.Since(p.At) > 2*time.Hour
		})
	} else {
		s.fail(w, err)
		return
	}
	var tampered *time.Time
	if err := s.db.QueryRow(ctx, `SELECT tampered_at FROM devices WHERE id=$1 AND tampered_at > now() - interval '30 days'`, id).Scan(&tampered); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, err)
		return
	}
	// expected declarations, to show what the device has not confirmed yet
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	res, err := resolveDevice(ctx, tx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	want := res.Decls
	var tags, people []string
	var primary string
	if err := tx.QueryRow(ctx, `SELECT d.tags, coalesce(u.email,'') FROM devices d LEFT JOIN dir_users u ON u.id=d.primary_user_id WHERE d.id=$1`, id).Scan(&tags, &primary); err != nil {
		s.fail(w, err)
		return
	}
	rowsP, err := tx.Query(ctx, `SELECT email FROM dir_users WHERE active ORDER BY email LIMIT 2000`)
	if err != nil {
		s.fail(w, err)
		return
	}
	if people, err = pgx.CollectRows(rowsP, pgx.RowTo[string]); err != nil {
		s.fail(w, err)
		return
	}
	encExcluded := func(string) bool { return false }
	if tab == "hardware" {
		if decls, err := effectiveDeclarations(ctx, tx, id); err == nil {
			if pol, _ := api.Compose(decls); pol.Extra.DiskEncryption != nil {
				encExcluded = pol.Extra.DiskEncryption.Excluded
			}
		}
	}
	// end the transaction before the queries below take further pool
	// connections: holding one while waiting for another starves the pool
	// under many parallel page loads
	_ = tx.Rollback(ctx)
	type declRow struct {
		Identifier, Type, State, Class string
		Reasons                        []string
	}
	sub := r.URL.Query().Get("sub")
	switch {
	case tab == "software" && sub != "sources" && sub != "flatpak" && sub != "catalog":
		sub = "packages"
	case tab == "accounts" && sub != "groups":
		sub = "users"
	}
	if !slices.Contains([]string{"overview", "hardware", "network", "software", "accounts", "compliance", "declarations", "commands"}, tab) {
		tab = "overview"
	}
	pkgQ := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var pkgView []api.Package
	for _, p := range data.Packages {
		if pkgQ == "" || strings.Contains(strings.ToLower(p.Name), pkgQ) {
			pkgView = append(pkgView, p)
		}
	}
	const pageSize = 100
	pageNo, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pages := max(1, (len(pkgView)+pageSize-1)/pageSize)
	pageNo = min(max(pageNo, 1), pages)
	matched := len(pkgView)
	pkgView = pkgView[(pageNo-1)*pageSize : min(pageNo*pageSize, matched)]
	failingChecks := 0
	for _, c := range data.Checks {
		if c.Status == "fail" {
			failingChecks++
		}
	}
	reported := map[string]api.DeclarationStatus{}
	for _, st := range data.Decl {
		reported[st.Identifier] = st
	}
	var declRows []declRow
	for _, dcl := range want {
		row := declRow{Identifier: dcl.Identifier, Type: dcl.Type}
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
		declRows = append(declRows, row)
	}
	var agentVersions []string
	if rows, err := s.db.Query(ctx, `SELECT version FROM agent_releases WHERE NOT blocked`); err == nil {
		agentVersions, _ = pgx.CollectRows(rows, pgx.RowTo[string])
		slices.SortFunc(agentVersions, func(a, b string) int { return api.CompareVersions(b, a) })
	}
	appNames, catalogFlatpaks := map[string]string{}, map[string]string{}
	if tab == "software" && sub == "flatpak" {
		if apps, err := s.catalogApps(ctx, s.db, ""); err == nil {
			for _, a := range apps {
				for _, src := range a.Sources {
					if src.Kind == "flatpak" {
						catalogFlatpaks[src.Flatpak] = a.ID
					}
				}
			}
		}
	}
	var appBusy map[string]string // app → "install" | "remove" while it runs
	var appNotes []appNote
	if tab == "software" && sub == "catalog" {
		if apps, err := s.catalogApps(ctx, s.db, ""); err == nil {
			for _, a := range apps {
				appNames[a.ID] = a.Name
			}
		}
		if appBusy, appNotes, err = s.appProgress(ctx, id, data.Inv.Apps, appNames); err != nil {
			s.fail(w, err)
			return
		}
	}
	var netCerts []netCertRow
	if tab == "network" {
		if netCerts, err = s.networkCerts(ctx, id); err != nil {
			s.fail(w, err)
			return
		}
	}
	bpSrc, err := s.blueprintSource(ctx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	// what happens after the grace period: the compliance item of this device
	comp, _ := api.Compose(want)
	var lockAt *time.Time
	if since != nil && comp.Compliance.LockAfterHours > 0 {
		t := since.Add(time.Duration(comp.Compliance.LockAfterHours) * time.Hour)
		lockAt = &t
	}
	s.render(w, r, sess, "device", map[string]any{"NetCerts": netCerts, "BPSource": bpSrc, "LockAt": lockAt, "Notify": comp.Compliance.Notify, "EncExcluded": encExcluded, "AgentVersions": agentVersions, "AppNames": appNames, "AppBusy": appBusy, "AppNotes": appNotes, "CatalogFlatpaks": catalogFlatpaks,
		"PwError": pwError(r), "PwMin": s.settings().Rules.Min(),
		"D": d, "Inv": data.Inv, "Checks": data.Checks, "Decl": declRows, "Users": strings.Join(userLines, "\n"),
		"PackageCount": len(data.Packages), "Packages": pkgView, "PkgQ": pkgQ, "PkgMatched": matched,
		"PkgPage": pageNo, "PkgPages": pages, "PkgFrom": min((pageNo-1)*pageSize+1, matched), "PkgTo": min(pageNo*pageSize, matched),
		"Commands": cmds, "Scripts": scripts, "Diagnostics": diags, "Blueprints": bps, "Enrolled": enrolled, "CertExp": certExp, "Tab": tab, "PreType": r.URL.Query().Get("type"),
		"Resolved": res, "Tags": strings.Join(tags, ", "), "TagList": tags, "Protective": protect, "Primary": primary, "People": people, "Since": since, "Charts": charts, "Recovery": recovery, "Tampered": tampered, "Events": events, "EvPage": evPage, "EvPages": evPages, "EvTotal": evTotal, "EvFrom": min((evPage-1)*evSize+1, evTotal), "EvTo": min(evPage*evSize, evTotal),
		"Failing": failingChecks, "Tabs": []string{"overview", "hardware", "network", "software", "accounts", "compliance", "declarations", "commands"},
		"Sub": sub, "ShowSystem": r.URL.Query().Get("system") == "1", "NetworkInfo": len(data.Inv.DNS)+len(data.Inv.Routes) > 0 || hasIPs(data.Inv.Interfaces),
	})
}

// pwError is the password policy message a redirect named, if any.
func pwError(r *http.Request) string {
	if i, err := strconv.Atoi(r.URL.Query().Get("pwerr")); err == nil && i >= 0 && i < len(passwordErrors) {
		return passwordErrors[i]
	}
	return ""
}

func (s *Server) deviceCommand(w http.ResponseWriter, r *http.Request, sess session) {
	id, typ := r.PathValue("id"), r.FormValue("type")
	if !s.inScope(r.Context(), sess, id) {
		http.NotFound(w, r)
		return
	}
	payload, code, msg := s.commandPayload(r, sess, id, typ)
	if i := slices.Index(passwordErrors, msg); i >= 0 {
		http.Redirect(w, r, "/devices/"+url.PathEscape(id)+"?tab=accounts&pwerr="+strconv.Itoa(i), http.StatusSeeOther)
		return
	}
	if code != 0 {
		s.errorPage(w, r, sess, code, msg)
		return
	}
	if s.needsApproval(typ) {
		_, err := s.requestApproval(r.Context(), sess, "command", id, commandApproval{Type: typ, Payload: payload}, strings.TrimSpace(r.FormValue("reason")))
		if err != nil {
			s.fail(w, err)
			return
		}
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}
	if err := s.queueCommand(r.Context(), sess.Email, id, typ, payload); err != nil {
		s.fail(w, err)
		return
	}
	s.notifyCommand(sess.Email, id, typ)
	back := "/devices/" + id
	switch {
	case typ == "app_install" || typ == "app_remove":
		back += "?tab=software&sub=catalog"
	case strings.HasPrefix(typ, "user_"):
		back += "?tab=accounts"
	case typ == "software_remove":
		back += "?tab=software&sub=" + url.QueryEscape(r.FormValue("back_sub"))
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
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

func parseUsers(text string) ([]api.User, error) {
	users := []api.User{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 || len(f) > 3 || (len(f) == 3 && f[2] != "admin") {
			return nil, fmt.Errorf("line %q: expected 'username email [admin]'", line)
		}
		u := api.User{Username: f[0], Email: strings.ToLower(f[1]), Admin: len(f) == 3}
		if err := u.Validate(); err != nil {
			return nil, err
		}
		if seen[u.Username] {
			return nil, fmt.Errorf("user %s listed twice", u.Username)
		}
		seen[u.Username] = true
		users = append(users, u)
	}
	return users, nil
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

func (s *Server) deviceAssign(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	users, err := parseUsers(r.FormValue("users"))
	if err != nil {
		s.errorPage(w, r, sess, http.StatusBadRequest, err.Error())
		return
	}
	var bpID *int64
	if v, err := strconv.ParseInt(r.FormValue("blueprint_id"), 10, 64); err == nil && v > 0 {
		if !s.tenantOwns(r.Context(), sess, "blueprints", v, true) {
			s.errorPage(w, r, sess, http.StatusBadRequest, "unknown blueprint")
			return
		}
		bpID = &v
	}
	tags, err := parseTags(r.FormValue("tags"))
	if err != nil {
		s.errorPage(w, r, sess, http.StatusBadRequest, err.Error())
		return
	}
	var primary *int64
	if email := strings.ToLower(strings.TrimSpace(r.FormValue("primary_user"))); email != "" {
		var uid int64
		if err := s.db.QueryRow(r.Context(), `SELECT id FROM dir_users WHERE email=$1`, email).Scan(&uid); err != nil {
			s.errorPage(w, r, sess, http.StatusBadRequest, "primary user not found in the directory")
			return
		}
		primary = &uid
	}
	ub, _ := json.Marshal(users)
	err = s.auditAction(r.Context(), sess.Email, "device.assign", id, fmt.Sprintf("blueprint=%v tags=%v users=%s", r.FormValue("blueprint_id"), tags, ub), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE devices SET users=$2, blueprint_id=$3, tags=$4, primary_user_id=$5 WHERE id=$1`, id, string(ub), bpID, tags, primary)
		if err == nil {
			err = signDeviceUsers(r.Context(), tx, id)
		}
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices/"+id, http.StatusSeeOther)
}

func (s *Server) deviceRetire(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	err := s.auditAction(r.Context(), sess.Email, "device.retire", id, "client certificate revoked", func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `UPDATE devices SET retired=true, cert_serial='', pending_serial=NULL WHERE id=$1`, id); err != nil {
			return err
		}
		return revokeNetworkCerts(r.Context(), tx, id, "retired")
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices/"+id, http.StatusSeeOther)
}

// ---- enrollment tokens ----

// tokenRevoke deletes an enrollment token; devices already enrolled with it stay.
func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != sha256.Size {
		s.notFound(w, r, sess)
		return
	}
	err = s.auditActionFn(r.Context(), func(tx pgx.Tx) (string, string, string, string, error) {
		var note string
		tcond, targs := tenantCond(sess, "tenant_id", 1)
		err := tx.QueryRow(r.Context(), `DELETE FROM enroll_tokens WHERE token_hash=$1 AND `+tcond+` RETURNING note`, append([]any{id}, targs...)...).Scan(&note)
		return sess.Email, "token.revoke", r.PathValue("id")[:12], note, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		s.notFound(w, r, sess)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) tokens(w http.ResponseWriter, r *http.Request, sess session) {
	s.tokenPage(w, r, sess, "")
}

func (s *Server) tokenPage(w http.ResponseWriter, r *http.Request, sess session, created string) {
	type tok struct {
		ID, Note, Blueprint, By string
		Uses                    int
		Expires                 time.Time
	}
	tcond, targs := tenantCond(sess, "t.tenant_id", 0)
	rows, err := s.db.Query(r.Context(), `SELECT encode(t.token_hash, 'hex'), t.note, coalesce(b.name,'default'), t.created_by, t.uses_left, t.expires_at
		FROM enroll_tokens t LEFT JOIN blueprints b ON b.id=t.blueprint_id WHERE t.expires_at > now() AND t.uses_left > 0 AND `+tcond+` ORDER BY t.expires_at`, targs...)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[tok])
	if err != nil {
		s.fail(w, err)
		return
	}
	bps, err := s.allBlueprints(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "tokens", map[string]any{"Tokens": list, "Blueprints": bps, "Created": created,
		"AgentURL": s.cfg.AgentURL, "Fingerprint": s.tlsCA().Fingerprint(), "PublicURL": s.cfg.PublicURL, "Repo": s.cfg.ReleaseRepo})
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request, sess session) {
	uses, err1 := strconv.Atoi(r.FormValue("uses"))
	days, err2 := strconv.Atoi(r.FormValue("days"))
	if err1 != nil || err2 != nil || uses < 1 || uses > 10000 || days < 1 || days > 90 {
		s.errorPage(w, r, sess, http.StatusBadRequest, "uses 1..10000, days 1..90")
		return
	}
	var bpID *int64
	if v, err := strconv.ParseInt(r.FormValue("blueprint_id"), 10, 64); err == nil && v > 0 {
		if !s.tenantOwns(r.Context(), sess, "blueprints", v, true) {
			s.errorPage(w, r, sess, http.StatusBadRequest, "unknown blueprint")
			return
		}
		bpID = &v
	}
	token := "lmt_" + randToken(24)
	note := truncate(r.FormValue("note"), 200)
	err := s.auditAction(r.Context(), sess.Email, "token.create", note, fmt.Sprintf("uses=%d days=%d blueprint=%v", uses, days, r.FormValue("blueprint_id")), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO enroll_tokens(token_hash, note, blueprint_id, uses_left, expires_at, created_by, tenant_id)
			VALUES ($1,$2,$3,$4, now() + make_interval(days => $5), $6, $7)`, sha(token), note, bpID, uses, days, sess.Email, ownerTenant(r.Context()))
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.tokenPage(w, r, sess, token)
}

// ---- compliance reporting ----

type checkAgg struct {
	ID, Title                string
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

func (s *Server) compliance(w http.ResponseWriter, r *http.Request, sess session) {
	fc, err := s.fleetComplianceFor(r.Context(), sess)
	if err != nil {
		s.fail(w, err)
		return
	}
	exceptions, err := s.riskExceptions(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	f := complianceFilter{Q: strings.ToLower(strings.TrimSpace(q.Get("q"))), State: q.Get("state"), Level: q.Get("level"),
		Framework: q.Get("framework"), Sort: q.Get("sort")}
	checks, controls := f.apply(fc.Checks, fc.Controls)
	s.render(w, r, sess, "compliance", map[string]any{
		"F": f, "Shown": len(checks), "All": len(fc.Checks),
		"Checks": checks, "Controls": controls, "Total": fc.Total, "Compliant": fc.Compliant, "Stale": fc.Stale,
		"NonCompliant": fc.Noncompl, "Pending": fc.Pending, "StaleHours": s.settings().StaleHours,
		"Exceptions": exceptions,
	})
}

// complianceFilter narrows and orders the compliance page via query parameters.
type complianceFilter struct {
	Q, State, Level, Framework, Sort string
}

var frameworkNames = map[string]string{"bsi": "BSI IT-Grundschutz", "cis": "CIS Benchmark", "iso": "ISO/IEC 27001:2022"}

func (f complianceFilter) apply(checks []*checkAgg, controls []*controlAgg) ([]*checkAgg, []*controlAgg) {
	var out []*checkAgg
	for _, c := range checks {
		switch {
		case f.State == "failing" && c.Fail == 0, f.State == "passing" && (c.Fail > 0 || c.Pass == 0):
			continue
		case f.Level != "" && strconv.Itoa(c.Level) != f.Level:
			continue
		case f.Q != "" && !strings.Contains(strings.ToLower(c.ID+" "+c.Title), f.Q):
			continue
		case f.Framework == "bsi" && len(c.Refs.BSI) == 0, f.Framework == "cis" && len(c.Refs.CIS) == 0, f.Framework == "iso" && len(c.Refs.ISO) == 0:
			continue
		}
		out = append(out, c)
	}
	switch f.Sort {
	case "fail":
		sort.SliceStable(out, func(i, j int) bool { return out[i].Fail > out[j].Fail })
	case "title":
		sort.SliceStable(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	case "level":
		sort.SliceStable(out, func(i, j int) bool { return out[i].Level < out[j].Level })
	}
	var ctl []*controlAgg
	for _, c := range controls {
		if name := frameworkNames[f.Framework]; f.Framework == "" || c.Framework == name {
			if f.State != "failing" || c.Fail > 0 {
				ctl = append(ctl, c)
			}
		}
	}
	return out, ctl
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
				a = &checkAgg{ID: c.ID, Title: c.Title, Level: c.Level, Refs: c.Refs}
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

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	q := r.URL.Query()
	f, where, args := auditFilter(q, sess)
	filter := url.Values{}
	for k, v := range f {
		if v != "" {
			filter.Set(k, v)
		}
	}
	const pageSize = 100
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	if before > 0 {
		args = append(args, before)
		where += " AND id < $" + strconv.Itoa(len(args))
	}
	rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash, tenant_id FROM audit_log WHERE `+where+
		` ORDER BY id DESC LIMIT `+strconv.Itoa(pageSize+1), args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[auditRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	var older, newest string
	if len(list) > pageSize {
		list = list[:pageSize]
		v := url.Values{}
		for k := range filter {
			v.Set(k, filter.Get(k))
		}
		v.Set("before", strconv.FormatInt(list[len(list)-1].ID, 10))
		older = "/audit?" + v.Encode()
	}
	if before > 0 {
		newest = "/audit?" + filter.Encode()
	}
	brokenAt, err := s.verifyAudit(ctx)
	full, verifiedAt := s.auditVerification(ctx)
	if err == nil && brokenAt == 0 && full != 0 {
		brokenAt = full
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	var actions []string
	if rows, err := s.db.Query(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY 1`); err == nil {
		actions, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	s.render(w, r, sess, "audit", map[string]any{"Entries": list, "BrokenAt": brokenAt, "F": f, "Actions": actions,
		"Older": older, "Newest": newest, "CSV": "/export/audit.csv?" + filter.Encode(), "JSONL": "/export/audit.jsonl?" + filter.Encode(),
		"VerifiedAt": verifiedAt, "Keyed": auditKeyedFrom > 0, "KeyedFrom": auditKeyedFrom})
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
		q = `SELECT d.id, d.hostname, coalesce(p->>'n',''), coalesce(p->>'v',''), coalesce(p->>'a','')
			FROM devices d, jsonb_array_elements(CASE WHEN jsonb_typeof(d.packages) = 'array' THEN d.packages ELSE '[]'::jsonb END) p
			WHERE NOT d.retired AND ` + cond + ` ORDER BY d.hostname, d.id, p->>'n'`
	case "audit.csv":
		var where string
		_, where, args = auditFilter(r.URL.Query(), sess)
		header = []string{"id", "at", "actor", "action", "target", "detail", "prev", "hash", "tenant_id"}
		q = `SELECT id::text, at::text, actor, action, target, detail, encode(prev,'hex'), encode(hash,'hex'), coalesce(tenant_id::text, '') FROM audit_log WHERE ` + where + ` ORDER BY id`
	case "audit.jsonl":
		s.auditExportJSONL(w, r, sess)
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

func hasIPs(nics []api.NIC) bool {
	for _, n := range nics {
		if len(n.IPs) > 0 {
			return true
		}
	}
	return false
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
