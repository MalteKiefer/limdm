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
	funcs := template.FuncMap{
		"dict": func(kv ...any) map[string]any { // arguments for shared partials
			m := make(map[string]any, len(kv)/2)
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
		"t":       T,
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
		"deref2":     func(p *string) string { return *p },
		"typeLabel": func(t string) string {
			if l, ok := typeLabels[t]; ok {
				return T(l)
			}
			return t
		},
		"actionLabel": func(a string) string {
			return T(map[string]string{"sync": "Sync now", "update": "Install all updates", "reboot": "Reboot",
				"shutdown": "Shut down", "lock": "Lock device", "unlock": "Unlock device", "script": "Run script",
				"lost": "Lost mode", "found": "End lost mode", "wipe": "Wipe device", "allow_uninstall": "Allow uninstall for 1 hour", "message": "Message",
				"app_install": "Install app", "app_remove": "Remove app",
				"user_create": "Create user", "user_admin": "Change admin rights", "user_lock": "Lock user", "user_unlock": "Unlock user",
				"user_password": "Reset password", "user_delete": "Delete user", "software_remove": "Remove software"}[a])
		},
		"join":      strings.Join,
		"hasPrefix": strings.HasPrefix,
		"fmtTime":   func(t time.Time) string { return t.Local().Format(layout) },
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
			http.Error(w, "not available for the helpdesk role", http.StatusForbidden)
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
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if sess.Role != "admin" && postRole != "self" && (postRole != "helpdesk" || sess.Role != "helpdesk") {
				http.Error(w, "your role cannot change this", http.StatusForbidden)
				return
			}
			if !s.csrfOK(r, sess) {
				http.Error(w, "csrf check failed", http.StatusForbidden)
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
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sess session, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Sess"] = sess
	data["CSRF"] = s.csrfToken(sess)
	data["Page"] = name
	b := s.branding()
	data["Brand"] = map[string]any{"Name": b.Name, "Logo": len(b.Logo) > 0, "V": b.Hash}
	var buf bytes.Buffer
	if err := pages[requestLang(r)+"/"+requestDateFormat(r)][name].Execute(&buf, data); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (s *Server) webRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.page(s.overview))
	mux.HandleFunc("GET /devices", s.page(s.devices))
	mux.HandleFunc("GET /devices/{id}", s.page(s.device))
	mux.HandleFunc("POST /devices/bulk", s.helpdeskPage(s.devicesBulk))
	mux.HandleFunc("POST /devices/{id}/command", s.helpdeskPage(s.deviceCommand))
	mux.HandleFunc("POST /devices/{id}/agent-update", s.page(s.deviceAgentUpdate))
	mux.HandleFunc("POST /devices/{id}/recovery", s.helpdeskPage(s.recoveryView))
	mux.HandleFunc("GET /directory", s.page(s.adminOrAuditor(s.directoryPage)))
	mux.HandleFunc("POST /directory/groups", s.page(s.groupAssign))
	mux.HandleFunc("POST /directory/scim-token", s.page(s.scimToken))
	mux.HandleFunc("POST /directory/google", s.page(s.googleConfigure))
	mux.HandleFunc("POST /directory/google/sync", s.page(s.googleSyncNow))
	mux.HandleFunc("GET /users", s.page(s.adminOrAuditor(s.usersPage)))
	mux.HandleFunc("GET /agents", s.page(s.adminOrAuditor(s.agentsPage)))
	mux.HandleFunc("GET /software", s.page(s.adminOrAuditor(s.softwarePage)))
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
	mux.HandleFunc("POST /settings", s.page(s.settingsSave))
	mux.HandleFunc("POST /devices/{id}/assign", s.page(s.deviceAssign))
	mux.HandleFunc("POST /devices/{id}/retire", s.page(s.deviceRetire))
	mux.HandleFunc("GET /blueprints", s.page(s.blueprints))
	mux.HandleFunc("GET /blueprints/{id}", s.page(s.blueprintEdit))
	mux.HandleFunc("POST /blueprints", s.page(s.blueprintSave))
	mux.HandleFunc("POST /blueprints/{id}/delete", s.page(s.blueprintDelete))
	mux.HandleFunc("GET /library", s.page(s.library))
	mux.HandleFunc("GET /library/{id}", s.page(s.libraryEdit))
	mux.HandleFunc("POST /library", s.page(s.librarySave))
	mux.HandleFunc("POST /library/{id}/delete", s.page(s.libraryDelete))
	mux.HandleFunc("GET /tokens", s.page(s.tokens))
	mux.HandleFunc("POST /tokens", s.page(s.tokenCreate))
	mux.HandleFunc("POST /tokens/{id}/revoke", s.page(s.tokenRevoke))
	mux.HandleFunc("GET /compliance", s.page(s.compliance))
	mux.HandleFunc("GET /audit", s.page(s.adminOrAuditor(s.auditPage)))
	mux.HandleFunc("GET /export/{kind}", s.page(s.adminOrAuditor(s.export)))
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
	rows, err := s.db.Query(ctx, `SELECT d.id, d.hostname, d.os_name, d.agent_version,
		coalesce(b.name, 'default'), d.tags,
		d.desktop, d.memory_mb, d.failing, d.checks_count, d.last_seen, d.retired, d.grace_until, d.auto_locked
		FROM devices d LEFT JOIN blueprints b ON b.id = d.blueprint_id WHERE `+where+` ORDER BY d.retired, d.hostname`, args...)
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
// a condition on d with the value as $1.
var deviceFilters = []struct{ Key, Label, Where string }{
	{"tag", "Tag", `$1 = ANY(d.tags)`},
	{"app", "Catalog app installed", `EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(d.inventory->'apps', '[]'::jsonb)) a WHERE a->>'id' = $1 AND (a->>'installed')::boolean)`},
	{"flatpak", "Flatpak installed", `EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(d.inventory->'flatpaks', '[]'::jsonb)) f WHERE f->>'id' = $1)`},
	{"remote", "Flatpak remote", `EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(d.inventory->'flatpak_remotes', '[]'::jsonb)) r WHERE r->>'name' = $1)`},
	{"blueprint", "Blueprint", `coalesce((SELECT name FROM blueprints WHERE id = d.blueprint_id), 'default') = $1`},
	{"agent", "Agent version", `d.agent_version = $1`},
	{"failing", "Failing check", `EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(d.checks, '[]'::jsonb)) c WHERE c->>'id' = $1 AND c->>'status' = 'fail')`},
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	where, args := "TRUE", []any{}
	var filter, filterKey, filterVal string
	for _, f := range deviceFilters {
		if v := strings.TrimSpace(r.URL.Query().Get(f.Key)); v != "" && len(v) <= 200 {
			where, args, filter, filterKey, filterVal = f.Where, []any{v}, f.Label, f.Key, v
			break
		}
	}
	list, err := s.listDevicesWhere(ctx, where, args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	q, status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))), r.URL.Query().Get("status")
	counts := map[string]int{}
	var shown []deviceRow
	for _, d := range list {
		counts[d.Status]++
		if status != "" && d.Status != status {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(d.Hostname+" "+d.OS+" "+d.ID+" "+d.Blueprints+" "+strings.Join(d.Tags, " ")), q) {
			continue
		}
		shown = append(shown, d)
	}
	var tags []string
	if err := s.db.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT t ORDER BY t), '{}') FROM devices, unnest(tags) t WHERE NOT retired`).Scan(&tags); err != nil {
		s.fail(w, err)
		return
	}
	apps, err := s.catalogApps(ctx, s.db, `WHERE enabled`)
	if err != nil {
		s.fail(w, err)
		return
	}
	keep := url.Values{}
	if filterKey != "" {
		keep.Set(filterKey, filterVal)
	}
	if q != "" {
		keep.Set("q", q)
	}
	s.render(w, r, sess, "devices", map[string]any{"Devices": shown, "Total": len(list), "Counts": counts, "Q": q, "Status": status,
		"Statuses": []string{"compliant", "in grace", "non-compliant", "stale", "pending", "retired"},
		"Filter":   filter, "FilterKey": filterKey, "FilterVal": filterVal, "Keep": keep.Encode(), "Tags": tags, "Apps": apps,
		"Back": r.URL.RequestURI()})
}

// devicesBulk runs one action on the selected devices: a command, an
// agent update, or adding and removing a tag. Destructive commands (lost
// mode, wipe) and scripts stay single device actions.
func (s *Server) devicesBulk(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ids := slices.Compact(slices.Sorted(slices.Values(r.Form["id"])))
	if len(ids) == 0 || len(ids) > 1000 {
		http.Error(w, "select 1 to 1000 devices", http.StatusBadRequest)
		return
	}
	var known int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = ANY($1) AND NOT retired`, ids).Scan(&known); err != nil || known != len(ids) {
		http.Error(w, "unknown or retired device selected", http.StatusBadRequest)
		return
	}
	op, typ, _ := strings.Cut(r.FormValue("action"), ":")
	switch op {
	case "tag-add", "tag-remove":
		if sess.Role != "admin" {
			http.Error(w, "this action requires the admin role", http.StatusForbidden)
			return
		}
		tags, err := parseTags(r.FormValue("tag"))
		if err != nil || len(tags) != 1 {
			http.Error(w, "one tag: up to 32 letters, digits, dot, dash, underscore", http.StatusBadRequest)
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
			http.Error(w, "this action requires the admin role", http.StatusForbidden)
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
		if typ == "lost" || typ == "wipe" || typ == "script" {
			http.Error(w, "lost mode, wipe and scripts are sent to one device at a time", http.StatusBadRequest)
			return
		}
		payload, code, msg := s.commandPayload(r, sess, ids[0], typ)
		if code != 0 {
			http.Error(w, msg, code)
			return
		}
		for _, id := range ids {
			if err := s.queueCommand(ctx, sess.Email, id, typ, payload); err != nil {
				s.fail(w, err)
				return
			}
		}
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
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
	list, err := s.listDevices(ctx)
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
	fc, err := s.fleetComplianceCached(ctx)
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
	rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash FROM audit_log ORDER BY id DESC LIMIT 8`)
	if err != nil {
		s.fail(w, err)
		return
	}
	recent, err := pgx.CollectRows(rows, pgx.RowToStructByPos[auditRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	donut := donutChart([]donutPart{{"compliant", counts["compliant"], "ok"}, {"non-compliant", counts["non-compliant"], "bad"},
		{"in grace", counts["in grace"], "warn"}, {"stale", counts["stale"], "warn"}, {"pending", counts["pending"], "na"}})
	trend, err := s.fleetChart(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "overview", map[string]any{"Trend": trend, "Active": active, "Counts": counts, "OSes": oses, "Failing": failing, "Donut": donut,
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
		http.NotFound(w, r)
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
	if tab == "commands" { // outputs can be large; only the commands tab shows them
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
	if r.URL.Query().Get("tab") == "commands" {
		rows, err := s.db.Query(ctx, `SELECT at, detail FROM device_events WHERE device_id=$1 ORDER BY id DESC LIMIT 100`, id)
		if err == nil {
			events, err = pgx.CollectRows(rows, pgx.RowToStructByPos[deviceEvent])
		}
		if err != nil {
			s.fail(w, err)
			return
		}
	}
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
	encExcluded := func(string) bool { return false }
	if tab == "hardware" {
		if tx, err := s.db.Begin(ctx); err == nil {
			if decls, err := effectiveDeclarations(ctx, tx, id); err == nil {
				if pol, _ := api.Compose(decls); pol.Extra.DiskEncryption != nil {
					encExcluded = pol.Extra.DiskEncryption.Excluded
				}
			}
			_ = tx.Rollback(ctx)
		}
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
	if tab == "software" && sub == "catalog" {
		if apps, err := s.catalogApps(ctx, s.db, ""); err == nil {
			for _, a := range apps {
				appNames[a.ID] = a.Name
			}
		}
	}
	s.render(w, r, sess, "device", map[string]any{"EncExcluded": encExcluded, "AgentVersions": agentVersions, "AppNames": appNames, "CatalogFlatpaks": catalogFlatpaks,
		"D": d, "Inv": data.Inv, "Checks": data.Checks, "Decl": declRows, "Users": strings.Join(userLines, "\n"),
		"PackageCount": len(data.Packages), "Packages": pkgView, "PkgQ": pkgQ, "PkgMatched": matched,
		"PkgPage": pageNo, "PkgPages": pages, "PkgFrom": min((pageNo-1)*pageSize+1, matched), "PkgTo": min(pageNo*pageSize, matched),
		"CommandTypes": commandTypesFor(sess.Role),
		"Commands":     cmds, "Blueprints": bps, "Enrolled": enrolled, "CertExp": certExp, "Tab": tab, "PreType": r.URL.Query().Get("type"),
		"Resolved": res, "Tags": strings.Join(tags, ", "), "TagList": tags, "Protective": protect, "Primary": primary, "People": people, "Since": since, "Charts": charts, "Recovery": recovery, "Tampered": tampered, "Events": events,
		"Failing": failingChecks, "Tabs": []string{"overview", "hardware", "network", "software", "accounts", "compliance", "declarations", "commands"},
		"Sub": sub, "ShowSystem": r.URL.Query().Get("system") == "1", "NetworkInfo": len(data.Inv.DNS)+len(data.Inv.Routes) > 0 || hasIPs(data.Inv.Interfaces),
	})
}

func (s *Server) deviceCommand(w http.ResponseWriter, r *http.Request, sess session) {
	id, typ := r.PathValue("id"), r.FormValue("type")
	payload, code, msg := s.commandPayload(r, sess, id, typ)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	if err := s.queueCommand(r.Context(), sess.Email, id, typ, payload); err != nil {
		s.fail(w, err)
		return
	}
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

// queueCommand stores a command for a device and audits it.
func (s *Server) queueCommand(ctx context.Context, actor, id, typ, payload string) error {
	detail := payload
	var u api.UserCommand
	if strings.HasPrefix(typ, "user_") && json.Unmarshal([]byte(payload), &u) == nil {
		u.Password = ""         // never in the audit log
		b, _ := json.Marshal(u) //nolint:gosec // the password was cleared just above
		detail = string(b)
	}
	return s.auditAction(ctx, actor, "command."+typ, id, truncate(detail, 2000), func(tx pgx.Tx) error {
		if err := s.insertCommand(ctx, tx, id, typ, payload, actor); err != nil {
			return err
		}
		if typ == "unlock" || typ == "lock" { // a manual action takes over from the compliance policy
			_, err := tx.Exec(ctx, `UPDATE devices SET auto_locked=false WHERE id=$1`, id)
			return err
		}
		return nil
	})
}

// commandPayload checks a command from the form and builds its payload; a
// non zero status rejects it with msg.
func (s *Server) commandPayload(r *http.Request, sess session, id, typ string) (string, int, string) {
	payload := r.FormValue("payload")
	if !slices.Contains(api.CommandTypes, typ) || len(payload) > 64<<10 {
		return "", http.StatusBadRequest, "invalid command"
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
		// protective actions: admins only, lost and wipe confirmed by typing the host name
		if sess.Role != "admin" {
			return "", http.StatusForbidden, "this action requires the admin role"
		}
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
		if sess.Role != "admin" {
			return "", http.StatusForbidden, "this action requires the admin role"
		}
		u := api.UserCommand{Username: strings.TrimSpace(r.FormValue("username")), FullName: strings.TrimSpace(r.FormValue("full_name")),
			Password: r.FormValue("password"), Admin: r.FormValue("admin") == "on" || r.FormValue("admin") == "1", KeepHome: r.FormValue("keep_home") == "on"}
		if err := u.Validate(typ); err != nil {
			return "", http.StatusBadRequest, err.Error()
		}
		b, _ := json.Marshal(u) //nolint:gosec // signed command payload over mTLS, cleared from the database once applied
		payload = string(b)
	case typ == "software_remove":
		if sess.Role != "admin" {
			return "", http.StatusForbidden, "this action requires the admin role"
		}
		sr := api.SoftwareRemove{Kind: r.FormValue("kind"), Name: r.FormValue("name"), Installation: r.FormValue("installation")}
		if err := sr.Validate(); err != nil {
			return "", http.StatusBadRequest, err.Error()
		}
		b, _ := json.Marshal(sr)
		payload = string(b)
	case typ == "app_install" || typ == "app_remove":
		if sess.Role != "admin" {
			return "", http.StatusForbidden, "this action requires the admin role"
		}
		var ok bool
		app := r.FormValue("app")
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM catalog_apps WHERE slug=$1)`, app).Scan(&ok); err != nil || !ok {
			return "", http.StatusBadRequest, "unknown catalog app"
		}
		payload = app
	case typ != "script":
		payload = ""
	case sess.Role != "admin":
		return "", http.StatusForbidden, "scripts require the admin role"
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var bpID *int64
	if v, err := strconv.ParseInt(r.FormValue("blueprint_id"), 10, 64); err == nil && v > 0 {
		bpID = &v
	}
	tags, err := parseTags(r.FormValue("tags"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var primary *int64
	if email := strings.ToLower(strings.TrimSpace(r.FormValue("primary_user"))); email != "" {
		var uid int64
		if err := s.db.QueryRow(r.Context(), `SELECT id FROM dir_users WHERE email=$1`, email).Scan(&uid); err != nil {
			http.Error(w, "primary user not found in the directory", http.StatusBadRequest)
			return
		}
		primary = &uid
	}
	ub, _ := json.Marshal(users)
	err = s.auditAction(r.Context(), sess.Email, "device.assign", id, fmt.Sprintf("blueprint=%v tags=%v users=%s", r.FormValue("blueprint_id"), tags, ub), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE devices SET users=$2, blueprint_id=$3, tags=$4, primary_user_id=$5 WHERE id=$1`, id, string(ub), bpID, tags, primary)
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
		_, err := tx.Exec(r.Context(), `UPDATE devices SET retired=true, cert_serial='', pending_serial=NULL WHERE id=$1`, id)
		return err
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
		http.NotFound(w, r)
		return
	}
	err = s.auditActionFn(r.Context(), func(tx pgx.Tx) (string, string, string, string, error) {
		var note string
		err := tx.QueryRow(r.Context(), `DELETE FROM enroll_tokens WHERE token_hash=$1 RETURNING note`, id).Scan(&note)
		return sess.Email, "token.revoke", r.PathValue("id")[:12], note, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
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
	rows, err := s.db.Query(r.Context(), `SELECT encode(t.token_hash, 'hex'), t.note, coalesce(b.name,'default'), t.created_by, t.uses_left, t.expires_at
		FROM enroll_tokens t LEFT JOIN blueprints b ON b.id=t.blueprint_id WHERE t.expires_at > now() AND t.uses_left > 0 ORDER BY t.expires_at`)
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
		"AgentURL": s.cfg.AgentURL, "Fingerprint": s.ca.Fingerprint(), "PublicURL": s.cfg.PublicURL, "Repo": s.cfg.ReleaseRepo})
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request, sess session) {
	uses, err1 := strconv.Atoi(r.FormValue("uses"))
	days, err2 := strconv.Atoi(r.FormValue("days"))
	if err1 != nil || err2 != nil || uses < 1 || uses > 10000 || days < 1 || days > 90 {
		http.Error(w, "uses 1..10000, days 1..90", http.StatusBadRequest)
		return
	}
	var bpID *int64
	if v, err := strconv.ParseInt(r.FormValue("blueprint_id"), 10, 64); err == nil && v > 0 {
		bpID = &v
	}
	token := "lmt_" + randToken(24)
	note := truncate(r.FormValue("note"), 200)
	err := s.auditAction(r.Context(), sess.Email, "token.create", note, fmt.Sprintf("uses=%d days=%d blueprint=%v", uses, days, r.FormValue("blueprint_id")), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO enroll_tokens(token_hash, note, blueprint_id, uses_left, expires_at, created_by)
			VALUES ($1,$2,$3,$4, now() + make_interval(days => $5), $6)`, sha(token), note, bpID, uses, days, sess.Email)
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
	fc, err := s.fleetComplianceCached(r.Context())
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
	fs, err := s.fleetCompliance(ctx)
	if err == nil {
		s.fleet.Store(&fleetCache{at: time.Now(), fs: fs})
	}
	return fs, err
}

func (s *Server) fleetCompliance(ctx context.Context) (fleetStats, error) {
	var fs fleetStats
	rows, err := s.db.Query(ctx, `SELECT hostname, checks, last_seen, failing FROM devices WHERE NOT retired`)
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
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, sess session) {
	q := r.URL.Query()
	f := map[string]string{"q": strings.TrimSpace(q.Get("q")), "actor": strings.TrimSpace(q.Get("actor")), "action": strings.TrimSpace(q.Get("action")),
		"target": strings.TrimSpace(q.Get("target")), "from": q.Get("from"), "to": q.Get("to")}
	where, args := []string{"true"}, []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$?", "$"+strconv.Itoa(len(args))))
	}
	if f["q"] != "" {
		add(`(actor || ' ' || action || ' ' || target || ' ' || detail) ILIKE '%' || $? || '%'`, f["q"])
	}
	if f["actor"] != "" {
		add(`actor ILIKE '%' || $? || '%'`, f["actor"])
	}
	if f["action"] != "" {
		add(`action LIKE $? || '%'`, f["action"])
	}
	if f["target"] != "" {
		add(`target = $?`, f["target"])
	}
	for k, cond := range map[string]string{"from": `at >= $?::date`, "to": `at < $?::date + 1`} {
		if _, err := time.Parse("2006-01-02", f[k]); err == nil {
			add(cond, f[k])
		} else {
			f[k] = ""
		}
	}
	rows, err := s.db.Query(r.Context(), `SELECT id, at, actor, action, target, detail, prev, hash FROM audit_log WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT 300`, args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[auditRow])
	if err != nil {
		s.fail(w, err)
		return
	}
	brokenAt, err := s.verifyAudit(r.Context())
	if full := s.auditBroken.Load(); err == nil && brokenAt == 0 && full != 0 {
		brokenAt = full
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	var actions []string
	if rows, err := s.db.Query(r.Context(), `SELECT DISTINCT action FROM audit_log ORDER BY 1`); err == nil {
		actions, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	s.render(w, r, sess, "audit", map[string]any{"Entries": list, "BrokenAt": brokenAt, "F": f, "Actions": actions})
}

// verifyAudit recomputes the hash chain. Returns the first broken id or 0.
// ponytail: full scan per page view; checkpoint verified ranges when the log reaches millions of rows.
// verifyAudit checks the hash chain and returns the first broken entry (0 =
// intact). The audit page verifies incrementally from the last checkpoint;
// the daily background run verifies everything from the start.
func (s *Server) verifyAudit(ctx context.Context) (int64, error) { return s.verifyAuditFrom(ctx, true) }

func (s *Server) verifyAuditFrom(ctx context.Context, incremental bool) (int64, error) {
	var from int64
	prev := make([]byte, 32)
	if incremental {
		var hash []byte
		err := s.db.QueryRow(ctx, `SELECT last_id, last_hash FROM audit_checkpoint`).Scan(&from, &hash)
		switch {
		case err == nil:
			prev = hash
		case !errors.Is(err, pgx.ErrNoRows):
			return 0, err
		}
	}
	rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, prev, hash FROM audit_log WHERE id > $1 ORDER BY id`, from)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	last := from
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.ID, &a.At, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.Prev, &a.Hash); err != nil {
			return 0, err
		}
		if !bytes.Equal(a.Prev, prev) || !bytes.Equal(a.Hash, auditHash(a.Prev, a.At, a.Actor, a.Action, a.Target, a.Detail)) {
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
	var header []string
	switch kind {
	case "compliance.csv":
		header = []string{"device_id", "hostname", "last_seen", "check_id", "level", "status", "detail", "bsi", "cis", "iso"}
		q = `SELECT d.id, d.hostname, coalesce(d.last_seen::text,''), c->>'id', coalesce(c->>'level',''), c->>'status', coalesce(c->>'detail',''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'bsi') x),''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'cis') x),''),
			coalesce((SELECT string_agg(x,'; ') FROM jsonb_array_elements_text(c->'refs'->'iso') x),'')
			FROM devices d, jsonb_array_elements(d.checks) c WHERE NOT d.retired ORDER BY d.hostname, c->>'id'`
	case "inventory.csv":
		header = []string{"device_id", "hostname", "os", "kernel", "agent", "serial", "vendor", "model", "cpu", "memory_mb", "disk_gb", "last_seen", "enrolled_at", "retired"}
		q = `SELECT id, hostname, coalesce(inventory->>'os_name',''), coalesce(inventory->>'kernel',''), agent_version,
			coalesce(inventory->>'serial',''), coalesce(inventory->>'vendor',''), coalesce(inventory->>'model',''), coalesce(inventory->>'cpu',''),
			coalesce(inventory->>'memory_mb',''), coalesce(inventory->>'disk_gb',''), coalesce(last_seen::text,''), enrolled_at::text, retired::text
			FROM devices ORDER BY hostname`
	case "audit.csv":
		header = []string{"id", "at", "actor", "action", "target", "detail", "hash"}
		q = `SELECT id::text, at::text, actor, action, target, detail, encode(hash,'hex') FROM audit_log ORDER BY id`
	default:
		http.NotFound(w, r)
		return
	}
	rows, err := s.db.Query(ctx, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	if err := s.auditAction(ctx, sess.Email, "export", kind, "", nil); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="limdm-%s-%s"`, time.Now().Format("20060102"), kind))
	cw := csv.NewWriter(w)
	cw.Write(header)
	vals := make([]string, len(header))
	ptrs := make([]any, len(header))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			s.log.Error("export", "err", err)
			return
		}
		out := make([]string, len(vals))
		for i, v := range vals {
			out[i] = csvSafe(v)
		}
		cw.Write(out)
	}
	cw.Flush()
}

func hasIPs(nics []api.NIC) bool {
	for _, n := range nics {
		if len(n.IPs) > 0 {
			return true
		}
	}
	return false
}

// commandTypesFor hides scripts and the protective actions from non admins.
func commandTypesFor(role string) []string {
	if role == "admin" {
		return api.CommandTypes
	}
	return slices.DeleteFunc(slices.Clone(api.CommandTypes), func(t string) bool {
		return t == "script" || t == "lost" || t == "found" || t == "wipe" || t == "allow_uninstall"
	})
}
