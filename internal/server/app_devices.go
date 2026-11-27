package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Endpoints of the console app's devices area: the device page in one
// document, its packages and timeline, the device actions that are no
// command (retire, delete, agent update, recovery key, remote shell, bulk),
// and the enrollment tokens. Every handler calls the same functions as the
// console pages, so roles, scope, tenant, four eyes and audit stay equal.

func (s *Server) appDevicesRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/devices/{id}/detail", s.need("read", s.apiDeviceDetail))
	m.HandleFunc("GET /api/v1/devices/{id}/packages", s.need("read", s.apiDevicePackages))
	m.HandleFunc("GET /api/v1/devices/{id}/timeline", s.need("read", s.apiDeviceTimeline))
	m.HandleFunc("GET /api/v1/devices/{id}/diagnostics/{cid}", s.need("helpdesk", s.apiDiagnosticsDownload))
	m.HandleFunc("POST /api/v1/devices/{id}/retire", s.need("admin", s.apiDeviceRetire))
	m.HandleFunc("DELETE /api/v1/devices/{id}", s.need("admin", s.apiDeviceDelete))
	m.HandleFunc("POST /api/v1/devices/{id}/agent-update", s.need("admin", s.apiDeviceAgentUpdate))
	m.HandleFunc("POST /api/v1/devices/{id}/recovery-keys/{uuid}/view", s.need("helpdesk", s.apiRecoveryView))
	m.HandleFunc("POST /api/v1/devices/{id}/shell", s.need("helpdesk", s.apiShellStart))
	m.HandleFunc("GET /api/v1/devices/{id}/shell-sessions", s.need("read", s.apiShellSessions))
	m.HandleFunc("GET /api/v1/shell-sessions/{sid}", s.need("read", s.apiShellSession))
	m.HandleFunc("GET /api/v1/shell-sessions/{sid}/transcript", s.need("audit", s.apiShellTranscript))
	m.HandleFunc("POST /api/v1/shell-sessions/{sid}/end", s.need("helpdesk", s.apiShellEnd))
	m.HandleFunc("POST /api/v1/devices/bulk", s.need("helpdesk", s.apiDevicesBulk))
	m.HandleFunc("GET /api/v1/devices/primary-users", s.need("admin", s.apiPrimaryUsers))
	m.HandleFunc("GET /api/v1/devices/catalog-apps", s.need("read", s.apiDeviceCatalogApps))
	m.HandleFunc("GET /api/v1/enrollment-tokens", s.need("read", s.apiEnrollTokens))
	m.HandleFunc("POST /api/v1/enrollment-tokens", s.need("admin", s.apiEnrollTokenCreate))
	m.HandleFunc("DELETE /api/v1/enrollment-tokens/{id}", s.need("admin", s.apiEnrollTokenRevoke))
}

// deviceFound loads nothing but answers 404 unless the device exists in
// the caller's scope; retired reports whether it is retired.
func (s *Server) deviceFound(w http.ResponseWriter, r *http.Request, c apiCaller, id string) (retired, ok bool) {
	err := s.db.QueryRow(r.Context(), `SELECT retired FROM devices WHERE id=$1`, id).Scan(&retired)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !s.inScope(r.Context(), c.sess(), id) {
		problem(w, http.StatusNotFound, "device not found")
		return false, false
	}
	if err != nil {
		s.apiFail(w, err)
		return false, false
	}
	return retired, true
}

// apiActionFail answers the error of a shared device action.
func (s *Server) apiActionFail(w http.ResponseWriter, err error) {
	if errors.Is(err, errNotFound) || errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "not found")
		return
	}
	s.apiFail(w, err)
}

type apiBlueprintRef struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Assigned bool   `json:"assigned"`
	Applies  bool   `json:"applies"`
}

type apiLibraryRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type apiRecoveryKey struct {
	UUID     string     `json:"uuid"`
	Device   string     `json:"device"`
	Escrowed time.Time  `json:"escrowed"`
	ViewedAt *time.Time `json:"viewed_at"`
	ViewedBy *string    `json:"viewed_by"`
	Rotate   bool       `json:"rotate"`
}

type apiNetCert struct {
	Serial    string     `json:"serial"`
	SANs      string     `json:"sans"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	State     string     `json:"state"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

type apiAppNote struct {
	App   string    `json:"app"`
	Type  string    `json:"type"`
	Error string    `json:"error,omitempty"`
	OK    bool      `json:"ok"`
	At    time.Time `json:"at"`
}

type apiMetric struct {
	At      time.Time `json:"at"`
	MemPct  float64   `json:"mem_pct"`
	RootPct float64   `json:"root_pct"`
	Load1   float64   `json:"load1"`
}

type apiCatalogRequest struct {
	ID        int64      `json:"id"`
	App       string     `json:"app"`
	Name      string     `json:"name"`
	Username  string     `json:"username"`
	Note      string     `json:"note"`
	Status    string     `json:"status"`
	DecidedBy *string    `json:"decided_by"`
	DecidedAt *time.Time `json:"decided_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// apiDeviceDetailDoc is everything the device page shows except the
// package list and the timeline, which are paged on their own.
type apiDeviceDetailDoc struct {
	apiDevice
	Inventory         api.Inventory           `json:"inventory"`
	CheckResults      []api.CheckResult       `json:"check_results"`
	Declarations      []declRow               `json:"declarations"`
	Chain             []apiBlueprintRef       `json:"chain"`
	Items             []apiLibraryRef         `json:"items"`
	Blueprints        []apiBlueprintRef       `json:"blueprints"`
	BlueprintSource   bpSource                `json:"blueprint_source"`
	PrimaryUser       string                  `json:"primary_user"`
	DesktopUsers      []api.User              `json:"desktop_users"`
	Protective        []protective            `json:"protective"`
	Tampered          *time.Time              `json:"tampered_at"`
	AutoLocked        bool                    `json:"auto_locked"`
	FailingSince      *time.Time              `json:"failing_since"`
	GraceUntil        *time.Time              `json:"grace_until"`
	LockAt            *time.Time              `json:"lock_at"`
	NotifyOnGrace     bool                    `json:"notify_on_grace"`
	CertExpires       time.Time               `json:"cert_expires"`
	TPMBound          bool                    `json:"tpm_bound"`     // the mTLS key is attested as held by a TPM (tpmattest.go)
	TPMEK             string                  `json:"tpm_ek_sha256"` // SHA-256 of the TPM's endorsement key, when bound
	UpdateState       string                  `json:"update_state"`
	UpdateVersion     string                  `json:"update_version"`
	UpdateRequested   bool                    `json:"update_requested"`
	ExternalIP        string                  `json:"external_ip"`
	Geo               *Geo                    `json:"geo"`
	Place             string                  `json:"place"`
	RecoveryKeys      []apiRecoveryKey        `json:"recovery_keys"`
	AgentVersions     []string                `json:"agent_versions"`
	NetworkCerts      []apiNetCert            `json:"network_certs"`
	AppNames          map[string]string       `json:"app_names"`
	AppBusy           map[string]string       `json:"app_busy"`
	AppNotes          []apiAppNote            `json:"app_notes"`
	CatalogFlatpaks   map[string]string       `json:"catalog_flatpaks"`
	CatalogRequests   []apiCatalogRequest     `json:"catalog_requests"`
	EncryptionExempt  []string                `json:"encryption_exempt"`
	Metrics           []apiMetric             `json:"metrics"`
	PackageCount      int                     `json:"package_count"`
	PasswordMin       int                     `json:"password_min"`
	Shell             apiShellSettings        `json:"shell"`
	FourEyesCommands  []string                `json:"four_eyes_commands"`
	FourEyesRecovery  bool                    `json:"four_eyes_recovery"`
	Diagnostics       []apiDiagnostics        `json:"diagnostics"`
	DeclarationStatus []api.DeclarationStatus `json:"-"`
}

type apiShellSettings struct {
	Enabled   bool `json:"enabled"`
	Allowed   bool `json:"allowed"` // the caller's role may start sessions
	AllowRoot bool `json:"allow_root"`
	Max       int  `json:"max_minutes"`
	Idle      int  `json:"idle_minutes"`
	FourEyes  bool `json:"four_eyes"`
	Policy    bool `json:"policy"` // the device's policy allows remote shells (com.limdm.agent remote_shell)
}

type apiDiagnostics struct {
	CommandID int64     `json:"command_id"`
	Size      int       `json:"size"`
	At        time.Time `json:"at"`
}

// apiDeviceDetail answers the device page: the same data the console's
// device page loads (web.go device), for every tab at once.
func (s *Server) apiDeviceDetail(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	base, err := s.apiDevice(ctx, id)
	if err != nil {
		s.apiActionFail(w, err)
		return
	}
	base.Inventory = nil // the typed inventory below replaces it
	d := apiDeviceDetailDoc{apiDevice: base}
	var inv, checks, decl, users []byte
	err = s.db.QueryRow(ctx, `SELECT d.inventory, d.checks, d.decl_status, d.users, d.cert_not_after, d.grace_until, d.auto_locked, d.noncompliant_since,
		d.update_state, d.update_version, d.update_requested, d.external_ip, d.geo, coalesce(u.email, ''),
		CASE WHEN d.tampered_at > now() - interval '30 days' THEN d.tampered_at END, d.tpm_bound, d.tpm_ek_sha256
		FROM devices d LEFT JOIN dir_users u ON u.id=d.primary_user_id WHERE d.id=$1`, id).
		Scan(&inv, &checks, &decl, &users, &d.CertExpires, &d.GraceUntil, &d.AutoLocked, &d.FailingSince,
			&d.UpdateState, &d.UpdateVersion, &d.UpdateRequested, &d.ExternalIP, &d.Geo, &d.PrimaryUser, &d.Tampered, &d.TPMBound, &d.TPMEK)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if err := errors.Join(json.Unmarshal(inv, &d.Inventory), json.Unmarshal(checks, &d.CheckResults),
		json.Unmarshal(decl, &d.DeclarationStatus), json.Unmarshal(users, &d.DesktopUsers)); err != nil {
		s.apiFail(w, err)
		return
	}
	if d.Geo != nil {
		d.Place = d.Geo.Place()
	}
	slices.SortStableFunc(d.CheckResults, func(a, b api.CheckResult) int { // failing first, as on the console page
		return boolInt(b.Status == "fail") - boolInt(a.Status == "fail")
	})
	if d.Protective, err = s.protectiveActions(ctx, id); err != nil {
		s.apiFail(w, err)
		return
	}
	// expected declarations and the resolved blueprint chain
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	res, err := resolveDevice(ctx, tx, id)
	var exempt func(string) bool
	shellPolicy := false
	if err == nil {
		if decls, derr := effectiveDeclarations(ctx, tx, id); derr == nil {
			pol, _ := api.Compose(decls)
			if pol.Extra.DiskEncryption != nil {
				exempt = pol.Extra.DiskEncryption.Excluded
			}
			shellPolicy = pol.RemoteShell
		}
	}
	_ = tx.Rollback(ctx) // free the connection before the next queries (see device)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	d.Declarations = declarationRows(res.Decls, d.DeclarationStatus)
	for _, b := range res.Chain {
		d.Chain = append(d.Chain, apiBlueprintRef{ID: b.ID, Name: b.Name})
	}
	for _, it := range res.Items {
		d.Items = append(d.Items, apiLibraryRef{ID: it.ID, Name: it.Name, Type: it.Type})
	}
	d.EncryptionExempt = []string{}
	if exempt != nil {
		for _, v := range d.Inventory.Volumes {
			if exempt(v.Mount) {
				d.EncryptionExempt = append(d.EncryptionExempt, v.Mount)
			}
		}
	}
	comp, _ := api.Compose(res.Decls)
	d.NotifyOnGrace = comp.Compliance.Notify
	if d.FailingSince != nil && comp.Compliance.LockAfterHours > 0 {
		t := d.FailingSince.Add(time.Duration(comp.Compliance.LockAfterHours) * time.Hour)
		d.LockAt = &t
	}
	bps, err := s.allBlueprints(ctx, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for _, b := range bps {
		d.Blueprints = append(d.Blueprints, apiBlueprintRef{ID: b.ID, Name: b.Name, Assigned: b.Assigned, Applies: b.Applies})
	}
	if d.BlueprintSource, err = s.blueprintSource(ctx, id); err != nil {
		s.apiFail(w, err)
		return
	}
	keys, err := s.recoveryKeys(ctx, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	d.RecoveryKeys = []apiRecoveryKey{}
	for _, k := range keys {
		d.RecoveryKeys = append(d.RecoveryKeys, apiRecoveryKey(k))
	}
	d.AgentVersions = []string{}
	if rows, err := s.db.Query(ctx, `SELECT version FROM agent_releases WHERE NOT blocked`); err == nil {
		d.AgentVersions, _ = pgx.CollectRows(rows, pgx.RowTo[string])
		slices.SortFunc(d.AgentVersions, func(a, b string) int { return api.CompareVersions(b, a) })
	}
	certs, err := s.networkCerts(ctx, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	d.NetworkCerts = []apiNetCert{}
	for _, nc := range certs {
		d.NetworkCerts = append(d.NetworkCerts, apiNetCert{Serial: nc.Serial, SANs: nc.SANs, NotBefore: nc.NotBefore, NotAfter: nc.NotAfter,
			State: nc.State(), RevokedAt: nc.RevokedAt, Reason: nc.Reason})
	}
	d.AppNames, d.CatalogFlatpaks = map[string]string{}, map[string]string{}
	if apps, err := s.catalogApps(ctx, s.db, ""); err == nil {
		for _, a := range apps {
			d.AppNames[a.ID] = a.Name
			for _, src := range a.Sources {
				if src.Kind == "flatpak" {
					d.CatalogFlatpaks[src.Flatpak] = a.ID
				}
			}
		}
	}
	busy, notes, err := s.appProgress(ctx, id, d.Inventory.Apps, d.AppNames)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	d.AppBusy, d.AppNotes = busy, []apiAppNote{}
	for _, n := range notes {
		d.AppNotes = append(d.AppNotes, apiAppNote(n))
	}
	if d.CatalogRequests, err = collect(ctx, s.db, pgx.RowToStructByPos[apiCatalogRequest], `SELECT id, coalesce(app, flatpak), coalesce(nullif(app_name, ''), app, flatpak),
		username, note, status, decided_by, decided_at, created_at FROM catalog_requests WHERE device_id=$1 ORDER BY id DESC LIMIT 50`, id); err != nil {
		s.apiFail(w, err)
		return
	}
	if d.Metrics, err = collect(ctx, s.db, pgx.RowToStructByPos[apiMetric], `SELECT at, mem_used_mb * 100.0 / greatest(mem_total_mb, 1), root_used_pct::float8, load1::float8
		FROM device_metrics WHERE device_id=$1 AND at > now() - interval '7 days' ORDER BY at`, id); err != nil {
		s.apiFail(w, err)
		return
	}
	pkgs, err := devicePackages(ctx, s.db, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	d.PackageCount = len(pkgs)
	d.Diagnostics = []apiDiagnostics{}
	if c.can("helpdesk") {
		diags, err := s.diagnosticsList(ctx, id)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		for _, g := range diags {
			d.Diagnostics = append(d.Diagnostics, apiDiagnostics(g))
		}
	}
	set := s.settings()
	maxM, idleM := set.RemoteShell.Limits()
	d.Shell = apiShellSettings{Enabled: set.RemoteShell.Enabled, Allowed: set.RemoteShell.allows(c.Role) && c.can("helpdesk"),
		AllowRoot: set.RemoteShell.AllowRoot, Max: maxM, Idle: idleM, FourEyes: set.FourEyesShell, Policy: shellPolicy}
	d.FourEyesCommands = []string{}
	for _, t := range []string{"wipe", "lost", "script", "package_downgrade"} {
		if s.needsApproval(t) {
			d.FourEyesCommands = append(d.FourEyesCommands, t)
		}
	}
	d.FourEyesRecovery = set.FourEyesRecovery
	d.PasswordMin = set.Rules.Min()
	nonNilSlices(&d)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, d)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nonNilSlices makes the lists of the detail document arrays, never null.
func nonNilSlices(d *apiDeviceDetailDoc) {
	if d.CheckResults == nil {
		d.CheckResults = []api.CheckResult{}
	}
	if d.Chain == nil {
		d.Chain = []apiBlueprintRef{}
	}
	if d.Items == nil {
		d.Items = []apiLibraryRef{}
	}
	if d.Blueprints == nil {
		d.Blueprints = []apiBlueprintRef{}
	}
	if d.DesktopUsers == nil {
		d.DesktopUsers = []api.User{}
	}
	if d.Protective == nil {
		d.Protective = []protective{}
	}
	if d.AppBusy == nil {
		d.AppBusy = map[string]string{}
	}
	if d.CatalogRequests == nil {
		d.CatalogRequests = []apiCatalogRequest{}
	}
	if d.Metrics == nil {
		d.Metrics = []apiMetric{}
	}
}

// apiDevicePackages lists every installed package of a device, sorted by
// name; the app filters and pages it.
func (s *Server) apiDevicePackages(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	list, err := devicePackages(r.Context(), s.db, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Arch    string `json:"arch"`
	}
	out := make([]pkg, len(list))
	for i, p := range list {
		out[i] = pkg{p.Name, p.Version, p.Arch}
	}
	writeJSON(w, listPage{Items: out})
}

// timelineEntry is one entry of a device's activity: a device event, a
// command, a script result, a remote shell session, a diagnostics bundle, a
// change of a compliance check result or an audit entry about the device.
type timelineEntry struct {
	Kind   string    `json:"kind"` // event | command | script | shell | diagnostics | compliance | audit
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Title  string    `json:"title"`
	Status string    `json:"status"`
	By     string    `json:"by"`
	Detail string    `json:"detail"`
	Extra  string    `json:"extra"`
}

// apiDeviceTimeline merges the device's events, commands, script results,
// remote shell sessions (the helpdesk sees its own), diagnostics bundles
// (admins and helpdesk), compliance check changes and audit entries with the
// device as target (audit permission), newest first; kind narrows it to one source.
func (s *Server) apiDeviceTimeline(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	// cursor: RFC 3339 time with nanoseconds, a space, the kind and id of the last entry
	curAt, curKey := time.Now().Add(time.Hour), "~"
	if cur != "" {
		ts, key, found := strings.Cut(cur, " ")
		t, err := time.Parse(time.RFC3339Nano, ts)
		if !found || err != nil {
			problem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		curAt, curKey = t, key
	}
	sess := c.sess()
	parts := []string{
		`SELECT 'event', id::text, at, '', '', '', detail, '' FROM device_events WHERE device_id=$1`,
		`SELECT 'command', id::text, created_at, type, status, created_by, output, '' FROM commands WHERE device_id=$1 AND type <> 'shell'`,
		`SELECT 'script', id::text, ended_at, coalesce(nullif(name, ''), '#' || command_id::text), exit_code::text, '', stdout, stderr FROM script_results WHERE device_id=$1`,
	}
	shell := `SELECT 'shell', id, created_at, local_user, CASE WHEN ended_at IS NOT NULL THEN 'ended' WHEN connected_at IS NOT NULL THEN 'active' ELSE 'waiting' END,
		requested_by, end_reason, '' FROM shell_sessions WHERE device_id=$1`
	args := []any{id}
	if sess.Role == "helpdesk" {
		shell += ` AND requested_by=$2`
		args = append(args, sess.Email)
	}
	parts = append(parts, shell)
	if c.can("helpdesk") {
		parts = append(parts, `SELECT 'diagnostics', command_id::text, created_at, '', '', '', length(content)::text, '' FROM diagnostics WHERE device_id=$1`)
	}
	parts = append(parts, `SELECT 'compliance', id::text, at, check_id, status, '', detail, '' FROM compliance_changes WHERE device_id=$1`)
	kind := r.URL.Query().Get("kind")
	if kind != "" && !slices.Contains([]string{"event", "command", "script", "shell", "diagnostics", "compliance", "audit"}, kind) {
		problem(w, http.StatusBadRequest, "kind: event, command, script, shell, diagnostics, compliance or audit")
		return
	}
	withAudit := c.can("audit") && (kind == "" || kind == "audit")
	if withAudit {
		// deviceFound checked tenant and scope of the device, so entries targeting it are visible
		parts = append(parts, `SELECT 'audit', id::text, at, action, '', actor, detail, '' FROM audit_log WHERE target=$1`)
		// reading audit entries is audited as on /api/v1/audit (LIMDM_AUDIT_API_READS)
		if s.auditRead(r, "audit") {
			if err := s.auditAction(ctx, c.actor(), "api.read", "GET /api/v1/devices/{id}/timeline", id, nil); err != nil {
				s.apiFail(w, err)
				return
			}
		}
	}
	n := len(args)
	q := `SELECT * FROM (` + strings.Join(parts, " UNION ALL ") + `) t(kind, id, at, title, status, by, detail, extra)
		WHERE (at, kind || ':' || id) < ($` + strconv.Itoa(n+1) + `, $` + strconv.Itoa(n+2) + `)`
	args = append(args, curAt, curKey)
	if kind != "" {
		args = append(args, kind)
		q += ` AND kind = $` + strconv.Itoa(len(args))
	}
	args = append(args, limit+1)
	q += ` ORDER BY at DESC, kind || ':' || id DESC LIMIT $` + strconv.Itoa(len(args))
	list, err := collect(ctx, s.db, pgx.RowToStructByPos[timelineEntry], q, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		l := list[limit-1]
		page.NextCursor = cursor(l.At.Format(time.RFC3339Nano) + " " + l.Kind + ":" + l.ID)
	}
	lang := requestLang(r)
	for i := range list {
		if list[i].Kind == "audit" {
			list[i].Extra = auditLabel(lang, list[i].Title, func(string) string { return "" })
		}
		list[i].Detail = truncate(list[i].Detail, 64<<10)
		list[i].Extra = truncate(list[i].Extra, 64<<10)
	}
	page.Items = list
	writeJSON(w, page)
}

// apiDiagnosticsDownload hands out one diagnostics bundle (diagnosticsDownload).
func (s *Server) apiDiagnosticsDownload(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if _, ok := s.deviceFound(w, r, c, r.PathValue("id")); !ok {
		return
	}
	s.diagnosticsDownload(w, r, c.sess())
}

func (s *Server) apiDeviceRetire(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	retired, ok := s.deviceFound(w, r, c, id)
	if !ok {
		return
	}
	if retired {
		problem(w, http.StatusConflict, "the device is retired")
		return
	}
	if err := s.retireDevice(r.Context(), c.actor(), id); err != nil {
		s.apiFail(w, err)
		return
	}
	s.apiDeviceGet(w, r, c)
}

// apiDeviceDelete deletes a retired device; confirm repeats its host name.
func (s *Server) apiDeviceDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	if err := s.deleteDevice(r.Context(), c.actor(), id, r.URL.Query().Get("confirm")); err != nil {
		var ue *userError
		switch {
		case errors.As(err, &ue) && strings.HasPrefix(ue.Msg, "retire"):
			problem(w, http.StatusConflict, ue.Msg)
		case errors.As(err, &ue):
			problemField(w, http.StatusUnprocessableEntity, "confirm", ue.Msg)
		default:
			s.apiActionFail(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiDeviceAgentUpdate(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	var body struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	if err := s.requestAgentUpdate(r.Context(), c.actor(), id, strings.TrimSpace(body.Version)); err != nil {
		var ue *userError
		if errors.As(err, &ue) {
			problemField(w, http.StatusUnprocessableEntity, "version", ue.Msg)
			return
		}
		if errors.Is(err, errNotFound) {
			problem(w, http.StatusConflict, "the device is retired")
			return
		}
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "requested"})
}

// apiRecoveryView opens a recovery key (viewRecoveryKey). With four eyes
// the answer names the state of the request instead of the key.
func (s *Server) apiRecoveryView(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	res, err := s.viewRecoveryKey(r.Context(), c.sess(), r.PathValue("id"), r.PathValue("uuid"), body.Reason)
	if err != nil {
		var ue *userError
		if errors.As(err, &ue) && ue.Status == http.StatusBadRequest {
			problemField(w, http.StatusUnprocessableEntity, "reason", ue.Msg)
			return
		}
		s.apiActionFail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, res)
}

// apiShellStart starts a remote shell session (startShell). The app opens
// the terminal at /shell/{id}/ws with the session's CSRF token.
func (s *Server) apiShellStart(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		User string `json:"user"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if c.Sess == nil {
		problem(w, http.StatusForbidden, "remote shell sessions are started from the console")
		return
	}
	sid, refused, err := s.startShell(r.Context(), c.sess(), r.PathValue("id"), body.User)
	switch {
	case err != nil:
		var ue *userError
		if errors.As(err, &ue) && ue.Status == http.StatusForbidden {
			s.deny(w, r, c, ue.Msg)
			return
		}
		s.apiActionFail(w, err)
	case refused == "approval":
		writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "approval"})
	case refused != "":
		problemField(w, http.StatusUnprocessableEntity, "user", shellErrors[refused])
	default:
		writeJSONStatus(w, http.StatusCreated, map[string]string{"id": sid, "status": "started"})
	}
}

type apiShell struct {
	ID         string     `json:"id"`
	DeviceID   string     `json:"device_id"`
	Hostname   string     `json:"hostname"`
	By         string     `json:"requested_by"`
	User       string     `json:"local_user"`
	State      string     `json:"state"`
	Reason     string     `json:"end_reason"`
	Created    time.Time  `json:"created_at"`
	Connected  *time.Time `json:"connected_at"`
	Ended      *time.Time `json:"ended_at"`
	Bytes      int        `json:"bytes"`
	Truncated  bool       `json:"truncated"`
	Live       bool       `json:"live"`    // the caller can open the terminal
	CanEnd     bool       `json:"can_end"` // the caller can end the session
	Transcript *string    `json:"transcript,omitempty"`
}

func (s *Server) toAPIShell(sr shellRow, sess session) apiShell {
	running := sr.State != "ended" && sr.State != "interrupted"
	return apiShell{ID: sr.ID, DeviceID: sr.Device, Hostname: sr.Hostname, By: sr.By, User: sr.User, State: sr.State, Reason: sr.Reason,
		Created: sr.Created, Connected: sr.Connected, Ended: sr.Ended, Bytes: sr.Bytes, Truncated: sr.Truncated,
		Live: running && sr.By == sess.Email, CanEnd: running && (sr.By == sess.Email || sess.Role == "admin")}
}

// apiShellSessions lists a device's remote shell sessions as the console's
// shell page does: the helpdesk sees its own.
func (s *Server) apiShellSessions(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	sess := c.sess()
	q := `SELECT ` + shellCols + ` FROM shell_sessions s JOIN devices d ON d.id=s.device_id WHERE s.device_id=$1`
	args := []any{id}
	if sess.Role == "helpdesk" {
		q += ` AND s.requested_by=$2`
		args = append(args, sess.Email)
	}
	rows, err := s.db.Query(r.Context(), q+` ORDER BY s.created_at DESC LIMIT 100`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	defer rows.Close()
	out := []apiShell{}
	for rows.Next() {
		sr, err := s.scanShell(rows)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		out = append(out, s.toAPIShell(sr, sess))
	}
	if err := rows.Err(); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: out})
}

// apiShellSession answers one session; the transcript goes to admins and
// auditors once the session ended (shellView).
func (s *Server) apiShellSession(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx, sid, sess := r.Context(), r.PathValue("sid"), c.sess()
	sr, err := s.scanShell(s.db.QueryRow(ctx, `SELECT `+shellCols+` FROM shell_sessions s JOIN devices d ON d.id=s.device_id WHERE s.id=$1`, sid))
	if err != nil || !s.inScope(ctx, sess, sr.Device) {
		problem(w, http.StatusNotFound, "session not found")
		return
	}
	out := s.toAPIShell(sr, sess)
	if !out.Live && sess.Role != "admin" && sess.Role != "auditor" {
		s.deny(w, r, c, "transcripts are available to admins and auditors")
		return
	}
	if !out.Live && sr.Ended != nil && c.can("audit") {
		var raw []byte
		if err := s.db.QueryRow(ctx, `SELECT transcript FROM shell_sessions WHERE id=$1`, sid).Scan(&raw); err != nil {
			s.apiFail(w, err)
			return
		}
		text := terminalText(raw)
		out.Transcript = &text
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}

// apiShellTranscript hands out the recorded bytes of an ended session for
// replay in a terminal or as a .log download. The route needs the audit
// level (admins, auditors), so the read is audited like /api/v1/audit.
func (s *Server) apiShellTranscript(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx, sid := r.Context(), r.PathValue("sid")
	sr, err := s.scanShell(s.db.QueryRow(ctx, `SELECT `+shellCols+` FROM shell_sessions s JOIN devices d ON d.id=s.device_id WHERE s.id=$1`, sid))
	if err != nil || !s.inScope(ctx, c.sess(), sr.Device) {
		problem(w, http.StatusNotFound, "session not found")
		return
	}
	if sr.Ended == nil {
		problem(w, http.StatusConflict, "the session has not ended yet")
		return
	}
	var raw []byte
	if err := s.db.QueryRow(ctx, `SELECT transcript FROM shell_sessions WHERE id=$1`, sid).Scan(&raw); err != nil {
		s.apiFail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="shell-`+sr.ID+`.log"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

// apiShellEnd ends a session, here or on another instance (shellEnd).
func (s *Server) apiShellEnd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx, sid, sess := r.Context(), r.PathValue("sid"), c.sess()
	device, owner, ok := "", "", false
	l := s.shells.get(sid)
	if l != nil {
		device, owner, ok = l.device, l.owner, true
	} else {
		device, owner, ok = s.remoteShell(ctx, sid)
	}
	if !ok || !s.inScope(ctx, sess, device) {
		problem(w, http.StatusNotFound, "session not found or ended")
		return
	}
	if owner != sess.Email && sess.Role != "admin" {
		s.deny(w, r, c, "only the user who started the session or an admin can end it")
		return
	}
	reason := "ended in the console by " + sess.Email
	if l != nil {
		l.end(reason)
		select {
		case <-l.stored:
		case <-time.After(5 * time.Second):
		}
	} else if err := s.relaySend(sid, "h", "e", []byte(reason)); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiDevicesBulk runs one action on many devices (bulkAction). Parameters
// are the console form fields, as for single commands.
func (s *Server) apiDevicesBulk(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		IDs    []string       `json:"ids"`
		Action string         `json:"action"`
		Params map[string]any `json:"params"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	form, ok := paramsForm(w, body.Params)
	if !ok {
		return
	}
	op, typ, _ := strings.Cut(body.Action, ":")
	if (op != "command" || !slices.Contains(helpdeskCommands, typ)) && !c.can("admin") {
		s.deny(w, r, c, "this action requires the admin role")
		return
	}
	fr := r.Clone(r.Context())
	fr.Form, fr.PostForm = form, form
	n, err := s.bulkAction(fr, c.sess(), body.IDs, body.Action)
	var ue *userError
	switch {
	case errors.As(err, &ue) && ue.Status == http.StatusForbidden:
		s.deny(w, r, c, ue.Msg)
	case errors.As(err, &ue):
		problemField(w, http.StatusUnprocessableEntity, "params", ue.Msg)
	case err != nil:
		s.apiFail(w, err)
	case n > 0:
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"status": "approval", "approvals": n})
	default:
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"status": "queued", "devices": len(body.IDs)})
	}
}

// paramsForm turns JSON parameters into console form values, as
// apiCommandCreate does: strings, numbers and booleans ("on" when true).
func paramsForm(w http.ResponseWriter, params map[string]any) (url.Values, bool) {
	form := url.Values{}
	for k, v := range params {
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
			problemField(w, http.StatusUnprocessableEntity, "params", "params: strings, numbers and booleans only")
			return nil, false
		}
	}
	return form, true
}

// apiPrimaryUsers suggests directory people for the primary user field.
func (s *Server) apiPrimaryUsers(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !s.limit.allow("people:"+c.actor(), 120, time.Minute) {
		w.Header().Set("Retry-After", "60")
		problem(w, http.StatusTooManyRequests, "rate limit: 120 searches per minute")
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	cond, args := dirPeopleCond(c.sess(), 1)
	list, err := collect(r.Context(), s.db, pgx.RowTo[string], `SELECT u.email FROM dir_users u WHERE u.active AND strpos(lower(u.email), $1) > 0 AND `+cond+`
		ORDER BY u.email LIMIT 20`, append([]any{q}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: list})
}

// apiDeviceCatalogApps lists the enabled catalog apps for the bulk install
// and removal of the device list (the console list offers the same).
func (s *Server) apiDeviceCatalogApps(w http.ResponseWriter, r *http.Request, c apiCaller) {
	apps, err := s.catalogApps(r.Context(), s.db, `WHERE enabled`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	type app struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	out := []app{}
	for _, a := range apps {
		out = append(out, app{a.ID, a.Name})
	}
	writeJSON(w, listPage{Items: out})
}

// dirPeopleCond limits directory people (alias u) to those the caller may
// see. The directory is installation wide (SCIM and Google sync have no
// tenant), so the global view of an unscoped account sees all of it; an
// account bound to a tenant or a device scope sees only the people who are
// already the primary user of a device in its tenant and scope.
func dirPeopleCond(sess session, n int) (string, []any) {
	if sess.Tenant == 0 && !sess.scoped() {
		return "TRUE", nil
	}
	cond, args := scopeCond(sess, n)
	return `EXISTS (SELECT 1 FROM devices d WHERE d.primary_user_id = u.id AND ` + cond + `)`, args
}

// dirPersonID finds a directory person by email among those the caller may
// see (dirPeopleCond).
func (s *Server) dirPersonID(ctx context.Context, sess session, email string) (int64, error) {
	cond, args := dirPeopleCond(sess, 1)
	var id int64
	err := s.db.QueryRow(ctx, `SELECT u.id FROM dir_users u WHERE u.email=$1 AND `+cond, append([]any{email}, args...)...).Scan(&id)
	return id, err
}

type apiEnrollToken struct {
	ID        string    `json:"id"`
	Note      string    `json:"note"`
	Blueprint string    `json:"blueprint"`
	By        string    `json:"created_by"`
	Uses      int       `json:"uses_left"`
	Expires   time.Time `json:"expires_at"`
}

// enrollInfo is what the add device flow needs besides the token.
type enrollInfo struct {
	Items       []apiEnrollToken `json:"items"`
	AgentURL    string           `json:"agent_url"`
	PublicURL   string           `json:"public_url"`
	Fingerprint string           `json:"fingerprint"`
	Repo        string           `json:"release_repo"`
	Limits      EnrollSettings   `json:"limits"` // defaults and maxima of a new token
}

// apiEnrollTokens lists the active enrollment tokens of the caller's tenant
// with the data of the install command and enroll.conf (tokenPage).
func (s *Server) apiEnrollTokens(w http.ResponseWriter, r *http.Request, c apiCaller) {
	tcond, targs := tenantCond(c.sess(), "t.tenant_id", 0)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[apiEnrollToken], `SELECT encode(t.token_hash, 'hex'), t.note, coalesce(b.name,'default'), t.created_by, t.uses_left, t.expires_at
		FROM enroll_tokens t LEFT JOIN blueprints b ON b.id=t.blueprint_id WHERE t.expires_at > now() AND t.uses_left > 0 AND `+tcond+` ORDER BY t.expires_at`, targs...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if list == nil {
		list = []apiEnrollToken{}
	}
	writeJSON(w, enrollInfo{Items: list, AgentURL: s.cfg.AgentURL, PublicURL: s.cfg.PublicURL, Fingerprint: s.tlsCA().Fingerprint(), Repo: s.cfg.ReleaseRepo,
		Limits: s.settings().Enroll.withDefaults()})
}

// apiEnrollTokenCreate creates a token (createEnrollToken); the answer is
// the only time it is shown.
func (s *Server) apiEnrollTokenCreate(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Note        string `json:"note"`
		BlueprintID int64  `json:"blueprint_id"`
		Uses        int    `json:"uses"`
		Days        int    `json:"days"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	token, err := s.createEnrollToken(r.Context(), c.sess(), body.Note, body.BlueprintID, body.Uses, body.Days)
	var ue *userError
	if errors.As(err, &ue) {
		field := "uses"
		if strings.Contains(ue.Msg, "blueprint") {
			field = "blueprint_id"
		}
		problemField(w, http.StatusUnprocessableEntity, field, ue.Msg)
		return
	} else if err != nil {
		s.apiFail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusCreated, map[string]string{"id": hex.EncodeToString(sha(token)), "token": token})
}

func (s *Server) apiEnrollTokenRevoke(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, err := hex.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != sha256.Size {
		problem(w, http.StatusNotFound, "token not found")
		return
	}
	if err := s.revokeEnrollToken(r.Context(), c.sess(), id); err != nil {
		s.apiActionFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
