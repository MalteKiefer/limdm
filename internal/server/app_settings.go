package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Admin API of the settings area of the console app: server settings,
// console users, tenants, keys, backup, notification channels, directory,
// network certificates, agent updates and the own profile. Every handler
// calls the function the classic console page calls, so roles, tenant
// rules, four eyes approval and audit entries are the same.

func (s *Server) appSettingsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/settings", s.need("audit", s.globalOnly(s.apiSettings)))
	m.HandleFunc("PATCH /api/v1/settings/{section}", s.need("admin", s.globalOnly(s.apiSettingsSave)))

	m.HandleFunc("GET /api/v1/users", s.need("audit", s.apiUsers))
	m.HandleFunc("POST /api/v1/users", s.need("admin", s.apiUserAdd))
	m.HandleFunc("PATCH /api/v1/users/{login}", s.need("admin", s.apiUserUpdate))
	m.HandleFunc("POST /api/v1/users/{login}/reset", s.need("admin", s.apiUserReset))

	m.HandleFunc("POST /api/v1/tenants/switch", s.need("read", s.apiTenantSwitch))
	m.HandleFunc("GET /api/v1/tenants/shared", s.need("admin", s.superAPI(s.apiTenantShared)))
	m.HandleFunc("PUT /api/v1/tenants/shared", s.need("admin", s.superAPI(s.apiTenantSharedSave)))
	m.HandleFunc("GET /api/v1/tenants/{id}", s.need("admin", s.apiTenantGet))
	m.HandleFunc("PATCH /api/v1/tenants/{id}", s.need("admin", s.apiTenantSave))

	m.HandleFunc("GET /api/v1/keys", s.need("admin", s.apiKeys))
	m.HandleFunc("POST /api/v1/keys/{kind}/{op}", s.need("admin", s.apiKeyAction))

	m.HandleFunc("GET /api/v1/backup", s.need("admin", s.apiBackup))
	m.HandleFunc("PUT /api/v1/backup", s.need("admin", s.apiBackupSave))
	m.HandleFunc("POST /api/v1/backup/run", s.need("admin", s.apiBackupRun))
	m.HandleFunc("POST /api/v1/backup/{id}/verify", s.need("admin", s.apiBackupVerify))
	m.HandleFunc("PUT /api/v1/backup/targets/{name}", s.need("admin", s.apiTargetSave))
	m.HandleFunc("DELETE /api/v1/backup/targets/{name}", s.need("admin", s.apiTargetDelete))
	m.HandleFunc("POST /api/v1/backup/targets/{name}/test", s.need("admin", s.apiTargetTest))
	m.HandleFunc("POST /api/v1/backup/schedules/preview", s.need("admin", s.apiSchedulePreview))
	m.HandleFunc("PUT /api/v1/backup/schedules/{name}", s.need("admin", s.apiScheduleSave))
	m.HandleFunc("DELETE /api/v1/backup/schedules/{name}", s.need("admin", s.apiScheduleOp))
	m.HandleFunc("POST /api/v1/backup/schedules/{name}/{op}", s.need("admin", s.apiScheduleOp))

	m.HandleFunc("GET /api/v1/notification-channels", s.need("audit", s.apiChannels))
	m.HandleFunc("POST /api/v1/notification-channels", s.need("admin", s.apiChannelAdd))
	m.HandleFunc("PATCH /api/v1/notification-channels/{id}", s.need("admin", s.apiChannelSet))
	m.HandleFunc("DELETE /api/v1/notification-channels/{id}", s.need("admin", s.apiChannelSet))
	m.HandleFunc("POST /api/v1/notification-channels/{id}/test", s.need("admin", s.apiChannelTest))

	m.HandleFunc("GET /api/v1/directory", s.need("audit", s.globalOnly(s.apiDirectory)))
	m.HandleFunc("GET /api/v1/directory/users", s.need("audit", s.globalOnly(s.apiDirectoryUsers)))
	m.HandleFunc("PUT /api/v1/directory/groups/{id}", s.need("admin", s.globalOnly(s.apiGroupAssign)))
	m.HandleFunc("POST /api/v1/directory/scim-token", s.need("admin", s.globalOnly(s.apiSCIMToken)))
	m.HandleFunc("PUT /api/v1/directory/google", s.need("admin", s.globalOnly(s.apiGoogleSave)))
	m.HandleFunc("POST /api/v1/directory/google/sync", s.need("admin", s.globalOnly(s.apiGoogleSync)))

	m.HandleFunc("GET /api/v1/network", s.need("audit", s.apiNetwork))
	m.HandleFunc("POST /api/v1/network/crl-token", s.need("admin", s.globalOnly(s.apiCRLToken)))

	m.HandleFunc("GET /api/v1/agents", s.need("audit", s.globalOnly(s.apiAgents)))
	m.HandleFunc("PUT /api/v1/agents/policy", s.need("admin", s.globalOnly(s.apiAgentPolicy)))
	m.HandleFunc("POST /api/v1/agents/fetch", s.need("admin", s.globalOnly(s.apiAgentFetch)))
	m.HandleFunc("POST /api/v1/agents/releases/{version}/{op}", s.need("admin", s.globalOnly(s.apiAgentRelease)))

	m.HandleFunc("GET /api/v1/glossary", s.need("read", s.apiGlossary))
	m.HandleFunc("GET /api/v1/profile", s.need("read", s.sessionOnly(s.apiProfile)))
	m.HandleFunc("POST /api/v1/profile/password", s.need("self", s.sessionOnly(s.apiProfilePassword)))
	m.HandleFunc("GET /api/v1/profile/totp/qr.svg", s.need("read", s.sessionOnly(s.apiProfileQR)))
	m.HandleFunc("POST /api/v1/profile/totp/{step}", s.need("self", s.sessionOnly(s.apiProfileTOTP)))
	m.HandleFunc("POST /api/v1/profile/recovery-codes", s.need("self", s.sessionOnly(s.apiProfileRecovery)))
}

// globalOnly refuses accounts and tokens bound to one tenant or limited
// to a device scope, as the console's global pages do (tenantRoutes,
// unscoped).
func (s *Server) globalOnly(h apiHandlerFunc) apiHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c apiCaller) {
		if sess := c.sess(); sess.TenantOnly() || sess.scoped() {
			s.deny(w, r, c, "only for accounts of the whole installation")
			return
		}
		h(w, r, c)
	}
}

// sessionOnly limits a route to console sessions (the own profile).
func (s *Server) sessionOnly(h apiHandlerFunc) apiHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, c apiCaller) {
		if c.Sess == nil {
			s.deny(w, r, c, "only for console sessions")
			return
		}
		h(w, r, c)
	}
}

// accepted answers a request that waits for four eyes approval.
func accepted(w http.ResponseWriter, id int64) {
	w.Header().Set("Location", "/api/v1/approvals/"+strconv.FormatInt(id, 10))
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"approval_id": id, "status": "pending"})
}

// ---- settings ----

type apiRetentionKind struct {
	Key     string `json:"key"`
	Days    int    `json:"days"`
	Default int    `json:"default"`
	Min     int    `json:"min"`
	Max     int    `json:"max"`
	Forever bool   `json:"forever"`
}

// apiSettingsView is the settings document of GET /api/v1/settings: the
// stored settings without secrets, plus what the forms show next to them.
type apiSettingsView struct {
	Settings
	HasOIDCSecret  bool               `json:"has_oidc_secret"`
	HasLogo        bool               `json:"has_logo"`
	PublicURL      string             `json:"public_url"`
	RedirectURI    string             `json:"redirect_uri"`
	ClientIP       string             `json:"client_ip"`
	WebhookSecret  string             `json:"webhook_secret,omitempty"` // admins only
	RetentionKinds []apiRetentionKind `json:"retention_kinds"`
}

func (s *Server) settingsView(r *http.Request, c apiCaller, set Settings) apiSettingsView {
	v := apiSettingsView{Settings: set, HasOIDCSecret: set.OIDCClientSecret != "", HasLogo: len(set.Logo) > 0,
		PublicURL: s.cfg.PublicURL, RedirectURI: s.cfg.PublicURL + "/auth/callback", ClientIP: clientIP(r)}
	v.Logo = nil
	v.Ops = v.Ops.withDefaults()
	v.Enroll = v.Enroll.withDefaults()
	for _, row := range retentionRows(set) {
		v.RetentionKinds = append(v.RetentionKinds, apiRetentionKind{row.Key, row.Days, row.Default, row.Min, row.Max, row.Forever})
	}
	if c.can("admin") {
		v.WebhookSecret = hex.EncodeToString(s.whKey)
	}
	return v
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request, c apiCaller) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, s.settingsView(r, c, s.settings()))
}

// apiSettingsSave changes one section. The body holds the fields of the
// section with the names of GET /api/v1/settings; fields left out keep
// their value. oidc_client_secret sets a new secret, clear_secret removes
// it, logo_png (base64 PNG) replaces the logo, remove_logo removes it.
func (s *Server) apiSettingsSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	in := s.settings()
	body := struct {
		*Settings
		OIDCClientSecret string `json:"oidc_client_secret"`
		ClearSecret      bool   `json:"clear_secret"`
		RemoveLogo       bool   `json:"remove_logo"`
	}{Settings: &in}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.OIDCClientSecret != "" {
		in.OIDCClientSecret = body.OIDCClientSecret
	}
	if body.ClearSecret {
		in.OIDCClientSecret = ""
	}
	if body.RemoveLogo {
		in.Logo = nil
	}
	set, err := s.saveSettings(r.Context(), c.sess(), clientIP(r), r.PathValue("section"), in)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, s.settingsView(r, c, set))
}

// ---- console users ----

type apiUser struct {
	Login       string     `json:"login"` // local accounts: local:name
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	Local       bool       `json:"local"`
	LastLogin   *time.Time `json:"last_login"`
	ScopeTags   []string   `json:"scope_tags"`
	ScopeGroups []string   `json:"scope_groups"`
	FromGroup   bool       `json:"from_group"`
	Tenant      string     `json:"tenant"`
	Self        bool       `json:"self"`
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request, c apiCaller) {
	sess := c.sess()
	list, err := s.consoleUsers(r.Context(), sess)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := make([]apiUser, len(list))
	for i, u := range list {
		login := u.Login
		if u.Local {
			login = localPrefix + u.Login
		}
		out[i] = apiUser{login, u.Role, u.Disabled, u.Local, u.LastLogin, nonNil(u.Tags), nonNil(u.Groups), u.FromGroup, u.Tenant, login == sess.Email}
	}
	writeJSON(w, map[string]any{"items": out, "local_login": s.settings().LocalLogin, "oidc": s.oidc() != nil, "four_eyes": s.settings().FourEyes})
}

// userResult answers an added or reset account: new local credentials
// (shown once), or 202 with the approval it waits for.
func userResult(w http.ResponseWriter, status int, creds string, approval int64) {
	if approval != 0 {
		accepted(w, approval)
		return
	}
	writeJSONStatus(w, status, map[string]string{"credentials": creds})
}

func (s *Server) apiUserAdd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		userAddition
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	body.Tenant = nil // always the caller's tenant
	creds, approval, err := s.addUser(r.Context(), c.sess(), body.userAddition, body.Reason)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	userResult(w, http.StatusCreated, creds, approval)
}

func (s *Server) apiUserUpdate(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Role        string   `json:"role"`
		Disabled    bool     `json:"disabled"`
		ScopeTags   []string `json:"scope_tags"`
		ScopeGroups []string `json:"scope_groups"`
		Reason      string   `json:"reason"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ch := userChange{Role: body.Role, Disabled: body.Disabled}
	var err error
	if ch.Tags, err = parseTags(strings.Join(body.ScopeTags, ",")); err != nil {
		s.apiFail(w, invalid("scope_tags", err))
		return
	}
	if ch.Groups, err = parseScopeGroups(strings.Join(body.ScopeGroups, ",")); err != nil {
		s.apiFail(w, invalid("scope_groups", err))
		return
	}
	approval, err := s.updateUser(r.Context(), c.sess(), r.PathValue("login"), ch, body.Reason)
	switch {
	case err != nil:
		s.apiFail(w, err)
	case approval != 0:
		accepted(w, approval)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) apiUserReset(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &body) {
		return
	}
	creds, approval, err := s.resetUser(r.Context(), c.sess(), r.PathValue("login"), body.Reason)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	userResult(w, http.StatusOK, creds, approval)
}

// ---- tenants ----

// apiTenantSwitch sets the tenant view of a super admin's session (0: all
// tenants), with the rules of the console's switch, and audits it.
func (s *Server) apiTenantSwitch(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if c.Sess == nil || !c.Sess.Super || !s.cfg.MultiTenant {
		s.deny(w, r, c, "only global administrators switch the tenant view")
		return
	}
	var body struct {
		Tenant int64 `json:"tenant"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Tenant != 0 {
		var ok bool
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1 AND NOT disabled)`, body.Tenant).Scan(&ok); err != nil {
			s.apiFail(w, err)
			return
		}
		if !ok {
			problem(w, http.StatusNotFound, "tenant not found")
			return
		}
	}
	if err := s.auditAction(r.Context(), c.actor(), "tenant.switch", strconv.FormatInt(body.Tenant, 10), "", nil); err != nil {
		s.apiFail(w, err)
		return
	}
	sess := *c.Sess
	sess.Tenant = body.Tenant
	s.setCookie(w, sessionCookie, s.seal(sess), maxSession-time.Since(sess.IAT))
	w.WriteHeader(http.StatusNoContent)
}

type apiSharedObject struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Shared bool   `json:"shared"`
}

func (s *Server) apiTenantShared(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	bps, err := collect(ctx, s.db, pgx.RowToStructByPos[apiSharedObject], `SELECT id, name, '', shared FROM blueprints WHERE tenant_id=1 ORDER BY name`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	items, err := collect(ctx, s.db, pgx.RowToStructByPos[apiSharedObject], `SELECT id, name, type, shared FROM library_items WHERE tenant_id=1 ORDER BY type, name`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"blueprints": bps, "items": items})
}

func (s *Server) apiTenantSharedSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Blueprints []int64 `json:"blueprints"`
		Items      []int64 `json:"items"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.setShared(r.Context(), c.sess(), nonNilIDs(body.Blueprints), nonNilIDs(body.Items)); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type apiTenantDetail struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Disabled    bool      `json:"disabled"`
	CompanyName string    `json:"company_name"`
	Color       string    `json:"color"`
	HasLogo     bool      `json:"has_logo"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) apiTenantGet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, err := s.loadTenantFor(r.Context(), c.sess(), id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, apiTenantDetail{t.ID, t.Name, t.Disabled, t.CompanyName, t.Color, t.HasLogo, t.CreatedAt})
}

// apiTenantSave changes a tenant: name and state (super admins), branding
// (also the tenant's own admins). Fields left out keep their value.
func (s *Server) apiTenantSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sess := c.sess()
	t, err := s.loadTenantFor(r.Context(), sess, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	in := t
	body := struct {
		Name        *string `json:"name"`
		Disabled    *bool   `json:"disabled"`
		CompanyName *string `json:"company_name"`
		Color       *string `json:"color"`
		Logo        []byte  `json:"logo_png"`
		RemoveLogo  bool    `json:"remove_logo"`
	}{Name: &in.Name, Disabled: &in.Disabled, CompanyName: &in.CompanyName, Color: &in.Color}
	if !decodeJSON(w, r, &body) {
		return
	}
	keep := body.Logo == nil && !body.RemoveLogo
	if err := s.updateTenant(r.Context(), sess, t, in, body.Logo, keep); err != nil {
		s.apiFail(w, err)
		return
	}
	t, err = s.loadTenantFor(r.Context(), sess, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, apiTenantDetail{t.ID, t.Name, t.Disabled, t.CompanyName, t.Color, t.HasLogo, t.CreatedAt})
}

// ---- keys ----

type apiKey struct {
	Kind     string     `json:"kind"`
	Active   string     `json:"active"`
	Previous string     `json:"previous"`
	Since    *time.Time `json:"since"`
	Done     int        `json:"done"`
	Total    int        `json:"total"`
	Restart  bool       `json:"restart"`
	Location string     `json:"location"`
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !keysAllowed(c.sess()) {
		s.deny(w, r, c, "only administrators of the whole installation manage keys")
		return
	}
	list, err := s.KeysStatus(r.Context())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := make([]apiKey, len(list))
	for i, k := range list {
		out[i] = apiKey{Kind: k.Kind, Active: k.Active, Previous: k.Previous, Done: k.Done, Total: k.Total, Restart: k.Restart, Location: k.Location}
		if !k.Since.IsZero() {
			out[i].Since = &list[i].Since
		}
	}
	writeJSON(w, listPage{Items: out})
}

// apiKeyAction starts (rotate) or ends (finish) a key rotation, as the
// keys card of the console settings does.
func (s *Server) apiKeyAction(w http.ResponseWriter, r *http.Request, c apiCaller) {
	sess := c.sess()
	if !keysAllowed(sess) {
		s.deny(w, r, c, "only administrators of the whole installation manage keys")
		return
	}
	var body struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &body) {
		return
	}
	kind, op := r.PathValue("kind"), r.PathValue("op")
	var msg string
	var err error
	switch {
	case kind == kindSession && op == "rotate":
		err = &userError{http.StatusUnprocessableEntity, "a new session key is generated on the server: limdm-server keys rotate session"}
	case op == "rotate":
		msg, err = s.RotateKey(r.Context(), sess.Email, kind, strings.TrimSpace(body.Name))
	case op == "finish":
		msg, err = s.FinishKey(r.Context(), sess.Email, kind, body.Force)
	default:
		problem(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		if code, _ := errStatus(err); code == 0 && !overloaded(err) {
			err = &userError{http.StatusUnprocessableEntity, err.Error()} // rotation steps explain refusals in their errors
		}
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]string{"message": msg})
}

// ---- backup ----

type apiTarget struct {
	StoreTarget
	HasSecret bool `json:"has_secret"`
	HasKey    bool `json:"has_key"`
}

type apiRetentionPreview struct {
	Runs   int         `json:"runs"`
	Kept   int         `json:"kept"`
	Oldest *time.Time  `json:"oldest"`
	Dates  []time.Time `json:"dates"`
}

type apiSchedule struct {
	BackupSchedule
	Next    []time.Time         `json:"next"`
	Preview apiRetentionPreview `json:"preview"`
}

func scheduleOut(sc BackupSchedule, now time.Time, loc *time.Location) apiSchedule {
	p := sc.preview(now, loc)
	out := apiSchedule{BackupSchedule: sc, Next: sc.nextRuns(now, loc, 5), Preview: apiRetentionPreview{Runs: p.Runs, Kept: p.Kept, Dates: p.Dates}}
	if !p.Oldest.IsZero() {
		out.Preview.Oldest = &p.Oldest
	}
	out.Next, out.Preview.Dates = nonNilTimes(out.Next), nonNilTimes(out.Preview.Dates)
	if out.Targets == nil {
		out.Targets = []string{}
	}
	return out
}

func nonNilTimes(v []time.Time) []time.Time {
	if v == nil {
		return []time.Time{}
	}
	return v
}

type apiBackupRow struct {
	ID               int64      `json:"id"`
	Name             string     `json:"name"`
	Reason           string     `json:"reason"`
	Actor            string     `json:"actor"`
	StartedAt        time.Time  `json:"started_at"`
	Size             int64      `json:"size"`
	SHA256           string     `json:"sha256"`
	Targets          []string   `json:"targets"`
	Status           string     `json:"status"`
	Error            string     `json:"error"`
	VerifiedAt       *time.Time `json:"verified_at"`
	VerifyError      string     `json:"verify_error"`
	RestoreTestedAt  *time.Time `json:"restore_tested_at"`
	RestoreTestError string     `json:"restore_test_error"`
	DeletedAt        *time.Time `json:"deleted_at"`
}

func (s *Server) apiBackup(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !backupAdmin(c.sess()) {
		s.apiFail(w, errBackupAdmin)
		return
	}
	ctx := r.Context()
	cfg, err := s.backupConfig(ctx, s.db)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	loc, now := cfg.location(), time.Now()
	targets := []apiTarget{}
	offsite, locked := false, false
	for _, t := range cfg.Targets {
		offsite = offsite || t.Kind != "local"
		locked = locked || t.LockMode != ""
		out := apiTarget{StoreTarget: t, HasSecret: t.SecretEnc != "", HasKey: t.KeyEnc != ""}
		out.SecretEnc, out.KeyEnc = "", ""
		targets = append(targets, out)
	}
	scheds := []apiSchedule{}
	for _, sc := range cfg.Schedules {
		scheds = append(scheds, scheduleOut(sc, now, loc))
	}
	history, err := collect(ctx, s.db, pgx.RowToStructByPos[apiBackupRow], `SELECT id, name, reason, actor, started_at, size, sha256, targets, status, error,
		verified_at, verify_error, restore_tested_at, restore_test_error, deleted_at FROM backups ORDER BY started_at DESC LIMIT 50`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"recipients": nonNil(cfg.Recipients), "time_zone": cfg.TimeZone, "zone": loc.String(), "keep": cfg.Keep,
		"targets": targets, "schedules": scheds, "history": history, "offsite": offsite, "locked": locked,
		"rule_321": len(cfg.Targets) >= 2 && offsite && locked})
}

func (s *Server) apiBackupSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Recipients []string `json:"recipients"`
		TimeZone   string   `json:"time_zone"`
		Keep       KeepRule `json:"keep"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	s.apiDone(w, s.saveBackupGeneral(r.Context(), c.sess(), body.Recipients, body.TimeZone, body.Keep))
}

// apiDone answers a change without a body: 204 or the error.
func (s *Server) apiDone(w http.ResponseWriter, err error) {
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiBackupRun(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if err := s.startBackup(c.sess(), ""); err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) apiBackupVerify(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !backupAdmin(c.sess()) {
		s.apiFail(w, errBackupAdmin)
		return
	}
	if err := s.verifyStored(r.Context(), id, c.actor()); err != nil {
		if code, _ := errStatus(err); code == 0 && !overloaded(err) {
			err = &userError{http.StatusUnprocessableEntity, err.Error()} // verification results explain themselves
		}
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiTargetSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in targetInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = r.PathValue("name")
	s.apiDone(w, s.saveTarget(r.Context(), c.sess(), in))
}

func (s *Server) apiTargetDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	s.apiDone(w, s.deleteTarget(r.Context(), c.sess(), r.PathValue("name")))
}

func (s *Server) apiTargetTest(w http.ResponseWriter, r *http.Request, c apiCaller) {
	note, err := s.testTarget(r.Context(), c.sess(), r.PathValue("name"))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]string{"message": note})
}

// apiSchedulePreview validates a schedule and shows its next runs and the
// archives its retention keeps, without saving it.
func (s *Server) apiSchedulePreview(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !backupAdmin(c.sess()) {
		s.apiFail(w, errBackupAdmin)
		return
	}
	var sc BackupSchedule
	if !decodeJSON(w, r, &sc) {
		return
	}
	cfg, err := s.backupConfig(r.Context(), s.db)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	sc.Name = strings.ToLower(strings.TrimSpace(sc.Name))
	sc.Cron = strings.Join(strings.Fields(sc.Cron), " ")
	if err := sc.validate(cfg.Targets); err != nil {
		s.apiFail(w, invalid("schedule", err))
		return
	}
	writeJSON(w, scheduleOut(sc, time.Now(), cfg.location()))
}

func (s *Server) apiScheduleSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var sc BackupSchedule
	if !decodeJSON(w, r, &sc) {
		return
	}
	sc.Name = r.PathValue("name")
	s.apiDone(w, s.saveSchedule(r.Context(), c.sess(), sc))
}

// apiScheduleOp runs, pauses, resumes (POST .../{op}) or deletes (DELETE) a schedule.
func (s *Server) apiScheduleOp(w http.ResponseWriter, r *http.Request, c apiCaller) {
	op := r.PathValue("op")
	if r.Method == http.MethodDelete {
		op = "delete"
	} else if op == "delete" {
		problem(w, http.StatusNotFound, "not found")
		return
	}
	err := s.scheduleOp(r.Context(), c.sess(), r.PathValue("name"), op)
	if err == nil && op == "run" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	s.apiDone(w, err)
}

// ---- notification channels ----

type apiChannel struct {
	ID        int64         `json:"id"`
	Name      string        `json:"name"`
	Kind      string        `json:"kind"`
	Target    string        `json:"target"`
	Events    []string      `json:"events"`
	Enabled   bool          `json:"enabled"`
	Global    bool          `json:"global"`
	Config    channelConfig `json:"config"`
	LastOK    *bool         `json:"last_ok"`
	LastError string        `json:"last_error"`
	LastEvent string        `json:"last_event"`
	LastAt    *time.Time    `json:"last_at"`
}

type apiEventType struct {
	Type  string `json:"type"`
	Label string `json:"label"`
}

func (s *Server) apiChannels(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	views, err := s.channelViews(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	chans, err := s.loadChannels(ctx, false)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := []apiChannel{}
	for _, v := range views {
		i := slices.IndexFunc(chans, func(ch channel) bool { return ch.ID == v.ID })
		if i < 0 {
			continue
		}
		ch := chans[i]
		out = append(out, apiChannel{ID: v.ID, Name: v.Name, Kind: v.Kind, Target: v.Target, Events: nonNil(ch.Events), Enabled: v.Enabled,
			Global: ch.Tenant == nil, Config: ch.Config, LastOK: v.LastOK, LastError: v.LastError, LastEvent: v.LastEv, LastAt: v.LastAt})
	}
	events := make([]apiEventType, len(notifyEvents))
	for i, e := range notifyEvents {
		events[i] = apiEventType{e.Type, e.Label}
	}
	res := map[string]any{"items": out, "events": events, "notify_private": s.settings().NotifyPrivate}
	if t := ctxTenant(ctx); t != 0 && c.can("admin") { // signing key of this tenant's webhook channels
		res["tenant_signing_key"] = hex.EncodeToString(s.tenantWebhookKey(t))
		res["tenant_id"] = t
	}
	writeJSON(w, res)
}

func (s *Server) apiChannelAdd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Name     string        `json:"name"`
		Kind     string        `json:"kind"`
		Events   []string      `json:"events"`
		URL      string        `json:"url"`
		Password string        `json:"password"`
		Config   channelConfig `json:"config"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ch := channel{Name: body.Name, Kind: body.Kind, Events: body.Events, Config: body.Config, Secret: body.URL}
	if ch.Kind == "email" {
		ch.Secret = body.Password
	}
	id, err := s.addChannel(r.Context(), c.sess(), ch)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]int64{"id": id})
}

// apiChannelSet switches a channel on or off (PATCH {"enabled": bool}) or deletes it.
func (s *Server) apiChannelSet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	op := "delete"
	if r.Method == http.MethodPatch {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Enabled == nil {
			problemField(w, http.StatusUnprocessableEntity, "enabled", "enabled: true or false")
			return
		}
		op = map[bool]string{true: "enable", false: "disable"}[*body.Enabled]
	}
	s.apiDone(w, s.setChannel(r.Context(), c.sess(), id, op))
}

func (s *Server) apiChannelTest(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.apiDone(w, s.testChannel(r.Context(), c.sess(), id))
}

// ---- directory ----

type apiDirGroup struct {
	ID         int64  `json:"id"`
	ExternalID string `json:"external_id"`
	Source     string `json:"source"`
	Name       string `json:"name"`
	Members    int    `json:"members"`
	Blueprint  *int64 `json:"blueprint_id"`
	Priority   *int   `json:"priority"`
}

func (s *Server) apiDirectory(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	groups, err := s.dirGroups(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := make([]apiDirGroup, len(groups))
	for i, g := range groups {
		out[i] = apiDirGroup(g)
	}
	gs, err := s.googleSettings(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	var scimSet bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='scim')`).Scan(&scimSet); err != nil {
		s.apiFail(w, err)
		return
	}
	google := map[string]any{"admin_email": gs.AdminEmail, "configured": gs.KeyEnc != "", "last_result": gs.LastResult, "last_sync": nil}
	if !gs.LastSync.IsZero() {
		google["last_sync"] = gs.LastSync
	}
	writeJSON(w, map[string]any{"groups": out, "google": google, "scim": map[string]any{"configured": scimSet, "url": s.scimBase()},
		"role_groups": nonNilGroups(s.settings().RoleGroups)})
}

func nonNilGroups(v []RoleGroup) []RoleGroup {
	if v == nil {
		return []RoleGroup{}
	}
	return v
}

type apiDirUser struct {
	ID          int64     `json:"id"`
	ExternalID  string    `json:"external_id"`
	Source      string    `json:"source"`
	UserName    string    `json:"user_name"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Department  string    `json:"department"`
	Title       string    `json:"title"`
	Active      bool      `json:"active"`
	Groups      []string  `json:"groups"`
	GroupIDs    []int64   `json:"group_ids"`
	Updated     time.Time `json:"updated_at"`
}

// apiDirectoryUsers lists people of the directory, filtered by q (name,
// email, department), at most 500 as on the console page.
func (s *Server) apiDirectoryUsers(w http.ResponseWriter, r *http.Request, c apiCaller) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[apiDirUser], `SELECT `+dirUserCols+` FROM dir_users u
		WHERE $1 = '' OR lower(u.email || ' ' || u.display_name || ' ' || u.department) LIKE '%' || $1 || '%'
		ORDER BY u.active DESC, u.display_name, u.email LIMIT 500`, q)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for i := range list {
		list[i].Groups, list[i].GroupIDs = nonNil(list[i].Groups), nonNilIDs(list[i].GroupIDs)
	}
	writeJSON(w, listPage{Items: list})
}

func (s *Server) apiGroupAssign(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Blueprint int64 `json:"blueprint_id"`
		Priority  *int  `json:"priority"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	prio := 100
	if body.Priority != nil {
		prio = *body.Priority
	}
	if prio < 0 || prio > 10000 {
		problemField(w, http.StatusUnprocessableEntity, "priority", "priority: 0 to 10000")
		return
	}
	s.apiDone(w, s.assignGroup(r.Context(), c.sess(), id, body.Blueprint, prio))
}

func (s *Server) apiSCIMToken(w http.ResponseWriter, r *http.Request, c apiCaller) {
	tok, err := s.rotateSCIMToken(r.Context(), c.sess())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]string{"token": tok, "url": s.scimBase()})
}

func (s *Server) apiGoogleSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		AdminEmail     string `json:"admin_email"`
		ServiceAccount string `json:"service_account"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.configureGoogle(r.Context(), c.sess(), body.AdminEmail, body.ServiceAccount); err != nil {
		s.apiFail(w, err)
		return
	}
	s.apiGoogleSync(w, r, c)
}

func (s *Server) apiGoogleSync(w http.ResponseWriter, r *http.Request, c apiCaller) {
	res, err := s.syncGoogle(r.Context())
	if err != nil {
		s.apiFail(w, &userError{http.StatusBadGateway, "Google sync failed: " + err.Error()})
		return
	}
	writeJSON(w, map[string]string{"message": res})
}

// ---- network certificates ----

type apiNetworkCert struct {
	Serial    string     `json:"serial"`
	DeviceID  string     `json:"device_id"`
	Hostname  string     `json:"hostname"`
	Subject   string     `json:"subject"`
	SANs      string     `json:"sans"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	RevokedAt *time.Time `json:"revoked_at"`
	Reason    string     `json:"reason"`
	State     string     `json:"state"`
}

func (s *Server) apiNetwork(w http.ResponseWriter, r *http.Request, c apiCaller) {
	sess := c.sess()
	if sess.scoped() {
		s.deny(w, r, c, "only for accounts without a device scope")
		return
	}
	ctx := r.Context()
	certs, err := s.networkCerts(ctx, "")
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := make([]apiNetworkCert, len(certs))
	for i, x := range certs {
		out[i] = apiNetworkCert{x.Serial, x.DeviceID, x.Hostname, x.Subject, x.SANs, x.NotBefore, x.NotAfter, x.RevokedAt, x.Reason, x.State()}
	}
	var tokenSet bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='network_crl')`).Scan(&tokenSet); err != nil {
		s.apiFail(w, err)
		return
	}
	sum := sha256.Sum256(s.netCA.cert.Raw)
	writeJSON(w, map[string]any{"certs": out, "crl_token_set": tokenSet, "crl_url": strings.TrimSuffix(s.cfg.PublicURL, "/") + "/network/crl.pem",
		"ca_url": "/network/ca.pem", "ca_fingerprint": hex.EncodeToString(sum[:]), "ca_subject": s.netCA.cert.Subject.String(), "ca_not_after": s.netCA.cert.NotAfter})
}

func (s *Server) apiCRLToken(w http.ResponseWriter, r *http.Request, c apiCaller) {
	tok, err := s.rotateCRLToken(r.Context(), c.sess())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]string{"token": tok})
}

// ---- agent updates ----

type apiRelease struct {
	Version       string     `json:"version"`
	PublishedAt   time.Time  `json:"published_at"`
	Signed        bool       `json:"signed"`
	ApprovedAt    *time.Time `json:"approved_at"`
	ApprovedBy    *string    `json:"approved_by"`
	Blocked       bool       `json:"blocked"`
	BlockedReason string     `json:"blocked_reason"`
	Devices       int        `json:"devices"`
	Failed        int        `json:"failed"`
	Older         bool       `json:"older"` // hidden on the console page until "show older"
}

func (s *Server) apiAgents(w http.ResponseWriter, r *http.Request, c apiCaller) {
	v, err := s.agentsOverview(r.Context())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	_, older := splitOlder(v.Releases, v.Fleet)
	rels := make([]apiRelease, len(v.Releases))
	for i, x := range v.Releases {
		rels[i] = apiRelease{x.Version, x.PublishedAt, x.SumsSig != "", x.ApprovedAt, x.ApprovedBy, x.Blocked, x.BlockedReason, x.Devices, x.Failed,
			slices.ContainsFunc(older, func(o releaseView) bool { return o.Version == x.Version })}
	}
	type fleet struct {
		Version string `json:"version"`
		Devices int    `json:"devices"`
	}
	fl := make([]fleet, len(v.Fleet))
	for i, f := range v.Fleet {
		fl[i] = fleet{f.Version, f.N}
	}
	type outdated struct {
		ID       string     `json:"id"`
		Hostname string     `json:"hostname"`
		Version  string     `json:"version"`
		LastSeen *time.Time `json:"last_seen"`
	}
	od := make([]outdated, len(v.Outdated))
	for i, d := range v.Outdated {
		od[i] = outdated(d)
	}
	writeJSON(w, map[string]any{"policy": v.Policy, "releases": rels, "fleet": fl, "latest": v.Latest, "outdated": od, "repo": s.cfg.ReleaseRepo})
}

func (s *Server) apiAgentPolicy(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var pol UpdatePolicy
	if !decodeJSON(w, r, &pol) {
		return
	}
	s.apiDone(w, s.saveUpdatePolicy(r.Context(), c.sess(), pol))
}

func (s *Server) apiAgentFetch(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	n, err := s.fetchReleases(ctx)
	if err != nil {
		s.log.Warn("agent releases", "err", err)
		s.apiFail(w, &userError{http.StatusBadGateway, "Fetching the releases failed, see the server log."})
		return
	}
	writeJSON(w, map[string]int{"fetched": n})
}

func (s *Server) apiAgentRelease(w http.ResponseWriter, r *http.Request, c apiCaller) {
	s.apiDone(w, s.releaseOp(r.Context(), c.sess(), r.PathValue("version"), r.PathValue("op")))
}

// ---- help ----

// apiGlossary serves the console glossary and the device states in the
// language of lang (de or en; else the request's language), sorted by term.
func (s *Server) apiGlossary(w http.ResponseWriter, r *http.Request, c apiCaller) {
	lang := r.URL.Query().Get("lang")
	if lang != "de" && lang != "en" {
		lang = requestLang(r)
	}
	type term struct {
		ID   string `json:"id"`
		Term string `json:"term"`
		Text string `json:"text"`
		Doc  string `json:"doc,omitempty"`
	}
	terms := make([]term, 0, len(glossary))
	for _, g := range glossary {
		e := term{ID: strings.ReplaceAll(strings.ToLower(g.Term), " ", "-"), Term: translate(lang, g.Term), Text: translate(lang, g.Text)}
		if g.Doc != "" {
			e.Doc = docsURL + g.Doc
		}
		terms = append(terms, e)
	}
	slices.SortStableFunc(terms, func(a, b term) int { return strings.Compare(strings.ToLower(a.Term), strings.ToLower(b.Term)) })
	states := map[string]string{}
	for k, v := range statusHelp {
		states[k] = translate(lang, v)
	}
	w.Header().Set("Cache-Control", "private, max-age=300")
	writeJSON(w, map[string]any{"terms": terms, "states": states, "docs": docsURL})
}

// ---- own profile ----

func (s *Server) apiProfile(w http.ResponseWriter, r *http.Request, c apiCaller) {
	sess := *c.Sess
	out := map[string]any{"login": sess.Email, "role": sess.Role, "local": false, "password_min": s.settings().Rules.Min(),
		"password_rules": s.settings().Rules, "recovery_left": 0, "totp_pending": false}
	if name, err := profileName(sess); err == nil {
		var left int
		var pending *string
		if err := s.db.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM local_recovery_codes WHERE name=$1 AND used_at IS NULL), totp_pending
			FROM local_admins WHERE name=$1`, name).Scan(&left, &pending); err != nil {
			s.apiFail(w, err)
			return
		}
		out["local"], out["name"], out["recovery_left"], out["totp_pending"] = true, name, left, pending != nil
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}

func (s *Server) apiProfilePassword(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
		Repeat  string `json:"repeat"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.changePassword(r.Context(), *c.Sess, clientIP(r), body.Current, body.New, body.Repeat); err != nil {
		s.apiFail(w, err)
		return
	}
	s.renewSession(w, r, *c.Sess) // other sessions of this account end
	w.WriteHeader(http.StatusNoContent)
}

// apiProfileTOTP starts (answers the pending secret and its otpauth URI),
// confirms or cancels a new authenticator app.
func (s *Server) apiProfileTOTP(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Current string `json:"current"`
		Code    string `json:"code"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &body) {
		return
	}
	ctx, sess := r.Context(), *c.Sess
	switch r.PathValue("step") {
	case "start":
		secret, err := s.startTOTP(ctx, sess, clientIP(r), body.Current)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		name, _ := profileName(sess)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"secret": secret, "uri": totpURI(name, secret)})
	case "confirm":
		if err := s.confirmTOTP(ctx, sess, body.Code); err != nil {
			s.apiFail(w, err)
			return
		}
		s.renewSession(w, r, sess)
		w.WriteHeader(http.StatusNoContent)
	case "cancel":
		s.apiDone(w, s.cancelTOTP(ctx, sess))
	default:
		problem(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) apiProfileRecovery(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Current string `json:"current"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	codes, err := s.newRecoveryCodes(r.Context(), *c.Sess, clientIP(r), body.Current)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"codes": codes})
}

// apiProfileQR draws the pending authenticator secret as a QR code (an
// image, so the page needs no inline markup).
func (s *Server) apiProfileQR(w http.ResponseWriter, r *http.Request, c apiCaller) {
	name, err := profileName(*c.Sess)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	var pending *string
	if err := s.db.QueryRow(r.Context(), `SELECT totp_pending FROM local_admins WHERE name=$1`, name).Scan(&pending); err != nil {
		s.apiFail(w, err)
		return
	}
	if pending == nil {
		problem(w, http.StatusNotFound, "no new secret pending")
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(qrSVG(totpURI(name, *pending))))
}
