package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Settings are the server options editable in the web UI. Bootstrap values
// (database, listeners, session key) stay in the environment; everything here
// starts from the environment and is overridden once saved in the UI.
type Settings struct {
	OIDCIssuer       string `json:"oidc_issuer"`
	OIDCClientID     string `json:"oidc_client_id"`
	OIDCClientSecret string `json:"-"` // stored encrypted, never rendered
	AllowedDomain    string `json:"allowed_domain"`
	LocalLogin       bool   `json:"local_login"`
	StaleHours       int    `json:"stale_hours"`
	WebhookURL       string `json:"webhook_url"`
	CompanyName      string `json:"company_name,omitempty"` // shown in the console and on devices
	Logo             []byte `json:"logo_png,omitempty"`     // PNG, at most 256 KiB and 1024 px
	// ConsoleAllow limits the console to these networks (CIDR or address);
	// empty allows every network. ConsoleBlock refuses networks always.
	// Loopback is always allowed, so the host itself can repair a mistake.
	ConsoleAllow []string `json:"console_allow,omitempty"`
	ConsoleBlock []string `json:"console_block,omitempty"`
	// Password rules for passwords chosen in the console: local accounts on
	// devices (create, reset) and local console accounts.
	Rules PasswordPolicy `json:"password_policy"` // password rules
	// FourEyes: wipe, lost mode, scripts and console role changes need a
	// second admin's approval; FourEyesRecovery adds recovery key views.
	FourEyes         bool `json:"four_eyes,omitempty"`
	FourEyesRecovery bool `json:"four_eyes_recovery,omitempty"`
	FourEyesShell    bool `json:"four_eyes_shell,omitempty"` // remote shell sessions
	// RequireMFA refuses OIDC sign ins whose id token shows no second factor
	// (amr), or, with MFAACR set, whose acr is not one of these values.
	RequireMFA bool     `json:"require_mfa,omitempty"`
	MFAACR     []string `json:"mfa_acr,omitempty"`
	// AuditRetentionDays deletes audit entries older than this (0 keeps them).
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
	// RoleGroups give console roles to members of directory groups or OIDC
	// group claims.
	RoleGroups []RoleGroup `json:"role_groups,omitempty"`
	// Privacy opt ins, both off by default: Geolocation sends device public
	// addresses to LIMDM_GEOIP_URL, FallbackDNS lets agents ask public DNS
	// over HTTPS resolvers when the system resolver fails.
	Geolocation bool                `json:"geolocation,omitempty"`
	FallbackDNS bool                `json:"fallback_dns,omitempty"`
	RemoteShell RemoteShellSettings `json:"remote_shell,omitzero"`
}

// PasswordPolicy: the minimum length (12..128, 12 when unset) and the
// character classes a password needs.
type PasswordPolicy struct {
	MinLength int  `json:"min_length,omitempty"`
	Upper     bool `json:"upper,omitempty"`
	Lower     bool `json:"lower,omitempty"`
	Digit     bool `json:"digit,omitempty"`
	Symbol    bool `json:"symbol,omitempty"`
	NoName    bool `json:"no_name,omitempty"` // must not contain the user name
}

// Min is the effective minimum length.
func (p PasswordPolicy) Min() int { return max(p.MinLength, 12) }

// passwordErrors are the messages of Check; the device page shows them by
// index after a redirect, so no free text travels in the URL.
var passwordErrors = []string{
	"The password is shorter than the password policy requires.",
	"The password is too long (at most 256 characters).",
	"The password needs an uppercase letter.",
	"The password needs a lowercase letter.",
	"The password needs a digit.",
	"The password needs a special character.",
	"The password must not contain the user name.",
	passwordMismatch, // not from Check: the repeat field of a console form differs
}

const passwordMismatch = "The passwords do not match."

// Check returns the first rule pw breaks, as a message for the console.
func (p PasswordPolicy) Check(pw, user string) string {
	var upper, lower, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case !unicode.IsSpace(r):
			symbol = true
		}
	}
	switch {
	case utf8.RuneCountInString(pw) < p.Min():
		return "The password is shorter than the password policy requires."
	case len(pw) > 256:
		return "The password is too long (at most 256 characters)."
	case p.Upper && !upper:
		return "The password needs an uppercase letter."
	case p.Lower && !lower:
		return "The password needs a lowercase letter."
	case p.Digit && !digit:
		return "The password needs a digit."
	case p.Symbol && !symbol:
		return "The password needs a special character."
	case p.NoName && len(user) >= 3 && strings.Contains(strings.ToLower(pw), strings.ToLower(user)):
		return "The password must not contain the user name."
	}
	return ""
}

// storedSettings is the database form; the client secret is AES-GCM sealed.
type storedSettings struct {
	Settings
	SecretEnc string `json:"oidc_client_secret_enc,omitempty"`
}

type runtimeState struct {
	set      Settings
	allow    []netip.Prefix // parsed ConsoleAllow
	block    []netip.Prefix // parsed ConsoleBlock
	auth     *oidcAuth      // nil when OIDC is not configured
	branding api.Branding   // derived from set once, sent to agents and shown in the console
}

func (s *Server) settings() Settings { return s.rt.Load().set }
func (s *Server) oidc() *oidcAuth    { return s.rt.Load().auth }
func (s *Server) staleAfter() time.Duration {
	return time.Duration(s.settings().StaleHours) * time.Hour
}

func envSettings(c Config) Settings {
	return Settings{OIDCIssuer: c.OIDCIssuer, OIDCClientID: c.OIDCClientID, OIDCClientSecret: c.OIDCSecret,
		AllowedDomain: c.AllowedDomain, LocalLogin: c.LocalLogin, StaleHours: int(c.StaleAfter.Hours())}
}

func (s *Server) loadSettings(ctx context.Context) error {
	set := envSettings(s.cfg)
	var raw []byte
	var at time.Time
	err := s.db.QueryRow(ctx, `SELECT value, updated_at FROM settings WHERE key='server'`).Scan(&raw, &at)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	default:
		s.ha.settingsAt.Store(at.UnixMicro())
		var st storedSettings
		if err := json.Unmarshal(raw, &st); err != nil {
			return err
		}
		if st.OIDCClientSecret, err = s.openField("settings.oidc_client_secret", st.SecretEnc); err != nil {
			return err
		}
		set = st.Settings
	}
	rt, err := s.prepare(ctx, set)
	if errors.Is(err, errDiscovery) {
		// the identity provider is down while the server starts: run without
		// OIDC (agents, local accounts) and retry instead of exiting
		s.log.Error("OIDC discovery failed, retrying in the background", "err", err)
		noOIDC := set
		noOIDC.OIDCIssuer, noOIDC.LocalLogin = "", true
		if rt, err = s.prepare(ctx, noOIDC); err == nil {
			rt.set = set
			s.rediscover.Store(true)
		}
	}
	if err != nil {
		return err
	}
	s.rt.Store(rt)
	return nil
}

// localAllowed: local accounts are on, or OIDC is configured but its
// provider could not be reached since the start (the fallback local accounts
// exist for).
func (s *Server) localAllowed() bool {
	return s.settings().LocalLogin || s.rediscover.Load() && s.oidc() == nil
}

// errDiscovery marks a failed OIDC discovery (network, provider down).
var errDiscovery = errors.New("OIDC discovery failed")

// rediscoverLoop retries the OIDC discovery that failed at startup.
func (s *Server) rediscoverLoop(ctx context.Context) {
	for s.rediscover.Load() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		cur := s.rt.Load()
		set := cur.set
		if cur.auth != nil || set.OIDCIssuer == "" { // a saved settings change did it already
			s.rediscover.Store(false)
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		auth, err := newOIDCAuthFrom(cctx, set.OIDCIssuer, set.OIDCClientID, set.OIDCClientSecret, s.cfg.PublicURL)
		cancel()
		if err != nil {
			continue
		}
		// under saveMu: a settings save loads, prepares and stores the runtime
		// in one step and would otherwise overwrite this with auth=nil
		s.saveMu.Lock()
		if now := s.rt.Load(); now.auth == nil && now.set.OIDCIssuer == set.OIDCIssuer &&
			now.set.OIDCClientID == set.OIDCClientID && now.set.OIDCClientSecret == set.OIDCClientSecret {
			next := *now
			next.auth = auth
			s.rt.Store(&next)
			s.log.Info("OIDC discovery succeeded")
		}
		s.rediscover.Store(false)
		s.saveMu.Unlock()
	}
}

// prepare validates settings and builds the runtime state (OIDC discovery
// runs here) without activating it.
func (s *Server) prepare(ctx context.Context, set Settings) (*runtimeState, error) {
	if set.StaleHours < 1 || set.StaleHours > 24*90 {
		return nil, errors.New("stale hours must be between 1 and 2160")
	}
	if set.WebhookURL != "" {
		if u, err := url.Parse(set.WebhookURL); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("webhook URL must be https")
		}
	}
	if n := set.Rules.MinLength; n != 0 && (n < 12 || n > 128) {
		return nil, errors.New("minimum password length: 12 to 128")
	}
	if d := set.AuditRetentionDays; d != 0 && (d < 365 || d > 36500) {
		return nil, errors.New("audit log retention: 0 (keep forever) or 365 to 36500 days")
	}
	if len(set.MFAACR) > 10 {
		return nil, errors.New("accepted acr values: at most 10")
	}
	for _, v := range set.MFAACR {
		if len(v) > 200 || strings.ContainsFunc(v, unicode.IsControl) {
			return nil, errors.New("accepted acr values: up to 200 printable characters each")
		}
	}
	if len(set.CompanyName) > 80 || strings.ContainsAny(set.CompanyName, "\x00\n\r\t") {
		return nil, errors.New("company name: up to 80 characters on one line")
	}
	if err := validLogo(set.Logo); err != nil {
		return nil, err
	}
	if err := set.RemoteShell.validate(); err != nil {
		return nil, err
	}
	allow, err := parseNets(set.ConsoleAllow)
	if err != nil {
		return nil, fmt.Errorf("allowed networks: %w", err)
	}
	block, err := parseNets(set.ConsoleBlock)
	if err != nil {
		return nil, fmt.Errorf("blocked networks: %w", err)
	}
	var auth *oidcAuth
	if cur := s.rt.Load(); cur != nil && set.OIDCIssuer != "" && cur.set.OIDCIssuer == set.OIDCIssuer &&
		cur.set.OIDCClientID == set.OIDCClientID && cur.set.OIDCClientSecret == set.OIDCClientSecret &&
		(cur.auth != nil || s.rediscover.Load()) {
		// unchanged provider: no new discovery when another tab is saved (also
		// while the startup discovery is still being retried)
		auth = cur.auth
	} else if set.OIDCIssuer != "" {
		if !strings.HasPrefix(set.OIDCIssuer, "https://") || set.OIDCClientID == "" {
			return nil, errors.New("OIDC needs an https issuer and a client ID")
		}
		var err error
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if auth, err = newOIDCAuthFrom(cctx, set.OIDCIssuer, set.OIDCClientID, set.OIDCClientSecret, s.cfg.PublicURL); err != nil {
			return nil, fmt.Errorf("%w: %w", errDiscovery, err)
		}
	}
	if auth == nil && !set.LocalLogin && (!s.rediscover.Load() || set.OIDCIssuer == "") {
		return nil, errors.New("enable at least one login method: OIDC or local accounts")
	}
	return &runtimeState{set: set, auth: auth, branding: computeBranding(set), allow: allow, block: block}, nil
}

// parseNets reads CIDRs or single addresses (one per entry).
func parseNets(list []string) ([]netip.Prefix, error) {
	var res []netip.Prefix
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !strings.Contains(v, "/") {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("%q is no address or CIDR", v)
			}
			res = append(res, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("%q is no address or CIDR", v)
		}
		res = append(res, p.Masked())
	}
	if len(res) > 200 {
		return nil, errors.New("at most 200 entries")
	}
	return res, nil
}

// consoleAllowed decides by the client address (clientIP).
func consoleAllowed(rt *runtimeState, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, p := range rt.block {
		if p.Contains(a) {
			return false
		}
	}
	if len(rt.allow) == 0 {
		return true
	}
	for _, p := range rt.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ---- settings page ----

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderSettings(w, r, sess, s.settings(), "", "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, sess session, set Settings, msg, errMsg string) {
	tab := r.FormValue("section")
	if tab == "" {
		tab = r.URL.Query().Get("tab")
	}
	if tab == "monitoring" || tab == "integrations" { // both forms live on the notifications tab
		tab = "notifications"
	}
	if !slices.Contains(settingsTabs, tab) {
		tab = "general"
	}
	tabs := settingsTabLabels
	if sess.TenantOnly() { // tenant accounts manage their notification channels only
		tab, set = "notifications", Settings{}
		tabs = slices.DeleteFunc(slices.Clone(tabs), func(t struct{ Key, Label string }) bool { return t.Key != tab })
	}
	data := map[string]any{}
	if tab == "notifications" {
		views, err := s.channelViews(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		data["Channels"], data["NotifyEvents"] = views, notifyEvents
	}
	if tab == "security" && keysAllowed(sess) {
		if keys, err := s.KeysStatus(r.Context()); err != nil {
			s.log.Error("key status", "err", err)
		} else {
			data["Keys"] = keys
		}
	}
	s.render(w, r, sess, "settings", map[string]any{"Set": set, "ClientIP": clientIP(r), "HasSecret": set.OIDCClientSecret != "", "Msg": msg, "Error": errMsg,
		"Tab": tab, "Tabs": tabs, "Channels": data["Channels"], "NotifyEvents": data["NotifyEvents"], "Keys": data["Keys"], "TenantOnly": sess.TenantOnly(),
		"Redirect": s.cfg.PublicURL + "/auth/callback", "PublicURL": s.cfg.PublicURL, "WebhookSecret": map[bool]string{false: s.webhookSecretHex()}[sess.TenantOnly()],
		"RoleGroupsText": roleGroupsText(set.RoleGroups)})
}

// settingsTabs are the sections of the settings page; each tab saves only
// its own fields.
var settingsTabs = []string{"general", "security", "sso", "notifications", "branding"}

var settingsTabLabels = []struct{ Key, Label string }{
	{"general", "General"}, {"security", "Security"}, {"sso", "SSO"}, {"notifications", "Notifications"}, {"branding", "Branding"},
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	// held from reading the current settings to storing them: two tabs saved
	// at once must not overwrite each other, nor leave runtime and database apart
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	// and across instances; a change another instance saved a moment ago
	// is loaded first, so this save does not undo it
	unlock, err := clusterLock(ctx, s.db, lockSettings, 30*time.Second)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer unlock()
	var at time.Time
	if err := s.db.QueryRow(ctx, `SELECT updated_at FROM settings WHERE key='server'`).Scan(&at); err == nil && at.UnixMicro() != s.ha.settingsAt.Load() {
		if err := s.loadSettings(ctx); err != nil {
			s.fail(w, err)
			return
		}
	}
	cur := s.settings()
	set := cur
	switch r.FormValue("section") {
	case "general":
		set.LocalLogin = r.FormValue("local_login") == "on"
		set.StaleHours, _ = strconv.Atoi(r.FormValue("stale_hours"))
	case "sso":
		set.OIDCIssuer = strings.TrimRight(strings.TrimSpace(r.FormValue("oidc_issuer")), "/")
		set.OIDCClientID = strings.TrimSpace(r.FormValue("oidc_client_id"))
		set.AllowedDomain = strings.ToLower(strings.TrimSpace(r.FormValue("allowed_domain")))
		set.RequireMFA = r.FormValue("require_mfa") == "on"
		set.MFAACR = strings.Fields(r.FormValue("mfa_acr"))
		groups, err := parseRoleGroups(r.FormValue("role_groups"))
		if err != nil {
			s.renderSettings(w, r, sess, set, "", err.Error())
			return
		}
		set.RoleGroups = groups
	case "monitoring":
		set.WebhookURL = strings.TrimSpace(r.FormValue("webhook_url"))
	case "network":
		set.ConsoleAllow, set.ConsoleBlock = strings.Fields(r.FormValue("console_allow")), strings.Fields(r.FormValue("console_block"))
	case "branding":
		set.CompanyName = strings.TrimSpace(r.FormValue("company_name"))
	case "security":
		n, _ := strconv.Atoi(r.FormValue("min_length"))
		set.Rules = PasswordPolicy{MinLength: n, Upper: r.FormValue("upper") == "on", Lower: r.FormValue("lower") == "on",
			Digit: r.FormValue("digit") == "on", Symbol: r.FormValue("symbol") == "on", NoName: r.FormValue("no_name") == "on"}
		set.FourEyes = r.FormValue("four_eyes") == "on"
		set.FourEyesRecovery = set.FourEyes && r.FormValue("four_eyes_recovery") == "on"
		set.FourEyesShell = set.FourEyes && r.FormValue("four_eyes_shell") == "on"
		set.AuditRetentionDays, _ = strconv.Atoi(r.FormValue("audit_retention_days"))
		if set.FourEyes && !cur.FourEyes {
			n, err := s.activeAdmins(ctx)
			if err != nil {
				s.fail(w, err)
				return
			}
			if n < 2 {
				s.renderSettings(w, r, sess, set, "", "Four eyes approval needs at least two active administrators: with one, nobody could approve a request.")
				return
			}
		}
		set.Geolocation, set.FallbackDNS = r.FormValue("geolocation") == "on", r.FormValue("fallback_dns") == "on"
	case "remote_shell":
		set.RemoteShell = remoteShellForm(r)
	default:
		s.errorPage(w, r, sess, http.StatusBadRequest, "unknown settings section")
		return
	}
	if f, _, err := r.FormFile("logo"); err == nil {
		b, err := io.ReadAll(io.LimitReader(f, maxLogo+1))
		f.Close()
		if err != nil {
			s.fail(w, err)
			return
		}
		set.Logo = b
	}
	if r.FormValue("remove_logo") == "on" {
		set.Logo = nil
	}
	if v := r.FormValue("oidc_client_secret"); v != "" {
		set.OIDCClientSecret = v
	}
	if r.FormValue("clear_secret") == "on" {
		set.OIDCClientSecret = ""
	}
	// never lock the admin who saves out of the console
	if rt, err := (&Server{}).netsOnly(set); err == nil && !consoleAllowed(rt, clientIP(r)) {
		s.renderSettings(w, r, sess, set, "", "Your own address would be refused; add it to the allowed networks first.")
		return
	}
	// never lock everybody out
	if !set.LocalLogin {
		var oidcAdmins int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM console_users WHERE role='admin' AND NOT disabled`).Scan(&oidcAdmins); err != nil {
			s.fail(w, err)
			return
		}
		if set.OIDCIssuer == "" || oidcAdmins == 0 {
			s.renderSettings(w, r, sess, set, "", "Local login can only be disabled when OIDC is configured and at least one OIDC administrator exists.")
			return
		}
		if strings.HasPrefix(sess.Email, localPrefix) {
			s.renderSettings(w, r, sess, set, "", "You are signed in with a local account; sign in with OIDC before disabling local login.")
			return
		}
	}
	rt, err := s.prepare(ctx, set)
	if err != nil {
		s.renderSettings(w, r, sess, set, "", err.Error())
		return
	}
	enc, err := s.sealField("settings.oidc_client_secret", set.OIDCClientSecret)
	if err != nil {
		s.fail(w, err)
		return
	}
	doc, _ := json.Marshal(storedSettings{Settings: set, SecretEnc: enc})
	detail := fmt.Sprintf("oidc=%q domain=%q local=%v stale=%d webhook=%v secret_changed=%v company=%q logo_bytes=%d allow=%q block=%q rules=%+v four_eyes=%v four_eyes_recovery=%v four_eyes_shell=%v require_mfa=%v acr=%q audit_retention_days=%d role_groups=%+v geolocation=%v fallback_dns=%v",
		set.OIDCIssuer, set.AllowedDomain, set.LocalLogin, set.StaleHours, set.WebhookURL != "", set.OIDCClientSecret != cur.OIDCClientSecret,
		set.CompanyName, len(set.Logo), set.ConsoleAllow, set.ConsoleBlock, set.Rules,
		set.FourEyes, set.FourEyesRecovery, set.FourEyesShell, set.RequireMFA, set.MFAACR, set.AuditRetentionDays, set.RoleGroups, set.Geolocation, set.FallbackDNS) + fmt.Sprintf(" remote_shell=%+v", set.RemoteShell)
	err = s.auditAction(ctx, sess.Email, "settings.save", "server", detail, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO settings(key, value) VALUES ('server', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()
			RETURNING updated_at`, string(doc)).Scan(&at)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rt.Store(rt) // only what is stored and audited becomes active
	s.ha.settingsAt.Store(at.UnixMicro())
	s.renderSettings(w, r, sess, set, "Settings saved and active.", "")
}

// netsOnly parses the network lists of settings for the self lockout check.
func (*Server) netsOnly(set Settings) (*runtimeState, error) {
	allow, err := parseNets(set.ConsoleAllow)
	if err != nil {
		return nil, err
	}
	block, err := parseNets(set.ConsoleBlock)
	if err != nil {
		return nil, err
	}
	return &runtimeState{allow: allow, block: block}, nil
}
