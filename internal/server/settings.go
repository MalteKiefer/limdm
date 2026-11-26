package server

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
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
	// SCIMAllow limits /scim/ to these networks (the identity provider's
	// provisioning addresses); empty allows every network.
	SCIMAllow []string `json:"scim_allow,omitempty"`
	// NotifyPrivate lets global notification channels reach private
	// networks (an internal SIEM or mail relay); tenant channels never can.
	NotifyPrivate bool `json:"notify_private_networks,omitempty"`
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
	// AuditRetentionDays is the audit period saved before Retention existed;
	// it still applies until the retention tab is saved (retention.go).
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
	// Retention is the period in days per data type (retentionKinds); a
	// missing entry uses the default.
	Retention map[string]int `json:"retention,omitempty"`
	// RoleGroups give console roles to members of directory groups or OIDC
	// group claims.
	RoleGroups []RoleGroup `json:"role_groups,omitempty"`
	// Privacy opt ins, both off by default: Geolocation sends device public
	// addresses to LIMDM_GEOIP_URL, FallbackDNS lets agents ask public DNS
	// over HTTPS resolvers when the system resolver fails.
	Geolocation bool                `json:"geolocation,omitempty"`
	FallbackDNS bool                `json:"fallback_dns,omitempty"`
	RemoteShell RemoteShellSettings `json:"remote_shell,omitzero"`
	Ops         OpsSettings         `json:"ops"`
}

// OpsSettings are the runtime operations of every instance (Settings,
// Operations). The environment variables of the same name only give the
// initial values; once saved in the console, the stored values apply.
type OpsSettings struct {
	LogLevel      string `json:"log_level"`       // debug, info, warn or error (LIMDM_LOG_LEVEL)
	AccessLog     bool   `json:"access_log"`      // a log line per request (LIMDM_ACCESS_LOG)
	AuditAPIReads string `json:"audit_api_reads"` // off, sensitive or all (LIMDM_AUDIT_API_READS)
	// parallel agent package downloads per instance (LIMDM_UPDATE_DOWNLOADS)
	UpdateDownloads int `json:"update_downloads"`
	MaxCheckins     int `json:"max_checkins"` // check ins processed at once per instance (LIMDM_MAX_CHECKINS)
	// load balancers that send a PROXY v2 header to the agent listener;
	// empty: PROXY protocol off (LIMDM_AGENT_PROXY_PROTOCOL)
	AgentProxyFrom []string `json:"agent_proxy_protocol"`
	Syslog         string   `json:"syslog"`    // udp://, tcp:// or tcp+tls://host:port (LIMDM_SYSLOG)
	SyslogCA       string   `json:"syslog_ca"` // PEM for tcp+tls; empty: system roots (LIMDM_SYSLOG_CA)
}

// withDefaults fills fields left empty (settings without Ops, tests).
func (o OpsSettings) withDefaults() OpsSettings {
	o.LogLevel = cmp.Or(o.LogLevel, "info")
	o.AuditAPIReads = cmp.Or(o.AuditAPIReads, "sensitive")
	o.UpdateDownloads = cmp.Or(o.UpdateDownloads, 20)
	o.MaxCheckins = cmp.Or(o.MaxCheckins, 64)
	return o
}

// validate checks the operations settings and returns the parsed PROXY sources.
func (o OpsSettings) validate() ([]netip.Prefix, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(o.LogLevel)); err != nil {
		return nil, errors.New("log level: debug, info, warn or error")
	}
	if !slices.Contains([]string{"off", "sensitive", "all"}, o.AuditAPIReads) {
		return nil, errors.New("audit of API reads: off, sensitive or all")
	}
	if o.UpdateDownloads < 1 || o.UpdateDownloads > 10000 || o.MaxCheckins < 1 || o.MaxCheckins > 10000 {
		return nil, errors.New("parallel downloads and check ins: 1 to 10000")
	}
	if o.Syslog != "" {
		u, err := url.Parse(o.Syslog)
		if err != nil || (u.Scheme != "udp" && u.Scheme != "tcp" && u.Scheme != "tcp+tls") || u.Host == "" || u.Port() == "" {
			return nil, errors.New("syslog target: udp://host:port, tcp://host:port or tcp+tls://host:port")
		}
	}
	if o.SyslogCA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(o.SyslogCA)) {
		return nil, errors.New("syslog CA: no PEM certificate found")
	}
	proxies, err := parseNets(o.AgentProxyFrom)
	if err != nil {
		return nil, fmt.Errorf("PROXY protocol sources: %w", err)
	}
	return proxies, nil
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
	scim     []netip.Prefix // parsed SCIMAllow
	proxy    []netip.Prefix // parsed Ops.AgentProxyFrom
	auth     *oidcAuth      // nil when OIDC is not configured
	branding api.Branding   // derived from set once, sent to agents and shown in the console
}

func (s *Server) settings() Settings { return s.rt.Load().set }
func (s *Server) oidc() *oidcAuth    { return s.rt.Load().auth }
func (s *Server) staleAfter() time.Duration {
	return time.Duration(s.settings().StaleHours) * time.Hour
}

// envSettings are the settings before anything was saved in the console;
// a stored setting overrides its field (loadSettings).
func envSettings(c Config) Settings {
	proxies := make([]string, len(c.AgentProxyFrom))
	for i, p := range c.AgentProxyFrom {
		proxies[i] = p.String()
	}
	return Settings{OIDCIssuer: c.OIDCIssuer, OIDCClientID: c.OIDCClientID, OIDCClientSecret: c.OIDCSecret,
		AllowedDomain: c.AllowedDomain, LocalLogin: c.LocalLogin, StaleHours: int(c.StaleAfter.Hours()),
		Ops: OpsSettings{LogLevel: c.LogLevel, AccessLog: c.AccessLog, AuditAPIReads: c.AuditAPIReads,
			UpdateDownloads: c.UpdateDownloads, MaxCheckins: c.MaxCheckins, AgentProxyFrom: proxies,
			Syslog: c.Syslog, SyslogCA: c.SyslogCA}.withDefaults()}
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
		// on top of the environment: fields saved before they existed in
		// the console (Ops after an upgrade) keep their environment value
		st := storedSettings{Settings: set}
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
	s.applyOps(rt)
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
	if err := validRetention(set.Retention); err != nil {
		return nil, err
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
	scim, err := parseNets(set.SCIMAllow)
	if err != nil {
		return nil, fmt.Errorf("SCIM networks: %w", err)
	}
	set.Ops = set.Ops.withDefaults()
	proxy, err := set.Ops.validate()
	if err != nil {
		return nil, err
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
	return &runtimeState{set: set, auth: auth, branding: computeBranding(set), allow: allow, block: block, scim: scim, proxy: proxy}, nil
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

// netsContain reports whether the address ip is in one of nets.
func netsContain(nets []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && slices.ContainsFunc(nets, func(p netip.Prefix) bool { return p.Contains(a.Unmap()) })
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

// settingsSections are the sections saveSettings accepts.
var settingsSections = []string{"general", "sso", "monitoring", "network", "branding", "security", "remote_shell", "operations", "retention"}

// saveSettings stores the fields of one settings section taken from in and
// makes them active. The console form and the admin API both call it, so
// validation, lockout guards and the audit entry are the same. It returns
// the settings it tried to store; a rejected change is a *userError.
func (s *Server) saveSettings(ctx context.Context, sess session, ip, section string, in Settings) (Settings, error) {
	if !backupAdmin(sess) {
		return in, &userError{http.StatusForbidden, "settings are managed by global administrators"}
	}
	if !slices.Contains(settingsSections, section) {
		return in, &userError{http.StatusBadRequest, "unknown settings section"}
	}
	// held from reading the current settings to storing them: two tabs saved
	// at once must not overwrite each other, nor leave runtime and database apart
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	// and across instances; a change another instance saved a moment ago
	// is loaded first, so this save does not undo it
	unlock, err := clusterLock(ctx, s.db, lockSettings, 30*time.Second)
	if err != nil {
		return in, err
	}
	defer unlock()
	var at time.Time
	if err := s.db.QueryRow(ctx, `SELECT updated_at FROM settings WHERE key='server'`).Scan(&at); err == nil && at.UnixMicro() != s.ha.settingsAt.Load() {
		if err := s.loadSettings(ctx); err != nil {
			return in, err
		}
	}
	reject := func(set Settings, msg string) (Settings, error) {
		return set, &userError{http.StatusUnprocessableEntity, msg}
	}
	cur := s.settings()
	set := cur
	switch section {
	case "general":
		set.LocalLogin, set.StaleHours = in.LocalLogin, in.StaleHours
	case "sso":
		set.OIDCIssuer = strings.TrimRight(strings.TrimSpace(in.OIDCIssuer), "/")
		set.OIDCClientID = strings.TrimSpace(in.OIDCClientID)
		set.AllowedDomain = strings.ToLower(strings.TrimSpace(in.AllowedDomain))
		set.RequireMFA, set.MFAACR = in.RequireMFA, in.MFAACR
		groups, err := parseRoleGroups(roleGroupsText(in.RoleGroups)) // the API sends a list: same rules as the form
		if err != nil {
			return reject(in, err.Error())
		}
		set.RoleGroups, set.OIDCClientSecret = groups, in.OIDCClientSecret
	case "monitoring":
		set.WebhookURL, set.NotifyPrivate = strings.TrimSpace(in.WebhookURL), in.NotifyPrivate
	case "network":
		set.ConsoleAllow, set.ConsoleBlock, set.SCIMAllow = in.ConsoleAllow, in.ConsoleBlock, in.SCIMAllow
	case "branding":
		set.CompanyName, set.Logo = strings.TrimSpace(in.CompanyName), in.Logo
	case "security":
		set.Rules = in.Rules
		set.FourEyes = in.FourEyes
		set.FourEyesRecovery = set.FourEyes && in.FourEyesRecovery
		set.FourEyesShell = set.FourEyes && in.FourEyesShell
		set.Geolocation, set.FallbackDNS = in.Geolocation, in.FallbackDNS
		if set.FourEyes && !cur.FourEyes {
			n, err := s.activeAdmins(ctx)
			if err != nil {
				return in, err
			}
			if n < 2 {
				return reject(set, "Four eyes approval needs at least two active administrators: with one, nobody could approve a request.")
			}
		}
	case "remote_shell":
		set.RemoteShell = in.RemoteShell
	case "operations":
		set.Ops = in.Ops
		set.Ops.Syslog, set.Ops.SyslogCA = strings.TrimSpace(set.Ops.Syslog), strings.TrimSpace(set.Ops.SyslogCA)
	case "retention":
		set.Retention = map[string]int{}
		for _, k := range retentionKinds {
			set.Retention[k.Key] = in.retentionDays(k.Key)
		}
		set.AuditRetentionDays = 0 // replaced by Retention["audit"]
	}
	// never lock the admin who saves out of the console
	if rt, err := (&Server{}).netsOnly(set); err == nil && !consoleAllowed(rt, ip) {
		return reject(set, "Your own address would be refused; add it to the allowed networks first.")
	}
	// never lock everybody out
	if !set.LocalLogin {
		var oidcAdmins int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM console_users WHERE role='admin' AND NOT disabled`).Scan(&oidcAdmins); err != nil {
			return set, err
		}
		if set.OIDCIssuer == "" || oidcAdmins == 0 {
			return reject(set, "Local login can only be disabled when OIDC is configured and at least one OIDC administrator exists.")
		}
		if strings.HasPrefix(sess.Email, localPrefix) {
			return reject(set, "You are signed in with a local account; sign in with OIDC before disabling local login.")
		}
	}
	rt, err := s.prepare(ctx, set)
	if err != nil {
		return reject(set, err.Error())
	}
	enc, err := s.sealField("settings.oidc_client_secret", set.OIDCClientSecret)
	if err != nil {
		return set, err
	}
	doc, _ := json.Marshal(storedSettings{Settings: set, SecretEnc: enc})
	detail := fmt.Sprintf("oidc=%q domain=%q local=%v stale=%d webhook=%v secret_changed=%v company=%q logo_bytes=%d allow=%q block=%q rules=%+v four_eyes=%v four_eyes_recovery=%v four_eyes_shell=%v require_mfa=%v acr=%q audit_retention_days=%d role_groups=%+v geolocation=%v fallback_dns=%v",
		set.OIDCIssuer, set.AllowedDomain, set.LocalLogin, set.StaleHours, set.WebhookURL != "", set.OIDCClientSecret != cur.OIDCClientSecret,
		set.CompanyName, len(set.Logo), set.ConsoleAllow, set.ConsoleBlock, set.Rules,
		set.FourEyes, set.FourEyesRecovery, set.FourEyesShell, set.RequireMFA, set.MFAACR, set.AuditRetentionDays, set.RoleGroups, set.Geolocation, set.FallbackDNS) + fmt.Sprintf(" remote_shell=%+v retention=%v scim_allow=%q notify_private=%v", set.RemoteShell, set.Retention, set.SCIMAllow, set.NotifyPrivate) +
		fmt.Sprintf(" log_level=%s access_log=%v audit_api_reads=%s update_downloads=%d max_checkins=%d agent_proxy_protocol=%q syslog=%q syslog_ca_bytes=%d",
			set.Ops.LogLevel, set.Ops.AccessLog, set.Ops.AuditAPIReads, set.Ops.UpdateDownloads, set.Ops.MaxCheckins, set.Ops.AgentProxyFrom, set.Ops.Syslog, len(set.Ops.SyslogCA))
	err = s.auditAction(ctx, sess.Email, "settings.save", "server", detail, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO settings(key, value) VALUES ('server', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()
			RETURNING updated_at`, string(doc)).Scan(&at)
	})
	if err != nil {
		return set, err
	}
	s.rt.Store(rt) // only what is stored and audited becomes active
	s.applyOps(rt)
	s.ha.settingsAt.Store(at.UnixMicro())
	return rt.set, nil
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
