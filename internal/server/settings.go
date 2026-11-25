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
	err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key='server'`).Scan(&raw)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	default:
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
	if err != nil {
		return err
	}
	s.rt.Store(rt)
	return nil
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
	if len(set.CompanyName) > 80 || strings.ContainsAny(set.CompanyName, "\x00\n\r\t") {
		return nil, errors.New("company name: up to 80 characters on one line")
	}
	if err := validLogo(set.Logo); err != nil {
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
		cur.set.OIDCClientID == set.OIDCClientID && cur.set.OIDCClientSecret == set.OIDCClientSecret {
		auth = cur.auth // unchanged provider: no new discovery when another tab is saved
	} else if set.OIDCIssuer != "" {
		if !strings.HasPrefix(set.OIDCIssuer, "https://") || set.OIDCClientID == "" {
			return nil, errors.New("OIDC needs an https issuer and a client ID")
		}
		var err error
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if auth, err = newOIDCAuthFrom(cctx, set.OIDCIssuer, set.OIDCClientID, set.OIDCClientSecret, s.cfg.PublicURL); err != nil {
			return nil, fmt.Errorf("OIDC discovery failed: %w", err)
		}
	}
	if auth == nil && !set.LocalLogin {
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
	if !slices.Contains(settingsTabs, tab) {
		tab = "general"
	}
	data := map[string]any{}
	if tab == "integrations" {
		views, err := s.channelViews(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		data["Channels"], data["NotifyEvents"] = views, notifyEvents
	}
	s.render(w, r, sess, "settings", map[string]any{"Set": set, "ClientIP": clientIP(r), "HasSecret": set.OIDCClientSecret != "", "Msg": msg, "Error": errMsg,
		"Tab": tab, "Tabs": settingsTabLabels, "Channels": data["Channels"], "NotifyEvents": data["NotifyEvents"],
		"Redirect": s.cfg.PublicURL + "/auth/callback", "PublicURL": s.cfg.PublicURL, "WebhookSecret": s.webhookSecretHex()})
}

// settingsTabs are the sections of the settings page; each tab saves only
// its own fields.
var settingsTabs = []string{"general", "sso", "monitoring", "branding", "integrations"}

var settingsTabLabels = []struct{ Key, Label string }{
	{"general", "General"}, {"sso", "SSO"}, {"monitoring", "Monitoring"}, {"branding", "Branding"}, {"integrations", "Integrations"},
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
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
	case "monitoring":
		set.WebhookURL = strings.TrimSpace(r.FormValue("webhook_url"))
	case "network":
		set.ConsoleAllow, set.ConsoleBlock = strings.Fields(r.FormValue("console_allow")), strings.Fields(r.FormValue("console_block"))
	case "branding":
		set.CompanyName = strings.TrimSpace(r.FormValue("company_name"))
	default:
		http.Error(w, "unknown settings section", http.StatusBadRequest)
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
	s.saveMu.Lock() // concurrent saves must not leave runtime and database apart
	defer s.saveMu.Unlock()
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
	detail := fmt.Sprintf("oidc=%q domain=%q local=%v stale=%d webhook=%v secret_changed=%v company=%q logo_bytes=%d",
		set.OIDCIssuer, set.AllowedDomain, set.LocalLogin, set.StaleHours, set.WebhookURL != "", set.OIDCClientSecret != cur.OIDCClientSecret,
		set.CompanyName, len(set.Logo))
	err = s.auditAction(ctx, sess.Email, "settings.save", "server", detail, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('server', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rt.Store(rt) // only what is stored and audited becomes active
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
