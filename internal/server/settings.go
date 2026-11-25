package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
}

// storedSettings is the database form; the client secret is AES-GCM sealed.
type storedSettings struct {
	Settings
	SecretEnc string `json:"oidc_client_secret_enc,omitempty"`
}

type runtimeState struct {
	set      Settings
	auth     *oidcAuth    // nil when OIDC is not configured
	branding api.Branding // derived from set once, sent to agents and shown in the console
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

// settingsKey derives the encryption key for stored secrets from the session key.
func (s *Server) settingsKey() ([]byte, error) {
	return hkdf.Key(sha256.New, s.cfg.SessionKey, nil, "limdm settings secrets v1", 32)
}

func (s *Server) seal32(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	key, err := s.settingsKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), []byte("oidc_client_secret"))), nil
}

func (s *Server) open32(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	key, err := s.settingsKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("stored secret too short")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte("oidc_client_secret"))
	if err != nil {
		return "", errors.New("stored secret cannot be decrypted (session key changed?)")
	}
	return string(plain), nil
}

// loadSettings reads saved settings (or the environment) and activates them.
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
		if st.OIDCClientSecret, err = s.open32(st.SecretEnc); err != nil {
			return err
		}
		set = st.Settings
	}
	return s.activate(ctx, set)
}

// activate validates the settings and swaps them in; OIDC discovery runs here.
func (s *Server) activate(ctx context.Context, set Settings) error {
	if set.StaleHours < 1 || set.StaleHours > 24*90 {
		return errors.New("stale hours must be between 1 and 2160")
	}
	if set.WebhookURL != "" {
		if u, err := url.Parse(set.WebhookURL); err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("webhook URL must be https")
		}
	}
	if len(set.CompanyName) > 80 || strings.ContainsAny(set.CompanyName, "\x00\n\r\t") {
		return errors.New("company name: up to 80 characters on one line")
	}
	if err := validLogo(set.Logo); err != nil {
		return err
	}
	var auth *oidcAuth
	if set.OIDCIssuer != "" {
		if !strings.HasPrefix(set.OIDCIssuer, "https://") || set.OIDCClientID == "" {
			return errors.New("OIDC needs an https issuer and a client ID")
		}
		var err error
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if auth, err = newOIDCAuthFrom(cctx, set.OIDCIssuer, set.OIDCClientID, set.OIDCClientSecret, s.cfg.PublicURL); err != nil {
			return fmt.Errorf("OIDC discovery failed: %w", err)
		}
	}
	if auth == nil && !set.LocalLogin {
		return errors.New("enable at least one login method: OIDC or local accounts")
	}
	s.rt.Store(&runtimeState{set: set, auth: auth, branding: computeBranding(set)})
	return nil
}

// ---- settings page ----

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderSettings(w, r, sess, s.settings(), "", "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, sess session, set Settings, msg, errMsg string) {
	s.render(w, r, sess, "settings", map[string]any{"Set": set, "HasSecret": set.OIDCClientSecret != "", "Msg": msg, "Error": errMsg,
		"Redirect": s.cfg.PublicURL + "/auth/callback", "PublicURL": s.cfg.PublicURL, "WebhookSecret": s.webhookSecretHex()})
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	cur := s.settings()
	stale, _ := strconv.Atoi(r.FormValue("stale_hours"))
	set := Settings{
		OIDCIssuer: strings.TrimRight(strings.TrimSpace(r.FormValue("oidc_issuer")), "/"), OIDCClientID: strings.TrimSpace(r.FormValue("oidc_client_id")),
		OIDCClientSecret: cur.OIDCClientSecret, AllowedDomain: strings.ToLower(strings.TrimSpace(r.FormValue("allowed_domain"))),
		LocalLogin: r.FormValue("local_login") == "on", StaleHours: stale, WebhookURL: strings.TrimSpace(r.FormValue("webhook_url")),
		CompanyName: strings.TrimSpace(r.FormValue("company_name")), Logo: cur.Logo,
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
	if err := s.activate(ctx, set); err != nil {
		s.renderSettings(w, r, sess, set, "", err.Error())
		return
	}
	enc, err := s.seal32(set.OIDCClientSecret)
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
	s.renderSettings(w, r, sess, set, "Settings saved and active.", "")
}
