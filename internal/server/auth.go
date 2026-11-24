package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "limdm_session"
	flowCookie    = "limdm_oidc"
	idleTimeout   = 30 * time.Minute
	maxSession    = 8 * time.Hour
)

type oidcAuth struct {
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
}

func newOIDCAuth(ctx context.Context, cfg Config) (*oidcAuth, error) {
	p, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, err
	}
	return &oidcAuth{
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		oauth: oauth2.Config{
			ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCSecret, Endpoint: p.Endpoint(),
			RedirectURL: cfg.PublicURL + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
	}, nil
}

type session struct {
	Email string    `json:"e"`
	Role  string    `json:"r"` // admin | auditor
	IAT   time.Time `json:"i"`
	Last  time.Time `json:"l"`
}

type flow struct {
	State, Nonce, Verifier string
	Exp                    time.Time
}

// signed cookies: base64(json).hex(hmac)
func (s *Server) seal(v any) string {
	b, _ := json.Marshal(v)
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + s.mac(p)
}

func (s *Server) unseal(raw string, v any) error {
	p, m, ok := strings.Cut(raw, ".")
	if !ok || !hmac.Equal([]byte(m), []byte(s.mac(p))) {
		return errors.New("bad signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *Server) mac(p string) string {
	h := hmac.New(sha256.New, s.cfg.SessionKey)
	h.Write([]byte(p))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Server) setCookie(w http.ResponseWriter, name, val string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: true, MaxAge: int(maxAge.Seconds()),
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	f := flow{State: randToken(24), Nonce: randToken(24), Verifier: oauth2.GenerateVerifier(), Exp: time.Now().Add(10 * time.Minute)}
	s.setCookie(w, flowCookie, s.seal(f), 10*time.Minute)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.Verifier), oidc.Nonce(f.Nonce)}
	if s.cfg.AllowedDomain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", s.cfg.AllowedDomain)) // Google account chooser hint, enforced below
	}
	http.Redirect(w, r, s.auth.oauth.AuthCodeURL(f.State, opts...), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var f flow
	c, err := r.Cookie(flowCookie)
	if err != nil || s.unseal(c.Value, &f) != nil || time.Now().After(f.Exp) ||
		!hmac.Equal([]byte(r.URL.Query().Get("state")), []byte(f.State)) {
		http.Error(w, "login expired, start again", http.StatusBadRequest)
		return
	}
	s.setCookie(w, flowCookie, "", -1)
	tok, err := s.auth.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := s.auth.verifier.Verify(ctx, raw)
	if err != nil || idt.Nonce != f.Nonce {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HD            string `json:"hd"`
	}
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	email := strings.ToLower(claims.Email)
	role := s.roleFor(email, claims.EmailVerified, claims.HD)
	if role == "" {
		if err := s.auditAction(ctx, email, "login.denied", "", "not an admin or auditor", nil); err != nil {
			s.log.Error("audit login.denied", "err", err)
		}
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	now := time.Now()
	if err := s.auditAction(ctx, email, "login", "", role, nil); err != nil {
		s.fail(w, err)
		return
	}
	s.setCookie(w, sessionCookie, s.seal(session{Email: email, Role: role, IAT: now, Last: now}), maxSession)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) roleFor(email string, verified bool, hd string) string {
	if !verified || email == "" {
		return ""
	}
	if d := s.cfg.AllowedDomain; d != "" && !strings.EqualFold(hd, d) && !strings.HasSuffix(email, "@"+d) {
		return ""
	}
	switch {
	case slices.Contains(s.cfg.Admins, email):
		return "admin"
	case slices.Contains(s.cfg.Auditors, email):
		return "auditor"
	}
	return ""
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.session(w, r); ok && s.csrfOK(r, sess) {
		if err := s.auditAction(r.Context(), sess.Email, "logout", "", "", nil); err != nil {
			s.log.Error("audit logout", "err", err)
		}
	}
	s.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// session validates the cookie, enforces idle and absolute timeouts and slides
// the idle window.
func (s *Server) session(w http.ResponseWriter, r *http.Request) (session, bool) {
	var sess session
	c, err := r.Cookie(sessionCookie)
	if err != nil || s.unseal(c.Value, &sess) != nil {
		return sess, false
	}
	now := time.Now()
	if now.Sub(sess.Last) > idleTimeout || now.Sub(sess.IAT) > maxSession {
		return sess, false
	}
	// Role is re-evaluated so removing someone from LIMDM_ADMINS takes effect on restart.
	switch {
	case slices.Contains(s.cfg.Admins, sess.Email):
		sess.Role = "admin"
	case slices.Contains(s.cfg.Auditors, sess.Email):
		sess.Role = "auditor"
	default:
		return sess, false
	}
	sess.Last = now
	s.setCookie(w, sessionCookie, s.seal(sess), maxSession-now.Sub(sess.IAT))
	return sess, true
}

func (s *Server) csrfToken(sess session) string {
	return s.mac(fmt.Sprintf("csrf|%s|%d", sess.Email, sess.IAT.UnixNano()))
}

func (s *Server) csrfOK(r *http.Request, sess session) bool {
	if o := r.Header.Get("Origin"); o != "" && o != s.cfg.PublicURL {
		return false
	}
	return hmac.Equal([]byte(r.FormValue("csrf")), []byte(s.csrfToken(sess)))
}
