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
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/maltekiefer/limdm/internal/api"
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

func newOIDCAuthFrom(ctx context.Context, issuer, clientID, secret, publicURL string) (*oidcAuth, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &oidcAuth{
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
		oauth: oauth2.Config{
			ClientID: clientID, ClientSecret: secret, Endpoint: p.Endpoint(),
			RedirectURL: publicURL + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
	}, nil
}

type session struct {
	Email string    `json:"e"`
	Role  string    `json:"r"` // admin | auditor
	IAT   time.Time `json:"i"`
	Last  time.Time `json:"l"`
	Gen   int64     `json:"g"` // session generation of the account at sign in
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

// setCookie sets a cookie for maxAge; maxAge <= 0 deletes it (Max-Age=0 on
// the wire, RFC 6265 5.2.2).
func (s *Server) setCookie(w http.ResponseWriter, name, val string, maxAge time.Duration) {
	age := int(maxAge / time.Second)
	if maxAge <= 0 {
		age, val = -1, ""
	}
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: true, MaxAge: age,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	auth := s.oidc()
	if auth == nil {
		http.NotFound(w, r)
		return
	}
	f := flow{State: randToken(24), Nonce: randToken(24), Verifier: oauth2.GenerateVerifier(), Exp: time.Now().Add(10 * time.Minute)}
	s.setCookie(w, flowCookie, s.seal(f), 10*time.Minute)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.Verifier), oidc.Nonce(f.Nonce)}
	if d := s.settings().AllowedDomain; d != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", d)) // Google account chooser hint, enforced below
	}
	http.Redirect(w, r, auth.oauth.AuthCodeURL(f.State, opts...), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	auth := s.oidc()
	if auth == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	var f flow
	c, err := r.Cookie(flowCookie)
	if err != nil || s.unseal(c.Value, &f) != nil || time.Now().After(f.Exp) ||
		!hmac.Equal([]byte(r.URL.Query().Get("state")), []byte(f.State)) {
		s.log.Warn("oidc login failed", "remote", clientIP(r), "reason", "state")
		http.Error(w, "login expired, start again", http.StatusBadRequest)
		return
	}
	s.setCookie(w, flowCookie, "", -1)
	tok, err := auth.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		s.log.Warn("oidc login failed", "remote", clientIP(r), "reason", "code exchange")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := auth.verifier.Verify(ctx, raw)
	if err != nil || idt.Nonce != f.Nonce {
		s.log.Warn("oidc login failed", "remote", clientIP(r), "reason", "id token")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HD            string `json:"hd"`
	}
	if err := idt.Claims(&claims); err != nil {
		s.log.Warn("oidc login failed", "remote", clientIP(r), "reason", "claims")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	email := strings.ToLower(claims.Email)
	role := s.roleFor(ctx, email, claims.EmailVerified, claims.HD)
	if role == "" {
		if err := s.auditAction(ctx, email, "login.denied", "", "not an admin or auditor", nil); err != nil {
			s.log.Error("audit login.denied", "err", err)
		}
		s.log.Warn("oidc login failed", "remote", clientIP(r), "reason", "not a console user")
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	now := time.Now()
	if err := s.auditAction(ctx, email, "login", "", role, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE console_users SET last_login=now() WHERE email=$1`, email)
		return err
	}); err != nil {
		s.fail(w, err)
		return
	}
	_, gen := s.account(r.Context(), email)
	s.setCookie(w, sessionCookie, s.seal(session{Email: email, Role: role, IAT: now, Last: now, Gen: gen}), maxSession)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) roleFor(ctx context.Context, email string, verified bool, hd string) string {
	if !verified || email == "" {
		return ""
	}
	if set := s.settings(); !api.DomainAllowed(set.OIDCIssuer, email, hd, set.AllowedDomain) {
		return ""
	}
	return s.oidcRole(ctx, email)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.session(w, r); ok && s.csrfOK(r, sess) {
		if err := s.revokeSessions(r.Context(), s.db, sess.Email); err != nil { // sign out everywhere
			s.log.Error("revoke sessions", "err", err)
		}
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
	// Role is re-evaluated on every request: disabling a user in the console
	// takes effect immediately, removing someone from LIMDM_ADMINS at restart.
	if strings.HasPrefix(sess.Email, localPrefix) && !s.settings().LocalLogin || !strings.HasPrefix(sess.Email, localPrefix) && s.oidc() == nil {
		return sess, false
	}
	role, gen := s.account(r.Context(), sess.Email)
	if role == "" || gen != sess.Gen { // disabled, removed, or sessions revoked
		return sess, false
	}
	sess.Role = role
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
