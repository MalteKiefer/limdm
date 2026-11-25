// Package server implements the LiMDM management server: declarative agent API
// over mTLS, admin web UI with OIDC login, and the audit trail.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

//go:embed schema.sql
var schema string

type Config struct {
	DatabaseURL   string
	Listen        string // admin UI
	PublicURL     string // admin UI URL, used for the OIDC redirect
	TLSCert       string // admin UI certificate (public CA); without it the UI binds to loopback only
	TLSKey        string
	AgentListen   string   // agent API, mTLS terminated here, never by a proxy
	AgentURL      string   // URL agents use, its host goes into the server certificate
	AgentHosts    []string // additional names/IPs for the agent certificate, e.g. the IP older agents enrolled with
	CADir         string
	LocalLogin    bool // local admin accounts with password and TOTP
	OIDCIssuer    string
	OIDCClientID  string
	OIDCSecret    string
	AllowedDomain string
	Admins        []string
	Auditors      []string
	SessionKey    []byte
	ReleaseDir    string
	StaleAfter    time.Duration
}

func ConfigFromEnv() (Config, error) {
	split := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	c := Config{
		DatabaseURL:   os.Getenv("LIMDM_DATABASE_URL"),
		PublicURL:     strings.TrimRight(os.Getenv("LIMDM_PUBLIC_URL"), "/"),
		TLSCert:       os.Getenv("LIMDM_TLS_CERT"),
		TLSKey:        os.Getenv("LIMDM_TLS_KEY"),
		AgentListen:   envOr("LIMDM_AGENT_LISTEN", ":8444"),
		AgentURL:      strings.TrimRight(os.Getenv("LIMDM_AGENT_URL"), "/"),
		CADir:         envOr("LIMDM_CA_DIR", "/var/lib/limdm-server/ca"),
		OIDCIssuer:    os.Getenv("LIMDM_OIDC_ISSUER"),
		OIDCClientID:  os.Getenv("LIMDM_OIDC_CLIENT_ID"),
		OIDCSecret:    os.Getenv("LIMDM_OIDC_CLIENT_SECRET"),
		AllowedDomain: strings.ToLower(os.Getenv("LIMDM_OIDC_ALLOWED_DOMAIN")),
		Admins:        split(os.Getenv("LIMDM_ADMINS")),
		Auditors:      split(os.Getenv("LIMDM_AUDITORS")),
		ReleaseDir:    os.Getenv("LIMDM_RELEASE_DIR"),
		LocalLogin:    os.Getenv("LIMDM_LOCAL_LOGIN") == "true",
		AgentHosts:    split(os.Getenv("LIMDM_AGENT_HOSTS")),
	}
	c.Listen = os.Getenv("LIMDM_LISTEN")
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
		if c.TLSCert != "" {
			c.Listen = ":8443"
		}
	}
	hours, err := strconv.Atoi(envOr("LIMDM_STALE_HOURS", "24"))
	if err != nil || hours < 1 {
		return c, errors.New("LIMDM_STALE_HOURS must be a positive integer")
	}
	c.StaleAfter = time.Duration(hours) * time.Hour
	var missing []string
	required := map[string]string{
		"LIMDM_DATABASE_URL": c.DatabaseURL, "LIMDM_PUBLIC_URL": c.PublicURL, "LIMDM_AGENT_URL": c.AgentURL,
	}
	if c.OIDCIssuer != "" {
		required["LIMDM_OIDC_CLIENT_ID"] = c.OIDCClientID
	}
	for k, v := range required {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing env: %s", strings.Join(missing, ", "))
	}
	c.SessionKey, err = hex.DecodeString(os.Getenv("LIMDM_SESSION_KEY"))
	if err != nil || len(c.SessionKey) < 32 {
		return c, errors.New("LIMDM_SESSION_KEY must be at least 32 bytes hex (openssl rand -hex 32)")
	}
	if c.OIDCIssuer == "" && !c.LocalLogin {
		return c, errors.New("enable at least one login method: LIMDM_OIDC_ISSUER or LIMDM_LOCAL_LOGIN=true")
	}
	if c.OIDCIssuer != "" && len(c.Admins) == 0 {
		return c, errors.New("LIMDM_ADMINS must name at least one admin email")
	}
	if !strings.HasPrefix(c.PublicURL, "https://") {
		return c, errors.New("LIMDM_PUBLIC_URL must be https")
	}
	if u, err := url.Parse(c.AgentURL); err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return c, errors.New("LIMDM_AGENT_URL must be https://host:port")
	}
	if c.TLSCert == "" && !isLoopback(c.Listen) {
		return c, errors.New("without LIMDM_TLS_CERT the admin UI may only listen on loopback (behind a local TLS reverse proxy)")
	}
	return c, nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// requireDBTLS refuses unencrypted or unverified database connections to
// anything but a local socket or loopback.
func requireDBTLS(pc *pgxpool.Config) error {
	cc := pc.ConnConfig
	if strings.HasPrefix(cc.Host, "/") || cc.Host == "localhost" || net.ParseIP(cc.Host).IsLoopback() {
		return nil
	}
	if cc.TLSConfig == nil || cc.TLSConfig.InsecureSkipVerify {
		return errors.New("database connection must use sslmode=verify-full")
	}
	for _, fb := range cc.Fallbacks {
		if fb.TLSConfig == nil {
			return errors.New("database connection must use sslmode=verify-full (no plaintext fallback)")
		}
	}
	return nil
}

type Server struct {
	cfg   Config
	db    *pgxpool.Pool
	ca    *deviceCA
	log   *slog.Logger
	limit limiter
	rt    atomic.Pointer[runtimeState] // settings editable in the UI and the OIDC client built from them
	hooks *http.Client                 // webhook client; nil uses http.DefaultClient (tests inject one)
}

func pgxPoolConfig(databaseURL string) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	return pc, requireDBTLS(pc)
}

func newPool(ctx context.Context, pc *pgxpool.Config) (*pgxpool.Pool, error) {
	return pgxpool.NewWithConfig(ctx, pc)
}

func New(ctx context.Context, cfg Config, log *slog.Logger) (*Server, error) {
	pc, err := pgxPoolConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	db, err := newPool(ctx, pc)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}
	ca, err := loadOrCreateCA(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("device CA: %w", err)
	}

	log.Info("device CA ready", "fingerprint", ca.Fingerprint())
	s := &Server{cfg: cfg, db: db, ca: ca, log: log}
	if err := s.seedConsoleUsers(ctx); err != nil {
		return nil, err
	}
	if err := s.loadSettings(ctx); err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	return s, nil
}

func (s *Server) Close() { s.db.Close() }

// Background runs periodic jobs until ctx ends.
func (s *Server) Background(ctx context.Context) {
	go s.googleSyncLoop(ctx)
	go s.historyLoop(ctx)
}

// AdminHandler serves the web UI.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.db.Ping(r.Context()); err != nil {
			http.Error(w, "db down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	s.scimRoutes(mux)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /lang/{lang}", s.setLang)
	mux.HandleFunc("GET /login/oidc", s.login)
	mux.HandleFunc("POST /login/local", s.localLogin)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	s.webRoutes(mux)
	return securityHeaders(mux)
}

// AgentHandler serves the agent API. Everything except fetching the CA and
// enrolling requires a valid, current client certificate.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.ca.pem)
	})
	mux.HandleFunc("POST /api/v1/enroll", s.enroll)
	mux.HandleFunc("POST /api/v1/renew", s.deviceAuth(s.renew, true))
	mux.HandleFunc("POST /api/v1/checkin", s.deviceAuth(s.checkin, false))
	mux.HandleFunc("GET /api/v1/releases/{file}", s.deviceAuth(s.release, false))
	return securityHeaders(mux)
}

// AgentTLSConfig: TLS 1.3 only, server certificate from the device CA. The
// handshake requests the client certificate and proves possession of its key;
// deviceAuth verifies it against the device CA, so renewal can accept an
// expired certificate.
func (s *Server) AgentTLSConfig() (*tls.Config, error) {
	u, _ := url.Parse(s.cfg.AgentURL)
	cert, err := s.ca.serverCert(append([]string{u.Hostname()}, s.cfg.AgentHosts...))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    s.ca.pool(),
	}, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: with no-referrer browsers send "Origin: null"
		// on form posts, which the CSRF origin check must reject.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ---- agent API ----

type ctxKey int

const deviceKey ctxKey = 1

// expiredRenewGrace is how long after expiry a device may still renew, so a
// laptop that was offline for a while does not need a new enrollment.
const expiredRenewGrace = 180 * 24 * time.Hour

// verifyDevice checks the client certificate against the device CA. With
// allowExpired, a certificate that expired less than expiredRenewGrace ago is
// verified as of its last valid minute.
func (s *Server) verifyDevice(r *http.Request, allowExpired bool) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("client certificate required")
	}
	leaf := r.TLS.PeerCertificates[0]
	opts := x509.VerifyOptions{Roots: s.ca.pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if now := time.Now(); allowExpired && now.After(leaf.NotAfter) && now.Sub(leaf.NotAfter) < expiredRenewGrace {
		opts.CurrentTime = leaf.NotAfter.Add(-time.Minute)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, err
	}
	return leaf, nil
}

// deviceAuth accepts only the certificate currently registered for the device,
// so retiring a device or renewing its certificate revokes the old one at once.
func (s *Server) deviceAuth(next http.HandlerFunc, allowExpired bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		leaf, err := s.verifyDevice(r, allowExpired)
		if err != nil {
			http.Error(w, "valid client certificate required", http.StatusUnauthorized)
			return
		}
		id := leaf.Subject.CommonName
		var current string
		err = s.db.QueryRow(r.Context(), `SELECT cert_serial FROM devices WHERE id=$1 AND NOT retired`, id).Scan(&current)
		if err != nil || current != leaf.SerialNumber.Text(16) {
			s.log.Warn("rejected device certificate", "device", id, "serial", leaf.SerialNumber.Text(16))
			http.Error(w, "certificate revoked", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), deviceKey, id)))
	}
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var blueprintID *int64
	err = tx.QueryRow(ctx, `UPDATE enroll_tokens SET uses_left = uses_left - 1
		WHERE token_hash=$1 AND uses_left > 0 AND expires_at > now() RETURNING blueprint_id`, sha(req.Token)).Scan(&blueprintID)
	if err != nil {
		s.log.Warn("enroll rejected", "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired token", http.StatusForbidden)
		return
	}
	id := hex.EncodeToString(sha(randToken(32))[:16])
	cert, serial, notAfter, err := s.ca.signCSR(req.CSR, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, machine_id, blueprint_id) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, serial, notAfter, truncate(req.Hostname, 255), truncate(req.MachineID, 64), blueprintID); err != nil {
		s.fail(w, err)
		return
	}
	if err := audit(ctx, tx, "device:"+id, "device.enroll", id, req.Hostname+" cert "+serial); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, api.EnrollResponse{DeviceID: id, Cert: cert})
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	var req api.RenewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cert, serial, notAfter, err := s.ca.signCSR(req.CSR, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = s.auditAction(r.Context(), "device:"+id, "device.cert_renew", id, serial, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE devices SET cert_serial=$2, cert_not_after=$3 WHERE id=$1`, id, serial, notAfter)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, api.EnrollResponse{DeviceID: id, Cert: cert})
}

func countFailing(checks []api.CheckResult) int {
	n := 0
	for _, c := range checks {
		if c.Status == "fail" {
			n++
		}
	}
	return n
}

func (s *Server) checkin(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	var req api.CheckinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)

	var users []byte
	var statusHash, pkgHash string
	err = tx.QueryRow(ctx, `UPDATE devices SET agent_version=$2, last_seen=now() WHERE id=$1 RETURNING users, status_hash, packages_hash`,
		id, truncate(req.AgentVersion, 32)).Scan(&users, &statusHash, &pkgHash)
	if err != nil {
		s.fail(w, err)
		return
	}
	if st := req.Status; st != nil {
		inv, _ := json.Marshal(st.Inventory)
		checks, _ := json.Marshal(st.Checks)
		decl, _ := json.Marshal(st.Declarations)
		if _, err := tx.Exec(ctx, `UPDATE devices SET hostname=$2, inventory=$3, checks=$4, decl_status=$5, failing=$6, status_hash=$7 WHERE id=$1`,
			id, truncate(st.Inventory.Hostname, 255), string(inv), string(checks), string(decl), countFailing(st.Checks), req.StatusHash); err != nil {
			s.fail(w, err)
			return
		}
		statusHash = req.StatusHash
	}
	if err := recordMetrics(ctx, tx, id, req.Metrics); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.escrowKeys(ctx, tx, id, req.RecoveryKeys); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Packages != nil {
		pk, _ := json.Marshal(req.Packages)
		if _, err := tx.Exec(ctx, `UPDATE devices SET packages=$2, packages_hash=$3 WHERE id=$1`, id, string(pk), req.PackagesHash); err != nil {
			s.fail(w, err)
			return
		}
		pkgHash = req.PackagesHash
	}
	for _, res := range req.Results {
		status := "failed"
		if res.OK {
			status = "ok"
		}
		if _, err := tx.Exec(ctx, `UPDATE commands SET status=$3, output=$4, updated_at=now() WHERE id=$1 AND device_id=$2 AND status='sent'`,
			res.ID, id, status, truncate(res.Output, 64<<10)); err != nil {
			s.fail(w, err)
			return
		}
		if err := audit(ctx, tx, "device:"+id, "command.result", strconv.FormatInt(res.ID, 10), status); err != nil {
			s.fail(w, err)
			return
		}
	}
	for i, ev := range req.Events {
		if i >= 500 {
			break
		}
		if err := audit(ctx, tx, "device:"+id, "agent.event", id, truncate(ev, 2000)); err != nil {
			s.fail(w, err)
			return
		}
	}

	resp := api.CheckinResponse{ServerTime: time.Now().UTC(),
		NeedStatus: statusHash != req.StatusHash, NeedPackages: pkgHash != req.PackagesHash}
	decls, err := effectiveDeclarations(ctx, tx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp.DeclarationsToken = api.DeclarationsToken(decls)
	if resp.DeclarationsToken != req.DeclarationsToken {
		resp.Declarations = decls
	}
	pol, _ := api.Compose(decls)
	event, err := s.enforceCompliance(ctx, tx, id, pol.Compliance, time.Now().UTC())
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := json.Unmarshal(users, &resp.Users); err != nil {
		s.fail(w, err)
		return
	}
	if resp.RecoveryRotate, err = s.rotations(ctx, tx, id); err != nil {
		s.fail(w, err)
		return
	}
	rows, err := tx.Query(ctx, `UPDATE commands SET status='sent', updated_at=now() WHERE device_id=$1 AND status='pending' RETURNING id, type, payload`, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	resp.Commands, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.Command, error) {
		var c api.Command
		return c, row.Scan(&c.ID, &c.Type, &c.Payload)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.fail(w, err)
		return
	}
	s.sendWebhook(event)
	if rel, ok := s.releaseFor(req.Arch); ok && api.NewerVersion(rel.Version, req.AgentVersion) {
		resp.AgentUpdate = &rel
	}
	writeJSON(w, resp)
}

// ---- releases ----

// manifest.json in ReleaseDir is written by `limdm-server release`.
func (s *Server) releaseFor(arch string) (api.Release, bool) {
	if s.cfg.ReleaseDir == "" {
		return api.Release{}, false
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.ReleaseDir, "manifest.json"))
	if err != nil {
		return api.Release{}, false
	}
	var rels []api.Release
	if json.Unmarshal(b, &rels) != nil {
		return api.Release{}, false
	}
	for _, r := range rels {
		if r.Arch == arch {
			return r, true
		}
	}
	return api.Release{}, false
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if s.cfg.ReleaseDir == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") || name == "manifest.json" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.ReleaseDir, name))
}

// ---- audit ----

// audit appends a hash chained entry. Each hash covers the previous hash, so
// any later modification of a row breaks verification of every following row.
func audit(ctx context.Context, tx pgx.Tx, actor, action, target, detail string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7363)`); err != nil {
		return err
	}
	prev := make([]byte, 32)
	if err := tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	_, err := tx.Exec(ctx, `INSERT INTO audit_log(at, actor, action, target, detail, prev, hash) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		at, actor, action, target, detail, prev, auditHash(prev, at, actor, action, target, detail))
	return err
}

func auditHash(prev []byte, at time.Time, fields ...string) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(at.UnixMicro())))
	for _, f := range fields {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(f))))
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

// auditAction runs an admin change and its audit entry in one transaction.
func (s *Server) auditAction(ctx context.Context, actor, action, target, detail string, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if fn != nil {
		if err := fn(tx); err != nil {
			return err
		}
	}
	if err := audit(ctx, tx, actor, action, target, detail); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n[truncated]"
}
