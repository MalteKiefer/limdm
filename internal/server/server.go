// Package server implements the LiMDM management server: declarative agent API
// over mTLS, admin web UI with OIDC login, and the audit trail.
package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"hash/crc32"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	ReleaseRepo   string   // GitHub owner/name the install script downloads agent packages from
	GeoIPURL      string   // location lookup for device addresses, the IP is appended; "" disables
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
		ReleaseDir:    envOr("LIMDM_RELEASE_DIR", "/var/lib/limdm-server/agent-releases"),
		LocalLogin:    os.Getenv("LIMDM_LOCAL_LOGIN") == "true",
		AgentHosts:    split(os.Getenv("LIMDM_AGENT_HOSTS")),
		ReleaseRepo:   os.Getenv("LIMDM_RELEASE_REPO"),
		GeoIPURL:      envOr("LIMDM_GEOIP_URL", "https://ipwho.is/"),
	}
	if c.GeoIPURL == "off" {
		c.GeoIPURL = ""
	}
	if c.ReleaseRepo == "" {
		c.ReleaseRepo = "MalteKiefer/limdm"
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
	cfg    Config
	db     *pgxpool.Pool
	ca     *deviceCA
	cmdKey ed25519.PrivateKey // signs commands (command.key next to the CA)
	log    *slog.Logger
	limit  limiter
	rt     atomic.Pointer[runtimeState] // settings editable in the UI and the OIDC client built from them
	hooks  *http.Client                 // webhook client; nil uses http.DefaultClient (tests inject one)
	geoSem chan struct{}                // one location lookup at a time

	saveMu     sync.Mutex  // serializes settings saves
	rediscover atomic.Bool // OIDC discovery failed at startup and is retried
	// ponytail: per process; a database row lock when SCIM runs on several instances
	scimMu sync.Mutex // serializes SCIM PATCH read-modify-write
	fleet  atomic.Pointer[fleetCache]
	// first broken audit entry found by the last full verification, 0 = intact
	auditBroken atomic.Int64
}

func pgxPoolConfig(databaseURL string) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	// explicit limits instead of the pgx default of max(4, CPUs); a pool_max_conns
	// parameter in the URL still wins
	if !strings.Contains(databaseURL, "pool_max_conns") {
		pc.MaxConns = 32
	}
	pc.MinConns = 2
	pc.MaxConnIdleTime = 5 * time.Minute
	// a hanging query or a transaction left open must not hold connections
	// until the pool runs dry; parameters in the URL still win
	for k, v := range map[string]string{"statement_timeout": "30s", "idle_in_transaction_session_timeout": "60s", "lock_timeout": "10s"} {
		if _, set := pc.ConnConfig.RuntimeParams[k]; !set {
			pc.ConnConfig.RuntimeParams[k] = v
		}
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
	cmdKey, err := loadOrCreateCommandKey(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("command key: %w", err)
	}
	itemKey = cmdKey
	if err := signExistingItems(ctx, db, cfg.CADir); err != nil {
		return nil, fmt.Errorf("signing library items: %w", err)
	}
	s := &Server{cfg: cfg, db: db, ca: ca, cmdKey: cmdKey, log: log, geoSem: make(chan struct{}, 1)}
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
	for name, loop := range map[string]func(context.Context){"google sync": s.googleSyncLoop, "history": s.historyLoop,
		"releases": s.releaseLoop, "catalog icons": s.iconLoop} {
		go s.background(ctx, name, loop)
	}
	go s.rediscoverLoop(ctx)
}

// background runs a loop for the life of the server: a panic is logged and
// the loop restarts after a minute instead of taking the server down. With
// several server instances only the one holding the loop's advisory lock
// runs it, so syncs and downloads do not happen twice.
func (s *Server) background(ctx context.Context, name string, loop func(context.Context)) {
	key := int64(crc32.ChecksumIEEE([]byte("limdm-loop:" + name)))
	for ctx.Err() == nil {
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("background loop panicked", "loop", name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				}
			}()
			conn, err := s.db.Acquire(ctx)
			if err != nil {
				return
			}
			defer conn.Release()
			var leader bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&leader); err != nil || !leader {
				return // another instance runs it
			}
			defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key) }()
			loop(ctx)
		}()
		select {
		case <-ctx.Done():
		case <-time.After(time.Minute):
		}
	}
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
	mux.HandleFunc("GET /datefmt/{format}", s.setDateFormat)
	mux.HandleFunc("GET /branding/logo.png", s.logo)
	mux.HandleFunc("GET /install.sh", s.installScript)
	mux.HandleFunc("GET /login/oidc", s.login)
	mux.HandleFunc("POST /login/local", s.localLogin)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	s.webRoutes(mux)
	s.apiRoutes(mux)
	return securityHeaders(s.consoleFilter(mux))
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
	mux.HandleFunc("POST /api/v1/poll", s.deviceAuth(s.poll, false))
	mux.HandleFunc("GET /api/v1/agent-packages/{version}/{file}", s.deviceAuth(s.agentPackage, false))
	mux.HandleFunc("GET /api/v1/catalog/icons/{id}", s.deviceAuth(s.catalogIcon, false))
	mux.HandleFunc("GET /api/v1/catalog/search", s.deviceAuth(s.deviceLimit(30, s.flathubSearchJSON), false))
	mux.HandleFunc("GET /api/v1/catalog/flathub-icon", s.deviceAuth(s.deviceLimit(300, s.flathubIcon), false))
	return securityHeaders(mux)
}

// AgentTLSConfig: TLS 1.3 only, server certificate from the device CA. The
// handshake requests the client certificate and proves possession of its key;
// deviceAuth verifies it against the device CA, so renewal can accept an
// expired certificate.
func (s *Server) AgentTLSConfig() (*tls.Config, error) {
	u, _ := url.Parse(s.cfg.AgentURL)
	names := append([]string{u.Hostname()}, s.cfg.AgentHosts...)
	cert, err := s.ca.serverCert(names)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// the certificate lives a year; a server running longer issues a new
		// one a month before it expires instead of failing every handshake
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()
			if time.Until(cert.Leaf.NotAfter) < 30*24*time.Hour {
				if next, err := s.ca.serverCert(names); err == nil {
					cert = next
				} else {
					s.log.Error("renew agent TLS certificate", "err", err)
				}
			}
			c := cert // a copy: handshakes read it after the lock is released
			return &c, nil
		},
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  s.ca.pool(),
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

// deviceLimit allows a device n requests per ten minutes to an endpoint that
// makes the server call out (Flathub), so one device cannot exhaust it.
func (s *Server) deviceLimit(n int, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := r.Context().Value(deviceKey).(string)
		if !s.limit.allow("dev:"+r.URL.Path+":"+id, n, 10*time.Minute) {
			problem(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	// no HTML escaping: declaration payloads travel byte for byte, so the
	// agent's declaration tokens match the server's (scripts with "&&")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		slog.Warn("writing a JSON response failed", "err", err) // the client went away
	}
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
			problem(w, http.StatusUnauthorized, "valid client certificate required")
			return
		}
		id, serial := leaf.Subject.CommonName, leaf.SerialNumber.Text(16)
		var current string
		var pending *string
		err = s.db.QueryRow(r.Context(), `SELECT cert_serial, pending_serial FROM devices WHERE id=$1 AND NOT retired`, id).Scan(&current, &pending)
		switch {
		case err != nil && !errors.Is(err, pgx.ErrNoRows):
			s.failAPI(w, err) // a database outage is not a revoked certificate
			return
		case err == nil && serial == current:
		case err == nil && pending != nil && serial == *pending:
			// first use of a renewed certificate: it replaces (and revokes) the previous one
			if err := s.auditAction(r.Context(), "device:"+id, "device.cert_activate", id, serial, func(tx pgx.Tx) error {
				_, err := tx.Exec(r.Context(), `UPDATE devices SET cert_serial=pending_serial, cert_not_after=pending_not_after,
					pending_serial=NULL, pending_not_after=NULL WHERE id=$1 AND pending_serial=$2`, id, serial)
				return err
			}); err != nil {
				s.failAPI(w, err)
				return
			}
		default:
			s.log.Warn("rejected device certificate", "device", id, "serial", serial)
			problem(w, http.StatusForbidden, "certificate revoked")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), deviceKey, id)))
	}
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	// unauthenticated: limit attempts per address before touching the database
	// only failures count: a mass rollout behind one office NAT must not hit it
	if s.limit.over("enroll:"+rateKey(r), 20, 5*time.Minute) {
		problem(w, http.StatusTooManyRequests, "too many enrollment attempts, try again later")
		return
	}
	var req api.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var blueprintID *int64
	err = tx.QueryRow(ctx, `UPDATE enroll_tokens SET uses_left = uses_left - 1
		WHERE token_hash=$1 AND uses_left > 0 AND expires_at > now() RETURNING blueprint_id`, sha(req.Token)).Scan(&blueprintID)
	if err != nil {
		s.limit.allow("enroll:"+rateKey(r), 20, 5*time.Minute) // counts the failure
		s.log.Warn("enroll rejected", "remote", clientIP(r))
		problem(w, http.StatusForbidden, "invalid or expired token")
		return
	}
	id := hex.EncodeToString(sha(randToken(32))[:16])
	cert, serial, notAfter, err := s.ca.signCSR(req.CSR, id)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid certificate signing request")
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, machine_id, blueprint_id) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, serial, notAfter, truncate(req.Hostname, 255), truncate(req.MachineID, 64), blueprintID); err != nil {
		s.failAPI(w, err)
		return
	}
	if err := audit(ctx, tx, "device:"+id, "device.enroll", id, truncate(req.Hostname, 255)+" cert "+serial); err != nil {
		s.failAPI(w, err)
		return
	}
	// the same machine ID enrolled again (reinstall): reported, not acted on.
	// The ID is readable by every user and cannot prove anything, so retiring
	// the older record stays an admin decision in the console.
	if mid := strings.TrimSpace(req.MachineID); mid != "" {
		rows, err := tx.Query(ctx, `SELECT id FROM devices WHERE machine_id=$1 AND id<>$2 AND NOT retired`, truncate(mid, 64), id)
		if err != nil {
			s.failAPI(w, err)
			return
		}
		old, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			s.failAPI(w, err)
			return
		}
		for _, o := range old {
			if err := audit(ctx, tx, "device:"+id, "device.duplicate", o, "enrolled again as "+id+" with the same machine ID; retire the older record if it is a reinstall"); err != nil {
				s.failAPI(w, err)
				return
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		s.failAPI(w, err)
		return
	}
	s.notifyDevice(id, []notice{{Type: "device.enrolled", Severity: "info", Title: "Device enrolled: " + truncate(req.Hostname, 80),
		Text: "A new device joined the fleet.", Hostname: truncate(req.Hostname, 255)}})
	writeJSON(w, api.EnrollResponse{DeviceID: id, Cert: cert})
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	var req api.RenewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	cert, serial, notAfter, err := s.ca.signCSR(req.CSR, id)
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid certificate signing request")
		return
	}
	err = s.auditAction(r.Context(), "device:"+id, "device.cert_renew", id, serial, func(tx pgx.Tx) error {
		// the current certificate stays valid until the new one is used once
		_, err := tx.Exec(r.Context(), `UPDATE devices SET pending_serial=$2, pending_not_after=$3 WHERE id=$1`, id, serial, notAfter)
		return err
	})
	if err != nil {
		s.failAPI(w, err)
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

// poll is the agent's cheap minute-by-minute question whether something waits
// for it (commands, a requested update); the agent then checks in at once.
func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	ctx := r.Context()
	var commands bool
	var running, state, version string
	var at *time.Time
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM commands WHERE device_id=$1 AND status='pending'),
		agent_version, update_state, update_version, update_at FROM devices WHERE id=$1`, id).Scan(&commands, &running, &state, &version, &at); err != nil {
		s.failAPI(w, err)
		return
	}
	pending := commands
	if !pending {
		// a desktop user of this device was suspended or deleted in the directory
		// since the last check in: the device locks the account at once
		if err := s.db.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM devices d, jsonb_array_elements(d.users) u
			WHERE d.id=$1 AND d.last_seen IS NOT NULL
			AND NOT EXISTS (SELECT 1 FROM dir_users a WHERE a.active AND lower(a.email)=lower(u->>'email')) AND (
				EXISTS (SELECT 1 FROM dir_users du WHERE (lower(du.email)=lower(u->>'email') OR lower(u->>'email') = ANY(du.previous_emails))
					AND NOT du.active AND du.updated_at > d.last_seen)
				OR EXISTS (SELECT 1 FROM dir_tombstones t WHERE t.email=lower(u->>'email') AND t.removed_at > d.last_seen)))`, id).Scan(&pending); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	if !pending {
		// agent updates can be security fixes: a due version triggers a check in
		// at once, unless it was just handed out and is being installed
		rel, clearTarget, err := s.dueUpdate(ctx, s.db, id, running)
		if err != nil {
			s.failAPI(w, err)
			return
		}
		installing := rel != nil && state == "offered" && version == rel.Version && at != nil && time.Since(*at) < 20*time.Minute
		pending = clearTarget || (rel != nil && !installing)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.PollResponse{Pending: pending})
}

func (s *Server) checkin(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	var req api.CheckinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	defer tx.Rollback(ctx)
	// one check in per device at a time: a retry or a poll triggered check in
	// running in parallel would otherwise overwrite this one's results
	if _, err := tx.Exec(ctx, `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE`, id); err != nil {
		s.failAPI(w, err)
		return
	}

	var users []byte
	var statusHash, pkgHash string
	var relocate bool
	ip := remoteIP(r)
	err = tx.QueryRow(ctx, `UPDATE devices SET agent_version=$2, last_seen=now(), external_ip=$3 WHERE id=$1
		RETURNING users, status_hash, packages_hash, $3 <> '' AND geo->>'ip' IS DISTINCT FROM $3 AND (geo_at IS NULL OR geo_at < now() - interval '1 hour')`,
		id, truncate(req.AgentVersion, 32), ip).Scan(&users, &statusHash, &pkgHash, &relocate)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	if st := req.Status; st != nil {
		if _, err := tx.Exec(ctx, `UPDATE devices SET hostname=$2, inventory=$3, checks=$4, decl_status=$5, failing=$6, status_hash=$7 WHERE id=$1`,
			id, truncate(st.Inventory.Hostname, 255), jsonb(st.Inventory), jsonb(st.Checks), jsonb(st.Declarations), countFailing(st.Checks), truncate(req.StatusHash, 128)); err != nil {
			s.failAPI(w, err)
			return
		}
		statusHash = req.StatusHash
	}
	if err := recordMetrics(ctx, tx, id, req.Metrics); err != nil {
		s.failAPI(w, err)
		return
	}
	if err := s.escrowKeys(ctx, tx, id, req.RecoveryKeys); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Packages != nil {
		if _, err := tx.Exec(ctx, `UPDATE devices SET packages=$2, packages_hash=$3 WHERE id=$1`, id, jsonb(req.Packages), truncate(req.PackagesHash, 128)); err != nil {
			s.failAPI(w, err)
			return
		}
		pkgHash = req.PackagesHash
	}
	var notices []notice // sent after the commit
	for _, res := range req.Results {
		status := "failed"
		if res.OK {
			status = "ok"
		}
		var typ string
		err := tx.QueryRow(ctx, `UPDATE commands SET status=$3, output=$4, updated_at=now(),
			payload=CASE WHEN type IN ('user_create','user_password') THEN '' ELSE payload END WHERE id=$1 AND device_id=$2 AND status='sent'
			RETURNING type`, res.ID, id, status, truncate(res.Output, 64<<10)).Scan(&typ)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.failAPI(w, err)
			return
		}
		if !res.OK && slices.Contains([]string{"lock", "unlock", "lost", "found", "wipe", "script"}, typ) {
			notices = append(notices, notice{Type: "command.failed", Severity: "critical", Title: "Command failed: " + typ,
				Text: truncate(strings.TrimSpace(res.Output), 500)})
		}
		if err := audit(ctx, tx, "device:"+id, "command.result", strconv.FormatInt(res.ID, 10), status); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	tamperEvent, err := s.storeEvents(ctx, tx, id, req.Events)
	if err != nil {
		s.failAPI(w, err)
		return
	}

	resp := api.CheckinResponse{ServerTime: time.Now().UTC(), CommandKey: hex.EncodeToString(s.cmdKey.Public().(ed25519.PublicKey)),
		NeedStatus: statusHash != req.StatusHash, NeedPackages: pkgHash != req.PackagesHash}
	res, err := resolveDevice(ctx, tx, id)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	decls := res.Decls
	pol, _ := api.Compose(decls)
	catalog, err := s.deviceCatalog(ctx, tx, id, res.Chain, pol.Extra.SoftwareStore)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	if err := recordAppRequests(ctx, tx, id, req.AppRequests, catalog); err != nil {
		s.failAPI(w, err)
		return
	}
	if len(req.AppRequests) > 0 { // the device sees its new request states in this answer
		if catalog, err = s.deviceCatalog(ctx, tx, id, res.Chain, pol.Extra.SoftwareStore); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	if catalog.Hash != req.CatalogHash {
		resp.Catalog = catalog
	}
	resp.DeclarationsToken = api.DeclarationsToken(decls)
	if resp.DeclarationsToken != req.DeclarationsToken {
		resp.Declarations = decls
	}
	if !pol.Privacy.NetworkInfo {
		// the public address and its location are network data too
		relocate = false
		if err := forgetPublicAddress(ctx, tx, id); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	event, err := s.enforceCompliance(ctx, tx, id, pol.Compliance, time.Now().UTC())
	if err != nil {
		s.failAPI(w, err)
		return
	}
	if err := json.Unmarshal(users, &resp.Users); err != nil {
		s.failAPI(w, err)
		return
	}
	// people deactivated in the directory (SCIM, Google) lose their device accounts:
	// the agent locks accounts that are no longer listed
	listed := resp.Users
	if resp.Users, err = activeUsers(ctx, tx, resp.Users); err != nil {
		s.failAPI(w, err)
		return
	}
	// notify once per disabled user and device, not at every check in
	var notified, disabled []string
	if err := tx.QueryRow(ctx, `SELECT users_disabled FROM devices WHERE id=$1`, id).Scan(&notified); err != nil {
		s.failAPI(w, err)
		return
	}
	for _, u := range listed {
		if !slices.ContainsFunc(resp.Users, func(k api.User) bool { return k.Username == u.Username }) {
			disabled = append(disabled, u.Username)
			if !slices.Contains(notified, u.Username) {
				notices = append(notices, notice{Type: "directory.user_disabled", Severity: "warning",
					Title: "Device user disabled: " + u.Email, Text: "The account " + u.Username + " is locked on the device and its sessions end."})
			}
		}
	}
	if !slices.Equal(notified, disabled) {
		if _, err := tx.Exec(ctx, `UPDATE devices SET users_disabled=$2 WHERE id=$1`, id, append([]string{}, disabled...)); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	if len(req.AppRequests) > 0 {
		var apps []string
		for i, ar := range req.AppRequests {
			if i == 5 {
				apps = append(apps, fmt.Sprintf("and %d more", len(req.AppRequests)-5))
				break
			}
			apps = append(apps, truncate(firstNonEmpty(ar.App, ar.Name, ar.Flatpak), 80)+" ("+truncate(ar.User, 64)+")")
		}
		notices = append(notices, notice{Type: "catalog.request", Severity: "info", Title: "App requested",
			Text: strings.Join(apps, ", ") + ". Decide under Software, Requests."})
	}
	if u := req.UpdateResult; u != nil && !u.OK {
		notices = append(notices, notice{Type: "agent.update_failed", Severity: "warning", Title: "Agent update failed: " + u.To,
			Text: fmt.Sprintf("%s to %s failed (rolled back: %v). %s", u.From, u.To, u.RolledBack, truncate(u.Detail, 300))})
	}
	if b := s.branding(); b.Hash != req.BrandingHash {
		resp.Branding = &b
	}
	if err := s.recordUpdateResult(ctx, tx, id, req.UpdateResult); err != nil {
		s.failAPI(w, err)
		return
	}
	if resp.AgentUpdate, err = s.offerUpdate(ctx, tx, id, req.AgentVersion); err != nil {
		s.failAPI(w, err)
		return
	}
	if resp.RecoveryRotate, err = s.rotations(ctx, tx, id); err != nil {
		s.failAPI(w, err)
		return
	}
	if resp.Commands, err = s.deliverCommands(ctx, tx, id); err != nil {
		s.failAPI(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.failAPI(w, err)
		return
	}
	if relocate {
		go s.locate(id, ip) //nolint:gosec // G118: the lookup outlives the request on purpose
	}
	s.sendWebhook(event)
	s.sendWebhook(tamperEvent)
	for _, ev := range []*webhookEvent{event, tamperEvent} {
		if ev != nil {
			notices = append(notices, noticeOf(ev))
		}
	}
	s.notifyDevice(id, notices)
	writeJSON(w, resp)
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

// problem answers the agent API with RFC 9457 problem details, so clients
// can tell errors apart by status and type instead of parsing text.
func problem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "detail": detail})
}

// failAPI logs an internal error and answers with a generic problem.
func (s *Server) failAPI(w http.ResponseWriter, err error) {
	s.log.Error("agent request failed", "err", err)
	problem(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// truncate makes text from devices and users storable: PostgreSQL TEXT takes
// neither NUL bytes nor invalid UTF-8. The result is at most n bytes and cut
// on a character boundary.
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "\uFFFD")
	if len(s) <= n {
		return s
	}
	suffix := "…"
	if n >= 1000 {
		suffix = "\n[truncated]"
	}
	cut := max(n-len(suffix), 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// jsonb encodes v for a JSONB column: nil slices become [] (not the JSON
// null that jsonb_array_* functions reject) and NUL characters, which JSONB
// refuses, are dropped from every string.
func jsonb(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return "[]"
	}
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return string(b)
	}
	var x any
	if json.Unmarshal(b, &x) != nil {
		return "[]"
	}
	var clean func(any) any
	clean = func(v any) any {
		switch t := v.(type) {
		case string:
			return strings.ReplaceAll(t, "\x00", "")
		case []any:
			for i := range t {
				t[i] = clean(t[i])
			}
		case map[string]any:
			m := make(map[string]any, len(t))
			for k, e := range t {
				m[strings.ReplaceAll(k, "\x00", "")] = clean(e)
			}
			return m
		}
		return v
	}
	b, _ = json.Marshal(clean(x))
	return string(b)
}

// consoleFilter refuses console requests from networks outside the allowed
// list or in the blocked list. Health checks, SCIM (bearer token, the
// identity provider's addresses) and the install script for devices stay
// reachable.
func (s *Server) consoleFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/healthz" || p == "/install.sh" || strings.HasPrefix(p, "/scim/") {
			next.ServeHTTP(w, r)
			return
		}
		if rt := s.rt.Load(); rt != nil && !consoleAllowed(rt, clientIP(r)) {
			ip := "invalid"
			if a, err := netip.ParseAddr(clientIP(r)); err == nil {
				ip = a.String() // parsed, never the raw header text
			}
			s.log.Warn("console request refused by network list", "ip", ip)
			http.Error(w, "access from this network is not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// storeEvents saves the device's event lines; tamper reports also go to the
// chained audit log and come back as a webhook event.
func (s *Server) storeEvents(ctx context.Context, tx pgx.Tx, id string, events []string) (*webhookEvent, error) {
	var tamper, evText []string
	var evAt []time.Time
	for i, ev := range events {
		if i >= 500 {
			break
		}
		at, msg := time.Now().UTC(), ev
		if ts, rest, ok := strings.Cut(ev, " "); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				at, msg = t, rest
			}
		}
		// only the event itself, not text inside it (script output names
		// anything): "<time> tamper: <message>"
		if rest, ok := strings.CutPrefix(msg, "tamper: "); ok { // security relevant: chained audit log
			tamper = append(tamper, rest)
			if err := audit(ctx, tx, "device:"+id, "agent.tamper", id, truncate(ev, 2000)); err != nil {
				return nil, err
			}
			continue
		}
		evAt, evText = append(evAt, at), append(evText, truncate(msg, 2000))
	}
	if len(evText) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO device_events(device_id, at, detail) SELECT $1, a, d FROM unnest($2::timestamptz[], $3::text[]) AS e(a, d)`,
			id, evAt, evText); err != nil {
			return nil, err
		}
	}
	if len(tamper) == 0 {
		return nil, nil
	}
	var host string
	if err := tx.QueryRow(ctx, `UPDATE devices SET tampered_at=now() WHERE id=$1 RETURNING hostname`, id).Scan(&host); err != nil {
		return nil, err
	}
	return &webhookEvent{Type: "device.tamper", DeviceID: id, Hostname: host, Detail: strings.Join(tamper, "; "),
		Console: s.cfg.PublicURL + "/devices/" + id}, nil
}

// deliverCommands hands out pending commands. They are delivered until a
// result arrives (the agent ignores IDs it already ran), so a lost response
// cannot drop them; after 7 days they expire and secrets in them are cleared.
func (s *Server) deliverCommands(ctx context.Context, tx pgx.Tx, id string) ([]api.Command, error) {
	if _, err := tx.Exec(ctx, `UPDATE commands SET status='expired', updated_at=now(),
		payload=CASE WHEN type IN ('user_create','user_password') THEN '' ELSE payload END
		WHERE device_id=$1 AND status IN ('pending','sent') AND created_at < now() - interval '7 days'`, id); err != nil {
		return nil, err
	}
	// RETURNING has no order; the agent runs commands in the order received,
	// so "install updates" before "restart" must stay in that order
	rows, err := tx.Query(ctx, `WITH sent AS (UPDATE commands SET status='sent', updated_at=now() WHERE device_id=$1 AND status IN ('pending','sent')
		RETURNING id, type, payload, created_at, signature) SELECT * FROM sent ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	cmds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.Command, error) {
		var c api.Command
		return c, row.Scan(&c.ID, &c.Type, &c.Payload, &c.CreatedAt, &c.Signature)
	})
	if err != nil {
		return nil, err
	}
	return cmds, s.attachRecoveryKeys(ctx, tx, id, cmds)
}

// noticeOf turns a compliance or tamper webhook event into a notice.
func noticeOf(ev *webhookEvent) notice {
	n := notice{Type: ev.Type, DeviceID: ev.DeviceID, Hostname: ev.Hostname, URL: ev.Console}
	switch ev.Type {
	case "device.tamper":
		n.Severity, n.Title, n.Text = "critical", "Tamper attempt on "+ev.Hostname, ev.Detail
	default:
		n.Severity, n.Title = "warning", ev.Hostname+" is non-compliant"
		n.Text = fmt.Sprintf("%d checks failing since %s.", ev.Failing, ev.Since.Local().Format("2006-01-02 15:04"))
	}
	return n
}

// notifyDevice completes notices of a device with host name and link and sends them.
func (s *Server) notifyDevice(id string, notices []notice) {
	if len(notices) == 0 {
		return
	}
	var host string
	_ = s.db.QueryRow(context.Background(), `SELECT hostname FROM devices WHERE id=$1`, id).Scan(&host)
	for _, n := range notices {
		n.DeviceID, n.Hostname = id, firstNonEmpty(n.Hostname, host)
		if n.URL == "" {
			n.URL = s.cfg.PublicURL + "/devices/" + id
		}
		if !strings.Contains(n.Title, n.Hostname) {
			n.Title += " (" + n.Hostname + ")"
		}
		s.notify(n)
	}
}
