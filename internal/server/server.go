// Package server implements the LiMDM management server: declarative agent API
// over mTLS, admin web UI with OIDC login, and the audit trail.
package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	mrand "math/rand/v2"
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
	DatabaseURL    string
	Listen         string // admin UI
	PublicURL      string // admin UI URL, used for the OIDC redirect
	TLSCert        string // admin UI certificate (public CA); without it the UI binds to loopback only
	TLSKey         string
	AgentListen    string   // agent API, mTLS terminated here, never by a proxy
	AgentURL       string   // URL agents use, its host goes into the server certificate
	AgentHosts     []string // additional names/IPs for the agent certificate, e.g. the IP older agents enrolled with
	ReleaseRepo    string   // GitHub owner/name the install script downloads agent packages from
	GeoIPURL       string   // location lookup for device addresses, the IP is appended; "" disables
	CADir          string
	LocalLogin     bool // local admin accounts with password and TOTP
	OIDCIssuer     string
	OIDCClientID   string
	OIDCSecret     string
	AllowedDomain  string
	Admins         []string
	Auditors       []string
	SessionKey     []byte   // the first key of LIMDM_SESSION_KEY: seals and signs
	OldSessionKeys [][]byte // further keys during a rotation: open only (keys.go)
	Keys           KeyProvider
	ReleaseDir     string
	StaleAfter     time.Duration
	Syslog         string // udp://host:port, tcp://host:port or tcp+tls://host:port: audit entries and device events as RFC 5424
	// proxies (load balancers) whose X-Forwarded-For is trusted for the client address, besides loopback
	TrustedProxies []netip.Prefix
	DrainDelay     time.Duration // between failing /readyz and closing connections at shutdown
	MultiTenant    bool          // tenant pages and switcher (tenant.go); isolation applies always
	DBMaxConns     int           // connections in the pool of this instance (LIMDM_DB_MAX_CONNS)
	// parallel agent package downloads per instance; more wait, then get 503 (LIMDM_UPDATE_DOWNLOADS)
	UpdateDownloads int
	MaxCheckins     int    // check ins decoded and processed at once per instance (LIMDM_MAX_CHECKINS)
	SyslogCA        string // CA file for tcp+tls syslog targets; empty: system roots
	AccessLog       bool   // a log line per request (LIMDM_ACCESS_LOG)
	AuditAPIReads   string // off, sensitive or all: API reads written to the audit log (LIMDM_AUDIT_API_READS)
	// load balancers that send a PROXY v2 header to the agent listener (LIMDM_AGENT_PROXY_PROTOCOL)
	AgentProxyFrom []netip.Prefix
}

// envInt reads a number setting within [lo, hi]; def when unset.
func envInt(k string, def, lo, hi int) (int, error) {
	n, err := strconv.Atoi(envOr(k, strconv.Itoa(def)))
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be %d to %d", k, lo, hi)
	}
	return n, nil
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
		Syslog:        os.Getenv("LIMDM_SYSLOG"),
		SyslogCA:      os.Getenv("LIMDM_SYSLOG_CA"),
		AccessLog:     os.Getenv("LIMDM_ACCESS_LOG") == "true",
		AuditAPIReads: envOr("LIMDM_AUDIT_API_READS", "sensitive"),
		MultiTenant:   os.Getenv("LIMDM_MULTI_TENANT") == "true",
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
	if c.TrustedProxies, err = parseProxies(os.Getenv("LIMDM_TRUSTED_PROXIES")); err != nil {
		return c, err
	}
	if c.AgentProxyFrom, err = parseProxies(os.Getenv("LIMDM_AGENT_PROXY_PROTOCOL")); err != nil {
		return c, fmt.Errorf("LIMDM_AGENT_PROXY_PROTOCOL: %w", err)
	}
	drain, err := strconv.Atoi(envOr("LIMDM_DRAIN_SECONDS", "5"))
	if err != nil || drain < 0 || drain > 300 {
		return c, errors.New("LIMDM_DRAIN_SECONDS must be 0 to 300")
	}
	c.DrainDelay = time.Duration(drain) * time.Second
	if c.DBMaxConns, err = envInt("LIMDM_DB_MAX_CONNS", 32, 4, 1000); err != nil {
		return c, err
	}
	if c.UpdateDownloads, err = envInt("LIMDM_UPDATE_DOWNLOADS", 20, 1, 10000); err != nil {
		return c, err
	}
	if c.MaxCheckins, err = envInt("LIMDM_MAX_CHECKINS", 64, 1, 10000); err != nil {
		return c, err
	}
	if !slices.Contains([]string{"off", "sensitive", "all"}, c.AuditAPIReads) {
		return c, errors.New("LIMDM_AUDIT_API_READS must be off, sensitive or all")
	}
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
	keys, err := parseSessionKeys(os.Getenv("LIMDM_SESSION_KEY"))
	if err != nil {
		return c, err
	}
	c.SessionKey, c.OldSessionKeys = keys[0], keys[1:]
	c.Keys = KeyProviderFromEnv()
	if err := c.Keys.validate(); err != nil {
		return c, err
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
	netCA  *deviceCA     // issues EAP-TLS device certificates (devicecerts.go)
	cmdKey crypto.Signer // signs commands (command.key next to the CA, or in the HSM)
	kr     keyring       // keys of running rotations (keys.go)
	log    *slog.Logger
	limit  limiter
	rt     atomic.Pointer[runtimeState] // settings editable in the UI and the OIDC client built from them
	hooks  *http.Client                 // webhook client; nil uses http.DefaultClient (tests inject one)
	whKey  []byte                       // webhook signing secret, loaded at startup (webhooksecret.go)
	geoSem chan struct{}                // one location lookup at a time

	saveMu     sync.Mutex  // serializes settings saves in this instance (clusterLock across instances)
	rediscover atomic.Bool // OIDC discovery failed at startup and is retried
	fleet      atomic.Pointer[fleetCache]
	shells     shellHub // remote shell sessions this instance holds
	ha         cluster  // instance identity, notifications, relay (cluster.go)
	brands     sync.Map // tenant id -> brandEntry (tenant.go)

	// load limits of the agent API; nil: no limit
	downloads chan struct{} // agent package downloads running (agentPackage)
	// check ins running, and those with a body over 1 MiB (inventory, package
	// list) among them (checkinSlot)
	checkins, bigCheckins chan struct{}
	rolloutC              atomic.Pointer[rolloutCache] // agentupdates.go
}

func pgxPoolConfig(databaseURL string, maxConns int) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	// explicit limits instead of the pgx default of max(4, CPUs); a pool_max_conns
	// parameter in the URL still wins
	if !strings.Contains(databaseURL, "pool_max_conns") {
		pc.MaxConns = int32(max(maxConns, 4)) //nolint:gosec // bounded by ConfigFromEnv
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
	pc, err := pgxPoolConfig(cfg.DatabaseURL, cfg.DBMaxConns)
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
	trustedProxies = cfg.TrustedProxies
	// instances starting at once must not each create keys or migrate data
	unlock, err := clusterLock(ctx, db, lockStartup, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("startup lock: %w", err)
	}
	defer unlock()
	s, err := openCore(ctx, cfg, log, db)
	if err != nil {
		return nil, err
	}
	log.Info("device CA ready", "fingerprint", s.tlsCA().Fingerprint())
	if err := signExistingItems(ctx, db, cfg.CADir); err != nil {
		return nil, fmt.Errorf("signing library items: %w", err)
	}
	if err := s.resignItems(ctx); err != nil {
		return nil, fmt.Errorf("signing library items with the new command key: %w", err)
	}
	if err := s.sealLoginSecrets(ctx); err != nil {
		return nil, fmt.Errorf("sealing login client secrets: %w", err)
	}
	// baseline version of items saved before versioning existed; here and not
	// in schema.sql, so it holds the signed payload with secrets sealed.
	// Network items get theirs masked at their first change (versions.go).
	if _, err := db.Exec(ctx, `INSERT INTO library_item_versions(item_id, version, name, type, description, payload, signature, note, created_by, created_at)
		SELECT i.id, 1, i.name, i.type, i.description, i.payload, i.signature, 'baseline', 'system', i.updated_at FROM library_items i
		WHERE i.type <> $1 AND NOT EXISTS (SELECT 1 FROM library_item_versions v WHERE v.item_id = i.id)`, api.TypeNetwork); err != nil {
		return nil, fmt.Errorf("library baseline versions: %w", err)
	}
	if err := s.seedConsoleUsers(ctx); err != nil {
		return nil, err
	}
	if err := s.loadSettings(ctx); err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	if err := s.startCluster(); err != nil {
		return nil, err
	}
	return s, nil
}

// openCore loads the keys and the audit chain state: what the server and
// limdm-server keys need.
func openCore(ctx context.Context, cfg Config, log *slog.Logger, db *pgxpool.Pool) (*Server, error) {
	s := &Server{cfg: cfg, db: db, log: log, geoSem: make(chan struct{}, 1), downloads: make(chan struct{}, max(cfg.UpdateDownloads, 1)),
		checkins: make(chan struct{}, max(cfg.MaxCheckins, 1)), bigCheckins: make(chan struct{}, max(cfg.MaxCheckins/8, 1))}
	if err := s.loadKeys(); err != nil {
		return nil, err
	}
	itemKey = s.cmdKey
	if s.kr.cmdPrev != nil {
		itemPrevKey = s.kr.cmdPrev.Public().(ed25519.PublicKey)
	}
	if err := s.checkSharedKeys(ctx); err != nil {
		return nil, err
	}
	if err := checkAuditSwitch(ctx, db, cfg.CADir); err != nil {
		return nil, err
	}
	if err := initAuditKey(ctx, db, cfg.CADir, s.cmdKey, s.kr.cmdPrev); err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	var err error
	if itemSecrets, err = s.aead(infoItems); err != nil {
		return nil, err
	}
	if s.whKey, err = s.loadWebhookSecret(ctx); err != nil {
		return nil, fmt.Errorf("webhook secret: %w", err)
	}
	return s, nil
}

// OpenKeys opens the database and the keys for limdm-server keys.
func OpenKeys(ctx context.Context, cfg Config, log *slog.Logger) (*Server, error) {
	pc, err := pgxPoolConfig(cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return nil, err
	}
	db, err := newPool(ctx, pc)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	s, err := openCore(ctx, cfg, log, db)
	if err != nil {
		db.Close()
		return nil, err
	}
	s.kr.cli = true
	return s, nil
}

// Close stops heartbeat and listener, deregisters the instance and closes
// the database pool.
func (s *Server) Close() {
	if s.ha.cancel != nil {
		s.ha.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = s.db.Exec(ctx, `DELETE FROM server_instances WHERE id=$1`, s.ha.id)
		cancel()
	}
	s.db.Close()
}

// Background runs periodic jobs until ctx ends.
func (s *Server) Background(ctx context.Context) {
	for name, loop := range map[string]func(context.Context){"google sync": s.googleSyncLoop, "history": s.historyLoop,
		"catalog icons": s.iconLoop, "syslog": s.syslogLoop, "reseal": s.resealLoop} {
		go s.background(ctx, name, loop, true)
	}
	// every instance serves agent packages from its own release directory
	go s.background(ctx, "releases", s.releaseLoop, false)
	go s.rediscoverLoop(ctx)
}

// background runs a loop for the life of the server: a panic is logged and
// the loop restarts after a minute instead of taking the server down. With
// several server instances only the one holding the loop's advisory lock
// runs it (leader), so syncs and downloads do not happen twice. The leader
// checks its lock connection; when the connection breaks the lock is gone
// and the loop stops, so another instance can take over without overlap.
func (s *Server) background(ctx context.Context, name string, loop func(context.Context), leader bool) {
	key := int64(crc32.ChecksumIEEE([]byte("limdm-loop:" + name)))
	for ctx.Err() == nil {
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("background loop panicked", "loop", name, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				}
			}()
			if !leader {
				loop(ctx)
				return
			}
			// an instance with an outdated audit key cannot write the
			// entries its jobs record: it leaves them to the others
			if stale, err := auditKeyStale(ctx, s.db); err != nil || stale {
				return
			}
			conn, err := s.db.Acquire(ctx)
			if err != nil {
				return
			}
			defer conn.Release()
			var got bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil || !got {
				return // another instance runs it
			}
			s.log.Info("leading background loop", "loop", name, "instance", s.ha.id)
			lctx, cancel := context.WithCancel(ctx)
			watched := make(chan struct{})
			go func() { // the lock lives as long as this session
				defer close(watched)
				t := time.NewTicker(leaderRetry)
				defer t.Stop()
				for {
					select {
					case <-lctx.Done():
						return
					case <-t.C:
						if _, err := conn.Exec(lctx, `SELECT 1`); err != nil && lctx.Err() == nil {
							s.log.Error("lost the background loop lock", "loop", name, "err", err)
							cancel()
							return
						}
						if stale, _ := auditKeyStale(lctx, s.db); stale {
							s.log.Warn("audit key outdated: handing the background loop over", "loop", name)
							cancel()
							return
						}
					}
				}
			}()
			defer func() {
				cancel()
				<-watched // the connection is free again
				if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key); err != nil {
					_ = conn.Conn().Close(context.WithoutCancel(ctx))
				}
			}()
			loop(lctx)
		}()
		select {
		case <-ctx.Done():
		case <-time.After(leaderRetry):
		}
	}
}

// AdminHandler serves the web UI.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	// liveness: the process serves requests; readiness (database, schema,
	// keys, notifications) is /readyz
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", s.readyz)
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
	return s.countRequests("console", securityHeaders(s.consoleFilter(mux)))
}

// AgentHandler serves the agent API. Everything except fetching the CA and
// enrolling requires a valid, current client certificate.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ca", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.tlsCA().pem)
	})
	mux.HandleFunc("POST /api/v1/enroll", s.enroll)
	mux.HandleFunc("POST /api/v1/renew", s.deviceAuth(s.renew, true))
	mux.HandleFunc("POST /api/v1/checkin", s.deviceAuth(s.checkin, false))
	mux.HandleFunc("POST /api/v1/poll", s.deviceAuth(s.poll, false))
	mux.HandleFunc("POST /api/v1/network-cert", s.deviceAuth(s.deviceLimit(5, s.networkCert), false))
	mux.HandleFunc("GET /api/v1/agent-packages/{version}/{file}", s.deviceAuth(s.agentPackage, false))
	mux.HandleFunc("GET /api/v1/catalog/icons/{id}", s.deviceAuth(s.catalogIcon, false))
	mux.HandleFunc("GET /api/v1/catalog/search", s.deviceAuth(s.deviceLimit(30, s.flathubSearchJSON), false))
	mux.HandleFunc("GET /api/v1/catalog/flathub-icon", s.deviceAuth(s.deviceLimit(300, s.flathubIcon), false))
	s.shellAgentRoutes(mux)
	return s.countRequests("agent", securityHeaders(mux))
}

// AgentTLSConfig: TLS 1.3 only, server certificate from the device CA. The
// handshake requests the client certificate and proves possession of its key;
// deviceAuth verifies it against the device CA, so renewal can accept an
// expired certificate.
func (s *Server) AgentTLSConfig() (*tls.Config, error) {
	u, _ := url.Parse(s.cfg.AgentURL)
	names := append([]string{u.Hostname()}, s.cfg.AgentHosts...)
	cert, err := s.tlsCA().serverCert(names)
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
				if next, err := s.tlsCA().serverCert(names); err == nil {
					cert = next
				} else {
					s.log.Error("renew agent TLS certificate", "err", err)
				}
			}
			c := cert // a copy: handshakes read it after the lock is released
			return &c, nil
		},
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  s.devicePool(),
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
	opts := x509.VerifyOptions{Roots: s.devicePool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
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
	var req api.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	// unauthenticated: failures are limited before touching the database, per
	// address and token (20 tries of one wrong token) and per address (200
	// failures): only failures count, so a mass rollout behind one office NAT
	// or a load balancer without PROXY protocol is not blocked by a few typos
	th := sha(req.Token)
	src := "enroll:" + rateKey(r)
	tokKey := src + ":" + hex.EncodeToString(th[:8])
	if s.limit.over(tokKey, 20, 5*time.Minute) || s.limit.over(src, 200, 5*time.Minute) {
		w.Header().Set("Retry-After", "300")
		problem(w, http.StatusTooManyRequests, "too many enrollment attempts, try again later")
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
	var tenantID int64 // the device joins the tenant of its token
	err = tx.QueryRow(ctx, `UPDATE enroll_tokens SET uses_left = uses_left - 1
		WHERE token_hash=$1 AND uses_left > 0 AND expires_at > now()
		AND tenant_id IN (SELECT id FROM tenants WHERE NOT disabled) RETURNING blueprint_id, tenant_id`, th).Scan(&blueprintID, &tenantID)
	if err != nil {
		s.limit.allow(tokKey, 20, 5*time.Minute) // counts the failure
		s.limit.allow(src, 200, 5*time.Minute)
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
	if _, err := tx.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, machine_id, blueprint_id, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, serial, notAfter, truncate(req.Hostname, 255), truncate(req.MachineID, 64), blueprintID, tenantID); err != nil {
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
		rows, err := tx.Query(ctx, `SELECT id FROM devices WHERE machine_id=$1 AND id<>$2 AND NOT retired AND tenant_id=$3`, truncate(mid, 64), id, tenantID)
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
				EXISTS (SELECT 1 FROM dir_users du WHERE lower(du.email)=lower(u->>'email') AND NOT du.active AND du.updated_at > d.last_seen)
				OR EXISTS (SELECT 1 FROM dir_users du WHERE du.previous_emails @> ARRAY[lower(u->>'email')] AND NOT du.active AND du.updated_at > d.last_seen)
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

// checkinSlot bounds the check ins decoded and processed at once, and among
// them those with a big body: memory and database connections stay bounded
// when the fleet comes back at once or a device floods the server. A check in
// that gets no slot within a few seconds is asked to come back later.
func (s *Server) checkinSlot(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	var held []chan struct{}
	release = func() {
		for _, c := range held {
			<-c
		}
	}
	sems := []chan struct{}{s.checkins}
	if r.ContentLength < 0 || r.ContentLength > 1<<20 {
		sems = append(sems, s.bigCheckins)
	}
	t := time.NewTimer(checkinWait)
	defer t.Stop()
	for _, c := range sems {
		if c == nil {
			continue
		}
		select {
		case c <- struct{}{}:
			held = append(held, c)
		case <-t.C:
			release()
			retryLater(w, 30+mrand.IntN(90), "too many check ins at once, retry later") //nolint:gosec // jitter, not a secret
			return nil, false
		case <-r.Context().Done():
			release()
			return nil, false
		}
	}
	return release, true
}

// checkinWait is how long a check in waits for a slot (checkinSlot).
var checkinWait = 5 * time.Second

func (s *Server) checkin(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	release, ok := s.checkinSlot(w, r)
	if !ok {
		return
	}
	defer release()
	var req api.CheckinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	ctx := r.Context()
	dbTx, err := s.db.Begin(ctx)
	if err != nil {
		s.failAPI(w, err)
		return
	}
	defer dbTx.Rollback(ctx)
	// audit entries (command results, tamper events, escrow, compliance) are
	// appended at the commit, so the global audit lock is held only there
	tx := &auditTx{Tx: dbTx}
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
		if err := recordCheckChanges(ctx, tx, id, st.Checks, st.CatalogVersion); err != nil {
			s.failAPI(w, err)
			return
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET hostname=$2, inventory=$3, checks=$4, decl_status=$5, failing=$6, status_hash=$7, catalog_version=$8 WHERE id=$1`,
			id, truncate(st.Inventory.Hostname, 255), jsonb(st.Inventory), jsonb(st.Checks), jsonb(st.Declarations), countFailing(st.Checks), truncate(req.StatusHash, 128),
			truncate(st.CatalogVersion, 32)); err != nil {
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
	var refused []api.CommandResult
	for _, res := range req.Results {
		status := "failed"
		if res.OK {
			status = "ok"
		}
		var typ string
		err := tx.QueryRow(ctx, `UPDATE commands SET status=$3, output=$4, updated_at=now(),
			payload=CASE WHEN type = ANY($5) THEN '' ELSE payload END WHERE id=$1 AND device_id=$2 AND status='sent'
			RETURNING type`, res.ID, id, status, truncate(res.Output, 64<<10), secretCommands).Scan(&typ)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.failAPI(w, err)
			return
		}
		if typ == "shell" && !res.OK {
			refused = append(refused, res) // after the commit: it needs its own connection
		}
		if !res.OK && slices.Contains([]string{"lock", "unlock", "lost", "found", "wipe", "script"}, typ) {
			notices = append(notices, notice{Type: "command.failed", Severity: "critical", Title: "Command failed: " + typ,
				Text: truncate(strings.TrimSpace(res.Output), 500)})
		}
		// target is the device like the entry of the enqueue; both name the
		// command ID, so the chain alone links who sent what with its result
		detail := fmt.Sprintf("command %d %s %s", res.ID, firstNonEmpty(typ, "unknown"), status)
		// the reason of a failure only: script output can hold anything, and
		// the chain cannot forget it
		if out := strings.TrimSpace(res.Output); out != "" && !res.OK {
			detail += ": " + truncate(lastLine(out), 200)
		}
		if err := audit(ctx, tx, "device:"+id, "command.result", id, detail); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	if err := storeDiagnostics(ctx, tx, id, req.Results); err != nil {
		s.failAPI(w, err)
		return
	}
	if err := storeScriptResults(ctx, tx, id, req); err != nil {
		s.failAPI(w, err)
		return
	}
	tamperEvent, err := s.storeEvents(ctx, tx, id, req.Events)
	if err != nil {
		s.failAPI(w, err)
		return
	}

	resp := api.CheckinResponse{ServerTime: time.Now().UTC(),
		NeedStatus: statusHash != req.StatusHash, NeedPackages: pkgHash != req.PackagesHash, FallbackDNS: s.settings().FallbackDNS}
	if err := s.keyCheckin(ctx, tx, id, r, req, &resp); err != nil {
		s.failAPI(w, err)
		return
	}
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
	if b := s.deviceBranding(ctx, tx, id); b.Hash != req.BrandingHash {
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
	for _, res := range refused {
		s.shellRefused(ctx, res.ID, res.Output)
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
// any later modification of a row breaks verification of every following row;
// the hash is keyed (audit.go), so it cannot be recomputed from the database.
func audit(ctx context.Context, tx pgx.Tx, actor, action, target, detail string) error {
	if d, ok := tx.(*auditTx); ok {
		d.pending = append(d.pending, auditEntry{ctxTenant(ctx), actor, action, target, detail})
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7363)`); err != nil {
		return err
	}
	var prev []byte
	var keyID *string
	if err := tx.QueryRow(ctx, `SELECT (SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1), (SELECT key_id FROM audit_key)`).Scan(&prev, &keyID); err != nil {
		return err
	}
	if prev == nil {
		prev = make([]byte, 32)
	}
	// another instance started with a new command key: entries keyed with
	// the old one would break the chain
	if auditKey != nil && keyID != nil && *keyID != auditKeyCur {
		return errAuditKeyStale
	}
	tenant, err := auditTenant(ctx, tx, target)
	if err != nil {
		return err
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(at, actor, action, target, detail, prev, hash, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		at, actor, action, target, detail, prev, auditHash(auditKey, prev, at, auditFields(actor, action, target, detail, tenant)...), tenant)
	return err
}

// auditTx is a transaction whose audit entries are appended at its commit:
// the global audit lock is then held for the append and the commit only, not
// for the rest of a long transaction such as a check in. Entries made inside
// a savepoint (tx.Begin) are written at once.
type auditTx struct {
	pgx.Tx
	pending  []auditEntry
	atCommit []func(context.Context, pgx.Tx) error // run before the audit entries
}

type auditEntry struct {
	tenant                        int64 // of the request (ctxTenant)
	actor, action, target, detail string
}

func (t *auditTx) Commit(ctx context.Context) error {
	for _, f := range t.atCommit {
		if err := f(ctx, t.Tx); err != nil {
			return err
		}
	}
	for _, e := range t.pending {
		if err := audit(withTenant(ctx, e.tenant), t.Tx, e.actor, e.action, e.target, e.detail); err != nil {
			return err
		}
	}
	return t.Tx.Commit(ctx)
}

// auditTenant is the tenant of an entry: the tenant the request acts for,
// else the tenant of the device it is about, else none (a global entry).
func auditTenant(ctx context.Context, tx pgx.Tx, target string) (*int64, error) {
	if t := ctxTenant(ctx); t != 0 {
		return &t, nil
	}
	if target == "" {
		return nil, nil
	}
	var t int64
	err := tx.QueryRow(ctx, `SELECT tenant_id FROM devices WHERE id=$1`, target).Scan(&t)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &t, nil
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

// retryLater answers 503 with Retry-After: the server is overloaded, not the
// request wrong; agents wait that long before they try again.
func retryLater(w http.ResponseWriter, seconds int, detail string) {
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	problem(w, http.StatusServiceUnavailable, detail)
}

// failAPI logs an internal error and answers with a generic problem; a busy
// database (lock or statement timeout, no free connection) is a 503 the
// agent retries after Retry-After.
func (s *Server) failAPI(w http.ResponseWriter, err error) {
	if overloaded(err) {
		s.log.Warn("agent request: database busy", "err", err, "request_id", requestID(w))
		retryLater(w, 30+mrand.IntN(90), "server busy, retry later") //nolint:gosec // jitter, not a secret
		return
	}
	s.log.Error("agent request failed", "err", err, "request_id", requestID(w))
	problem(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if overloaded(err) {
		s.log.Warn("request: database busy", "err", err, "request_id", requestID(w))
		w.Header().Set("Retry-After", "30")
		http.Error(w, "server busy, try again in a moment", http.StatusServiceUnavailable)
		return
	}
	s.log.Error("request failed", "err", err, "request_id", requestID(w))
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
		if p == "/healthz" || p == "/readyz" || p == "/install.sh" || strings.HasPrefix(p, "/scim/") {
			next.ServeHTTP(w, r)
			return
		}
		if rt := s.rt.Load(); rt != nil && !consoleAllowed(rt, clientIP(r)) {
			ip := "invalid"
			if a, err := netip.ParseAddr(clientIP(r)); err == nil {
				ip = a.String() // parsed, never the raw header text
			}
			s.log.Warn("console request refused by network list", "ip", ip)
			s.errorPage(w, r, session{}, http.StatusForbidden, "access from this network is not allowed")
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
		// one writer at a time from the insert to the commit, as for the audit
		// log: ids then become visible in commit order, and the syslog cursor
		// (id > last sent) cannot skip an event committed late with a smaller id
		insert := func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockEvents); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO device_events(device_id, at, detail) SELECT $1, a, d FROM unnest($2::timestamptz[], $3::text[]) AS e(a, d)`,
				id, evAt, evText)
			return err
		}
		if d, ok := tx.(*auditTx); ok {
			d.atCommit = append(d.atCommit, insert) // the lock is then held for the commit only
		} else if err := insert(ctx, tx); err != nil {
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
	var tenantID int64
	_ = s.db.QueryRow(context.Background(), `SELECT hostname, tenant_id FROM devices WHERE id=$1`, id).Scan(&host, &tenantID)
	for _, n := range notices {
		n.DeviceID, n.Hostname, n.Tenant = id, firstNonEmpty(n.Hostname, host), tenantID
		if n.URL == "" {
			n.URL = s.cfg.PublicURL + "/devices/" + id
		}
		if !strings.Contains(n.Title, n.Hostname) {
			n.Title += " (" + n.Hostname + ")"
		}
		s.notify(n)
	}
}

// secretCommands carry a credential in their payload, cleared once the
// device answered.
var secretCommands = []string{"user_create", "user_password"}

// logSafe keeps a value on one log line.
func logSafe(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\r", "")
}
