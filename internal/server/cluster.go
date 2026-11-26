package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// High availability: several server instances share one PostgreSQL
// database (docs/high-availability.md). State that must agree between them
// lives in the database; changes reach the other instances with
// LISTEN/NOTIFY (settings, remote shell relay). Background jobs run on the
// instance holding their advisory lock (Background), critical sections are
// serialized with clusterLock.

// advisory lock keys besides the audit (7363) and schema (7364) locks
const (
	lockStartup  = 7366 // key material and data initialization at startup
	lockSettings = 7367 // console settings saves
	lockSCIM     = 7368 // SCIM read, modify and write
)

const (
	instanceBeat  = 10 * time.Second
	instanceAlive = "30 seconds" // an instance not seen for this long is gone
)

// leaderRetry is how often an instance tries to take over a background loop
// another instance runs (and the restart delay after a panic).
var leaderRetry = 15 * time.Second

type cluster struct {
	id        string
	cancel    context.CancelFunc // stops heartbeat and listener (Close)
	listening atomic.Bool        // the notification connection is up
	draining  atomic.Bool        // shutting down: /readyz fails
	stopping  chan struct{}      // closed by Drain
	stopOnce  sync.Once
	// last settings change this instance loaded or saved (updated_at, Unix µs)
	settingsAt atomic.Int64

	mu    sync.Mutex
	boxes map[string]chan relayMsg // remote shell relay mailboxes (shellrelay.go)
}

// startCluster registers this instance and starts its heartbeat and the
// notification listener; Close stops them.
func (s *Server) startCluster() error {
	host, _ := os.Hostname()
	s.ha.id = host + "-" + randToken(6)
	s.ha.stopping = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	s.ha.cancel = cancel
	if err := s.heartbeat(ctx, host); err != nil {
		cancel()
		return fmt.Errorf("register instance: %w", err)
	}
	go func() {
		t := time.NewTicker(instanceBeat)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if err := s.heartbeat(ctx, host); err != nil && ctx.Err() == nil {
				s.log.Warn("instance heartbeat", "err", err)
			}
		}
	}()
	go s.listen(ctx)
	return nil
}

func (s *Server) heartbeat(ctx context.Context, host string) error {
	if _, err := s.db.Exec(ctx, `INSERT INTO server_instances(id, hostname, version) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET seen_at = now()`, s.ha.id, host, Version); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM server_instances WHERE seen_at < now() - interval '1 day'`)
	return err
}

// listen keeps one connection listening for notifications, reconnecting
// after failures.
func (s *Server) listen(ctx context.Context) {
	for ctx.Err() == nil {
		err := s.listenOnce(ctx)
		s.ha.listening.Store(false)
		if ctx.Err() != nil {
			return
		}
		s.log.Warn("cluster notifications interrupted, reconnecting", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

func (s *Server) listenOnce(ctx context.Context) error {
	pc, err := s.db.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := pc.Hijack() // never back into the pool with LISTEN active
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if _, err := conn.Exec(ctx, `LISTEN limdm_settings; LISTEN limdm_shell`); err != nil {
		return err
	}
	s.ha.listening.Store(true)
	go s.reloadSettings(ctx) // a change saved while the connection was down
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		switch n.Channel {
		case "limdm_settings":
			if n.Payload == "server" {
				go s.reloadSettings(ctx)
			}
		case "limdm_shell":
			s.relayDispatch(n.Payload)
		}
	}
}

// reloadSettings activates settings another instance saved.
func (s *Server) reloadSettings(ctx context.Context) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	was := s.rediscover.Load()
	if err := s.loadSettings(ctx); err != nil {
		s.log.Error("reload settings", "err", err)
		return
	}
	if !was && s.rediscover.Load() {
		go s.rediscoverLoop(ctx)
	}
}

// clusterLock serializes a critical section across all server instances
// with a session advisory lock, waiting at most wait for it. unlock
// releases the lock and the connection.
func clusterLock(ctx context.Context, db *pgxpool.Pool, key int64, wait time.Duration) (unlock func(), err error) {
	conn, err := db.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		var ok bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
			conn.Release()
			return nil, err
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			conn.Release()
			return nil, errors.New("timed out waiting for another server instance")
		}
		select {
		case <-ctx.Done():
			conn.Release()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return func() {
		uctx := context.WithoutCancel(ctx)
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
			_ = conn.Conn().Close(uctx) // ending the session releases the lock
		}
		conn.Release()
	}, nil
}

// schemaHash identifies the schema this binary applies (readyz).
func schemaHash() string {
	h := sha256.New()
	h.Write([]byte(schema))
	for _, m := range migrations {
		fmt.Fprintf(h, "|%d", m.version)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readyz is the readiness check for load balancers: the database answers,
// holds the schema of this version, keys are loaded, notifications from the
// other instances arrive and the instance is not shutting down.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var problems []string
	if s.ha.draining.Load() {
		problems = append(problems, "shutting down")
	}
	var current bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_applied WHERE hash=$1)`, schemaHash()).Scan(&current); err != nil {
		problems = append(problems, "database unreachable")
	} else if !current {
		problems = append(problems, "database schema does not match this version")
	}
	if s.ca == nil || s.netCA == nil || s.cmdKey == nil || auditKey == nil {
		problems = append(problems, "keys not loaded")
	}
	if !s.ha.listening.Load() {
		problems = append(problems, "not receiving notifications from other instances")
	}
	if len(problems) > 0 {
		http.Error(w, strings.Join(problems, "; "), http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ready"))
}

// Drain starts a graceful shutdown: /readyz fails so load balancers stop
// sending requests; after delay the remote shells this instance holds or
// relays end and are stored. The HTTP servers shut down afterwards.
func (s *Server) Drain(delay time.Duration) {
	s.ha.draining.Store(true)
	time.Sleep(delay)
	s.ha.stopOnce.Do(func() {
		if s.ha.stopping != nil {
			close(s.ha.stopping)
		}
	})
	live := s.shells.all()
	for _, l := range live {
		l.end("the server instance is shutting down")
	}
	deadline := time.After(10 * time.Second)
	for _, l := range live {
		select {
		case <-l.stored:
		case <-deadline:
			return
		}
	}
}

// checkSharedKeys makes sure every instance uses the same key material: the
// first instance records the fingerprints, later ones must match them. Two
// instances with separate, freshly created CA directories would otherwise
// each run their own device CA.
func (s *Server) checkSharedKeys(ctx context.Context) error {
	fp := map[string]string{"device_ca": s.ca.Fingerprint(), "network_ca": s.netCA.Fingerprint(),
		"command_key": fmt.Sprintf("%x", sha256.Sum256(s.cmdKey.Public().(ed25519.PublicKey)))}
	doc, _ := json.Marshal(fp)
	var stored map[string]string
	err := s.db.QueryRow(ctx, `INSERT INTO settings(key, value) VALUES ('key_fingerprints', $1) ON CONFLICT (key) DO UPDATE SET key = settings.key
		RETURNING value`, doc).Scan(&stored)
	if err != nil {
		return err
	}
	for k, v := range fp {
		if stored[k] != v {
			return fmt.Errorf("%s in %s differs from the one the other server instances use: give every instance the same CA directory (docs/high-availability.md)", k, s.cfg.CADir)
		}
	}
	return nil
}

// checkAuditSwitch refuses to start when the audit chain switched to keyed
// hashes but this instance's CA directory lacks the recorded switch point:
// it would record a second one and break the chain.
func checkAuditSwitch(ctx context.Context, db *pgxpool.Pool, caDir string) error {
	if _, err := ReadAuditKeyedFrom(caDir); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var switched bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_log WHERE action='audit.keyed')`).Scan(&switched); err != nil {
		return err
	}
	if switched {
		return fmt.Errorf("%s/%s is missing although the audit chain already uses keyed hashes: give every instance the same CA directory (docs/high-availability.md)", caDir, auditKeyedFile)
	}
	return nil
}

// storeAuditVerification records the result of a full audit chain
// verification for all instances and returns the previous result.
func (s *Server) storeAuditVerification(ctx context.Context, broken int64) (prev int64, err error) {
	err = s.db.QueryRow(ctx, `WITH old AS (SELECT (value->>'broken')::bigint AS b FROM settings WHERE key='audit_verification')
		INSERT INTO settings(key, value) VALUES ('audit_verification', jsonb_build_object('broken', $1::bigint, 'at', now()))
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()
		RETURNING coalesce((SELECT b FROM old), 0)`, broken).Scan(&prev)
	return prev, err
}

// auditVerification is the last full verification: the first broken entry
// (0 = intact) and when it ran (nil = not yet).
func (s *Server) auditVerification(ctx context.Context) (broken int64, at *time.Time) {
	var t time.Time
	if err := s.db.QueryRow(ctx, `SELECT (value->>'broken')::bigint, (value->>'at')::timestamptz FROM settings WHERE key='audit_verification'`).Scan(&broken, &t); err != nil {
		return 0, nil
	}
	return broken, &t
}
