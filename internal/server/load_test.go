package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// loadTestDB is a fresh schema on the test database with a pool of maxConns.
func loadTestDB(t *testing.T, maxConns int32, rtt ...time.Duration) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pc.MaxConns = maxConns
	if len(rtt) > 0 {
		pc.ConnConfig.Tracer = rttTracer(rtt[0])
	}
	db, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

// rttTracer delays every statement, as a database across the network does.
type rttTracer time.Duration

func (d rttTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	time.Sleep(time.Duration(d))
	return ctx
}
func (rttTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func loadTestServer(db *pgxpool.Pool) *Server {
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), geoSem: make(chan struct{}, 1),
		cfg: Config{PublicURL: "https://mdm.test", SessionKey: bytes.Repeat([]byte{7}, 32)}}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24}})
	return s
}

func agentCall(s *Server, h http.HandlerFunc, id, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	// a request that waits for itself fails instead of hanging the test
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), deviceKey, id), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// A check in must never wait for a second pool connection while its
// transaction is open: with a pool of one it would wait for itself.
func TestCheckinSingleConnection(t *testing.T) {
	db := loadTestDB(t, 1)
	s := loadTestServer(db)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1','s',now(),'pc1');
		INSERT INTO commands(device_id, type, status, created_by) VALUES ('d1','shell','sent','a'), ('d1','lock','sent','a')`); err != nil {
		t.Fatal(err)
	}
	w := agentCall(s, s.checkin, "d1", "/api/v1/checkin", api.CheckinRequest{AgentVersion: "1.0.0",
		Results: []api.CommandResult{{ID: 1, OK: false, Output: "refused"}, {ID: 2, OK: true}}})
	if w.Code != http.StatusOK {
		t.Fatalf("checkin waits for a second connection while its transaction holds the first: %d", w.Code)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='command.result'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit entries: %d %v", n, err)
	}
	if w := agentCall(s, s.poll, "d1", "/api/v1/poll", nil); w.Code != http.StatusOK {
		t.Fatalf("poll: %d", w.Code)
	}
}

// Many devices report command results at once: every check in succeeds, the
// audit chain stays intact, and the audit lock is held only for the append
// at the commit, so the time scales with the database, not with a queue of
// whole check ins behind one lock.
func TestCheckinsConcurrent(t *testing.T) {
	db := loadTestDB(t, 16, time.Millisecond)
	s := loadTestServer(db)
	ctx := context.Background()
	const n = 64
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname)
		SELECT 'd'||i, 's'||i, now(), 'pc'||i FROM generate_series(1, 64) i;
		INSERT INTO commands(device_id, type, status, created_by) SELECT 'd'||i, 'lock', 'sent', 'a' FROM generate_series(1, 64) i`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	codes := make(chan int, n)
	for i := 1; i <= n; i++ {
		go func() {
			codes <- agentCall(s, s.checkin, "d"+strconv.Itoa(i), "/api/v1/checkin", api.CheckinRequest{AgentVersion: "1.0.0",
				Results: []api.CommandResult{{ID: int64(i), OK: true}}}).Code
		}()
	}
	for range n {
		if c := <-codes; c != http.StatusOK {
			t.Fatalf("checkin: %d", c)
		}
	}
	// with the lock held for the whole check in this took about 2.3 s (each
	// of the 64 waited for all before it), with the append at the commit 0.4 s
	took := time.Since(start)
	t.Logf("%d concurrent audited check ins: %v", n, took)
	if took > 1500*time.Millisecond {
		t.Errorf("check ins serialized behind the audit lock: %v", took)
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("chain broken at %d: %v", broken, err)
	}
	var got int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='command.result'`).Scan(&got); err != nil || got != n {
		t.Fatalf("audit entries: %d %v", got, err)
	}
}

// A restart with an unchanged schema takes no lock: it neither waits for the
// migration lock nor for running transactions on the tables.
func TestMigrateUnchangedTakesNoLock(t *testing.T) {
	db := loadTestDB(t, 4)
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE devices IN ROW EXCLUSIVE MODE; SELECT pg_advisory_xact_lock(7364)`); err != nil {
		t.Fatal(err)
	}
	mctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := migrate(mctx, db); err != nil {
		t.Fatalf("restart with an unchanged schema waited: %v", err)
	}
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version IN (9, 10)`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("one off migrations: %d %v", n, err)
	}
}

func TestRolloutOffset(t *testing.T) {
	spread := 24 * time.Hour
	if rolloutOffset("d1", "1.0.0", spread) != rolloutOffset("d1", "1.0.0", spread) {
		t.Fatal("offset not stable")
	}
	var early int
	for i := range 1000 {
		o := rolloutOffset("d"+strconv.Itoa(i), "1.0.0", spread)
		if o < 0 || o >= spread {
			t.Fatalf("offset outside the window: %v", o)
		}
		if o < spread/4 {
			early++
		}
	}
	if early < 200 || early > 300 { // a quarter of the fleet in the first quarter
		t.Fatalf("offsets not spread: %d of 1000 in the first quarter", early)
	}
	if rolloutOffset("d1", "1.0.0", 0) != 0 {
		t.Fatal("no window, no offset")
	}
}

// An approved release reaches the fleet spread over the rollout window,
// pilot devices at once; package downloads beyond the limit get 503 with
// Retry-After instead of saturating the server.
func TestStaggeredRollout(t *testing.T) {
	db := loadTestDB(t, 8)
	s := loadTestServer(db)
	s.cfg.ReleaseDir = t.TempDir()
	ctx := context.Background()
	file := api.PackageName("9.0.0", "amd64", "deb")
	if err := os.MkdirAll(s.cfg.ReleaseDir+"/9.0.0", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cfg.ReleaseDir+"/9.0.0/"+file, []byte("pkg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags)
			SELECT 'd'||i, 's', now(), 'pc'||i, CASE WHEN i = 1 THEN ARRAY['pilot'] ELSE '{}' END FROM generate_series(1, 200) i;
		INSERT INTO settings(key, value) VALUES ('agent_updates', '{"auto": true, "delay_days": 0, "pilot_tag": "pilot", "spread_hours": 24}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO agent_releases(version, published_at, sums, approved_at) VALUES ('9.0.0', now(), $1, now() - interval '6 hours')`,
		strings.Repeat("a", 64)+"  "+file+"\n"); err != nil {
		t.Fatal(err)
	}
	due := 0
	for i := 1; i <= 200; i++ {
		rel, _, err := s.dueUpdate(ctx, db, "d"+strconv.Itoa(i), "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if rel != nil {
			due++
		} else if i == 1 {
			t.Fatal("pilot device waits")
		}
	}
	if due < 25 || due > 80 { // about a quarter after 6 of 24 hours
		t.Fatalf("%d of 200 devices due 6 hours into a 24 hour window", due)
	}

	s.downloads = make(chan struct{}, 1)
	s.downloads <- struct{}{} // one download running
	prev := downloadWait
	downloadWait = 10 * time.Millisecond
	t.Cleanup(func() { downloadWait = prev })
	get := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/v1/agent-packages/9.0.0/"+file, nil)
		r.SetPathValue("version", "9.0.0")
		r.SetPathValue("file", file)
		r = r.WithContext(context.WithValue(r.Context(), deviceKey, "d1"))
		w := httptest.NewRecorder()
		s.agentPackage(w, r)
		return w
	}
	if w := get(); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("download over the limit: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	<-s.downloads
	if w := get(); w.Code != http.StatusOK || w.Body.String() != "pkg" {
		t.Fatalf("download: %d", w.Code)
	}
	// an old agent reports the refused download as failure: it must not count
	if err := s.recordUpdateResult(ctx, &auditTx{Tx: mustBegin(t, db)}, "d2", &api.UpdateResult{From: "1.0.0", To: "9.0.0",
		Detail: "download " + file + ": 503 Service Unavailable"}); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.QueryRow(ctx, `SELECT update_state FROM devices WHERE id='d2'`).Scan(&state); err != nil || state == "failed" {
		t.Fatalf("refused download counted as failed update: %q %v", state, err)
	}
}

func mustBegin(t *testing.T, db *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback(context.Background()) })
	return tx
}
