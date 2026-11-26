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
