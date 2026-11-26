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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// loadTestDB is a fresh schema on the test database with a pool of maxConns.
func loadTestDB(t *testing.T, maxConns int32) *pgxpool.Pool {
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
