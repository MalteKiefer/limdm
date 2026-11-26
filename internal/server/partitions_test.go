package server

import (
	"context"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// An installation of an earlier version keeps its metric history when
// device_metrics becomes partitioned; check ins keep writing; old days go
// by dropping partitions, the legacy table once it is empty.
func TestMetricPartitions(t *testing.T) {
	db := loadTestDB(t, 4)
	s := loadTestServer(db)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatal(q, err)
		}
	}
	exec(`INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1','s',now(),'a')`)
	// the table as earlier versions created it, with history
	exec(`DROP TABLE device_metrics CASCADE`)
	exec(`CREATE TABLE device_metrics (
		device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, at TIMESTAMPTZ NOT NULL,
		mem_used_mb BIGINT NOT NULL, mem_total_mb BIGINT NOT NULL, root_used_pct REAL NOT NULL, load1 REAL NOT NULL,
		PRIMARY KEY (device_id, at))`)
	exec(`CREATE INDEX device_metrics_at ON device_metrics USING brin(at)`)
	exec(`INSERT INTO device_metrics SELECT 'd1', now() - make_interval(hours => h), 1, 2, 3, 4 FROM generate_series(1, 48) h`)
	// a row from a clock ahead of this host must not fail the conversion
	// (it is dropped)
	exec(`INSERT INTO device_metrics VALUES ('d1', now() + interval '2 days', 1, 2, 3, 4)`)
	tx := mustBegin(t, db)
	if err := partitionMetrics(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	var kind string
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM device_metrics), (SELECT relkind::text FROM pg_class WHERE oid='device_metrics'::regclass)`).Scan(&n, &kind); err != nil || n != 48 || kind != "p" {
		t.Fatalf("after conversion: %d rows, kind %q, %v", n, kind, err)
	}
	// a check in writes into it, also on days ahead
	tx2 := mustBegin(t, db)
	if err := recordMetrics(ctx, tx2, "d1", &api.Metrics{MemTotalMB: 8, MemUsedMB: 4, RootUsedPct: 10, Load1: 1}); err != nil {
		t.Fatal(err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO device_metrics VALUES ('d1', now() + interval '3 days', 1, 2, 3, 4)`)
	if err := db.QueryRow(ctx, `SELECT count(*) FROM device_metrics_default`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows in the default partition: %d %v", n, err)
	}
	// the legacy table goes once prune emptied it; then whole days are dropped
	exec(`DELETE FROM device_metrics WHERE at < now() + interval '1 day'`)
	if err := s.metricPartitions(ctx); err != nil {
		t.Fatal(err)
	}
	old := metricPartition(time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -40))
	exec(`CREATE TABLE ` + old + ` PARTITION OF device_metrics FOR VALUES FROM ('2000-01-01') TO ('2000-01-02')`)
	if err := s.metricPartitions(ctx); err != nil {
		t.Fatal(err)
	}
	var legacy, oldLeft bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('device_metrics_legacy') IS NOT NULL, to_regclass($1) IS NOT NULL`, old).Scan(&legacy, &oldLeft); err != nil || legacy || oldLeft {
		t.Fatalf("legacy %v, old partition %v: %v", legacy, oldLeft, err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM device_metrics`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows ahead: %d %v", n, err)
	}
}
