package server

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// device_metrics is partitioned by day: at 50,000 devices it holds about 140
// million rows for its default 30 days, and dropping a day's partition replaces the
// hourly DELETE that left the table and its indexes bloated. Partitions are
// created a week ahead; a default partition catches rows of a day whose
// partition is missing, so a check in never fails on it.

// metricPartition names the partition of day (UTC).
func metricPartition(day time.Time) string { return "device_metrics_" + day.Format("20060102") }

// partitionMetrics turns the plain device_metrics of earlier versions into a
// partitioned table (migration 11). The existing rows stay: the old table
// becomes the partition of everything before tomorrow and is dropped once it
// is empty, 30 days later.
func partitionMetrics(ctx context.Context, tx pgx.Tx) error {
	var kind string
	if err := tx.QueryRow(ctx, `SELECT relkind::text FROM pg_class WHERE oid = 'device_metrics'::regclass`).Scan(&kind); err != nil || kind == "p" {
		return err
	}
	tomorrow := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 1)
	// rows dated from this host's tomorrow on (the database clock ahead
	// across midnight) do not fit the legacy partition and would fail the
	// ATTACH and the start; they are minutes of metrics, dropped
	if _, err := tx.Exec(ctx, `DELETE FROM device_metrics WHERE at >= $1`, tomorrow); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE device_metrics RENAME TO device_metrics_legacy;
		ALTER TABLE device_metrics_legacy RENAME CONSTRAINT device_metrics_pkey TO device_metrics_legacy_pkey;
		ALTER INDEX IF EXISTS device_metrics_at RENAME TO device_metrics_legacy_at;
		CREATE TABLE device_metrics (
			device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			at            TIMESTAMPTZ NOT NULL,
			mem_used_mb   BIGINT NOT NULL,
			mem_total_mb  BIGINT NOT NULL,
			root_used_pct REAL NOT NULL,
			load1         REAL NOT NULL,
			PRIMARY KEY (device_id, at)
		) PARTITION BY RANGE (at);
		CREATE INDEX device_metrics_at ON device_metrics USING brin(at);
		CREATE TABLE device_metrics_default PARTITION OF device_metrics DEFAULT`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER TABLE device_metrics ATTACH PARTITION device_metrics_legacy FOR VALUES FROM (MINVALUE) TO ('%s')`,
		tomorrow.Format(time.RFC3339))); err != nil {
		return err
	}
	return ensureMetricPartitions(ctx, tx, tomorrow)
}

// ensureMetricPartitions creates the daily partitions from day a week ahead
// (day is tomorrow: today is covered by yesterday's run or the legacy table).
func ensureMetricPartitions(ctx context.Context, q execer, day time.Time) error {
	for d := day; d.Before(day.AddDate(0, 0, 8)); d = d.AddDate(0, 0, 1) {
		if _, err := q.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF device_metrics FOR VALUES FROM ('%s') TO ('%s')`,
			metricPartition(d), d.Format(time.RFC3339), d.AddDate(0, 0, 1).Format(time.RFC3339))); err != nil {
			return fmt.Errorf("%s: %w", metricPartition(d), err)
		}
	}
	return nil
}

// metricPartitions keeps the partitions of device_metrics: a week ahead,
// none older than the metrics retention (Settings, Data retention), the legacy partition until it is empty. Run
// by the history job next to prune.
func (s *Server) metricPartitions(ctx context.Context) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if err := ensureMetricPartitions(ctx, s.db, today.AddDate(0, 0, 1)); err != nil {
		return err
	}
	rows, err := s.db.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'device_metrics'::regclass AND c.relname ~ '^device_metrics_[0-9]{8}$'`)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	cutoff := today.AddDate(0, 0, -s.settings().retentionDays("metrics"))
	for _, n := range names {
		if day, err := time.Parse("20060102", n[len("device_metrics_"):]); err == nil && day.AddDate(0, 0, 1).Before(cutoff) {
			if _, err := s.db.Exec(ctx, `DROP TABLE `+n); err != nil {
				return fmt.Errorf("drop %s: %w", n, err)
			}
		}
	}
	// prune deletes the old rows of the legacy partition; then it goes
	var legacy, empty bool
	if err := s.db.QueryRow(ctx, `SELECT to_regclass('device_metrics_legacy') IS NOT NULL`).Scan(&legacy); err != nil || !legacy {
		return err
	}
	if err := s.db.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM device_metrics_legacy)`).Scan(&empty); err != nil || !empty {
		return err
	}
	_, err = s.db.Exec(ctx, `DROP TABLE device_metrics_legacy`)
	return err
}
