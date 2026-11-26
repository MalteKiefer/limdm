package server

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// recordMetrics stores at most one sample per device every 15 minutes.
func recordMetrics(ctx context.Context, tx pgx.Tx, deviceID string, m *api.Metrics) error {
	if m == nil || m.MemTotalMB == 0 || m.MemTotalMB > 1<<40 || m.MemUsedMB > m.MemTotalMB || m.RootUsedPct < 0 || m.RootUsedPct > 100 ||
		m.Load1 < 0 || m.Load1 > 10000 || math.IsNaN(m.Load1) || math.IsNaN(m.RootUsedPct) {
		return nil // ignore implausible values instead of failing the check in
	}
	_, err := tx.Exec(ctx, `INSERT INTO device_metrics(device_id, at, mem_used_mb, mem_total_mb, root_used_pct, load1)
		SELECT $1, now(), $2, $3, $4, $5
		WHERE NOT EXISTS (SELECT 1 FROM device_metrics WHERE device_id=$1 AND at > now() - interval '15 minutes')`,
		deviceID, m.MemUsedMB, m.MemTotalMB, m.RootUsedPct, m.Load1)
	return err
}

// historyLoop snapshots fleet compliance daily and prunes old samples.
func (s *Server) historyLoop(ctx context.Context) {
	lastFull := time.Time{}
	tick := func() {
		if err := s.snapshotFleet(ctx); err != nil {
			s.log.Error("fleet snapshot", "err", err)
		}
		if time.Since(lastFull) > 24*time.Hour { // full chain check: catches changes behind the checkpoint
			if broken, err := s.verifyAuditFrom(ctx, false); err != nil {
				s.log.Error("audit verification", "err", err)
			} else {
				// shown on the audit page next to the incremental result, on every instance
				prev, err := s.storeAuditVerification(ctx, broken)
				if err != nil {
					s.log.Error("store audit verification", "err", err)
				}
				if err == nil && broken != 0 && prev != broken {
					s.notify(notice{Type: "audit.broken", Severity: "critical", Title: "Audit log verification failed",
						Text: fmt.Sprintf("The hash chain of the audit log is broken at entry %d: entries were changed or removed outside LiMDM.", broken),
						URL:  s.cfg.PublicURL + "/audit"})
				}
				if broken != 0 {
					s.log.Error("audit log hash chain broken", "entry", broken)
				} else if err := s.pruneAudit(ctx); err != nil { // only behind a verified chain
					s.log.Error("audit retention", "err", err)
				}
			}
			lastFull = time.Now()
		}
		if err := s.prune(ctx); err != nil {
			s.log.Error("prune history", "err", err)
		}
		if err := s.metricPartitions(ctx); err != nil {
			s.log.Error("device_metrics partitions", "err", err)
		}
	}
	tick()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// snapshotFleet upserts today's row, so the last value of the day remains.
func (s *Server) snapshotFleet(ctx context.Context) error {
	list, err := s.listDevices(ctx)
	if err != nil {
		return err
	}
	c := map[string]int{}
	for _, d := range list {
		c[d.Status]++
	}
	_, err = s.db.Exec(ctx, `INSERT INTO fleet_history(day, compliant, noncompliant, in_grace, stale, pending) VALUES (current_date,$1,$2,$3,$4,$5)
		ON CONFLICT (day) DO UPDATE SET compliant=EXCLUDED.compliant, noncompliant=EXCLUDED.noncompliant, in_grace=EXCLUDED.in_grace,
		stale=EXCLUDED.stale, pending=EXCLUDED.pending`, c["compliant"], c["non-compliant"], c["in grace"], c["stale"], c["pending"])
	if err != nil {
		return err
	}
	return s.snapshotUpdates(ctx) // security updates and agent versions (app_home_updates.go)
}
