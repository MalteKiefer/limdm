package server

import (
	"context"
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// recordMetrics stores at most one sample per device every 15 minutes.
func recordMetrics(ctx context.Context, tx pgx.Tx, deviceID string, m *api.Metrics) error {
	if m == nil || m.MemTotalMB == 0 || m.MemUsedMB > m.MemTotalMB || m.RootUsedPct < 0 || m.RootUsedPct > 100 ||
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
	tick := func() {
		if err := s.snapshotFleet(ctx); err != nil {
			s.log.Error("fleet snapshot", "err", err)
		}
		if _, err := s.db.Exec(ctx, `DELETE FROM device_metrics WHERE at < now() - interval '30 days';
			DELETE FROM fleet_history WHERE day < current_date - 400`); err != nil {
			s.log.Error("prune history", "err", err)
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
	return err
}

type point struct {
	T time.Time
	V float64
}

type series struct {
	Label  string
	Class  string
	Points []point
}

// lineChart renders series as an inline SVG. Only numbers, fixed class names
// and escaped labels go into the markup; colours come from CSS (the CSP
// forbids inline styles).
func lineChart(title, unit string, maxV float64, from, to time.Time, ss []series) template.HTML {
	const w, h, padL, padB, padT = 600.0, 160.0, 36.0, 20.0, 8.0
	for _, s := range ss {
		for _, p := range s.Points {
			maxV = math.Max(maxV, p.V)
		}
	}
	if maxV <= 0 {
		maxV = 1
	}
	span := to.Sub(from).Seconds()
	if span <= 0 {
		span = 1
	}
	x := func(t time.Time) float64 { return padL + (w-padL-4)*t.Sub(from).Seconds()/span }
	y := func(v float64) float64 { return padT + (h-padT-padB)*(1-v/maxV) }
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s">`, w, h, template.HTMLEscapeString(title))
	for i := 0; i <= 4; i++ {
		v := maxV * float64(i) / 4
		fmt.Fprintf(&b, `<line class="grid" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/><text class="axis" x="%.1f" y="%.1f">%s</text>`,
			padL, w-4, y(v), y(v), padL-4, y(v)+3, template.HTMLEscapeString(fmtNum(v)+unit))
	}
	fmt.Fprintf(&b, `<text class="axis start" x="%.1f" y="%.1f">%s</text><text class="axis end" x="%.1f" y="%.1f">%s</text>`,
		padL, h-4, from.Local().Format("Jan 2"), w-4, h-4, to.Local().Format("Jan 2"))
	for _, s := range ss {
		if len(s.Points) == 0 {
			continue
		}
		var pts strings.Builder
		for _, p := range s.Points {
			fmt.Fprintf(&pts, "%.1f,%.1f ", x(p.T), y(p.V))
		}
		fmt.Fprintf(&b, `<polyline class="line %s" points="%s"><title>%s</title></polyline>`, s.Class, strings.TrimSpace(pts.String()), template.HTMLEscapeString(s.Label))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // numbers, constant classes and escaped labels only
}

func fmtNum(v float64) string {
	if v >= 10 || v == math.Trunc(v) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

// deviceCharts returns memory, disk and load charts for the last 7 days.
func (s *Server) deviceCharts(ctx context.Context, id string) ([]template.HTML, error) {
	rows, err := s.db.Query(ctx, `SELECT at, mem_used_mb, mem_total_mb, root_used_pct, load1 FROM device_metrics
		WHERE device_id=$1 AND at > now() - interval '7 days' ORDER BY at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mem, disk, load []point
	for rows.Next() {
		var at time.Time
		var used, total int64
		var root, l float32
		if err := rows.Scan(&at, &used, &total, &root, &l); err != nil {
			return nil, err
		}
		mem = append(mem, point{at, float64(used) * 100 / float64(max(total, 1))})
		disk = append(disk, point{at, float64(root)})
		load = append(load, point{at, float64(l)})
	}
	if err := rows.Err(); err != nil || len(mem) < 2 {
		return nil, err
	}
	to := time.Now()
	from := to.Add(-7 * 24 * time.Hour)
	return []template.HTML{
		lineChart("Memory used", "%", 100, from, to, []series{{"memory", "accent", mem}}),
		lineChart("Root filesystem used", "%", 100, from, to, []series{{"disk", "accent", disk}}),
		lineChart("Load (1 min)", "", 1, from, to, []series{{"load", "accent", load}}),
	}, nil
}

// fleetChart shows compliance over the last 30 days.
func (s *Server) fleetChart(ctx context.Context) (template.HTML, error) {
	rows, err := s.db.Query(ctx, `SELECT day, compliant, noncompliant, in_grace, stale + pending FROM fleet_history
		WHERE day > current_date - 30 ORDER BY day`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var ok, bad, grace, other []point
	for rows.Next() {
		var day time.Time
		var c, n, g, o int
		if err := rows.Scan(&day, &c, &n, &g, &o); err != nil {
			return "", err
		}
		ok = append(ok, point{day, float64(c)})
		bad = append(bad, point{day, float64(n)})
		grace = append(grace, point{day, float64(g)})
		other = append(other, point{day, float64(o)})
	}
	if err := rows.Err(); err != nil || len(ok) < 2 {
		return "", err
	}
	to := time.Now()
	return lineChart("Fleet compliance, 30 days", "", 1, to.AddDate(0, 0, -30), to, []series{
		{"compliant", "ok", ok}, {"non-compliant", "bad", bad}, {"in grace", "warn", grace}, {"stale or pending", "na", other},
	}), nil
}
