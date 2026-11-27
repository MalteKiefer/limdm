package server

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/maltekiefer/limdm/internal/api"
)

// Log management (docs/logs.md). Agents with com.limdm.logging send batches
// of lines to POST /api/v1/logs; the lines go to device_logs, partitioned
// by day. The logs job (Background, one instance) keeps the partitions:
// two days ahead, none older than the retention (Settings, Logs), archived
// and verified first when archiving is on (logs_archive.go). A disk guard
// refuses new lines while the log store is over its size or the database
// disk is nearly full.

func init() {
	auditActions["logs.export"] = "Logs exported"
	auditActions["logs.restore"] = "Archived logs restored"
	auditActions["logs.key_rotate"] = "Log archive keys rotated"
	auditActions["logs.alert_save"] = "Log alert saved"
	auditActions["logs.alert_delete"] = "Log alert deleted"
	auditActions["logs.archive_run"] = "Log archive started"
	notifyEvents = append(notifyEvents,
		struct{ Type, Label string }{"logs.alert", "Log alert rule matched"},
		struct{ Type, Label string }{"logs.guard", "Log store full or archive failed"})
}

// LogSettings is the settings section logs (Settings, Logs).
type LogSettings struct {
	RetentionDays        int            `json:"retention_days"`         // days on the server, 1..90 (default 7)
	MaxStoreGB           int            `json:"max_store_gb"`           // size of the log store that stops new lines, 0: no limit
	MinFreePct           int            `json:"min_free_pct"`           // free space of the database disk that stops new lines, 0: off
	DeviceMBPerDay       int            `json:"device_mb_per_day"`      // per device and day, 1..10240 (default 200)
	TenantMBPerDay       int            `json:"tenant_mb_per_day"`      // per tenant and day, 0: no limit
	TenantQuotas         map[string]int `json:"tenant_quotas"`          // tenant ID: MB per day, overrides tenant_mb_per_day
	HelpdeskDevice       bool           `json:"helpdesk_device_logs"`   // helpdesk reads the logs of single devices in its scope
	Archive              bool           `json:"archive"`                // export each day, encrypted, to ArchiveTarget
	ArchiveTarget        string         `json:"archive_target"`         // a storage target of Settings, Backup
	ArchiveRetentionDays int            `json:"archive_retention_days"` // archived days are deleted after this, 0: kept
	RestoreHours         int            `json:"restore_hours"`          // a restored day stays searchable this long (default 24)
}

func (l LogSettings) withDefaults() LogSettings {
	if l.RetentionDays == 0 {
		l.RetentionDays = 7
	}
	if l.DeviceMBPerDay == 0 {
		l.DeviceMBPerDay = 200
	}
	if l.RestoreHours == 0 {
		l.RestoreHours = 24
	}
	if l.TenantQuotas == nil {
		l.TenantQuotas = map[string]int{}
	}
	return l
}

func (l LogSettings) validate() string {
	switch {
	case l.RetentionDays < 1 || l.RetentionDays > 90:
		return "logs: retention_days must be 1 to 90"
	case l.MaxStoreGB < 0 || l.MaxStoreGB > 100000:
		return "logs: max_store_gb must be 0 to 100000"
	case l.MinFreePct < 0 || l.MinFreePct > 50:
		return "logs: min_free_pct must be 0 to 50"
	case l.DeviceMBPerDay < 1 || l.DeviceMBPerDay > 10240:
		return "logs: device_mb_per_day must be 1 to 10240"
	case l.TenantMBPerDay < 0 || l.TenantMBPerDay > 1048576:
		return "logs: tenant_mb_per_day must be 0 to 1048576"
	case l.ArchiveRetentionDays < 0 || l.ArchiveRetentionDays > 3650:
		return "logs: archive_retention_days must be 0 to 3650"
	case l.RestoreHours < 1 || l.RestoreHours > 720:
		return "logs: restore_hours must be 1 to 720"
	case l.Archive && l.ArchiveTarget == "":
		return "logs: archiving needs a storage target"
	case len(l.TenantQuotas) > 1000:
		return "logs: at most 1000 tenant quotas"
	}
	for k, v := range l.TenantQuotas {
		if n, err := strconv.ParseInt(k, 10, 64); err != nil || n < 1 || v < 0 || v > 1048576 {
			return "logs: tenant_quotas maps tenant IDs to 0 to 1048576 MB"
		}
	}
	return ""
}

// tenantQuota is the daily volume of a tenant in bytes, 0 without limit.
func (l LogSettings) tenantQuota(tenant int64) int64 {
	mb, ok := l.TenantQuotas[strconv.FormatInt(tenant, 10)]
	if !ok {
		mb = l.TenantMBPerDay
	}
	return int64(mb) << 20
}

// logPartition names the partition of a day (UTC).
func logPartition(day time.Time) string { return "device_logs_" + day.Format("20060102") }

// ensureLogPartitions creates the daily partitions from first to last.
func ensureLogPartitions(ctx context.Context, q execer, first, last time.Time) error {
	for d := first.UTC().Truncate(24 * time.Hour); !d.After(last); d = d.AddDate(0, 0, 1) {
		if _, err := q.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF device_logs FOR VALUES FROM ('%s') TO ('%s')`,
			logPartition(d), d.Format(time.RFC3339), d.AddDate(0, 0, 1).Format(time.RFC3339))); err != nil {
			return fmt.Errorf("%s: %w", logPartition(d), err)
		}
	}
	return nil
}

// logDays lists the days that have a partition, oldest first.
func logDays(ctx context.Context, q querier) ([]time.Time, error) {
	rows, err := q.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'device_logs'::regclass AND c.relname ~ '^device_logs_[0-9]{8}$' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	var out []time.Time
	for _, n := range names {
		if d, err := time.Parse("20060102", strings.TrimPrefix(n, "device_logs_")); err == nil {
			out = append(out, d)
		}
	}
	return out, err
}

// logGuard caches the disk guard of this instance for a minute.
type logGuard struct {
	mu     sync.Mutex
	at     time.Time
	reason string // why new lines are refused, empty when they are accepted
	// archiveNoticed is when a failed archive run was last announced
	archiveNoticed time.Time
}

var logGuards sync.Map // *Server -> *logGuard: per server, also in tests

func (s *Server) logGuard() *logGuard {
	g, _ := logGuards.LoadOrStore(s, &logGuard{})
	return g.(*logGuard)
}

// logStoreBytes is the size of all log partitions with their indexes.
func logStoreBytes(ctx context.Context, q querier) (int64, error) {
	var n int64
	err := q.QueryRow(ctx, `SELECT coalesce(sum(pg_total_relation_size(i.inhrelid)), 0)::bigint FROM pg_inherits i
		WHERE i.inhparent = 'device_logs'::regclass`).Scan(&n)
	return n, err
}

// diskFreePct reads the free space of the database's data directory where
// the server can see it (same host, a role allowed to read the setting);
// -1 when it cannot.
func diskFreePct(ctx context.Context, q querier) float64 {
	var dir string
	if err := q.QueryRow(ctx, `SELECT current_setting('data_directory')`).Scan(&dir); err != nil || dir == "" {
		return -1
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil || st.Blocks == 0 {
		return -1
	}
	return float64(st.Bavail) * 100 / float64(st.Blocks)
}

// guardReason checks the disk guard (cached for a minute); a change to
// refusing is announced once.
func (s *Server) guardReason(ctx context.Context) string {
	g := s.logGuard()
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.at) < time.Minute {
		return g.reason
	}
	set := s.settings().Logs.withDefaults()
	reason := ""
	if set.MaxStoreGB > 0 {
		if n, err := logStoreBytes(ctx, s.db); err == nil && n >= int64(set.MaxStoreGB)<<30 {
			reason = fmt.Sprintf("the log store holds %d GB, the limit is %d GB", n>>30, set.MaxStoreGB)
		}
	}
	if set.MinFreePct > 0 && reason == "" {
		if pct := diskFreePct(ctx, s.db); pct >= 0 && pct < float64(set.MinFreePct) {
			reason = fmt.Sprintf("the database disk has %.1f %% free, the minimum is %d %%", pct, set.MinFreePct)
		}
	}
	if reason != "" && g.reason == "" {
		s.log.Warn("log store refuses new lines", "reason", reason)
		s.notify(notice{Type: "logs.guard", Severity: "critical", Title: "Log store refuses new lines",
			Text: "Devices keep their logs in their buffers until there is room again: " + reason + ".", URL: s.cfg.PublicURL + "/app/settings?s=logs"})
	}
	g.at, g.reason = time.Now(), reason
	return reason
}

// secondsToMidnight is when the daily quotas start again (UTC), at most an hour.
func secondsToMidnight(now time.Time) int {
	next := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, 1)
	return min(int(next.Sub(now).Seconds())+1, 3600)
}

// agentLogs stores a batch of log lines of the device (POST /api/v1/logs).
func (s *Server) agentLogs(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(deviceKey).(string)
	ctx := r.Context()
	if !s.limit.allow("logs:"+id, 30, time.Minute) {
		w.Header().Set("Retry-After", "60")
		problem(w, http.StatusTooManyRequests, "too many log batches")
		return
	}
	if reason := s.guardReason(ctx); reason != "" {
		retryLater(w, 600, "log store full: "+reason)
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, api.LogBatchBytes)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			problem(w, http.StatusBadRequest, "bad gzip body")
			return
		}
		defer func() { _ = zr.Close() }()
		body = io.LimitReader(zr, api.LogBatchBytes+1)
	}
	var b api.LogBatch
	if err := json.NewDecoder(body).Decode(&b); err != nil {
		problem(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(b.Lines) > api.LogBatchLines {
		problem(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("at most %d lines per batch", api.LogBatchLines))
		return
	}
	set := s.settings().Logs.withDefaults()
	var tenant, devBytes, tenantBytes int64
	if err := s.db.QueryRow(ctx, `SELECT d.tenant_id, coalesce((SELECT u.bytes FROM log_usage u WHERE u.device_id = d.id AND u.day = (now() AT TIME ZONE 'UTC')::date), 0)
		FROM devices d WHERE d.id = $1`, id).Scan(&tenant, &devBytes); err != nil {
		s.failAPI(w, err)
		return
	}
	quota := set.tenantQuota(tenant)
	if quota > 0 {
		if err := s.db.QueryRow(ctx, `SELECT coalesce(sum(bytes), 0)::bigint FROM log_usage WHERE tenant_id = $1 AND day = (now() AT TIME ZONE 'UTC')::date`, tenant).Scan(&tenantBytes); err != nil {
			s.failAPI(w, err)
			return
		}
	}
	if devBytes >= int64(set.DeviceMBPerDay)<<20 || quota > 0 && tenantBytes >= quota {
		w.Header().Set("Retry-After", strconv.Itoa(secondsToMidnight(time.Now())))
		problem(w, http.StatusTooManyRequests, "daily log quota reached")
		return
	}
	res, size, err := s.storeLogLines(ctx, id, tenant, set.RetentionDays, b.Lines, time.Now())
	if err != nil {
		s.failAPI(w, err)
		return
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO log_usage(device_id, day, tenant_id, bytes, lines, dropped) VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2, $3, $4, $5)
		ON CONFLICT (device_id, day) DO UPDATE SET bytes = log_usage.bytes + EXCLUDED.bytes, lines = log_usage.lines + EXCLUDED.lines,
		dropped = log_usage.dropped + EXCLUDED.dropped, last_at = now()`, id, tenant, size, res.Stored, max(b.Dropped, 0)); err != nil {
		s.failAPI(w, err)
		return
	}
	writeJSON(w, res)
}

// logDedup identifies a line: device, source and the agent's cursor.
func logDedup(device, source, cursor string) []byte {
	h := sha256.Sum256([]byte(device + "\x00" + source + "\x00" + cursor))
	return h[:16]
}

// storeLogLines inserts lines, cleaned and bounded, skipping duplicates and
// lines outside the retention window. It returns the counts and the bytes
// stored.
func (s *Server) storeLogLines(ctx context.Context, device string, tenant int64, retention int, lines []api.LogLine, now time.Time) (api.LogBatchResult, int64, error) {
	var res api.LogBatchResult
	first := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, 1-retention)
	var (
		ats                        []time.Time
		sources, units, hosts, msg []string
		prios                      []int16
		fields                     []*string
		dedups                     [][]byte
		size                       int64
	)
	for _, l := range lines {
		t := l.Time.UTC()
		if t.After(now.Add(5*time.Minute)) || t.IsZero() {
			t = now.UTC() // a device clock ahead or no time: when it arrived
		}
		switch l.Source {
		case api.LogSourceJournald, api.LogSourceContainer, api.LogSourceFile:
		default:
			res.Skipped++
			continue
		}
		if t.Before(first) || l.Cursor == "" {
			res.Skipped++
			continue
		}
		var f *string
		if len(l.Fields) > 0 {
			clean := map[string]string{}
			for k, v := range l.Fields {
				if len(clean) < 32 && logFieldRe.MatchString(k) {
					clean[k] = strings.ToValidUTF8(truncate(v, 1024), "?")
				}
			}
			b, _ := json.Marshal(clean)
			js := string(b)
			f = &js
			size += int64(len(js))
		}
		m := strings.ReplaceAll(strings.ToValidUTF8(truncate(l.Message, api.LogMessageBytes), "?"), "\x00", "")
		ats = append(ats, t)
		sources = append(sources, l.Source)
		units = append(units, strings.ToValidUTF8(truncate(l.Unit, 256), "?"))
		hosts = append(hosts, strings.ToValidUTF8(truncate(l.Host, 255), "?"))
		msg = append(msg, m)
		prios = append(prios, int16(min(max(l.Priority, 0), 7)))
		fields = append(fields, f)
		dedups = append(dedups, logDedup(device, l.Source, truncate(l.Cursor, 512)))
		size += int64(len(m) + len(l.Unit))
	}
	if len(ats) == 0 {
		return res, 0, nil
	}
	insert := func() (pgconn.CommandTag, error) {
		return s.db.Exec(ctx, `INSERT INTO device_logs(at, device_id, tenant_id, source, unit, priority, host, message, fields, dedup)
			SELECT u.at, $1, $2, u.source, u.unit, u.priority, u.host, u.message, u.fields::jsonb, u.dedup
			FROM unnest($3::timestamptz[], $4::text[], $5::text[], $6::smallint[], $7::text[], $8::text[], $9::text[], $10::bytea[])
				u(at, source, unit, priority, host, message, fields, dedup)
			ON CONFLICT DO NOTHING`, device, tenant, ats, sources, units, prios, hosts, msg, fields, dedups)
	}
	tag, err := insert()
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23514" { // no partition yet: the logs job has not run
		if err := ensureLogPartitions(ctx, s.db, first, now.AddDate(0, 0, 2)); err != nil {
			return res, 0, err
		}
		tag, err = insert()
	}
	if err != nil {
		return res, 0, err
	}
	res.Stored = int(tag.RowsAffected())
	res.Duplicates = len(ats) - res.Stored
	return res, size, nil
}

// logsLoop keeps the partitions, archives and evaluates alert rules.
func (s *Server) logsLoop(ctx context.Context) {
	last := time.Time{}
	tick := func() {
		if err := s.evalLogAlerts(ctx, time.Now()); err != nil {
			s.log.Error("log alerts", "err", err)
		}
		if time.Since(last) < 10*time.Minute {
			return
		}
		last = time.Now()
		if err := s.maintainLogs(ctx, time.Now()); err != nil {
			s.log.Error("log partitions", "err", err)
		}
	}
	tick()
	t := time.NewTicker(time.Minute)
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

// maintainLogs creates partitions, archives finished days and drops the
// days past the retention (only archived and verified ones when archiving
// is on; a restored day stays until its restore ends).
func (s *Server) maintainLogs(ctx context.Context, now time.Time) error {
	set := s.settings().Logs.withDefaults()
	today := now.UTC().Truncate(24 * time.Hour)
	first := today.AddDate(0, 0, 1-set.RetentionDays)
	if err := ensureLogPartitions(ctx, s.db, first, today.AddDate(0, 0, 2)); err != nil {
		return err
	}
	var archErr error
	if set.Archive {
		archErr = s.archiveLogs(ctx, set, today)
	}
	days, err := logDays(ctx, s.db)
	if err != nil {
		return err
	}
	for _, d := range days {
		if !d.Before(first) {
			continue
		}
		var restored bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM log_restores WHERE day = $1 AND until > now())`, d).Scan(&restored); err != nil || restored {
			if err != nil {
				return err
			}
			continue
		}
		if set.Archive {
			ok, err := s.dayArchived(ctx, d)
			if err != nil {
				return err
			}
			if !ok {
				s.log.Warn("log partition kept: its archive is not verified", "day", d.Format(time.DateOnly))
				continue
			}
		}
		if _, err := s.db.Exec(ctx, `DROP TABLE IF EXISTS `+logPartition(d)); err != nil {
			return fmt.Errorf("drop %s: %w", logPartition(d), err)
		}
		if _, err := s.db.Exec(ctx, `DELETE FROM log_restores WHERE day = $1`, d); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM log_usage WHERE day < $1`, today.AddDate(0, 0, -95)); err != nil {
		return err
	}
	return archErr
}
