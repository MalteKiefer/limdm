package server

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/maltekiefer/limdm/internal/api"
)

// The Logs area of the console (docs/logs.md): search across the devices
// of the caller's scope or one device, histogram, context, facets,
// export, alert rules, and the state of the store and the archive.
//
// Admins and auditors read every device of their scope; the helpdesk reads
// single devices of its scope when Settings, Logs allows it. Every export is
// audited.

func (s *Server) appLogRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/logs", s.need("read", s.apiLogs))
	m.HandleFunc("GET /api/v1/logs/histogram", s.need("read", s.apiLogHistogram))
	m.HandleFunc("GET /api/v1/logs/facets", s.need("read", s.apiLogFacets))
	m.HandleFunc("GET /api/v1/logs/context", s.need("read", s.apiLogContext))
	m.HandleFunc("GET /api/v1/logs/export", s.need("read", s.apiLogExport))
	m.HandleFunc("GET /api/v1/logs/status", s.need("audit", s.globalOnly(s.apiLogStatus)))
	m.HandleFunc("POST /api/v1/logs/keys/rotate", s.need("admin", s.globalOnly(s.apiLogKeyRotate)))
	m.HandleFunc("POST /api/v1/logs/archive/run", s.need("admin", s.globalOnly(s.apiLogArchiveRun)))
	m.HandleFunc("POST /api/v1/logs/archive/restore", s.need("admin", s.globalOnly(s.apiLogRestore)))
	m.HandleFunc("GET /api/v1/logs/alerts", s.need("audit", s.apiLogAlerts))
	m.HandleFunc("POST /api/v1/logs/alerts", s.need("admin", s.apiLogAlertSave))
	m.HandleFunc("PUT /api/v1/logs/alerts/{id}", s.need("admin", s.apiLogAlertSave))
	m.HandleFunc("DELETE /api/v1/logs/alerts/{id}", s.need("admin", s.apiLogAlertDelete))
	m.HandleFunc("POST /api/v1/logs/alerts/{id}/test", s.need("admin", s.apiLogAlertTest))
}

var errLogAccess = &userError{http.StatusForbidden, "your role cannot read these logs"}

// logAccess: admins and auditors read all logs of their scope; the
// helpdesk one device at a time when the setting allows it.
func (s *Server) logAccess(c apiCaller, device string) bool {
	if c.can("audit") {
		return true
	}
	return device != "" && c.Role == "helpdesk" && s.settings().Logs.HelpdeskDevice
}

// logFilter is the WHERE clause of a request on device_logs l and devices d.
type logFilter struct {
	where    string
	args     *vulnArgs
	from, to time.Time
}

// parseLogFilter reads q, from, to and device of a request.
func (s *Server) parseLogFilter(c apiCaller, v url.Values, now time.Time) (logFilter, error) {
	f := logFilter{args: &vulnArgs{}, to: now.UTC()}
	device := strings.TrimSpace(v.Get("device"))
	if !s.logAccess(c, device) {
		return f, errLogAccess
	}
	for _, p := range []struct {
		key string
		t   *time.Time
	}{{"from", &f.from}, {"to", &f.to}} {
		if x := v.Get(p.key); x != "" {
			t, err := time.Parse(time.RFC3339, x)
			if err != nil {
				return f, &fieldError{p.key, p.key + ": RFC 3339 time"}
			}
			*p.t = t.UTC()
		}
	}
	if f.from.IsZero() {
		f.from = f.to.Add(-time.Hour)
	}
	if !f.from.Before(f.to) || f.to.Sub(f.from) > 400*24*time.Hour {
		return f, &fieldError{"from", "from must be before to, at most 400 days apart"}
	}
	conds := []string{"l.at >= " + f.args.add(f.from), "l.at < " + f.args.add(f.to)}
	sess := c.sess()
	tc, targs := tenantCond(sess, "l.tenant_id", len(f.args.list))
	f.args.list = append(f.args.list, targs...)
	sc, sargs := scopeCond(sess, len(f.args.list))
	f.args.list = append(f.args.list, sargs...)
	conds = append(conds, tc, sc)
	if device != "" {
		conds = append(conds, "l.device_id = "+f.args.add(device))
	}
	qc, err := logQueryConds(v.Get("q"), f.args)
	if err != nil {
		return f, err
	}
	f.where = strings.Join(append(conds, qc...), " AND ")
	return f, nil
}

// logRead runs fn in a read only transaction with a statement timeout:
// a regular expression or a wide search cannot hold the database.
func (s *Server) logRead(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '20s'`); err != nil {
		return err
	}
	err = fn(tx)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "57014" || pe.Code == "2201B") {
		if pe.Code == "2201B" {
			return &fieldError{"q", "query: invalid regular expression"}
		}
		return &userError{http.StatusUnprocessableEntity, "the search took too long: narrow the time range or the filter"}
	}
	return err
}

// logItem is one line in an answer.
type logItem struct {
	ID       string            `json:"id"`
	At       time.Time         `json:"at"`
	Device   string            `json:"device_id"`
	Hostname string            `json:"hostname"`
	Source   string            `json:"source"`
	Unit     string            `json:"unit"`
	Priority int               `json:"priority"`
	Host     string            `json:"host"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields,omitempty"`
}

const logCols = `l.at, l.device_id, d.hostname, l.source, l.unit, l.priority, l.host, l.message, l.fields, l.dedup`

func scanLogItem(row pgx.CollectableRow) (logItem, error) {
	var it logItem
	var fields []byte
	var dedup []byte
	var prio int16
	if err := row.Scan(&it.At, &it.Device, &it.Hostname, &it.Source, &it.Unit, &prio, &it.Host, &it.Message, &fields, &dedup); err != nil {
		return it, err
	}
	it.Priority = int(prio)
	if len(fields) > 0 {
		_ = json.Unmarshal(fields, &it.Fields)
	}
	it.ID = it.Device + "~" + strconv.FormatInt(it.At.UnixNano(), 10) + "~" + hex.EncodeToString(dedup)
	return it, nil
}

// parseLogID splits a line ID into device, time and dedup key.
func parseLogID(id string) (string, time.Time, []byte, bool) {
	parts := strings.Split(id, "~")
	if len(parts) != 3 {
		return "", time.Time{}, nil, false
	}
	ns, err := strconv.ParseInt(parts[1], 10, 64)
	d, err2 := hex.DecodeString(parts[2])
	if err != nil || err2 != nil || parts[0] == "" {
		return "", time.Time{}, nil, false
	}
	return parts[0], time.Unix(0, ns).UTC(), d, true
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request, c apiCaller) {
	q := r.URL.Query()
	f, err := s.parseLogFilter(c, q, time.Now())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	limit := 200
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			problemField(w, http.StatusBadRequest, "limit", "limit: 1 to 1000")
			return
		}
		limit = n
	}
	where := f.where
	if v := q.Get("cursor"); v != "" {
		ns, d, ok := strings.Cut(v, "~")
		n, err := strconv.ParseInt(ns, 10, 64)
		dedup, err2 := hex.DecodeString(d)
		if !ok || err != nil || err2 != nil {
			problemField(w, http.StatusBadRequest, "cursor", "cursor: the next_cursor of the previous page")
			return
		}
		where += " AND (l.at, l.dedup) < (" + f.args.add(time.Unix(0, n).UTC()) + ", " + f.args.add(dedup) + ")"
	}
	var items []logItem
	err = s.logRead(r.Context(), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT `+logCols+` FROM device_logs l JOIN devices d ON d.id = l.device_id
			WHERE `+where+` ORDER BY l.at DESC, l.dedup DESC LIMIT `+strconv.Itoa(limit), f.args.list...)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, scanLogItem)
		return err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := listPage{Items: nonNilSlice(items)}
	if len(items) == limit {
		last := items[len(items)-1]
		_, _, d, _ := parseLogID(last.ID)
		out.NextCursor = strconv.FormatInt(last.At.UnixNano(), 10) + "~" + hex.EncodeToString(d)
	}
	writeJSON(w, out)
}

// histogramBucket picks a bucket so the range has at most about 120.
func histogramBucket(d time.Duration) time.Duration {
	for _, b := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 24 * time.Hour} {
		if d/b <= 120 {
			return b
		}
	}
	return 7 * 24 * time.Hour
}

func (s *Server) apiLogHistogram(w http.ResponseWriter, r *http.Request, c apiCaller) {
	f, err := s.parseLogFilter(c, r.URL.Query(), time.Now())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	b := histogramBucket(f.to.Sub(f.from))
	type bucket struct {
		At     time.Time `json:"at"`
		Counts [8]int64  `json:"counts"` // per priority 0 (emerg) to 7 (debug)
	}
	start := f.from.Truncate(b)
	var list []bucket
	for t := start; t.Before(f.to); t = t.Add(b) {
		list = append(list, bucket{At: t})
	}
	err = s.logRead(r.Context(), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT date_bin(`+f.args.add(fmt.Sprintf("%d seconds", int(b.Seconds())))+`::interval, l.at, `+f.args.add(start)+`), l.priority, count(*)
			FROM device_logs l JOIN devices d ON d.id = l.device_id WHERE `+f.where+` GROUP BY 1, 2`, f.args.list...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t time.Time
			var p int16
			var n int64
			if err := rows.Scan(&t, &p, &n); err != nil {
				return err
			}
			if i := int(t.Sub(start) / b); i >= 0 && i < len(list) && p >= 0 && p < 8 {
				list[i].Counts[p] += n
			}
		}
		return rows.Err()
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"bucket_seconds": int(b.Seconds()), "from": f.from, "to": f.to, "buckets": nonNilSlice(list)})
}

func (s *Server) apiLogFacets(w http.ResponseWriter, r *http.Request, c apiCaller) {
	f, err := s.parseLogFilter(c, r.URL.Query(), time.Now())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	type unit struct {
		Source string `json:"source"`
		Unit   string `json:"unit"`
		Count  int64  `json:"count"`
	}
	var units []unit
	err = s.logRead(r.Context(), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT l.source, l.unit, count(*) FROM device_logs l JOIN devices d ON d.id = l.device_id
			WHERE `+f.where+` GROUP BY 1, 2 ORDER BY 3 DESC, 2 LIMIT 100`, f.args.list...)
		if err != nil {
			return err
		}
		units, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (unit, error) {
			var u unit
			return u, row.Scan(&u.Source, &u.Unit, &u.Count)
		})
		return err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"units": nonNilSlice(units)})
}

// apiLogContext answers the lines before and after one line of a device.
func (s *Server) apiLogContext(w http.ResponseWriter, r *http.Request, c apiCaller) {
	dev, at, dedup, ok := parseLogID(r.URL.Query().Get("id"))
	if !ok {
		problemField(w, http.StatusBadRequest, "id", "id: the id of a log line")
		return
	}
	n := 25
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x >= 1 && x <= 200 {
			n = x
		}
	}
	if !s.logAccess(c, dev) {
		s.apiFail(w, errLogAccess)
		return
	}
	sess := c.sess()
	a := &vulnArgs{}
	pd, pat, pdd, pn := a.add(dev), a.add(at), a.add(dedup), a.add(n)
	sc, sargs := scopeCond(sess, len(a.list))
	a.list = append(a.list, sargs...)
	tc, targs := tenantCond(sess, "l.tenant_id", len(a.list))
	a.list = append(a.list, targs...)
	base := `SELECT ` + logCols + ` FROM device_logs l JOIN devices d ON d.id = l.device_id
		WHERE l.device_id = ` + pd + ` AND l.at >= ` + pat + `::timestamptz - interval '1 day' AND l.at <= ` + pat + `::timestamptz + interval '1 day' AND ` + sc + ` AND ` + tc
	var before, after []logItem
	err := s.logRead(r.Context(), func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), base+` AND (l.at, l.dedup) < (`+pat+`, `+pdd+`) ORDER BY l.at DESC, l.dedup DESC LIMIT `+pn, a.list...)
		if err != nil {
			return err
		}
		if before, err = pgx.CollectRows(rows, scanLogItem); err != nil {
			return err
		}
		rows, err = tx.Query(r.Context(), base+` AND (l.at, l.dedup) >= (`+pat+`, `+pdd+`) ORDER BY l.at, l.dedup LIMIT `+pn+` + 1`, a.list...)
		if err != nil {
			return err
		}
		after, err = pgx.CollectRows(rows, scanLogItem)
		return err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	// newest first, like the list
	out := make([]logItem, 0, len(before)+len(after))
	for i := len(after) - 1; i >= 0; i-- {
		out = append(out, after[i])
	}
	out = append(out, before...)
	writeJSON(w, map[string]any{"items": out, "id": r.URL.Query().Get("id")})
}

// logExportMax bounds an export.
const logExportMax = 100000

func (s *Server) apiLogExport(w http.ResponseWriter, r *http.Request, c apiCaller) {
	q := r.URL.Query()
	format := q.Get("format")
	if format != "csv" && format != "ndjson" {
		problemField(w, http.StatusBadRequest, "format", "format: ndjson or csv")
		return
	}
	f, err := s.parseLogFilter(c, q, time.Now())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	detail := fmt.Sprintf("format=%s from=%s to=%s device=%q q=%q", format, f.from.Format(time.RFC3339), f.to.Format(time.RFC3339), q.Get("device"), truncate(q.Get("q"), 500))
	if err := s.auditAction(r.Context(), c.actor(), "logs.export", "logs", detail, nil); err != nil {
		s.apiFail(w, err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `SET LOCAL statement_timeout = '120s'`); err != nil {
		s.apiFail(w, err)
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT `+logCols+` FROM device_logs l JOIN devices d ON d.id = l.device_id
		WHERE `+f.where+` ORDER BY l.at DESC, l.dedup DESC LIMIT `+strconv.Itoa(logExportMax), f.args.list...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	defer rows.Close()
	name := "limdm-logs-" + f.to.Format("20060102-150405")
	var cw *csv.Writer
	var enc *json.Encoder
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		cw = csv.NewWriter(w)
		_ = cw.Write([]string{"time", "device_id", "hostname", "source", "unit", "priority", "host", "message"})
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.ndjson"`)
		enc = json.NewEncoder(w)
		enc.SetEscapeHTML(false)
	}
	for rows.Next() {
		it, err := scanLogItem(rows)
		if err != nil {
			s.log.Warn("log export", "err", err)
			return // the client sees a short file
		}
		if cw != nil {
			_ = cw.Write([]string{it.At.Format(time.RFC3339Nano), it.Device, csvSafe(it.Hostname), it.Source, csvSafe(it.Unit),
				api.LogPriorities[min(max(it.Priority, 0), 7)], csvSafe(it.Host), csvSafe(it.Message)})
		} else if err := enc.Encode(it); err != nil {
			return
		}
	}
	if cw != nil {
		cw.Flush()
	}
}

// ---- status, keys, archive ----

func (s *Server) apiLogStatus(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	type part struct {
		Day   string `json:"day"`
		Rows  int64  `json:"rows"` // estimate from the statistics
		Bytes int64  `json:"bytes"`
	}
	type key struct {
		ID      string    `json:"id"`
		Tenant  int64     `json:"tenant_id"`
		Created time.Time `json:"created_at"`
		Active  bool      `json:"active"`
	}
	type archive struct {
		Tenant   int64      `json:"tenant_id"`
		Day      string     `json:"day"`
		Target   string     `json:"target"`
		Objects  int        `json:"objects"`
		Lines    int64      `json:"lines"`
		Bytes    int64      `json:"bytes"`
		KeyID    string     `json:"key_id"`
		Verified *time.Time `json:"verified_at"`
	}
	type restore struct {
		Day   string    `json:"day"`
		Until time.Time `json:"until"`
		By    string    `json:"restored_by"`
	}
	out := struct {
		Partitions []part    `json:"partitions"`
		StoreBytes int64     `json:"store_bytes"`
		FreePct    *float64  `json:"free_pct"`
		Guard      string    `json:"guard"`
		Keys       []key     `json:"keys"`
		Archives   []archive `json:"archives"`
		Restores   []restore `json:"restores"`
		Today      struct {
			Devices int64 `json:"devices"`
			Lines   int64 `json:"lines"`
			Bytes   int64 `json:"bytes"`
			Dropped int64 `json:"dropped"`
		} `json:"today"`
	}{Guard: s.guardReason(ctx)}
	rows, err := s.db.Query(ctx, `SELECT c.relname, greatest(c.reltuples, 0)::bigint, pg_total_relation_size(c.oid) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'device_logs'::regclass ORDER BY c.relname DESC`)
	if err == nil {
		out.Partitions, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (part, error) {
			var p part
			var name string
			err := row.Scan(&name, &p.Rows, &p.Bytes)
			if d, perr := time.Parse("20060102", strings.TrimPrefix(name, "device_logs_")); perr == nil {
				p.Day = d.Format(time.DateOnly)
			}
			out.StoreBytes += p.Bytes
			return p, err
		})
	}
	if err == nil {
		if pct := diskFreePct(ctx, s.db); pct >= 0 {
			out.FreePct = &pct
		}
		rows, err = s.db.Query(ctx, `SELECT id, tenant_id, created_at, active FROM log_keys ORDER BY created_at DESC LIMIT 200`)
	}
	if err == nil {
		out.Keys, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (key, error) {
			var k key
			return k, row.Scan(&k.ID, &k.Tenant, &k.Created, &k.Active)
		})
	}
	if err == nil {
		rows, err = s.db.Query(ctx, `SELECT tenant_id, day::text, target, objects, lines, bytes, key_id, verified_at FROM log_archives ORDER BY day DESC, tenant_id LIMIT 400`)
	}
	if err == nil {
		out.Archives, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (archive, error) {
			var a archive
			return a, row.Scan(&a.Tenant, &a.Day, &a.Target, &a.Objects, &a.Lines, &a.Bytes, &a.KeyID, &a.Verified)
		})
	}
	if err == nil {
		rows, err = s.db.Query(ctx, `SELECT day::text, until, restored_by FROM log_restores WHERE until > now() ORDER BY day`)
	}
	if err == nil {
		out.Restores, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (restore, error) {
			var x restore
			return x, row.Scan(&x.Day, &x.Until, &x.By)
		})
	}
	if err == nil {
		err = s.db.QueryRow(ctx, `SELECT count(*), coalesce(sum(lines), 0)::bigint, coalesce(sum(bytes), 0)::bigint, coalesce(sum(dropped), 0)::bigint
			FROM log_usage WHERE day = (now() AT TIME ZONE 'UTC')::date`).Scan(&out.Today.Devices, &out.Today.Lines, &out.Today.Bytes, &out.Today.Dropped)
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out.Partitions, out.Keys, out.Archives, out.Restores = nonNilSlice(out.Partitions), nonNilSlice(out.Keys), nonNilSlice(out.Archives), nonNilSlice(out.Restores)
	writeJSON(w, out)
}

func (s *Server) apiLogKeyRotate(w http.ResponseWriter, r *http.Request, c apiCaller) {
	n, err := s.rotateLogKeys(r.Context(), c.actor())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]int{"rotated": n})
}

func (s *Server) apiLogArchiveRun(w http.ResponseWriter, r *http.Request, c apiCaller) {
	set := s.settings().Logs.withDefaults()
	if !set.Archive {
		problem(w, http.StatusConflict, "archiving is off")
		return
	}
	if err := s.auditAction(r.Context(), c.actor(), "logs.archive_run", "logs", set.ArchiveTarget, nil); err != nil {
		s.apiFail(w, err)
		return
	}
	// may take long; the result shows in the status and, on failure, as a notification
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Hour)
	go func() {
		defer cancel()
		if err := s.archiveLogs(ctx, set, time.Now().UTC().Truncate(24*time.Hour)); err != nil {
			s.log.Error("log archive", "err", err)
		}
	}()
	writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func (s *Server) apiLogRestore(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var body struct {
		Day    string `json:"day"`
		Tenant int64  `json:"tenant_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	day, err := time.Parse(time.DateOnly, body.Day)
	if err != nil {
		problemField(w, http.StatusUnprocessableEntity, "day", "day: YYYY-MM-DD")
		return
	}
	n, err := s.restoreLogDay(r.Context(), c.actor(), day, body.Tenant)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"lines": n, "day": body.Day})
}

// ---- alert rules ----

type logAlert struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Query         string     `json:"query"`
	Threshold     int        `json:"threshold"`
	WindowMinutes int        `json:"window_minutes"`
	Severity      string     `json:"severity"`
	Enabled       bool       `json:"enabled"`
	CreatedBy     string     `json:"created_by"`
	LastCount     *int       `json:"last_count"`
	LastFiredAt   *time.Time `json:"last_fired_at"`
	Tenant        *int64     `json:"-"`
}

func (a logAlert) validate() error {
	switch {
	case strings.TrimSpace(a.Name) == "" || len(a.Name) > 100:
		return &fieldError{"name", "name: 1 to 100 characters"}
	case a.Threshold < 1 || a.Threshold > 1000000:
		return &fieldError{"threshold", "threshold: 1 to 1000000 lines"}
	case a.WindowMinutes < 1 || a.WindowMinutes > 1440:
		return &fieldError{"window_minutes", "window_minutes: 1 to 1440"}
	case a.Severity != "info" && a.Severity != "warning" && a.Severity != "critical":
		return &fieldError{"severity", "severity: info, warning or critical"}
	case strings.TrimSpace(a.Query) == "":
		return &fieldError{"query", "query: a filter is required"}
	}
	_, err := logQueryConds(a.Query, &vulnArgs{})
	return err
}

const logAlertCols = `id, name, query, threshold, window_minutes, severity, enabled, created_by, last_count, last_fired_at, tenant_id`

func scanLogAlert(row pgx.CollectableRow) (logAlert, error) {
	var a logAlert
	return a, row.Scan(&a.ID, &a.Name, &a.Query, &a.Threshold, &a.WindowMinutes, &a.Severity, &a.Enabled, &a.CreatedBy, &a.LastCount, &a.LastFiredAt, &a.Tenant)
}

func (s *Server) apiLogAlerts(w http.ResponseWriter, r *http.Request, c apiCaller) {
	cond, args := tenantCond(c.sess(), "tenant_id", 0)
	rows, err := s.db.Query(r.Context(), `SELECT `+logAlertCols+` FROM log_alerts WHERE `+cond+` ORDER BY name, id`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, scanLogAlert)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}

// alertByID loads an alert rule the caller's tenant owns.
func (s *Server) alertByID(ctx context.Context, sess session, raw string) (logAlert, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return logAlert{}, &userError{http.StatusNotFound, "alert rule not found"}
	}
	cond, args := tenantCond(sess, "tenant_id", 1)
	rows, err := s.db.Query(ctx, `SELECT `+logAlertCols+` FROM log_alerts WHERE id = $1 AND `+cond, append([]any{id}, args...)...)
	if err != nil {
		return logAlert{}, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanLogAlert)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, &userError{http.StatusNotFound, "alert rule not found"}
	}
	return a, err
}

func (s *Server) apiLogAlertSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx, sess := r.Context(), c.sess()
	var a logAlert
	if !decodeJSON(w, r, &a) {
		return
	}
	a.Name, a.Query = strings.TrimSpace(a.Name), strings.TrimSpace(a.Query)
	if a.Severity == "" {
		a.Severity = "warning"
	}
	if err := a.validate(); err != nil {
		s.apiFail(w, err)
		return
	}
	var tenant *int64
	if sess.Tenant != 0 {
		tenant = &sess.Tenant
	}
	idText := r.PathValue("id")
	if idText != "" {
		cur, err := s.alertByID(ctx, sess, idText)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		a.ID = cur.ID
	}
	detail := fmt.Sprintf("name=%q query=%q threshold=%d window=%d severity=%s enabled=%v", a.Name, a.Query, a.Threshold, a.WindowMinutes, a.Severity, a.Enabled)
	err := s.auditAction(ctx, c.actor(), "logs.alert_save", a.Name, detail, func(tx pgx.Tx) error {
		if a.ID != 0 {
			_, err := tx.Exec(ctx, `UPDATE log_alerts SET name=$2, query=$3, threshold=$4, window_minutes=$5, severity=$6, enabled=$7 WHERE id=$1`,
				a.ID, a.Name, a.Query, a.Threshold, a.WindowMinutes, a.Severity, a.Enabled)
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO log_alerts(tenant_id, name, query, threshold, window_minutes, severity, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`, tenant, a.Name, a.Query, a.Threshold, a.WindowMinutes, a.Severity, a.Enabled, c.actor()).Scan(&a.ID)
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	saved, err := s.alertByID(ctx, sess, strconv.FormatInt(a.ID, 10))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, saved)
}

func (s *Server) apiLogAlertDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	a, err := s.alertByID(r.Context(), c.sess(), r.PathValue("id"))
	if err == nil {
		err = s.auditAction(r.Context(), c.actor(), "logs.alert_delete", a.Name, "", func(tx pgx.Tx) error {
			_, err := tx.Exec(r.Context(), `DELETE FROM log_alerts WHERE id = $1`, a.ID)
			return err
		})
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// alertSession is the scope an alert rule counts in: its tenant, or every
// device for a rule of a global administrator.
func alertSession(a logAlert) session {
	if a.Tenant == nil {
		return session{Email: "logs", Role: "admin", Super: true}
	}
	return session{Email: "logs", Role: "admin", Tenant: *a.Tenant}
}

// countAlert counts the lines that match a rule in its window up to now.
func (s *Server) countAlert(ctx context.Context, a logAlert, now time.Time) (int, error) {
	v := url.Values{"q": {a.Query}, "from": {now.Add(-time.Duration(a.WindowMinutes) * time.Minute).Format(time.RFC3339)}, "to": {now.Format(time.RFC3339)}}
	f, err := s.parseLogFilter(apiCaller{Role: "admin", Sess: ptr(alertSession(a))}, v, now)
	if err != nil {
		return 0, err
	}
	n := 0
	err = s.logRead(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM device_logs l JOIN devices d ON d.id = l.device_id WHERE `+f.where+`
			LIMIT `+strconv.Itoa(a.Threshold)+`) x`, f.args.list...).Scan(&n)
	})
	return n, err
}

func ptr[T any](v T) *T { return &v }

func (s *Server) alertNotice(a logAlert, n int, test bool) notice {
	title := "Log alert: " + a.Name
	if test {
		title = "Test: " + title
	}
	t := int64(0)
	if a.Tenant != nil {
		t = *a.Tenant
	}
	return notice{Type: "logs.alert", Severity: a.Severity, Title: title, Tenant: t,
		Text: fmt.Sprintf("%d or more lines matched %q in the last %d minutes (threshold %d).", n, a.Query, a.WindowMinutes, a.Threshold),
		URL:  s.cfg.PublicURL + "/app/logs?q=" + url.QueryEscape(a.Query)}
}

// apiLogAlertTest counts the rule now and sends a test notification to the
// channels that subscribed to log alerts.
func (s *Server) apiLogAlertTest(w http.ResponseWriter, r *http.Request, c apiCaller) {
	a, err := s.alertByID(r.Context(), c.sess(), r.PathValue("id"))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	n, err := s.countAlert(r.Context(), a, time.Now())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	s.notify(s.alertNotice(a, n, true))
	writeJSON(w, map[string]any{"count": n, "matches": n >= a.Threshold})
}

// evalLogAlerts fires the rules whose count reached the threshold, at
// most once per window.
func (s *Server) evalLogAlerts(ctx context.Context, now time.Time) error {
	rows, err := s.db.Query(ctx, `SELECT `+logAlertCols+` FROM log_alerts WHERE enabled`)
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, scanLogAlert)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range list {
		n, err := s.countAlert(ctx, a, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("alert %d: %w", a.ID, err))
			continue
		}
		fire := n >= a.Threshold && (a.LastFiredAt == nil || now.Sub(*a.LastFiredAt) >= time.Duration(a.WindowMinutes)*time.Minute)
		if fire {
			s.notify(s.alertNotice(a, n, false))
		}
		if _, err := s.db.Exec(ctx, `UPDATE log_alerts SET last_count = $2, last_fired_at = CASE WHEN $3 THEN $4 ELSE last_fired_at END WHERE id = $1`,
			a.ID, n, fire, now); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
