package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Prometheus metrics in the text exposition format, standard library only.
// /metrics on the console listener takes an API token of the metrics,
// admin or auditor role; the console's network list applies as well.

type httpKey struct {
	listener, method string
	code             int
}

// httpCounts counts requests per listener, method and status for all
// servers of the process.
var httpCounts = struct {
	sync.Mutex
	m map[httpKey]uint64
}{m: map[httpKey]uint64{}}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// latencyBuckets are the upper bounds (seconds) of the request duration
// histogram.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// httpLatency is the request duration histogram per listener: counts per
// bucket (not cumulative; the last is +Inf), sum and count.
var httpLatency = struct {
	sync.Mutex
	m map[string]*latencyHist
}{m: map[string]*latencyHist{}}

type latencyHist struct {
	buckets []uint64
	sum     float64
	n       uint64
}

func observeLatency(listener string, d time.Duration) {
	sec := d.Seconds()
	httpLatency.Lock()
	defer httpLatency.Unlock()
	h := httpLatency.m[listener]
	if h == nil {
		h = &latencyHist{buckets: make([]uint64, len(latencyBuckets)+1)}
		httpLatency.m[listener] = h
	}
	i := sort.SearchFloat64s(latencyBuckets, sec) // first bound >= sec
	h.buckets[i]++
	h.sum += sec
	h.n++
}

// requestIDRe is a request id a client or proxy may hand in.
var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

// requestID is the id of the request w answers (X-Request-ID), for log
// lines of handlers that only have the writer.
func requestID(w http.ResponseWriter) string { return w.Header().Get("X-Request-ID") }

// countRequests gives every request of a listener a request id (an
// X-Request-ID a proxy set, else a random one; returned in the answer),
// counts it by method and status, records its duration and, with
// LIMDM_ACCESS_LOG, writes an access log line.
func (s *Server) countRequests(listener string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-ID")
		if !requestIDRe.MatchString(id) {
			id = randToken(9)
		}
		w.Header().Set("X-Request-ID", id)
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		took := time.Since(start)
		observeLatency(listener, took)
		if s.ops().AccessLog {
			// the path only: query strings can carry codes and filters
			s.log.Info("request", "listener", listener, "method", r.Method, "path", truncate(r.URL.Path, 200), "status", max(rec.code, 200),
				"ms", took.Milliseconds(), "remote", clientIP(r), "request_id", id)
		}
		method := r.Method
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		default:
			method = "other" // clients pick methods freely; keep the label set small
		}
		if rec.code == 0 {
			rec.code = http.StatusOK
		}
		httpCounts.Lock()
		httpCounts.m[httpKey{listener, method, rec.code}]++
		httpCounts.Unlock()
	})
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// promWriter writes metric families; label values from devices are
// escaped and shortened.
type promWriter struct{ bytes.Buffer }

func (p *promWriter) family(name, typ, help string) {
	fmt.Fprintf(p, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// sample writes one value; labels are name, value pairs.
func (p *promWriter) sample(name string, v float64, labels ...string) {
	p.WriteString(name)
	if len(labels) > 0 {
		p.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				p.WriteByte(',')
			}
			fmt.Fprintf(p, `%s="%s"`, labels[i], labelEscaper.Replace(truncate(labels[i+1], 128)))
		}
		p.WriteByte('}')
	}
	p.WriteByte(' ')
	p.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	p.WriteByte('\n')
}

// counts runs a query of (label, count) rows.
func (s *Server) counts(ctx context.Context, sql string, args ...any) (map[string]float64, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]float64{}
	for rows.Next() {
		var k string
		var v float64
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	c, ok := s.bearer(w, r)
	if !ok {
		return
	}
	if c.Role == "helpdesk" || c.sess().scoped() || c.Tenant != 0 { // fleet wide numbers: global, unscoped tokens only
		s.deny(w, r, c, "metrics need a metrics, admin or auditor token without a device scope")
		return
	}
	ctx := r.Context()
	var p promWriter

	byStatus, _, err := s.deviceCounts(ctx, deviceQuery{stale: s.staleAfter().Seconds()})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	p.family("limdm_devices", "gauge", "Devices by status.")
	for _, st := range deviceStatuses {
		p.sample("limdm_devices", float64(byStatus[st]), "status", st)
	}

	queries := []struct{ name, help, label, sql string }{
		{"limdm_devices_last_checkin", "Active devices by time since their last check in.", "age", `SELECT CASE
			WHEN last_seen IS NULL THEN 'never' WHEN last_seen > now() - interval '1 hour' THEN 'lt_1h'
			WHEN last_seen > now() - interval '1 day' THEN 'lt_24h' WHEN last_seen > now() - interval '7 days' THEN 'lt_7d'
			WHEN last_seen > now() - interval '30 days' THEN 'lt_30d' ELSE 'ge_30d' END, count(*) FROM devices WHERE NOT retired GROUP BY 1`},
		{"limdm_compliance_failing_devices", "Active devices failing a compliance check.", "check", `SELECT c->>'id', count(*) FROM devices d,
			jsonb_array_elements(CASE WHEN jsonb_typeof(d.checks) = 'array' THEN d.checks ELSE '[]'::jsonb END) c
			WHERE NOT d.retired AND c->>'status' = 'fail' GROUP BY 1`},
		{"limdm_commands_open", "Commands not yet answered by the device.", "status", `SELECT s, (SELECT count(*) FROM commands WHERE status = s)
			FROM unnest(ARRAY['pending', 'sent']) s`},
		{"limdm_agent_versions", "Active devices by agent version.", "version", `SELECT agent_version, count(*) FROM devices WHERE NOT retired GROUP BY 1`},
		{"limdm_notifications_24h", "Notification deliveries in the last 24 hours.", "result", `SELECT r, (SELECT count(*) FROM notification_log
			WHERE at > now() - interval '1 day' AND ok = (r = 'ok')) FROM unnest(ARRAY['ok', 'failed']) r`},
	}
	for _, q := range queries {
		m, err := s.counts(ctx, q.sql)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		p.family(q.name, "gauge", q.help)
		for _, k := range sortedKeys(m) {
			p.sample(q.name, m[k], q.label, k)
		}
	}

	brokenAt, err := s.verifyAudit(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	intact := 1.0
	if full, _ := s.auditVerification(ctx); brokenAt != 0 || full != 0 {
		intact = 0
	}
	p.family("limdm_audit_chain_intact", "gauge", "1 while the audit log hash chain verifies, 0 when an entry was changed.")
	p.sample("limdm_audit_chain_intact", intact)
	var verified *time.Time
	if err := s.db.QueryRow(ctx, `SELECT max(verified_at) FROM audit_checkpoint`).Scan(&verified); err != nil {
		s.apiFail(w, err)
		return
	}
	if verified != nil {
		p.family("limdm_audit_verified_timestamp_seconds", "gauge", "Time of the last audit chain verification.")
		p.sample("limdm_audit_verified_timestamp_seconds", float64(verified.Unix()))
	}

	if err := s.backupMetrics(ctx, &p); err != nil { // backup.go
		s.apiFail(w, err)
		return
	}
	p.family("limdm_http_requests_total", "counter", "HTTP requests by listener, method and status code.")
	httpCounts.Lock()
	keys := make([]httpKey, 0, len(httpCounts.m))
	for k := range httpCounts.m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a.listener+a.method+strconv.Itoa(a.code) < b.listener+b.method+strconv.Itoa(b.code)
	})
	for _, k := range keys {
		p.sample("limdm_http_requests_total", float64(httpCounts.m[k]), "listener", k.listener, "method", k.method, "code", strconv.Itoa(k.code))
	}
	httpCounts.Unlock()

	p.family("limdm_http_request_duration_seconds", "histogram", "HTTP request duration by listener.")
	httpLatency.Lock()
	for _, l := range []string{"agent", "console"} {
		h := httpLatency.m[l]
		if h == nil {
			continue
		}
		var cum uint64
		for i, le := range latencyBuckets {
			cum += h.buckets[i]
			p.sample("limdm_http_request_duration_seconds_bucket", float64(cum), "listener", l, "le", strconv.FormatFloat(le, 'g', -1, 64))
		}
		p.sample("limdm_http_request_duration_seconds_bucket", float64(h.n), "listener", l, "le", "+Inf")
		p.sample("limdm_http_request_duration_seconds_sum", h.sum, "listener", l)
		p.sample("limdm_http_request_duration_seconds_count", float64(h.n), "listener", l)
	}
	httpLatency.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	p.WriteTo(w)
}
