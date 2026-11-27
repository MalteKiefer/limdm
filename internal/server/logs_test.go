package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestLogQueryLanguage(t *testing.T) {
	a := &vulnArgs{}
	conds, err := logQueryConds(`device:mail unit:postfix* prio<=err "connection refused" -healthcheck /timeout after \d+/ field._PID:42 source:docker https://x.test:443`, a)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.Join(conds, " AND ")
	for _, want := range []string{"lower(d.hostname) = lower($1)", "l.unit LIKE $3", "l.priority <= 3", "l.message ILIKE $4", "NOT (l.message ILIKE $5)",
		"l.message ~* $6", "l.fields->>$7 = $8", "l.source = 'container'", "l.message ILIKE $9"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in %s", want, sql)
		}
	}
	if a.list[2] != "postfix%" || a.list[3] != "%connection refused%" || a.list[5] != `timeout after \d+` || a.list[8] != "%https://x.test:443%" {
		t.Errorf("args %q", a.list)
	}
	if c, _ := logQueryConds(`unit:a_b%`, &vulnArgs{}); len(c) != 1 {
		t.Fatal("unit")
	}
	for _, bad := range []string{`"open`, `/(/`, `prio:loud`, `source:x`, `device:`, `field.a$:1`, `tag<3`, `/` + strings.Repeat("a", 201) + `/`} {
		if _, err := logQueryConds(bad, &vulnArgs{}); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	if histogramBucket(time.Hour) != time.Minute || histogramBucket(24*time.Hour) != 15*time.Minute || histogramBucket(7*24*time.Hour) != 3*time.Hour {
		t.Error("buckets")
	}
	if d, at, dd, ok := parseLogID("d1~1700000000000000000~0aff"); !ok || d != "d1" || at.Unix() != 1700000000 || len(dd) != 2 {
		t.Error("id")
	}
}

func TestLogArchiveCrypto(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	plain := bytes.Repeat([]byte("line of log\n"), 20000) // several chunks
	var buf bytes.Buffer
	w, err := newLogSealer(&buf, "lk-1-x", key)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plain[:100])
	w.Write(plain[100:])
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("line of log")) {
		t.Fatal("plain text in the archive")
	}
	read := func(b []byte) ([]byte, error) {
		r, id, err := openLogArchive(bytes.NewReader(b), func(string) ([]byte, error) { return key, nil })
		if err != nil {
			return nil, err
		}
		if id != "lk-1-x" {
			t.Fatalf("key id %s", id)
		}
		return io.ReadAll(r)
	}
	if got, err := read(buf.Bytes()); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	enc := buf.Bytes()
	for name, b := range map[string][]byte{
		"truncated": enc[:len(enc)-100],
		"cut chunk": enc[:len(enc)-20],
		"appended":  append(append([]byte{}, enc...), 1, 2, 3),
		"flipped":   append(append(append([]byte{}, enc[:300]...), enc[300]^1), enc[301:]...),
	} {
		if _, err := read(b); err == nil {
			t.Errorf("%s archive read", name)
		}
	}
	// a wrong key fails
	if r, _, err := openLogArchive(bytes.NewReader(enc), func(string) ([]byte, error) { return bytes.Repeat([]byte{1}, 32), nil }); err == nil {
		if _, err := io.ReadAll(r); err == nil {
			t.Error("wrong key read")
		}
	}
}

func TestLogSettingsAndPersonal(t *testing.T) {
	ok := LogSettings{}.withDefaults()
	if ok.validate() != "" || ok.RetentionDays != 7 || ok.DeviceMBPerDay != 200 {
		t.Fatal(ok)
	}
	for _, bad := range []LogSettings{{RetentionDays: 91}, {Archive: true}, {TenantQuotas: map[string]int{"x": 1}}, {MinFreePct: 60}} {
		if bad.withDefaults().validate() == "" {
			t.Errorf("%+v accepted", bad)
		}
	}
	q := LogSettings{TenantMBPerDay: 10, TenantQuotas: map[string]int{"2": 0}}
	if q.tenantQuota(1) != 10<<20 || q.tenantQuota(2) != 0 {
		t.Error("quotas")
	}
	on := json.RawMessage(`{"enabled":true,"journald":true}`)
	if string(refuseLogging(on, api.TemplateVars{Tags: []string{"personal"}})) == string(on) {
		t.Error("personal device collects")
	}
	if string(refuseLogging(on, api.TemplateVars{Attributes: map[string]string{"ownership": "company"}})) != string(on) {
		t.Error("company device refused")
	}
	allowed := json.RawMessage(`{"enabled":true,"journald":true,"allow_personal":true}`)
	if string(refuseLogging(allowed, api.TemplateVars{Attributes: map[string]string{"ownership": "personal"}})) != string(allowed) {
		t.Error("allow_personal ignored")
	}
}

// memStore is a blob store in memory (the archive target of the tests).
type memStore struct{ m map[string][]byte }

func (s *memStore) Put(_ context.Context, name, file string) error {
	b, err := os.ReadFile(file)
	s.m[name] = b
	return err
}
func (s *memStore) Get(_ context.Context, name string) (io.ReadCloser, error) {
	b, ok := s.m[name]
	if !ok {
		return nil, &userError{404, "missing"}
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (s *memStore) List(context.Context, string) ([]blobInfo, error) { return nil, nil }
func (s *memStore) Delete(_ context.Context, name string) error      { delete(s.m, name); return nil }

func TestLogs(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id, name) VALUES (2, 'Zweig');
		INSERT INTO console_users(email, role, tenant_id) VALUES ('admin@zweig.test', 'admin', 2);
		INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags, last_seen, checks, failing, tenant_id)
			VALUES ('t2', 's', now(), 'mail.zweig.test', '{}', now(), '[]', 0, 2)`)
	now := time.Now().UTC()
	line := func(src, unit, msg, cur string, prio int, at time.Time) api.LogLine {
		return api.LogLine{Time: at, Source: src, Unit: unit, Priority: prio, Message: msg, Cursor: cur, Fields: map[string]string{"_PID": "42", "bad key": "x"}}
	}
	res, _, err := s.storeLogLines(ctx, "d1", 1, 7, []api.LogLine{
		line("journald", "postfix@-.service", "connect to mx: Connection refused", "c1", 3, now.Add(-10*time.Minute)),
		line("journald", "sshd.service", "Accepted publickey for root", "c2", 6, now.Add(-5*time.Minute)),
		line("container", "paperless", "GET /healthcheck 200", "c3", 6, now.Add(-4*time.Minute)),
		line("journald", "old.service", "too old", "c4", 6, now.AddDate(0, 0, -30)),
		line("bogus", "x", "bad source", "c5", 6, now),
	}, now)
	if err != nil || res.Stored != 3 || res.Skipped != 2 {
		t.Fatalf("store: %+v %v", res, err)
	}
	if res, _, _ := s.storeLogLines(ctx, "d1", 1, 7, []api.LogLine{line("journald", "sshd.service", "again", "c2", 6, now.Add(-5*time.Minute))}, now); res.Duplicates != 1 {
		t.Fatalf("dedup: %+v", res)
	}
	if _, _, err := s.storeLogLines(ctx, "t2", 2, 7, []api.LogLine{line("journald", "postfix.service", "Connection refused in tenant two", "x1", 3, now.Add(-time.Minute))}, now); err != nil {
		t.Fatal(err)
	}

	get := func(sess session, path string, want int) string {
		t.Helper()
		code, body := call(sess, "GET", path, "")
		if code != want {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		return body
	}
	q := func(s string) string { return url.QueryEscape(s) }
	// global search over the scope; tenant isolation
	body := get(dashAuditor, "/api/v1/logs?q="+q(`"connection refused"`), 200)
	if strings.Count(body, `"id"`) != 2 || !strings.Contains(body, `"_PID":"42"`) || strings.Contains(body, "bad key") {
		t.Fatalf("search: %s", body)
	}
	tenant2 := session{Email: "admin@zweig.test", Role: "admin", Tenant: 2}
	if body := get(tenant2, "/api/v1/logs?q="+q("refused"), 200); strings.Count(body, `"id"`) != 1 || !strings.Contains(body, "tenant two") {
		t.Fatalf("tenant: %s", body)
	}
	if body := get(dashAuditor, "/api/v1/logs?q="+q(`device:alpha prio<=err`), 200); strings.Count(body, `"id"`) != 1 {
		t.Fatalf("device and prio: %s", body)
	}
	if body := get(dashAuditor, "/api/v1/logs?q="+q(`/accepted \w+ for/ -container:x`), 200); !strings.Contains(body, "publickey") {
		t.Fatalf("regex: %s", body)
	}
	page := get(dashAuditor, "/api/v1/logs?device=d1&limit=2", 200)
	var p struct {
		Items []logItem `json:"items"`
		Next  string    `json:"next_cursor"`
	}
	json.Unmarshal([]byte(page), &p)
	if len(p.Items) != 2 || p.Next == "" || p.Items[0].Message != "GET /healthcheck 200" {
		t.Fatalf("page: %s", page)
	}
	if body := get(dashAuditor, "/api/v1/logs?device=d1&limit=2&cursor="+q(p.Next), 200); strings.Count(body, `"id"`) != 1 {
		t.Fatalf("next page: %s", body)
	}
	get(dashAuditor, "/api/v1/logs?q="+q(`prio:loud`), 422)
	// helpdesk: only single devices, only with the setting
	get(dashHelpdesk, "/api/v1/logs", 403)
	get(dashHelpdesk, "/api/v1/logs?device=d1", 403)
	set := s.settings()
	set.Logs.HelpdeskDevice = true
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	get(dashHelpdesk, "/api/v1/logs?device=d1", 200)
	get(dashHelpdesk, "/api/v1/logs", 403)

	if body := get(dashAuditor, "/api/v1/logs/histogram?device=d1", 200); !strings.Contains(body, `"bucket_seconds":60`) || !strings.Contains(body, `"counts":[0,0,0,1,0,0,0,0]`) {
		t.Fatalf("histogram: %s", body)
	}
	if body := get(dashAuditor, "/api/v1/logs/facets", 200); !strings.Contains(body, `"unit":"paperless"`) {
		t.Fatalf("facets: %s", body)
	}
	if body := get(dashAuditor, "/api/v1/logs/context?n=1&id="+q(p.Items[1].ID), 200); strings.Count(body, `"id"`) != 4 { // 3 lines and the id field
		t.Fatalf("context: %s", body)
	}
	get(tenant2, "/api/v1/logs/context?id="+q(p.Items[1].ID), 200) // empty: not its device
	if body := get(tenant2, "/api/v1/logs/context?id="+q(p.Items[1].ID), 200); strings.Contains(body, "publickey") {
		t.Fatal("context across tenants")
	}
	csvBody := get(dashAuditor, "/api/v1/logs/export?format=csv&q="+q("refused"), 200)
	if !strings.HasPrefix(csvBody, "time,device_id") || !strings.Contains(csvBody, ",err,") {
		t.Fatalf("csv: %s", csvBody)
	}
	var audited int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='logs.export'`).Scan(&audited)
	if audited != 1 {
		t.Fatal("export not audited")
	}

	// ingest through the agent endpoint: gzip, quota
	post := func(b api.LogBatch) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		json.NewEncoder(zw).Encode(b)
		zw.Close()
		r := httptest.NewRequest("POST", "/api/v1/logs", &buf)
		r.Header.Set("Content-Encoding", "gzip")
		r = r.WithContext(context.WithValue(r.Context(), deviceKey, "d2"))
		w := httptest.NewRecorder()
		s.agentLogs(w, r)
		return w
	}
	if w := post(api.LogBatch{Lines: []api.LogLine{line("file", "/var/log/app.log", "hello", "1:0", 6, now)}, Dropped: 5}); w.Code != 200 || !strings.Contains(w.Body.String(), `"stored":1`) {
		t.Fatalf("ingest: %d %s", w.Code, w.Body)
	}
	exec(`UPDATE log_usage SET bytes = 300 << 20 WHERE device_id = 'd2'`)
	if w := post(api.LogBatch{Lines: []api.LogLine{line("file", "/var/log/app.log", "more", "1:6", 6, now)}}); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("quota: %d", w.Code)
	}

	// alert rules
	code, body := call(dashAdmin, "POST", "/api/v1/logs/alerts", `{"name":"MX down","query":"\"connection refused\"","threshold":1,"window_minutes":60,"enabled":true}`)
	var alert logAlert
	if json.Unmarshal([]byte(body), &alert); code != 200 || alert.ID == 0 || alert.Severity != "warning" {
		t.Fatalf("alert: %d %s", code, body)
	}
	if code, _ := call(dashAdmin, "POST", "/api/v1/logs/alerts", `{"name":"x","query":"prio:loud","threshold":1,"window_minutes":5}`); code != 422 {
		t.Fatal("bad alert query accepted")
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/logs/alerts/"+strconv.FormatInt(alert.ID, 10)+"/test", ""); code != 200 || !strings.Contains(body, `"matches":true`) {
		t.Fatalf("alert test: %d %s", code, body)
	}
	if code, _ := call(tenant2, "DELETE", "/api/v1/logs/alerts/"+strconv.FormatInt(alert.ID, 10), ""); code != 404 {
		t.Fatal("tenant deleted a global alert")
	}
	if err := s.evalLogAlerts(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	var fired *time.Time
	db.QueryRow(ctx, `SELECT last_fired_at FROM log_alerts WHERE id=$1`, alert.ID).Scan(&fired)
	if fired == nil {
		t.Fatal("alert did not fire")
	}

	// alert scope: a rule counts only the devices of the account that saved it
	if _, _, err := s.storeLogLines(ctx, "d3", 1, 7, []api.LogLine{line("journald", "x.service", "scope probe refused", "s1", 3, now.Add(-time.Minute))}, now); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO log_alerts(tenant_id, name, query, threshold, window_minutes, created_by, scope_tags)
		VALUES (1, 'scoped', '"scope probe"', 1, 60, 'audit@firma.de', '{prod}'), (NULL, 'orphan', '"scope probe"', 1, 60, 'x', '{}')`)
	code, body = call(tenant2, "POST", "/api/v1/logs/alerts", `{"name":"tenant two","query":"refused","threshold":10,"window_minutes":60,"enabled":true}`)
	var t2alert logAlert
	if json.Unmarshal([]byte(body), &t2alert); code != 200 {
		t.Fatalf("tenant alert: %d %s", code, body)
	}
	if err := s.evalLogAlerts(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	rows, _ := db.Query(ctx, `SELECT name, coalesce(last_count, -1) FROM log_alerts`)
	for rows.Next() {
		var n string
		var c int
		rows.Scan(&n, &c)
		counts[n] = c
	}
	rows.Close()
	if counts["scoped"] != 0 || counts["orphan"] != 0 || counts["tenant two"] != 1 || counts["MX down"] != 1 {
		t.Fatalf("alert scope: %v", counts)
	}
	// the test button counts with the caller's scope: the global admin sees every tenant
	if code, body := call(tenant2, "POST", "/api/v1/logs/alerts/"+strconv.FormatInt(t2alert.ID, 10)+"/test", ""); code != 200 || !strings.Contains(body, `"count":1`) {
		t.Fatalf("tenant test: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/logs/alerts/"+strconv.FormatInt(t2alert.ID, 10)+"/test", ""); code != 200 || !strings.Contains(body, `"count":3`) {
		t.Fatalf("global test: %d %s", code, body)
	}

	// partitions: an old day is archived (encrypted, verified), then dropped, then restored
	store := &memStore{m: map[string][]byte{}}
	logTargetHook = func(string) blobStore { return store }
	defer func() { logTargetHook = nil }()
	old := now.Truncate(24*time.Hour).AddDate(0, 0, -9)
	if err := ensureLogPartitions(ctx, db, old, old); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.storeLogLines(ctx, "d1", 1, 30, []api.LogLine{line("journald", "cron.service", "nightly job ran", "o1", 6, old.Add(time.Hour))}, now); err != nil {
		t.Fatal(err)
	}
	set = s.settings()
	set.Logs = LogSettings{Archive: true, ArchiveTarget: "arch"}.withDefaults()
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	if err := s.maintainLogs(ctx, now); err != nil {
		t.Fatal(err)
	}
	var exists bool
	db.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, logPartition(old)).Scan(&exists)
	man := store.m[logManifestName(1, old)]
	obj := store.m[logObjectName(1, "d1", old)]
	if exists || len(man) == 0 || len(obj) == 0 || bytes.Contains(obj, []byte("nightly")) {
		t.Fatalf("archive and drop: partition %v manifest %d object %d", exists, len(man), len(obj))
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/logs/archive/restore", `{"day":"`+old.Format(time.DateOnly)+`"}`); code != 200 || !strings.Contains(body, `"lines":1`) {
		t.Fatalf("restore: %d %s", code, body)
	}
	from := old.Format(time.RFC3339)
	if body := get(dashAuditor, "/api/v1/logs?from="+q(from)+"&q=nightly", 200); !strings.Contains(body, "nightly job ran") {
		t.Fatalf("restored day not searchable: %s", body)
	}
	if err := s.maintainLogs(ctx, now); err != nil { // the restore holds the day
		t.Fatal(err)
	}
	if body := get(dashAuditor, "/api/v1/logs?from="+q(from)+"&q=nightly", 200); !strings.Contains(body, "nightly") {
		t.Fatal("restored day dropped early")
	}
	// a damaged object is refused
	store.m[logObjectName(1, "d1", old)] = append(obj[:len(obj)-1:len(obj)-1], obj[len(obj)-1]^1)
	if _, err := s.restoreLogDay(ctx, "test", old, 0); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("damaged object: %v", err)
	}
	// key rotation: a new key, the old one still opens its archives
	if code, body := call(dashAdmin, "POST", "/api/v1/logs/keys/rotate", ""); code != 200 || !strings.Contains(body, `"rotated":1`) {
		t.Fatalf("rotate: %d %s", code, body)
	}
	if body := get(dashAuditor, "/api/v1/logs/status", 200); strings.Count(body, `"active":true`) != 1 || strings.Count(body, `"active":false`) != 1 || !strings.Contains(body, `"verified_at":"`) {
		t.Fatalf("status: %s", body)
	}
	get(tenant2, "/api/v1/logs/status", 403)
}
