package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Scheduled reports: a saved report preset (a saved view of the list
// "reports", query "kind=...&days=...") gets a cadence and recipients. The
// leader runs it as its owner in the tenant view it was scheduled in, with
// the owner's role and scope as they are at run time, through the console's
// export (audited as export and export.done), stores the file and sends a
// link (never the file) to the chosen notification channels or e-mail
// addresses (through an e-mail channel of the tenant). Every step is audited.

const (
	reportRunsKept   = 10       // files kept per schedule
	reportMaxBytes   = 64 << 20 // larger exports are refused, not stored
	reportHour       = 6        // local time of day the reports run
	reportMaxEmails  = 20
	reportLoopPeriod = 5 * time.Minute
)

var reportCadences = []string{"daily", "weekly", "monthly"}

func init() {
	for a, l := range map[string]string{"report.schedule": "Report scheduled", "report.unschedule": "Report schedule deleted",
		"report.run": "Scheduled report run", "report.download": "Report downloaded"} {
		auditActions[a] = l
	}
}

func (s *Server) appReportScheduleRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/report-schedules", s.need("audit", s.apiReportSchedules))
	m.HandleFunc("POST /api/v1/report-schedules", s.need("self", s.apiReportScheduleSave))
	m.HandleFunc("DELETE /api/v1/report-schedules/{id}", s.need("self", s.apiReportScheduleDelete))
	m.HandleFunc("POST /api/v1/report-schedules/{id}/run", s.need("self", s.apiReportScheduleRun))
	m.HandleFunc("GET /api/v1/report-schedules/{id}/runs", s.need("audit", s.apiReportRuns))
	m.HandleFunc("GET /api/v1/report-runs/{id}", s.need("audit", s.apiReportRunFile))
}

// nextReportRun is the first run of cadence after t: daily at 06:00, weekly
// on Monday, monthly on the first, in the server's time zone.
func nextReportRun(cadence string, t time.Time) time.Time {
	y, m, d := t.Date()
	at := func(y int, m time.Month, d int) time.Time {
		return time.Date(y, m, d, reportHour, 0, 0, 0, t.Location())
	}
	switch cadence {
	case "weekly":
		n := at(y, m, d+(8-int(t.Weekday()))%7)
		if !n.After(t) {
			n = n.AddDate(0, 0, 7)
		}
		return n
	case "monthly":
		n := at(y, m, 1)
		if !n.After(t) {
			n = at(y, m+1, 1)
		}
		return n
	}
	n := at(y, m, d)
	if !n.After(t) {
		n = at(y, m, d+1)
	}
	return n
}

// presetExport turns a preset query into the export kind and its query,
// relative days resolved against now (as the app's presetHref).
func presetExport(preset string, now time.Time) (string, url.Values, error) {
	in, err := url.ParseQuery(preset)
	if err != nil {
		return "", nil, err
	}
	kind := in.Get("kind")
	if !slices.Contains(exportKinds, kind) {
		return "", nil, errors.New("the preset names no known report")
	}
	out := url.Values{}
	keep := func(keys ...string) {
		for _, k := range keys {
			if v := in.Get(k); v != "" {
				out.Set(k, v)
			}
		}
	}
	switch kind {
	case "compliance-history.csv":
		keep("at", "device")
	case "audit.csv", "audit.jsonl":
		keep("q", "actor", "action", "target")
		if v := in.Get("days"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 3650 {
				return "", nil, errors.New("days must be 1..3650")
			}
			out.Set("from", now.AddDate(0, 0, -n).Format("2006-01-02"))
		}
	}
	return kind, out, nil
}

type reportSchedule struct {
	ID        int64      `json:"id"`
	ViewID    int64      `json:"view_id"`
	Name      string     `json:"name"`
	Query     string     `json:"query"`
	Owner     string     `json:"owner"`
	Tenant    *int64     `json:"tenant_id"`
	Cadence   string     `json:"cadence"`
	Channels  []int64    `json:"channels"`
	Emails    []string   `json:"emails"`
	NextRun   time.Time  `json:"next_run"`
	LastRun   *time.Time `json:"last_run"`
	LastError string     `json:"last_error"`
}

const reportScheduleCols = `r.id, r.view_id, v.name, v.query, r.owner, r.tenant_id, r.cadence, r.channels, r.emails, r.next_run, r.last_run, r.last_error`

type reportChannel struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// reportScheduleCond limits schedules to the caller: its own, and for
// admins every schedule of its tenant view.
func reportScheduleCond(c apiCaller, n int) (string, []any) {
	t := c.sess().Tenant
	if c.can("admin") {
		if t == 0 {
			return "TRUE", nil
		}
		return "r.tenant_id = $" + strconv.Itoa(n+1), []any{t}
	}
	return "r.owner = $" + strconv.Itoa(n+1), []any{c.actor()}
}

// channelsFor lists the enabled channels a schedule in tenant may send to.
func (s *Server) channelsFor(ctx context.Context, tenant int64) ([]channel, error) {
	all, err := s.loadChannels(ctx, true)
	if err != nil {
		return nil, err
	}
	ctx = withTenant(ctx, tenant)
	return slices.DeleteFunc(all, func(c channel) bool { return !channelOwned(ctx, c) }), nil
}

func (s *Server) apiReportSchedules(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	cond, args := reportScheduleCond(c, 0)
	list, err := collect(ctx, s.db, pgx.RowToStructByPos[reportSchedule], `SELECT `+reportScheduleCols+`
		FROM report_schedules r JOIN saved_views v ON v.id = r.view_id WHERE `+cond+` ORDER BY lower(v.name), r.id`, args...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	chans, err := s.channelsFor(ctx, c.sess().Tenant)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := []reportChannel{}
	for _, ch := range chans {
		out = append(out, reportChannel{ch.ID, ch.Name, ch.Kind})
	}
	writeJSON(w, map[string]any{"items": nonNilSlice(list), "channels": out})
}

type reportScheduleInput struct {
	ViewID   int64    `json:"view_id"`
	Cadence  string   `json:"cadence"`
	Channels []int64  `json:"channels"`
	Emails   []string `json:"emails"`
}

// scheduleOwner refuses callers a schedule cannot run as: tokens (a
// schedule belongs to a person) and roles without exports.
func (s *Server) scheduleOwner(w http.ResponseWriter, r *http.Request, c apiCaller) bool {
	if c.Sess == nil {
		s.deny(w, r, c, "report schedules belong to people, not tokens")
		return false
	}
	if !c.can("audit") {
		s.deny(w, r, c, "only admins and auditors export reports")
		return false
	}
	return true
}

// apiReportScheduleSave creates or replaces the caller's schedule of a
// saved report preset it can see.
func (s *Server) apiReportScheduleSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !s.scheduleOwner(w, r, c) {
		return
	}
	var in reportScheduleInput
	if !decodeJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	if !slices.Contains(reportCadences, in.Cadence) {
		problemField(w, http.StatusUnprocessableEntity, "cadence", "cadence: daily, weekly or monthly")
		return
	}
	var name, query string
	err := s.db.QueryRow(ctx, `SELECT name, query FROM saved_views WHERE id=$1 AND list='reports'
		AND (owner = $2 OR shared AND tenant_id IS NOT DISTINCT FROM $3)`, in.ViewID, c.actor(), viewTenant(c)).Scan(&name, &query)
	if errors.Is(err, pgx.ErrNoRows) {
		problemField(w, http.StatusUnprocessableEntity, "view_id", "view_id: a saved report you can see")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if _, _, err := presetExport(query, time.Now()); err != nil {
		problemField(w, http.StatusUnprocessableEntity, "view_id", "view_id: "+err.Error())
		return
	}
	chans, err := s.channelsFor(ctx, c.sess().Tenant)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	in.Channels = slices.Compact(slices.Sorted(slices.Values(in.Channels)))
	for _, id := range in.Channels {
		if !slices.ContainsFunc(chans, func(ch channel) bool { return ch.ID == id }) {
			problemField(w, http.StatusUnprocessableEntity, "channels", "channels: an enabled notification channel of this view")
			return
		}
	}
	emails := []string{}
	for _, e := range in.Emails {
		a, err := mail.ParseAddress(strings.TrimSpace(e))
		if err != nil || a.Name != "" {
			problemField(w, http.StatusUnprocessableEntity, "emails", "emails: plain addresses such as name@example.com")
			return
		}
		if !slices.Contains(emails, strings.ToLower(a.Address)) {
			emails = append(emails, strings.ToLower(a.Address))
		}
	}
	switch {
	case len(emails) > reportMaxEmails:
		problemField(w, http.StatusUnprocessableEntity, "emails", fmt.Sprintf("emails: at most %d", reportMaxEmails))
		return
	case len(emails) > 0 && !slices.ContainsFunc(chans, func(ch channel) bool { return ch.Kind == "email" }):
		problemField(w, http.StatusUnprocessableEntity, "emails", "emails: set up an e-mail channel first, its server sends them")
		return
	case len(emails) == 0 && len(in.Channels) == 0:
		problemField(w, http.StatusUnprocessableEntity, "channels", "channels: pick a channel or give e-mail addresses")
		return
	}
	var id int64
	err = s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		err := tx.QueryRow(ctx, `INSERT INTO report_schedules(view_id, owner, tenant_id, cadence, channels, emails, next_run) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (view_id, owner) DO UPDATE SET cadence=EXCLUDED.cadence, channels=EXCLUDED.channels, emails=EXCLUDED.emails,
				next_run=EXCLUDED.next_run, tenant_id=EXCLUDED.tenant_id RETURNING id`,
			in.ViewID, c.actor(), viewTenant(c), in.Cadence, in.Channels, emails, nextReportRun(in.Cadence, time.Now())).Scan(&id)
		return c.actor(), "report.schedule", name, fmt.Sprintf("#%d %s channels=%v emails=%v query=%s", id, in.Cadence, in.Channels, emails, truncate(query, 300)), err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	s.writeReportSchedule(w, r, c, id, http.StatusOK)
}

func (s *Server) writeReportSchedule(w http.ResponseWriter, r *http.Request, c apiCaller, id int64, status int) {
	cond, args := reportScheduleCond(c, 1)
	sch, err := collectOne(r.Context(), s.db, pgx.RowToStructByPos[reportSchedule], `SELECT `+reportScheduleCols+`
		FROM report_schedules r JOIN saved_views v ON v.id = r.view_id WHERE r.id=$1 AND `+cond, append([]any{id}, args...)...)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "schedule not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, status, sch)
}

// ownSchedule finds a schedule the caller may change: its own, or (admins)
// one of its tenant view.
func (s *Server) ownSchedule(w http.ResponseWriter, r *http.Request, c apiCaller) (int64, string, bool) {
	id, ok := pathID(w, r)
	if !ok {
		return 0, "", false
	}
	cond, args := reportScheduleCond(c, 1)
	var name string
	err := s.db.QueryRow(r.Context(), `SELECT v.name FROM report_schedules r JOIN saved_views v ON v.id = r.view_id WHERE r.id=$1 AND `+cond,
		append([]any{id}, args...)...).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "schedule not found")
		return 0, "", false
	}
	if err != nil {
		s.apiFail(w, err)
		return 0, "", false
	}
	return id, name, true
}

func (s *Server) apiReportScheduleDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !c.can("audit") {
		s.deny(w, r, c, "only admins and auditors export reports")
		return
	}
	id, name, ok := s.ownSchedule(w, r, c)
	if !ok {
		return
	}
	err := s.auditAction(r.Context(), c.actor(), "report.unschedule", name, fmt.Sprintf("#%d", id), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `DELETE FROM report_schedules WHERE id=$1`, id)
		return err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiReportScheduleRun runs a schedule now, as its owner, and sends it.
func (s *Server) apiReportScheduleRun(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !c.can("audit") {
		s.deny(w, r, c, "only admins and auditors export reports")
		return
	}
	id, _, ok := s.ownSchedule(w, r, c)
	if !ok {
		return
	}
	run, err := s.runReport(context.WithoutCancel(r.Context()), id, c.actor())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, run)
}

type reportRun struct {
	ID         int64     `json:"id"`
	ScheduleID int64     `json:"schedule_id"`
	At         time.Time `json:"at"`
	Kind       string    `json:"kind"`
	Rows       int       `json:"rows"`
	SHA256     string    `json:"sha256"`
	Error      string    `json:"error"`
}

func (s *Server) apiReportRuns(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, _, ok := s.ownSchedule(w, r, c)
	if !ok {
		return
	}
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[reportRun], `SELECT id, schedule_id, at, kind, rows, sha256, error
		FROM report_runs WHERE schedule_id=$1 ORDER BY id DESC`, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}

// apiReportRunFile hands out a stored report: to its owner, and to admins
// and auditors who see at least as much (the all tenants view, or the
// same tenant without a device scope). Audited like an export.
func (s *Server) apiReportRunFile(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var owner, kind, sum string
	var tenant *int64
	var content []byte
	err := s.db.QueryRow(ctx, `SELECT s.owner, s.tenant_id, x.kind, x.sha256, x.content FROM report_runs x JOIN report_schedules s ON s.id = x.schedule_id
		WHERE x.id=$1 AND x.error = ''`, id).Scan(&owner, &tenant, &kind, &sum, &content)
	sess := c.sess()
	allowed := owner == c.actor() || !sess.scoped() && (sess.Tenant == 0 || tenant != nil && *tenant == sess.Tenant)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !allowed {
		problem(w, http.StatusNotFound, "report not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if err := s.auditAction(ctx, c.actor(), "report.download", kind, fmt.Sprintf("run #%d sha256=%s", id, sum), nil); err != nil {
		s.apiFail(w, err)
		return
	}
	ctype := "text/csv; charset=utf-8"
	if strings.HasSuffix(kind, ".jsonl") {
		ctype = "application/x-ndjson"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="limdm-report-%d-%s"`, id, kind))
	_, _ = w.Write(content)
}

// bufferWriter captures what export writes.
type bufferWriter struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (b *bufferWriter) Header() http.Header         { return b.h }
func (b *bufferWriter) WriteHeader(code int)        { b.code = code }
func (b *bufferWriter) Write(p []byte) (int, error) { return b.buf.Write(p) }

// ownerSession is the owner's session as it would be now in the tenant
// view tenant (0: all tenants): its current role and scope.
func (s *Server) ownerSession(ctx context.Context, owner string, tenant int64) (session, error) {
	sess := session{Email: owner}
	role, _ := s.account(ctx, owner)
	if role != "admin" && role != "auditor" {
		return sess, errors.New("the owner is disabled or no longer an admin or auditor")
	}
	sess.Role = role
	if err := s.loadScope(ctx, &sess); err != nil {
		return sess, err
	}
	bound := sess
	if err := s.loadTenant(ctx, &bound); err != nil {
		return sess, err
	}
	switch {
	case bound.Super:
		sess.Super, sess.Tenant = true, tenant
	case bound.Tenant != tenant:
		return sess, errors.New("the owner no longer belongs to the report's tenant")
	default:
		sess.Tenant = tenant
	}
	return sess, nil
}

// runReport runs schedule id now: the export as its owner, the file kept
// (the last reportRunsKept), a link to the recipients. actor is who started
// it ("system" for the schedule).
func (s *Server) runReport(ctx context.Context, id int64, actor string) (reportRun, error) {
	var owner, name, query string
	var tenant *int64
	var chanIDs []int64
	var emails []string
	err := s.db.QueryRow(ctx, `SELECT r.owner, r.tenant_id, v.name, v.query, r.channels, r.emails FROM report_schedules r
		JOIN saved_views v ON v.id = r.view_id WHERE r.id=$1`, id).Scan(&owner, &tenant, &name, &query, &chanIDs, &emails)
	if err != nil {
		return reportRun{}, err
	}
	t := int64(0)
	if tenant != nil {
		t = *tenant
		ctx = withTenant(ctx, t)
	}
	run := reportRun{ScheduleID: id, At: time.Now()}
	content, err := s.generateReport(ctx, owner, t, query, &run)
	if err != nil {
		run.Error, content = truncate(err.Error(), 500), []byte{}
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO report_runs(schedule_id, kind, rows, sha256, content, error) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, at`,
			id, run.Kind, run.Rows, run.SHA256, content, run.Error).Scan(&run.ID, &run.At); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM report_runs WHERE schedule_id=$1 AND id NOT IN (SELECT id FROM report_runs WHERE schedule_id=$1 ORDER BY id DESC LIMIT $2)`,
			id, reportRunsKept); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE report_schedules SET last_run=now(), last_error=$2 WHERE id=$1`, id, run.Error); err != nil {
			return err
		}
		detail := fmt.Sprintf("schedule #%d run #%d as %s: ", id, run.ID, owner)
		if run.Error != "" {
			detail += "failed: " + run.Error
		} else {
			detail += fmt.Sprintf("%s rows=%d sha256=%s channels=%v emails=%v", run.Kind, run.Rows, run.SHA256, chanIDs, emails)
		}
		return audit(ctx, tx, actor, "report.run", name, detail)
	})
	if err != nil {
		return run, err
	}
	s.sendReport(ctx, t, name, run, chanIDs, emails)
	return run, nil
}

// generateReport runs the export of a preset as the owner.
func (s *Server) generateReport(ctx context.Context, owner string, tenant int64, query string, run *reportRun) ([]byte, error) {
	kind, q, err := presetExport(query, time.Now())
	if err != nil {
		return nil, err
	}
	run.Kind = kind
	sess, err := s.ownerSession(ctx, owner, tenant)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/exports/"+kind+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.SetPathValue("kind", kind)
	w := &bufferWriter{h: http.Header{}, code: http.StatusOK}
	s.export(w, req, sess)
	out := w.buf.Bytes()
	switch {
	case w.code != http.StatusOK:
		return nil, fmt.Errorf("export answered %d", w.code)
	case bytes.Contains(out, []byte("\nERROR: export incomplete")):
		return nil, errors.New("export incomplete")
	case len(out) > reportMaxBytes:
		return nil, fmt.Errorf("the report has more than %d MB; narrow the preset", reportMaxBytes>>20)
	}
	sum := sha256.Sum256(out)
	run.SHA256 = hex.EncodeToString(sum[:])
	run.Rows = max(bytes.Count(out, []byte("\n"))-1, 0)
	if strings.HasSuffix(kind, ".jsonl") {
		run.Rows++
	}
	return out, nil
}

// sendReport tells the recipients a report is ready: a link, the row count
// and the hash; the file stays on the server behind the sign in.
func (s *Server) sendReport(ctx context.Context, tenant int64, name string, run reportRun, chanIDs []int64, emails []string) {
	n := notice{Type: "report.ready", Severity: "info", Title: "Report ready: " + name, Tenant: tenant, At: time.Now().UTC(),
		URL: s.cfg.PublicURL + "/api/v1/report-runs/" + strconv.FormatInt(run.ID, 10)}
	if run.Error != "" {
		n.Type, n.Severity, n.Title = "report.failed", "warning", "Report failed: "+name
		n.Text = "The scheduled report could not be created: " + run.Error
		n.URL = s.cfg.PublicURL + "/app/reports"
	} else {
		n.Text = fmt.Sprintf("%s with %d rows (SHA-256 %s). Sign in to download it; the server keeps the last %d runs.", run.Kind, run.Rows, run.SHA256, reportRunsKept)
	}
	chans, err := s.channelsFor(ctx, tenant)
	if err != nil {
		s.log.Error("report channels", "err", err)
		return
	}
	for _, c := range chans {
		if slices.Contains(chanIDs, c.ID) {
			go s.deliverWithRetry(c, n) //nolint:gosec // delivery outlives the request, with its own timeouts
		}
	}
	if len(emails) == 0 {
		return
	}
	i := slices.IndexFunc(chans, func(c channel) bool { return c.Kind == "email" })
	if i < 0 {
		s.log.Warn("report not mailed: no e-mail channel", "report", name)
		return
	}
	c := chans[i]
	c.Config.To = emails
	go s.deliverWithRetry(c, n) //nolint:gosec // delivery outlives the request, with its own timeouts
}

// reportLoop runs the due schedules (leader only, Background).
func (s *Server) reportLoop(ctx context.Context) {
	t := time.NewTicker(reportLoopPeriod)
	defer t.Stop()
	for {
		if err := s.runDueReports(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("scheduled reports", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) runDueReports(ctx context.Context) error {
	type due struct {
		ID      int64
		Cadence string
		Next    time.Time
	}
	list, err := collect(ctx, s.db, pgx.RowToStructByPos[due], `SELECT id, cadence, next_run FROM report_schedules WHERE next_run <= now() ORDER BY next_run LIMIT 20`)
	if err != nil {
		return err
	}
	for _, d := range list {
		// claim the run first: a crash skips one run instead of repeating it
		tag, err := s.db.Exec(ctx, `UPDATE report_schedules SET next_run=$3 WHERE id=$1 AND next_run=$2`, d.ID, d.Next, nextReportRun(d.Cadence, time.Now()))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if _, err := s.runReport(ctx, d.ID, "system"); err != nil {
			s.log.Error("scheduled report", "schedule", d.ID, "err", err)
		}
	}
	return nil
}
