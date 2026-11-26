package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Aggregates of the console app's home page. Each answers for the caller's
// tenant and device scope; the installation wide history and the backup
// state only in the global view.

type statsFleet struct {
	Total         int            `json:"total"` // active devices (not retired)
	Online        int            `json:"online"`
	Status        map[string]int `json:"status"`
	AgentVersions []facetCount   `json:"agent_versions"`
	OS            []facetCount   `json:"os"`
	Cells         []fleetCell    `json:"cells"` // one per device, worst status first, at most fleetCellCap
	Truncated     bool           `json:"truncated"`
}

type fleetCell struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Status   string `json:"status"`
}

const fleetCellCap = 5000

// statusRank orders the fleet grid: what needs attention first.
var statusRank = []string{"non-compliant", "in grace", "stale", "pending", "compliant"}

func (s *Server) apiStatsFleet(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	scope, args := scopeCond(c.sess(), 1)
	stale := s.staleAfter().Seconds()
	where := ` WHERE NOT d.retired AND ` + scope
	st := statsFleet{Status: map[string]int{}}
	rows, err := s.db.Query(ctx, `SELECT d.id, d.hostname, `+deviceStatusSQL+deviceFrom+where+` ORDER BY d.hostname, d.id`, append([]any{stale}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for rows.Next() {
		var cell fleetCell
		if err := rows.Scan(&cell.ID, &cell.Hostname, &cell.Status); err != nil {
			rows.Close()
			s.apiFail(w, err)
			return
		}
		st.Total++
		st.Status[cell.Status]++
		if cell.Status != "stale" && cell.Status != "pending" {
			st.Online++
		}
		st.Cells = append(st.Cells, cell)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.apiFail(w, err)
		return
	}
	slices.SortStableFunc(st.Cells, func(a, b fleetCell) int {
		return slices.Index(statusRank, a.Status) - slices.Index(statusRank, b.Status)
	})
	if len(st.Cells) > fleetCellCap {
		st.Cells, st.Truncated = st.Cells[:fleetCellCap], true
	}
	if st.Cells == nil {
		st.Cells = []fleetCell{}
	}
	scope0, args0 := scopeCond(c.sess(), 0)
	for _, f := range []struct {
		expr string
		dst  *[]facetCount
	}{{"d.agent_version", &st.AgentVersions}, {"d.os_name", &st.OS}} {
		if *f.dst, err = facetQuery(ctx, s, `SELECT `+f.expr+`, count(*) FROM devices d WHERE NOT d.retired AND `+scope0+` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 12`, args0...); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	writeJSON(w, st)
}

type statsFramework struct {
	ID   string  `json:"id"`
	Name string  `json:"name"`
	Pass int     `json:"pass"`
	Fail int     `json:"fail"`
	Rate float64 `json:"rate"` // passing share of the framework's check results, percent
}

type statsCheck struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Fail  int    `json:"fail"`
}

type statsDay struct {
	Day          string  `json:"day"`
	Compliant    int     `json:"compliant"`
	NonCompliant int     `json:"noncompliant"`
	InGrace      int     `json:"in_grace"`
	Stale        int     `json:"stale"`
	Pending      int     `json:"pending"`
	Score        float64 `json:"score"`
}

type statsCompliance struct {
	// Score is the share of reporting devices that pass every check, in
	// percent; the history uses the same definition per day.
	Score      float64          `json:"score"`
	Reporting  int              `json:"reporting"`
	Compliant  int              `json:"compliant"`
	Frameworks []statsFramework `json:"frameworks"`
	TopFailing []statsCheck     `json:"top_failing"`
	History    []statsDay       `json:"history"` // global view only, oldest first
}

// frameworkIDs maps the framework names of the check references to stable ids.
var frameworkIDs = []struct{ ID, Name string }{{"bsi", "BSI IT-Grundschutz"}, {"cis", "CIS Benchmark"}, {"iso", "ISO/IEC 27001:2022"}}

func percent(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(int(float64(part)*1000/float64(whole)+0.5)) / 10
}

func (s *Server) apiStatsCompliance(w http.ResponseWriter, r *http.Request, c apiCaller) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 400 {
			problem(w, http.StatusBadRequest, "days must be 1..400")
			return
		}
		days = n
	}
	ctx := r.Context()
	sess := c.sess()
	fc, err := s.fleetComplianceFor(ctx, sess)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	reporting := fc.Total - fc.Stale - fc.Pending
	out := statsCompliance{Score: percent(fc.Compliant, reporting), Reporting: reporting, Compliant: fc.Compliant,
		Frameworks: []statsFramework{}, TopFailing: []statsCheck{}, History: []statsDay{}}
	for _, f := range frameworkIDs {
		fw := statsFramework{ID: f.ID, Name: f.Name}
		for _, ctl := range fc.Controls {
			if ctl.Framework == f.Name {
				fw.Pass += ctl.Pass
				fw.Fail += ctl.Fail
			}
		}
		fw.Rate = percent(fw.Pass, fw.Pass+fw.Fail)
		out.Frameworks = append(out.Frameworks, fw)
	}
	for _, ch := range fc.Checks {
		if ch.Fail > 0 {
			out.TopFailing = append(out.TopFailing, statsCheck{ch.ID, ch.Title, ch.Fail})
		}
	}
	slices.SortStableFunc(out.TopFailing, func(a, b statsCheck) int { return b.Fail - a.Fail })
	out.TopFailing = out.TopFailing[:min(len(out.TopFailing), 8)]
	if sess.Tenant == 0 && !sess.scoped() { // the history is installation wide
		if out.History, err = s.fleetHistory(ctx, days); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	writeJSON(w, out)
}

func (s *Server) fleetHistory(ctx context.Context, days int) ([]statsDay, error) {
	rows, err := s.db.Query(ctx, `SELECT to_char(day, 'YYYY-MM-DD'), compliant, noncompliant, in_grace, stale, pending FROM fleet_history
		WHERE day > current_date - $1::int ORDER BY day`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []statsDay{}
	for rows.Next() {
		var d statsDay
		if err := rows.Scan(&d.Day, &d.Compliant, &d.NonCompliant, &d.InGrace, &d.Stale, &d.Pending); err != nil {
			return nil, err
		}
		d.Score = percent(d.Compliant, d.Compliant+d.NonCompliant+d.InGrace)
		out = append(out, d)
	}
	return out, rows.Err()
}

type statsBackup struct {
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	Size      int64     `json:"size"`
	Error     string    `json:"error"`
}

type statsAttention struct {
	ApprovalsPending   int          `json:"approvals_pending"`
	CommandsFailed24h  int          `json:"commands_failed_24h"`
	CommandsSent24h    int          `json:"commands_sent_24h"`
	NonCompliant       int          `json:"noncompliant"`
	Stale              int          `json:"stale"`
	ExceptionsExpiring int          `json:"exceptions_expiring_7d"`
	LastBackup         *statsBackup `json:"last_backup"` // global view, admin and auditor only
}

func (s *Server) apiStatsAttention(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	sess := c.sess()
	var a statsAttention
	acond, aargs := approvalCond(c, 0)
	scope, sargs := scopeCond(sess, 0)
	tcond, targs := tenantCond(sess, "tenant_id", 0)
	st := renum(deviceStatusSQL, len(sargs))
	queries := []struct {
		sql  string
		args []any
		dst  []any
	}{
		{`SELECT count(*) FROM approvals WHERE status='pending' AND expires_at > now() AND ` + acond, aargs, []any{&a.ApprovalsPending}},
		{`SELECT count(*) FILTER (WHERE c.status='failed'), count(*) FROM commands c JOIN devices d ON d.id=c.device_id
			WHERE c.updated_at > now() - interval '1 day' AND ` + scope, sargs, []any{&a.CommandsFailed24h, &a.CommandsSent24h}},
		{`SELECT count(*) FROM risk_exceptions WHERE revoked_at IS NULL AND expires_at BETWEEN now() AND now() + interval '7 days' AND ` + tcond, targs, []any{&a.ExceptionsExpiring}},
		{`SELECT count(*) FILTER (WHERE ` + st + ` = 'non-compliant'), count(*) FILTER (WHERE ` + st + ` = 'stale')` + deviceFrom + ` WHERE NOT d.retired AND ` + scope,
			append(append([]any{}, sargs...), s.staleAfter().Seconds()), []any{&a.NonCompliant, &a.Stale}},
	}
	for _, q := range queries {
		if err := s.db.QueryRow(ctx, q.sql, q.args...).Scan(q.dst...); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	if sess.Tenant == 0 && !sess.scoped() && c.allows("audit") {
		var b statsBackup
		err := s.db.QueryRow(ctx, `SELECT status, started_at, size, error FROM backups WHERE deleted_at IS NULL ORDER BY started_at DESC LIMIT 1`).
			Scan(&b.Status, &b.StartedAt, &b.Size, &b.Error)
		switch {
		case err == nil:
			a.LastBackup = &b
		case !errors.Is(err, pgx.ErrNoRows):
			s.apiFail(w, err)
			return
		}
	}
	writeJSON(w, a)
}
