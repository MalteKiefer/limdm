package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Security updates and agent versions for the home page KPI, and the
// events the history charts mark. The agent reports pending updates in the
// detail of the check updates.security ("3 security updates, 12 updates in
// total pending"); the newest approved agent release comes from
// agent_releases. historyLoop records the daily values (snapshotUpdates).

const securityCheck = "updates.security"

type statsUpdatesDay struct {
	Day             string `json:"day"`
	SecurityDevices *int   `json:"security_devices"` // nil before the day was recorded
	SecurityOld     *int   `json:"security_old"`
	AgentCurrent    *int   `json:"agent_current"`
	AgentTotal      *int   `json:"agent_total"`
}

type statsUpdates struct {
	SecurityDevices int               `json:"security_devices"` // devices with pending security updates
	SecurityUpdates int               `json:"security_updates"` // their sum
	SecurityOld     int               `json:"security_old"`     // devices failing the check for more than 14 days
	AgentNewest     string            `json:"agent_newest"`     // newest approved release, else the newest version reported
	AgentApproved   bool              `json:"agent_approved"`   // AgentNewest is an approved release
	AgentCurrent    int               `json:"agent_current"`    // devices on AgentNewest or later
	AgentTotal      int               `json:"agent_total"`      // active devices that report a version
	History         []statsUpdatesDay `json:"history"`          // global view only, oldest first
}

// newestVersion is the highest version of list ("" for none).
func newestVersion(list []string) string {
	best := ""
	for _, v := range list {
		if best == "" || api.CompareVersions(v, best) > 0 {
			best = v
		}
	}
	return best
}

// updateStats counts pending security updates and current agents for the
// devices in the scope of sess.
func (s *Server) updateStats(ctx context.Context, sess session) (statsUpdates, error) {
	var st statsUpdates
	scope, args := scopeCond(sess, 1)
	err := s.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE x.n > 0)::int, coalesce(sum(x.n), 0)::int,
			count(*) FILTER (WHERE x.n > 0 AND x.since < now() - interval '14 days')::int
		FROM (SELECT coalesce(substring(c->>'detail' from '^(\d+) security updates')::int, 0) AS n,
				CASE WHEN c->>'status' = 'fail' THEN (SELECT h.at FROM compliance_changes h WHERE h.device_id = d.id AND h.check_id = $1 ORDER BY h.id DESC LIMIT 1) END AS since
			FROM devices d CROSS JOIN LATERAL jsonb_array_elements(d.checks) c
			WHERE NOT d.retired AND c->>'id' = $1 AND `+scope+`) x`, append([]any{securityCheck}, args...)...).
		Scan(&st.SecurityDevices, &st.SecurityUpdates, &st.SecurityOld)
	if err != nil {
		return st, err
	}
	approved, err := collect(ctx, s.db, pgx.RowTo[string], `SELECT version FROM agent_releases WHERE approved_at IS NOT NULL AND NOT blocked`)
	if err != nil {
		return st, err
	}
	scope0, args0 := scopeCond(sess, 0)
	type versionCount struct {
		V string
		N int
	}
	versions, err := collect(ctx, s.db, pgx.RowToStructByPos[versionCount], `SELECT d.agent_version, count(*)::int FROM devices d
		WHERE NOT d.retired AND d.agent_version <> '' AND `+scope0+` GROUP BY 1`, args0...)
	if err != nil {
		return st, err
	}
	st.AgentNewest, st.AgentApproved = newestVersion(approved), len(approved) > 0
	if !st.AgentApproved {
		seen := make([]string, 0, len(versions))
		for _, v := range versions {
			seen = append(seen, v.V)
		}
		st.AgentNewest = newestVersion(seen)
	}
	for _, v := range versions {
		st.AgentTotal += v.N
		if api.CompareVersions(v.V, st.AgentNewest) >= 0 {
			st.AgentCurrent += v.N
		}
	}
	return st, nil
}

// daysParam reads ?days= (1..400, default def).
func daysParam(w http.ResponseWriter, r *http.Request, def int) (int, bool) {
	v := r.URL.Query().Get("days")
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 400 {
		problemField(w, http.StatusBadRequest, "days", "days must be 1..400")
		return 0, false
	}
	return n, true
}

func (s *Server) apiStatsUpdates(w http.ResponseWriter, r *http.Request, c apiCaller) {
	days, ok := daysParam(w, r, 30)
	if !ok {
		return
	}
	ctx := r.Context()
	sess := c.sess()
	st, err := s.updateStats(ctx, sess)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	st.History = []statsUpdatesDay{}
	if sess.Tenant == 0 && !sess.scoped() { // the history is installation wide
		if st.History, err = collect(ctx, s.db, pgx.RowToStructByPos[statsUpdatesDay], `SELECT to_char(day, 'YYYY-MM-DD'),
				security_devices, security_old, agent_current, agent_total FROM fleet_history WHERE day > current_date - $1::int ORDER BY day`, days); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	writeJSON(w, st)
}

// snapshotUpdates adds today's update and agent counts of the whole
// installation to the fleet history.
func (s *Server) snapshotUpdates(ctx context.Context) error {
	st, err := s.updateStats(ctx, session{Role: "admin"})
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE fleet_history SET security_devices=$1, security_old=$2, agent_current=$3, agent_total=$4 WHERE day=current_date`,
		st.SecurityDevices, st.SecurityOld, st.AgentCurrent, st.AgentTotal)
	return err
}

// annotatedActions are the audit actions the history charts mark.
var annotatedActions = []string{"keys.rotate", "agent_release.approve", "blueprint.save", "blueprint.delete", "blueprint.rollback", "backup.failed"}

type statsAnnotation struct {
	Day    string `json:"day"`
	Action string `json:"action"`
	Label  string `json:"label"`
	Target string `json:"target"`
	Count  int    `json:"count"` // entries of this action on this day
}

// apiStatsAnnotations lists the events the history charts mark, one per
// day and action, from the audit log in the caller's tenant and scope
// (admins and auditors).
func (s *Server) apiStatsAnnotations(w http.ResponseWriter, r *http.Request, c apiCaller) {
	days, ok := daysParam(w, r, 30)
	if !ok {
		return
	}
	cond, args := auditScope(c.sess(), 2)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[statsAnnotation], `SELECT to_char(at, 'YYYY-MM-DD') AS day, action, '',
			min(target), count(*)::int FROM audit_log WHERE action = ANY($1) AND at > current_date - $2::int AND `+cond+`
		GROUP BY 1, 2 ORDER BY 1, 2 LIMIT 400`, append([]any{annotatedActions, days}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	lang := requestLang(r)
	for i := range list {
		list[i].Label = auditLabel(lang, list[i].Action)
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}
