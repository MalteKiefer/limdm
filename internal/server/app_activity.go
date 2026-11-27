package server

import (
	"cmp"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// The activity area of the console app: the audit log and the device
// events as one stream, a histogram per day and category, the state of the
// audit hash chain and its full verification. The audit log follows the
// rules of the console's audit page (admins and auditors, tenant, scope);
// device events follow the device scope like the device page.

func (s *Server) appActivityRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/activity", s.need("read", s.apiActivity))
	m.HandleFunc("GET /api/v1/activity/histogram", s.need("read", s.apiActivityHistogram))
	m.HandleFunc("GET /api/v1/audit/status", s.need("audit", s.apiAuditStatus))
	m.HandleFunc("POST /api/v1/audit/verify", s.need("audit", s.apiAuditVerify))
}

type activityItem struct {
	ID       string    `json:"id"`   // a<audit id> or e<device event id>
	Kind     string    `json:"kind"` // audit | device
	Category string    `json:"category"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Label    string    `json:"label"`
	Target   string    `json:"target"`
	Hostname string    `json:"hostname,omitempty"`
	Detail   string    `json:"detail"`
	// device events: the text in the reader's language and its key and
	// parameters (api.ParseEvent); empty when the text matches no format
	Text   string   `json:"text,omitempty"`
	Key    string   `json:"key,omitempty"`
	Params []string `json:"params,omitempty"`
}

// activityCategory groups an audit action for filters and the histogram.
func activityCategory(action string) string {
	prefix, _, _ := strings.Cut(action, ".")
	switch prefix {
	case "command", "shell", "agent_update":
		return "commands"
	case "approval":
		return "approvals"
	case "login", "logout", "profile", "api":
		if action == "api.read" {
			return "audit"
		}
		return "access"
	case "device", "agent", "compliance", "recovery":
		return "devices"
	case "export", "audit":
		return "audit"
	}
	return "changes"
}

// activityCategories are the categories in display order; "events" are
// the devices' own log lines.
var activityCategories = []string{"commands", "changes", "approvals", "access", "devices", "audit", "events"}

// activitySources tells which streams a filter reads: the audit log (only
// for admins and auditors) and the device events (no actor, action
// "device.event"). The category filter picks one or the other.
func activitySources(q url.Values, c apiCaller) (audit, events bool) {
	kind, cat := q.Get("kind"), q.Get("category")
	audit = c.can("audit") && kind != "device" && cat != "events"
	events = kind != "audit" && q.Get("actor") == "" && (cat == "" || cat == "events") &&
		strings.HasPrefix("device.event", q.Get("action"))
	return audit, events
}

// eventFilter is the condition on device_events e joined with devices d,
// from the same parameters as auditFilter.
func eventFilter(q url.Values, sess session) (string, []any) {
	var w sqlWhere
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		w.add(`(e.detail || ' ' || d.hostname || ' ' || d.id) ILIKE '%' || $1 || '%'`, v)
	}
	if v := strings.TrimSpace(q.Get("target")); v != "" {
		w.add(`e.device_id = $1`, v)
	}
	if v := q.Get("from"); validDay(v) {
		w.add(`e.at >= $1::date`, v)
	}
	if v := q.Get("to"); validDay(v) {
		w.add(`e.at < $1::date + 1`, v)
	}
	cond, args := scopeCond(sess, 0)
	w.add(cond, args...)
	return w.sql(), w.args
}

func validDay(v string) bool {
	_, err := time.Parse("2006-01-02", v)
	return err == nil
}

// activityCursor holds the last audit and event id sent; 0 is the start.
func parseActivityCursor(cur string) (a, e int64, ok bool) {
	if cur == "" {
		return 0, 0, true
	}
	as, es, found := strings.Cut(cur, ":")
	a, err1 := strconv.ParseInt(as, 10, 64)
	e, err2 := strconv.ParseInt(es, 10, 64)
	return a, e, found && err1 == nil && err2 == nil && a >= 0 && e >= 0
}

// apiActivity merges both streams newest first. Each source is read by id
// (keyset) and the page holds the newest of both by time.
// ponytail: device event times come from the agent, so ids follow time only
// roughly; an (at, id) keyset per source if the order must be exact.
func (s *Server) apiActivity(w http.ResponseWriter, r *http.Request, c apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	aBefore, eBefore, ok := parseActivityCursor(cur)
	if !ok {
		problem(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	sess := c.sess()
	lang := requestLang(r)
	withAudit, withEvents := activitySources(q, c)
	if cat := q.Get("category"); cat != "" && !slices.Contains(activityCategories, cat) {
		problem(w, http.StatusBadRequest, "category: one of "+strings.Join(activityCategories, ", "))
		return
	}
	var items []activityItem
	if withAudit {
		// reading the audit log is audited as on /api/v1/audit (LIMDM_AUDIT_API_READS)
		if s.auditRead(r, "audit") {
			if err := s.auditAction(ctx, c.actor(), "api.read", "GET /api/v1/activity", truncate(r.URL.RawQuery, 500), nil); err != nil {
				s.apiFail(w, err)
				return
			}
		}
		where, args := auditFilter(q, sess)
		if aBefore > 0 {
			args = append(args, aBefore)
			where += " AND id < $" + strconv.Itoa(len(args))
		}
		// the category is computed in Go: read more rows when it filters
		n := limit + 1
		if q.Get("category") != "" {
			n = 2000
		}
		rows, err := collect(ctx, s.db, pgx.RowToStructByPos[auditRow], `SELECT id, at, actor, action, target, detail, prev, hash, tenant_id FROM audit_log WHERE `+
			where+` ORDER BY id DESC LIMIT `+strconv.Itoa(n), args...)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		for _, a := range rows {
			cat := activityCategory(a.Action)
			if q.Get("category") != "" && cat != q.Get("category") {
				continue
			}
			items = append(items, activityItem{ID: "a" + strconv.FormatInt(a.ID, 10), Kind: "audit", Category: cat, At: a.At, Actor: a.Actor,
				Action: a.Action, Label: auditLabel(lang, a.Action), Target: a.Target, Detail: a.Detail})
			if len(items) > limit {
				break
			}
		}
	}
	if withEvents {
		where, args := eventFilter(q, sess)
		if eBefore > 0 {
			args = append(args, eBefore)
			where += " AND e.id < $" + strconv.Itoa(len(args))
		}
		rows, err := s.db.Query(ctx, `SELECT e.id, e.at, e.device_id, d.hostname, e.detail FROM device_events e JOIN devices d ON d.id = e.device_id
			WHERE `+where+` ORDER BY e.id DESC LIMIT `+strconv.Itoa(limit+1), args...)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		for rows.Next() {
			var id int64
			it := activityItem{Kind: "device", Category: "events", Action: "device.event"}
			if err := rows.Scan(&id, &it.At, &it.Target, &it.Hostname, &it.Detail); err != nil {
				rows.Close()
				s.apiFail(w, err)
				return
			}
			it.ID, it.Actor, it.Label = "e"+strconv.FormatInt(id, 10), it.Hostname, translate(lang, "Device event")
			it.Key, it.Params, it.Text = eventText(lang, it.Detail)
			items = append(items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	slices.SortStableFunc(items, func(x, y activityItem) int { return y.At.Compare(x.At) })
	page := listPage{}
	if len(items) > limit {
		items = items[:limit]
		for _, it := range items {
			id, _ := strconv.ParseInt(it.ID[1:], 10, 64)
			if it.Kind == "audit" {
				aBefore = id
			} else {
				eBefore = id
			}
		}
		page.NextCursor = cursor(strconv.FormatInt(aBefore, 10) + ":" + strconv.FormatInt(eBefore, 10))
	}
	if items == nil {
		items = []activityItem{}
	}
	page.Items = items
	writeJSON(w, page)
}

type activityDay struct {
	Day    string         `json:"day"`
	Counts map[string]int `json:"counts"` // per category
}

// apiActivityHistogram counts the filtered stream per day and category,
// from "from" (default 30 days back) to "to" (default today), at most 400 days.
func (s *Server) apiActivityHistogram(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	q := r.URL.Query()
	to := time.Now()
	if v, err := time.ParseInLocation("2006-01-02", q.Get("to"), time.Local); err == nil {
		to = v
	}
	from := to.AddDate(0, 0, -29)
	if v, err := time.ParseInLocation("2006-01-02", q.Get("from"), time.Local); err == nil {
		from = v
	}
	if from.After(to) || to.Sub(from) > 400*24*time.Hour {
		problem(w, http.StatusBadRequest, "from..to: up to 400 days")
		return
	}
	q.Set("from", from.Format("2006-01-02"))
	q.Set("to", to.Format("2006-01-02"))
	days := map[string]map[string]int{}
	var order []string
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		k := d.Format("2006-01-02")
		days[k], order = map[string]int{}, append(order, k)
	}
	add := func(sql string, args []any, cat func(string) string) bool {
		rows, err := s.db.Query(ctx, sql, args...)
		if err != nil {
			s.apiFail(w, err)
			return false
		}
		defer rows.Close()
		for rows.Next() {
			var day, key string
			var n int
			if err := rows.Scan(&day, &key, &n); err != nil {
				s.apiFail(w, err)
				return false
			}
			if m, ok := days[day]; ok {
				m[cat(key)] += n
			}
		}
		if err := rows.Err(); err != nil {
			s.apiFail(w, err)
			return false
		}
		return true
	}
	withAudit, withEvents := activitySources(q, c)
	if withAudit {
		where, args := auditFilter(q, c.sess())
		if !add(`SELECT to_char(at, 'YYYY-MM-DD'), action, count(*) FROM audit_log WHERE `+where+` GROUP BY 1, 2`, args, activityCategory) {
			return
		}
	}
	if withEvents {
		where, args := eventFilter(q, c.sess())
		if !add(`SELECT to_char(e.at, 'YYYY-MM-DD'), 'events', count(*) FROM device_events e JOIN devices d ON d.id = e.device_id WHERE `+where+` GROUP BY 1`,
			args, func(string) string { return "events" }) {
			return
		}
	}
	out := make([]activityDay, 0, len(order))
	for _, k := range order {
		m := days[k]
		if cat := q.Get("category"); cat != "" {
			m = map[string]int{cat: m[cat]}
		}
		out = append(out, activityDay{k, m})
	}
	writeJSON(w, map[string]any{"days": out, "categories": activityCategories})
}

type auditStatus struct {
	BrokenAt   int64      `json:"broken_at"` // first broken entry, 0 = intact
	VerifiedAt *time.Time `json:"verified_at"`
	KeyedFrom  int64      `json:"keyed_from"` // first entry keyed with HMAC, 0 = none
	Actions    []string   `json:"actions"`
}

// auditState checks the chain from the last checkpoint and adds the result
// of the last full verification, as the console's audit page shows it.
func (s *Server) auditState(r *http.Request) (auditStatus, error) {
	ctx := r.Context()
	broken, err := s.verifyAudit(ctx)
	if err != nil {
		return auditStatus{}, err
	}
	full, at := s.auditVerification(ctx)
	st := auditStatus{BrokenAt: cmp.Or(broken, full), VerifiedAt: at, KeyedFrom: auditKeyedFrom}
	st.Actions, err = collect(ctx, s.db, pgx.RowTo[string], `SELECT DISTINCT action FROM audit_log ORDER BY 1`)
	return st, err
}

func (s *Server) apiAuditStatus(w http.ResponseWriter, r *http.Request, c apiCaller) {
	st, err := s.auditState(r)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, st)
}

// apiAuditVerify verifies the whole chain on demand, as the console's
// "Verify whole chain" (admins and auditors).
func (s *Server) apiAuditVerify(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if err := s.verifyAuditChain(r.Context(), c.actor()); err != nil {
		s.apiFail(w, err)
		return
	}
	st, err := s.auditState(r)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, st)
}
