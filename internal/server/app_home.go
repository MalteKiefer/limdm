package server

import (
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// The home page of the console app ("Lage") beyond appstats.go: the tenant
// comparison of the all tenants view, failed commands per day for the KPI
// sparkline, and the first steps of a new installation.

func (s *Server) appHomeRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/stats/tenants", s.need("admin", s.superAPI(s.apiStatsTenants)))
	m.HandleFunc("GET /api/v1/stats/commands", s.need("read", s.apiStatsCommands))
	m.HandleFunc("GET /api/v1/onboarding", s.need("read", s.apiOnboarding))
	m.HandleFunc("GET /api/v1/stats/updates", s.need("read", s.apiStatsUpdates))
	m.HandleFunc("GET /api/v1/stats/annotations", s.need("audit", s.apiStatsAnnotations))
}

type statsTenant struct {
	ID               int64   `json:"id"`
	Name             string  `json:"name"`
	Devices          int     `json:"devices"` // not retired
	Compliant        int     `json:"compliant"`
	NonCompliant     int     `json:"noncompliant"`
	Stale            int     `json:"stale"`
	Pending          int     `json:"pending"`
	Score            float64 `json:"score"` // as /stats/compliance: compliant share of reporting devices
	ApprovalsPending int     `json:"approvals_pending"`
}

// apiStatsTenants compares the tenants: super admins in the all tenants
// view only (superAPI), like the tenant list.
func (s *Server) apiStatsTenants(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if c.Tenant != 0 || c.Sess != nil && c.Sess.Tenant != 0 {
		problem(w, http.StatusForbidden, "the tenant comparison needs the all tenants view")
		return
	}
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[statsTenant], `SELECT t.id, t.name, count(x.st)::int,
			count(*) FILTER (WHERE x.st = 'compliant')::int, count(*) FILTER (WHERE x.st = 'non-compliant')::int,
			count(*) FILTER (WHERE x.st = 'stale')::int, count(*) FILTER (WHERE x.st = 'pending')::int, 0::float8,
			(SELECT count(*) FROM approvals a WHERE a.tenant_id = t.id AND a.status = 'pending' AND a.expires_at > now())::int
		FROM tenants t LEFT JOIN (SELECT d.tenant_id, `+deviceStatusSQL+` AS st FROM devices d WHERE NOT d.retired) x ON x.tenant_id = t.id
		GROUP BY t.id, t.name ORDER BY lower(t.name), t.id`, s.staleAfter().Seconds())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for i := range list {
		t := &list[i]
		t.Score = percent(t.Compliant, t.Devices-t.Stale-t.Pending)
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}

type statsCommandDay struct {
	Day    string `json:"day"`
	Failed int    `json:"failed"`
	Total  int    `json:"total"`
}

// apiStatsCommands counts commands per day by their last change, for the
// devices in scope (?days= 1..90, default 14).
func (s *Server) apiStatsCommands(w http.ResponseWriter, r *http.Request, c apiCaller) {
	days := 14
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 90 {
			problemField(w, http.StatusBadRequest, "days", "days must be 1..90")
			return
		}
		days = n
	}
	scope, args := scopeCond(c.sess(), 1)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[statsCommandDay], `SELECT to_char(day, 'YYYY-MM-DD'),
			count(c.status) FILTER (WHERE c.status = 'failed')::int, count(c.status)::int
		FROM generate_series(current_date - ($1::int - 1), current_date, interval '1 day') day
		LEFT JOIN (SELECT c.updated_at, c.status FROM commands c JOIN devices d ON d.id = c.device_id
			WHERE c.updated_at >= current_date - ($1::int - 1) AND `+scope+`) c ON c.updated_at >= day AND c.updated_at < day + interval '1 day'
		GROUP BY day ORDER BY day`, append([]any{days}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}

// onboardingIDs name the steps of onboarding() in their order.
var onboardingIDs = []string{"branding", "sso", "token", "blueprint", "device"}

type onboardingItem struct {
	ID   string `json:"id"`
	Done bool   `json:"done"`
}

// apiOnboarding lists the first steps of a new installation (admins in the
// global view, until all are done or hidden in the console); empty else.
func (s *Server) apiOnboarding(w http.ResponseWriter, r *http.Request, c apiCaller) {
	out := []onboardingItem{}
	if sess := c.sess(); sess.Tenant == 0 && c.can("admin") {
		steps, err := s.onboarding(r.Context(), r, sess)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		for i, st := range steps {
			out = append(out, onboardingItem{onboardingIDs[i], st.Done})
		}
	}
	writeJSON(w, listPage{Items: out})
}
