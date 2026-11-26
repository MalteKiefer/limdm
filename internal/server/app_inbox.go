package server

import (
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// The inbox of the console app: approvals come from /api/v1/approvals
// (adminapi_admin.go), warnings from /api/v1/stats/attention; this adds the
// commands of the whole fleet in the caller's scope, e.g. the failed ones.

func (s *Server) appInboxRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/commands", s.need("read", s.apiCommands))
}

type apiFleetCommand struct {
	ID        int64     `json:"id"`
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Output    string    `json:"output"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// apiCommands lists commands of every device in scope, newest first:
// ?status= (pending, sent, ok, failed, expired), ?days= (changed within, 1..90).
// The payload is never returned (it can hold a password).
func (s *Server) apiCommands(w http.ResponseWriter, r *http.Request, c apiCaller) {
	limit, cur, ok := pageArgs(w, r)
	if !ok {
		return
	}
	before, ok := idCursor(w, cur)
	if !ok {
		return
	}
	if before == 0 {
		before = 1<<63 - 1
	}
	q := r.URL.Query()
	status := q.Get("status")
	if status != "" && !slices.Contains([]string{"pending", "sent", "ok", "failed", "expired"}, status) {
		problemField(w, http.StatusBadRequest, "status", "status: pending, sent, ok, failed or expired")
		return
	}
	days := 7
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 90 {
			problemField(w, http.StatusBadRequest, "days", "days must be 1..90")
			return
		}
		days = n
	}
	scope, args := scopeCond(c.sess(), 4)
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[apiFleetCommand], `SELECT c.id, c.device_id, d.hostname, c.type, c.status, c.output, c.created_by, c.created_at, c.updated_at
		FROM commands c JOIN devices d ON d.id = c.device_id
		WHERE c.id < $1 AND ($2 = '' OR c.status = $2) AND c.updated_at > now() - make_interval(days => $3) AND `+scope+`
		ORDER BY c.id DESC LIMIT $4`, append([]any{before, status, days, limit + 1}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	page := listPage{}
	if len(list) > limit {
		list = list[:limit]
		page.NextCursor = cursor(strconv.FormatInt(list[limit-1].ID, 10))
	}
	page.Items = nonNilSlice(list)
	writeJSON(w, page)
}
