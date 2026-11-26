package server

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

// Saved views of the console app: a named filter, sort and column set of a
// list (devices, activity, ...). Each belongs to its owner; admins may share
// one with everybody in their tenant (or the global view). Changes to shared
// views are audited, personal ones are preferences and are not.

type savedView struct {
	ID        int64     `json:"id"`
	List      string    `json:"list"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	Sort      string    `json:"sort"`
	Columns   []string  `json:"columns"`
	Shared    bool      `json:"shared"`
	Owner     string    `json:"owner"`
	Mine      bool      `json:"mine"`
	UpdatedAt time.Time `json:"updated_at"`
}

type savedViewInput struct {
	List    string   `json:"list"`
	Name    string   `json:"name"`
	Query   string   `json:"query"`
	Sort    string   `json:"sort"`
	Columns []string `json:"columns"`
	Shared  bool     `json:"shared"`
}

var viewListRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

const maxViewsPerOwner = 100

func (v *savedViewInput) validate() error {
	v.Name = strings.TrimSpace(v.Name)
	switch {
	case !viewListRe.MatchString(v.List):
		return &fieldError{"list", "a list name: lower case letters, digits and -, up to 32 characters"}
	case v.Name == "" || len(v.Name) > 100 || strings.ContainsFunc(v.Name, unicode.IsControl):
		return &fieldError{"name", "1 to 100 characters"}
	case len(v.Query) > 1000 || strings.ContainsFunc(v.Query, unicode.IsControl):
		return &fieldError{"query", "at most 1000 characters"}
	case len(v.Sort) > 64:
		return &fieldError{"sort", "at most 64 characters"}
	case len(v.Columns) > 50:
		return &fieldError{"columns", "at most 50 columns"}
	}
	for _, c := range v.Columns {
		if c == "" || len(c) > 64 || strings.ContainsFunc(c, unicode.IsControl) {
			return &fieldError{"columns", "column names of 1 to 64 characters"}
		}
	}
	if v.Columns == nil {
		v.Columns = []string{}
	}
	return nil
}

// viewTenant is the tenant column value of the caller's views: NULL in the
// global view.
func viewTenant(c apiCaller) *int64 {
	if t := c.sess().Tenant; t != 0 {
		return &t
	}
	return nil
}

const savedViewCols = `id, list, name, query, sort, columns, shared, owner, owner = $1, updated_at`

// apiViews lists the caller's own views and the views shared in its
// tenant, optionally of one list (?list=devices).
func (s *Server) apiViews(w http.ResponseWriter, r *http.Request, c apiCaller) {
	list := r.URL.Query().Get("list")
	if list != "" && !viewListRe.MatchString(list) {
		problem(w, http.StatusBadRequest, "invalid list")
		return
	}
	views, err := collect(r.Context(), s.db, pgx.RowToStructByPos[savedView], `SELECT `+savedViewCols+` FROM saved_views
		WHERE (owner = $1 OR shared AND tenant_id IS NOT DISTINCT FROM $2) AND ($3 = '' OR list = $3)
		ORDER BY list, shared, lower(name), id`, c.actor(), viewTenant(c), list)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if views == nil {
		views = []savedView{}
	}
	writeJSON(w, listPage{Items: views})
}

// apiViewSave creates (POST) or replaces (PUT, owner only) a view. Only
// admins share views.
func (s *Server) apiViewSave(w http.ResponseWriter, r *http.Request, c apiCaller) {
	var in savedViewInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := in.validate(); err != nil {
		s.apiFail(w, err)
		return
	}
	if in.Shared && !c.allows("admin") {
		s.deny(w, r, c, "only admins share views")
		return
	}
	ctx := r.Context()
	var id int64
	if r.Method == http.MethodPut {
		var ok bool
		if id, ok = pathID(w, r); !ok {
			return
		}
	}
	id, err := s.saveView(ctx, c, id, in)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	v, err := collectOne(ctx, s.db, pgx.RowToStructByPos[savedView], `SELECT `+savedViewCols+` FROM saved_views WHERE id=$2`, c.actor(), id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSONStatus(w, status, v)
}

// saveView inserts the view (id 0) or updates the caller's own view id and
// returns its id; pgx.ErrNoRows when it is not the caller's.
func (s *Server) saveView(ctx context.Context, c apiCaller, id int64, in savedViewInput) (int64, error) {
	tenant := viewTenant(c)
	write := func(tx pgx.Tx) (bool, error) {
		if id == 0 {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM saved_views WHERE owner=$1`, c.actor()).Scan(&n); err != nil {
				return false, err
			}
			if n >= maxViewsPerOwner {
				return false, &userError{http.StatusConflict, "at most " + strconv.Itoa(maxViewsPerOwner) + " saved views per person"}
			}
			return in.Shared, tx.QueryRow(ctx, `INSERT INTO saved_views(owner, tenant_id, list, name, query, sort, columns, shared)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, c.actor(), tenant, in.List, in.Name, in.Query, in.Sort, in.Columns, in.Shared).Scan(&id)
		}
		var was bool
		err := tx.QueryRow(ctx, `UPDATE saved_views n SET list=$3, name=$4, query=$5, sort=$6, columns=$7, shared=$8, updated_at=now()
			FROM saved_views o WHERE n.id=$1 AND o.id=n.id AND n.owner=$2 RETURNING o.shared`,
			id, c.actor(), in.List, in.Name, in.Query, in.Sort, in.Columns, in.Shared).Scan(&was)
		return was || in.Shared, err
	}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		shared, err := write(tx)
		if err != nil || !shared {
			return err
		}
		return audit(ctx, tx, c.actor(), "view.save", in.Name, "list="+in.List+" shared="+strconv.FormatBool(in.Shared)+" query="+truncate(in.Query, 500))
	})
	return id, err
}

// apiViewDelete deletes the caller's own view, or (admins) a shared one.
func (s *Server) apiViewDelete(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var name string
		var shared bool
		err := tx.QueryRow(ctx, `DELETE FROM saved_views WHERE id=$1 AND (owner=$2 OR $3 AND shared AND tenant_id IS NOT DISTINCT FROM $4) RETURNING name, shared`,
			id, c.actor(), c.allows("admin"), viewTenant(c)).Scan(&name, &shared)
		if err != nil || !shared {
			return err
		}
		return audit(ctx, tx, c.actor(), "view.delete", name, "")
	})
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
