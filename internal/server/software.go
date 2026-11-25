package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Console pages of the software catalog.

var softwareTabs = []struct{ Key, Label string }{{"catalog", "Catalog"}, {"requests", "Requests"}, {"settings", "Settings"}}

type appRequestRow struct {
	ID                      int64
	DeviceID, Hostname, App string
	AppName, User, Note     string
	Status                  string
	DecidedBy               *string
	CreatedAt               time.Time
	DecidedAt               *time.Time
}

func (s *Server) softwarePage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderSoftware(w, r, sess, "", "")
}

func (s *Server) renderSoftware(w http.ResponseWriter, r *http.Request, sess session, msg, errMsg string) {
	ctx := r.Context()
	tab := r.FormValue("tab")
	if !slices.ContainsFunc(softwareTabs, func(t struct{ Key, Label string }) bool { return t.Key == tab }) {
		tab = "catalog"
	}
	data := map[string]any{"Tab": tab, "Tabs": softwareTabs, "Msg": msg, "Error": errMsg}
	switch tab {
	case "catalog":
		apps, err := s.catalogApps(ctx, s.db, "")
		if err != nil {
			s.fail(w, err)
			return
		}
		counts := map[string]int{}
		rows, err := s.db.Query(ctx, `SELECT a->>'id', count(*) FROM devices d, jsonb_array_elements(coalesce(d.inventory->'apps', '[]'::jsonb)) a
			WHERE NOT d.retired AND (a->>'installed')::boolean GROUP BY 1`)
		if err != nil {
			s.fail(w, err)
			return
		}
		for rows.Next() {
			var id string
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				s.fail(w, err)
				return
			}
			counts[id] = n
		}
		rows.Close()
		for i := range apps {
			apps[i].Installs = counts[apps[i].ID]
		}
		data["Apps"] = apps
	case "requests":
		rows, err := s.db.Query(ctx, `SELECT q.id, q.device_id, d.hostname, q.app, a.name, q.username, q.note, q.status, q.decided_by, q.created_at, q.decided_at
			FROM catalog_requests q JOIN devices d ON d.id=q.device_id JOIN catalog_apps a ON a.slug=q.app
			ORDER BY (q.status='pending') DESC, q.created_at DESC LIMIT 300`)
		if err != nil {
			s.fail(w, err)
			return
		}
		reqs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[appRequestRow])
		if err != nil {
			s.fail(w, err)
			return
		}
		data["Requests"] = reqs
	case "settings":
		set, err := s.softwareSettings(ctx, s.db)
		if err != nil {
			s.fail(w, err)
			return
		}
		data["Set"] = set
	}
	var pending int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM catalog_requests WHERE status='pending'`).Scan(&pending)
	data["Pending"] = pending
	s.render(w, r, sess, "software", data)
}

// appEdit shows the form for a new or an existing catalog app.
func (s *Server) appEdit(w http.ResponseWriter, r *http.Request, sess session) {
	var app catalogRow
	app.Mode, app.Enabled = api.AppAvailable, true
	if id := r.PathValue("id"); id != "" {
		apps, err := s.catalogApps(r.Context(), s.db, `WHERE slug=$1`, id)
		if err != nil || len(apps) == 0 {
			http.NotFound(w, r)
			return
		}
		app = apps[0]
	}
	s.renderApp(w, r, sess, app, r.PathValue("id") == "", "")
}

func (s *Server) renderApp(w http.ResponseWriter, r *http.Request, sess session, app catalogRow, isNew bool, errMsg string) {
	bps, err := s.allBlueprints(r.Context(), "")
	if err != nil {
		s.fail(w, err)
		return
	}
	var fl, deb, rpm string
	prefer := "flatpak"
	for i, src := range app.Sources {
		switch src.Kind {
		case "flatpak":
			fl = src.Flatpak
		case "package":
			deb, rpm = src.Debian, src.Fedora
			if i == 0 {
				prefer = "package"
			}
		}
	}
	s.render(w, r, sess, "app", map[string]any{"App": app, "New": isNew, "Blueprints": bps, "Error": errMsg,
		"Flatpak": fl, "Debian": deb, "Fedora": rpm, "Prefer": prefer, "Detect": strings.Join(app.Detect, " ")})
}

// appSave stores a catalog app from the form.
func (s *Server) appSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	isNew := r.FormValue("new") == "1"
	app := catalogRow{CatalogApp: api.CatalogApp{ID: strings.TrimSpace(r.FormValue("id")), Name: strings.TrimSpace(r.FormValue("name")),
		Summary: strings.TrimSpace(r.FormValue("summary")), Category: strings.TrimSpace(r.FormValue("category")), Mode: r.FormValue("mode")},
		Enabled: r.FormValue("enabled") == "on"}
	flatpak := api.AppSource{Kind: "flatpak", Flatpak: strings.TrimSpace(r.FormValue("flatpak"))}
	pkgs := api.AppSource{Kind: "package", Debian: strings.Join(strings.Fields(r.FormValue("debian")), " "), Fedora: strings.Join(strings.Fields(r.FormValue("fedora")), " ")}
	var srcs []api.AppSource
	if flatpak.Flatpak != "" {
		srcs = append(srcs, flatpak)
	}
	if pkgs.Debian != "" || pkgs.Fedora != "" {
		if r.FormValue("prefer") == "package" {
			srcs = append([]api.AppSource{pkgs}, srcs...)
		} else {
			srcs = append(srcs, pkgs)
		}
	}
	app.Sources = srcs
	app.Detect = strings.Fields(r.FormValue("detect"))
	for _, v := range r.Form["scope"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			app.Scope = append(app.Scope, id)
		}
	}
	var icon []byte
	if f, _, err := r.FormFile("icon"); err == nil {
		icon, err = io.ReadAll(io.LimitReader(f, maxLogo+1))
		f.Close()
		if err == nil {
			err = validLogo(icon)
		}
		if err != nil {
			s.renderApp(w, r, sess, app, isNew, strings.Replace(err.Error(), "logo", "icon", 1))
			return
		}
	}
	if err := app.Validate(); err != nil {
		s.renderApp(w, r, sess, app, isNew, err.Error())
		return
	}
	src, _ := json.Marshal(app.Sources)
	detect := append([]string{}, app.Detect...)
	scope := append([]int64{}, app.Scope...)
	err := s.auditAction(ctx, sess.Email, "catalog.save", app.ID, string(src), func(tx pgx.Tx) error {
		var tag interface{ RowsAffected() int64 }
		var err error
		if isNew {
			tag, err = tx.Exec(ctx, `INSERT INTO catalog_apps(slug, name, summary, category, mode, enabled, sources, detect, scope)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (slug) DO NOTHING`,
				app.ID, app.Name, app.Summary, app.Category, app.Mode, app.Enabled, src, detect, scope)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE catalog_apps SET name=$2, summary=$3, category=$4, mode=$5, enabled=$6, sources=$7, detect=$8, scope=$9,
				icon_tried=NULL, updated_at=now() WHERE slug=$1`,
				app.ID, app.Name, app.Summary, app.Category, app.Mode, app.Enabled, src, detect, scope)
		}
		if err == nil && tag.RowsAffected() == 0 {
			err = errAppExists
		}
		if err == nil && icon != nil {
			_, err = tx.Exec(ctx, `UPDATE catalog_apps SET icon=$2 WHERE slug=$1`, app.ID, icon)
		}
		if err == nil && r.FormValue("remove_icon") == "on" && icon == nil {
			_, err = tx.Exec(ctx, `UPDATE catalog_apps SET icon=NULL, icon_tried=now() WHERE slug=$1`, app.ID)
		}
		return err
	})
	if errors.Is(err, errAppExists) {
		msg := "An app with this ID exists already."
		if !isNew {
			msg = "Unknown app."
		}
		s.renderApp(w, r, sess, app, isNew, msg)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/software", http.StatusSeeOther)
}

var errAppExists = errors.New("app exists or is unknown")

func (s *Server) appDelete(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	err := s.auditAction(r.Context(), sess.Email, "catalog.delete", id, "", func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `DELETE FROM catalog_apps WHERE slug=$1`, id)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/software", http.StatusSeeOther)
}

// requestDecide approves or denies a user's request.
func (s *Server) requestDecide(w http.ResponseWriter, r *http.Request, sess session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	op := r.PathValue("op")
	status := map[string]string{"approve": "approved", "deny": "denied"}[op]
	if err != nil || status == "" {
		http.NotFound(w, r)
		return
	}
	err = s.auditActionFn(r.Context(), func(tx pgx.Tx) (string, string, string, string, error) {
		var device, app string
		err := tx.QueryRow(r.Context(), `UPDATE catalog_requests SET status=$2, decided_by=$3, decided_at=now() WHERE id=$1 AND status='pending'
			RETURNING device_id, app`, id, status, sess.Email).Scan(&device, &app)
		return sess.Email, "catalog.request." + op, device, app, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/software?tab=requests", http.StatusSeeOther)
}

func (s *Server) softwareSettingsSave(w http.ResponseWriter, r *http.Request, sess session) {
	set := SoftwareSettings{RestrictFlathub: r.FormValue("restrict_flathub") == "on", StoresReadOnly: r.FormValue("stores_read_only") == "on"}
	doc, _ := json.Marshal(set)
	err := s.auditAction(r.Context(), sess.Email, "catalog.settings", "software", string(doc), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO settings(key, value) VALUES ('software', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	r.Form.Set("tab", "settings")
	s.renderSoftware(w, r, sess, "Settings saved and active.", "")
}
