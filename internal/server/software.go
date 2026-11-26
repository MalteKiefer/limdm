package server

import (
	"context"
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

var softwareTabs = []struct{ Key, Label string }{{"catalog", "Catalog"}, {"requests", "Requests"}, {"remotes", "Remotes"}, {"packages", "Packages"}, {"settings", "Settings"}}

// remoteRow is a managed remote with the number of devices that have it.
type remoteRow struct {
	api.CatalogRemote
	Devices int
}

// foundRemote is a remote on devices that IT does not manage yet.
type foundRemote struct {
	Name, URL, Title string
	Devices          int
}

type appRequestRow struct {
	ID                      int64
	DeviceID, Hostname, App string
	AppName, User, Note     string
	Status                  string
	DecidedBy               *string
	CreatedAt               time.Time
	DecidedAt               *time.Time
	Flatpak, Remote         string // a Flatpak outside the catalog
}

func (s *Server) softwarePage(w http.ResponseWriter, r *http.Request, sess session) {
	if r.FormValue("tab") == "packages" { // its own page (packages.go)
		http.Redirect(w, r, "/software/packages", http.StatusSeeOther)
		return
	}
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
		if data["Fleet"], err = s.fleetFlatpaks(ctx); err != nil {
			s.fail(w, err)
			return
		}
	case "requests":
		rows, err := s.db.Query(ctx, `SELECT q.id, q.device_id, d.hostname, coalesce(q.app, ''), coalesce(a.name, q.app_name), q.username, q.note, q.status,
			q.decided_by, q.created_at, q.decided_at, q.flatpak, q.remote
			FROM catalog_requests q JOIN devices d ON d.id=q.device_id LEFT JOIN catalog_apps a ON a.slug=q.app
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
	case "remotes":
		managed, err := s.catalogRemotes(ctx, s.db)
		if err != nil {
			s.fail(w, err)
			return
		}
		counts := map[string]int{}
		rows, err := s.db.Query(ctx, `SELECT r->>'name', count(DISTINCT d.id) FROM devices d, jsonb_array_elements(coalesce(d.inventory->'flatpak_remotes', '[]'::jsonb)) r
			WHERE NOT d.retired AND NOT coalesce((r->>'disabled')::boolean, false) GROUP BY 1`)
		if err != nil {
			s.fail(w, err)
			return
		}
		for rows.Next() {
			var n string
			var c int
			if err := rows.Scan(&n, &c); err != nil {
				rows.Close()
				s.fail(w, err)
				return
			}
			counts[n] = c
		}
		rows.Close()
		var list []remoteRow
		for _, m := range managed {
			list = append(list, remoteRow{m, counts[m.Name]})
		}
		rows, err = s.db.Query(ctx, `SELECT r->>'name', max(r->>'url'), max(coalesce(r->>'title', '')), count(DISTINCT d.id)
			FROM devices d, jsonb_array_elements(coalesce(d.inventory->'flatpak_remotes', '[]'::jsonb)) r
			WHERE NOT d.retired AND NOT EXISTS (SELECT 1 FROM catalog_remotes c WHERE c.name = r->>'name')
			GROUP BY 1 ORDER BY 4 DESC, 1`)
		if err != nil {
			s.fail(w, err)
			return
		}
		found, err := pgx.CollectRows(rows, pgx.RowToStructByPos[foundRemote])
		if err != nil {
			s.fail(w, err)
			return
		}
		data["Remotes"], data["Found"] = list, found
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
	var debRepo, rpmRepo api.Repository
	remote, prefer := "flathub", "flatpak"
	for i, src := range app.Sources {
		switch src.Kind {
		case "flatpak":
			fl, remote = src.Flatpak, src.RemoteOf()
		case "package":
			deb, rpm = src.Debian, src.Fedora
			for _, r := range src.Repos {
				if r.Family == "debian" {
					debRepo = r
				} else {
					rpmRepo = r
				}
			}
			if i == 0 {
				prefer = "package"
			}
		}
	}
	remotes, err := s.catalogRemotes(r.Context(), s.db)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "app", map[string]any{"App": app, "New": isNew, "Blueprints": bps, "Error": errMsg, "Remotes": remotes, "Remote": remote,
		"Flatpak": fl, "Debian": deb, "Fedora": rpm, "DebRepo": debRepo, "RpmRepo": rpmRepo, "Prefer": prefer, "Detect": strings.Join(app.Detect, " ")})
}

// appSave stores a catalog app from the form.
func (s *Server) appSave(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	isNew := r.FormValue("new") == "1"
	app := catalogRow{CatalogApp: api.CatalogApp{ID: strings.TrimSpace(r.FormValue("id")), Name: strings.TrimSpace(r.FormValue("name")),
		Summary: strings.TrimSpace(r.FormValue("summary")), Category: strings.TrimSpace(r.FormValue("category")), Mode: r.FormValue("mode")},
		Enabled: r.FormValue("enabled") == "on"}
	flatpak := api.AppSource{Kind: "flatpak", Flatpak: strings.TrimSpace(r.FormValue("flatpak"))}
	if rem := r.FormValue("flatpak_remote"); rem != "" && rem != "flathub" {
		flatpak.Remote = rem
	}
	pkgs := api.AppSource{Kind: "package", Debian: strings.Join(strings.Fields(r.FormValue("debian")), " "), Fedora: strings.Join(strings.Fields(r.FormValue("fedora")), " ")}
	repoName := r.FormValue("repo_name") // keeps the file names on the devices stable
	if repoName == "" {
		repoName = app.ID
	}
	if u := strings.TrimSpace(r.FormValue("deb_repo_url")); u != "" {
		pkgs.Repos = append(pkgs.Repos, api.Repository{Name: repoName, Family: "debian", URL: u, Suites: strings.TrimSpace(r.FormValue("deb_repo_suite")),
			Components: strings.TrimSpace(r.FormValue("deb_repo_components")), Key: strings.TrimSpace(r.FormValue("deb_repo_key")) + "\n"})
	}
	if u := strings.TrimSpace(r.FormValue("rpm_repo_url")); u != "" {
		pkgs.Repos = append(pkgs.Repos, api.Repository{Name: repoName, Family: "fedora", URL: u, Key: strings.TrimSpace(r.FormValue("rpm_repo_key")) + "\n",
			SignedMetadata: r.FormValue("rpm_repo_signed_metadata") == "on"})
	}
	var srcs []api.AppSource
	if flatpak.Flatpak != "" {
		srcs = append(srcs, flatpak)
	}
	if len(pkgs.Repos) > 0 && pkgs.Debian == "" && pkgs.Fedora == "" {
		app.Sources = srcs
		s.renderApp(w, r, sess, app, isNew, "A vendor repository needs the package names to install from it.")
		return
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
	pending, err := s.saveCatalogApp(ctx, sess, app, isNew, icon, r.FormValue("remove_icon") == "on")
	if errors.Is(err, errAppExists) {
		msg := "An app with this ID exists already."
		if !isNew {
			msg = "Unknown app."
		}
		s.renderApp(w, r, sess, app, isNew, msg)
		return
	}
	if code, msg := errStatus(err); code != 0 && code < 500 {
		s.renderApp(w, r, sess, app, isNew, msg)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if pending {
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/software", http.StatusSeeOther)
}

// saveCatalogApp validates and stores a catalog app with its audit entry,
// or files it for four eyes approval (pending; an uploaded icon is then not
// kept). The console and the admin API both save through here.
func (s *Server) saveCatalogApp(ctx context.Context, sess session, app catalogRow, isNew bool, icon []byte, removeIcon bool) (bool, error) {
	if err := app.Validate(); err != nil {
		return false, invalid("app", err)
	}
	if s.appNeedsApproval(app.CatalogApp) { // four eyes (foureyes.go)
		_, err := s.requestApproval(ctx, sess, "catalog.save", app.ID, catalogApproval{App: app, New: isNew}, "")
		return err == nil, err
	}
	src, _ := json.Marshal(app.Sources)
	return false, s.auditAction(ctx, sess.Email, "catalog.save", app.ID, string(src), func(tx pgx.Tx) error {
		err := s.writeCatalogApp(ctx, tx, app, isNew)
		if err == nil && icon != nil {
			_, err = tx.Exec(ctx, `UPDATE catalog_apps SET icon=$2 WHERE slug=$1`, app.ID, icon)
		}
		if err == nil && removeIcon && icon == nil {
			_, err = tx.Exec(ctx, `UPDATE catalog_apps SET icon=NULL, icon_tried=now() WHERE slug=$1`, app.ID)
		}
		return err
	})
}

var errAppExists = errors.New("app exists or is unknown")

// deleteCatalogApp removes an app from the catalog; installed copies stay.
func (s *Server) deleteCatalogApp(ctx context.Context, actor, id string) error {
	return s.auditAction(ctx, actor, "catalog.delete", id, "", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM catalog_apps WHERE slug=$1`, id)
		return err
	})
}

func (s *Server) appDelete(w http.ResponseWriter, r *http.Request, sess session) {
	if err := s.deleteCatalogApp(r.Context(), sess.Email, r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/software", http.StatusSeeOther)
}

// requestDecide approves or denies a user's request.
func (s *Server) requestDecide(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	op := r.PathValue("op")
	status := map[string]string{"approve": "approved", "approve-all": "approved", "deny": "denied"}[op]
	if err != nil || status == "" {
		http.NotFound(w, r)
		return
	}
	err = s.decideAppRequest(ctx, sess.Email, id, op)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.failUser(w, r, sess, err)
		return
	}
	http.Redirect(w, r, "/software?tab=requests", http.StatusSeeOther)
}

// decideAppRequest approves (op approve or approve-all) or denies (deny) a
// pending app request; pgx.ErrNoRows when it is unknown or decided.
func (s *Server) decideAppRequest(ctx context.Context, actor string, id int64, op string) error {
	status := map[string]string{"approve": "approved", "approve-all": "approved", "deny": "denied"}[op]
	if status == "" {
		return pgx.ErrNoRows
	}
	return s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var device, app, flatpak, remote, name string
		err := tx.QueryRow(ctx, `UPDATE catalog_requests SET status=$2, decided_by=$3, decided_at=now() WHERE id=$1 AND status='pending'
			RETURNING device_id, coalesce(app, ''), flatpak, remote, app_name`, id, status, actor).Scan(&device, &app, &flatpak, &remote, &name)
		if err != nil || status != "approved" || flatpak == "" {
			return actor, "catalog.request." + op, device, app + flatpak, err
		}
		// an app from outside the catalog joins it: "on request" for this
		// device only, or available for everyone
		mode := api.AppOnRequest
		if op == "approve-all" {
			mode = api.AppAvailable
		}
		if err := tx.QueryRow(ctx, `SELECT a.slug FROM catalog_apps a, jsonb_array_elements(a.sources) src WHERE src->>'flatpak'=$1 LIMIT 1`, flatpak).Scan(&app); errors.Is(err, pgx.ErrNoRows) {
			if app, err = s.slugFor(ctx, tx, name); err != nil {
				return "", "", "", "", err
			}
			src := api.AppSource{Kind: "flatpak", Flatpak: flatpak}
			if remote != "" && remote != "flathub" {
				src.Remote = remote
			}
			doc, _ := json.Marshal([]api.AppSource{src})
			if _, err := tx.Exec(ctx, `INSERT INTO catalog_apps(slug, name, mode, sources) VALUES ($1,$2,$3,$4)`, app, truncate(name, 80), mode, doc); err != nil {
				return "", "", "", "", err
			}
			if err := s.signCatalogApp(ctx, tx, app); err != nil {
				return "", "", "", "", err
			}
		} else if err != nil {
			return "", "", "", "", err
		} else if op == "approve-all" {
			// "on request" opens up; a required app stays required, and a
			// paused required app stays paused (enabling it would force-install it)
			if err := s.catalogAppIntact(ctx, tx, app); err != nil {
				return "", "", "", "", err
			}
			if _, err := tx.Exec(ctx, `UPDATE catalog_apps SET mode=CASE WHEN mode='request' THEN 'available' ELSE mode END,
				enabled = enabled OR mode<>'required', updated_at=now() WHERE slug=$1`, app); err != nil {
				return "", "", "", "", err
			}
			if err := s.signCatalogApp(ctx, tx, app); err != nil {
				return "", "", "", "", err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE catalog_requests SET app=$2 WHERE id=$1`, id, app)
		return actor, "catalog.request." + op, device, flatpak + " -> " + app, err
	})
}

func (s *Server) softwareSettingsSave(w http.ResponseWriter, r *http.Request, sess session) {
	set := SoftwareSettings{RestrictFlathub: r.FormValue("restrict_flathub") == "on", StoresReadOnly: r.FormValue("stores_read_only") == "on",
		OnlyManagedRemotes: r.FormValue("only_managed_remotes") == "on"}
	if err := s.saveSoftwareSettings(r.Context(), sess.Email, set); err != nil {
		s.fail(w, err)
		return
	}
	r.Form.Set("tab", "settings")
	s.renderSoftware(w, r, sess, "Settings saved and active.", "")
}

// saveSoftwareSettings stores the store settings with their audit entry.
func (s *Server) saveSoftwareSettings(ctx context.Context, actor string, set SoftwareSettings) error {
	doc, _ := json.Marshal(set)
	return s.auditAction(ctx, actor, "catalog.settings", "software", string(doc), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('software', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
}

// fleetFlatpak is a Flatpak app installed somewhere in the fleet.
type fleetFlatpak struct {
	ID, Name, Origin string
	Devices          int
}

// fleetFlatpaks lists installed Flatpak apps that no catalog app covers yet.
func (s *Server) fleetFlatpaks(ctx context.Context) ([]fleetFlatpak, error) {
	rows, err := s.db.Query(ctx, `SELECT f->>'id', max(coalesce(nullif(f->>'name', ''), f->>'id')), max(coalesce(f->>'origin', '')), count(DISTINCT d.id)
		FROM devices d, jsonb_array_elements(coalesce(d.inventory->'flatpaks', '[]'::jsonb)) f
		WHERE NOT d.retired AND f->>'id' IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM catalog_apps a, jsonb_array_elements(a.sources) src WHERE src->>'flatpak' = f->>'id')
		GROUP BY 1 ORDER BY 4 DESC, 2`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[fleetFlatpak])
}

// slugFor turns an app name into a free catalog ID.
func (s *Server) slugFor(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	base := strings.Trim(nonName.ReplaceAllString(strings.ToLower(name), "-"), "-._")
	base = strings.ReplaceAll(strings.ReplaceAll(base, ".", "-"), "_", "-")
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	if base == "" {
		base = "app"
	}
	slug := base
	for i := 2; ; i++ {
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_apps WHERE slug=$1)`, slug).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return slug, nil
		}
		slug = base + "-" + strconv.Itoa(i)
	}
}

// appImport adds installed Flatpaks to the catalog (mode available); devices
// that have them count them as installed and managed from then on.
func (s *Server) appImport(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	if _, err := s.importFleetFlatpaks(ctx, sess.Email, r.Form["flatpak"]); err != nil {
		s.fail(w, err)
		return
	}
	back := "/software"
	if d := r.FormValue("device"); d != "" {
		back = "/devices/" + d + "?tab=software&sub=flatpak"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// importFleetFlatpaks adds installed Flatpaks (IDs from fleetFlatpaks) to
// the catalog, mode available; devices that have them count them as
// installed and managed from then on. Unknown IDs are skipped.
func (s *Server) importFleetFlatpaks(ctx context.Context, actor string, ids []string) ([]string, error) {
	fleet, err := s.fleetFlatpaks(ctx)
	if err != nil {
		return nil, err
	}
	names, origins := map[string]string{}, map[string]string{}
	for _, f := range fleet {
		names[f.ID], origins[f.ID] = f.Name, f.Origin
	}
	var added []string
	err = s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		for _, id := range ids {
			name, ok := names[id]
			if !ok {
				continue // unknown, or already in the catalog
			}
			src := api.AppSource{Kind: "flatpak", Flatpak: id}
			if o := origins[id]; o != "" && o != "flathub" {
				src.Remote = o // keeps installing from where it came from
			}
			app := api.CatalogApp{Name: truncate(name, 80), Mode: api.AppAvailable, Sources: []api.AppSource{src}}
			slug, err := s.slugFor(ctx, tx, name)
			if err != nil {
				return "", "", "", "", err
			}
			app.ID = slug
			if err := app.Validate(); err != nil {
				continue
			}
			doc, _ := json.Marshal(app.Sources)
			if _, err := tx.Exec(ctx, `INSERT INTO catalog_apps(slug, name, mode, sources) VALUES ($1,$2,'available',$3)`, app.ID, app.Name, doc); err != nil {
				return "", "", "", "", err
			}
			if err := s.signCatalogApp(ctx, tx, app.ID); err != nil {
				return "", "", "", "", err
			}
			added = append(added, id)
		}
		return actor, "catalog.import", "catalog", strings.Join(added, " "), nil
	})
	if err != nil {
		return nil, err
	}
	go s.fetchIcons(context.WithoutCancel(ctx)) // icon, summary and category from Flathub
	return added, nil
}

// remoteSave adds or changes a managed remote (also to take over one found
// on devices, as allowed or blocked).
func (s *Server) remoteSave(w http.ResponseWriter, r *http.Request, sess session) {
	rem := api.CatalogRemote{Name: strings.TrimSpace(r.FormValue("name")), URL: strings.TrimSpace(r.FormValue("url")),
		Title: truncate(strings.TrimSpace(r.FormValue("title")), 80), State: r.FormValue("state"), CatalogOnly: r.FormValue("catalog_only") == "on"}
	if rem.State == "" {
		rem.State = "allowed"
	}
	err := s.saveCatalogRemote(r.Context(), sess.Email, rem)
	var fe *fieldError
	if errors.As(err, &fe) {
		r.Form.Set("tab", "remotes")
		s.renderSoftware(w, r, sess, "", fe.Msg)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/software?tab=remotes", http.StatusSeeOther)
}

// saveCatalogRemote validates and stores a managed remote, signed and audited.
func (s *Server) saveCatalogRemote(ctx context.Context, actor string, rem api.CatalogRemote) error {
	if err := rem.Validate(); err != nil {
		return invalid("remote", err)
	}
	doc, _ := json.Marshal(rem)
	return s.auditAction(ctx, actor, "catalog.remote", rem.Name, string(doc), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO catalog_remotes(name, url, title, state, catalog_only) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (name) DO UPDATE SET url=EXCLUDED.url, title=EXCLUDED.title, state=EXCLUDED.state, catalog_only=EXCLUDED.catalog_only, updated_at=now()`,
			rem.Name, rem.URL, rem.Title, rem.State, rem.CatalogOnly)
		if err == nil {
			err = s.signCatalogRemote(ctx, tx, rem.Name)
		}
		return err
	})
}

// remoteOp allows, blocks, switches the catalog filter of, or stops managing a remote.
func (s *Server) remoteOp(w http.ResponseWriter, r *http.Request, sess session) {
	err := s.catalogRemoteOp(r.Context(), sess.Email, r.PathValue("name"), r.PathValue("op"))
	if errors.Is(err, errRemoteNotHTTPS) {
		r.Form.Set("tab", "remotes")
		s.renderSoftware(w, r, sess, "", err.Error())
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.failUser(w, r, sess, err)
		return
	}
	http.Redirect(w, r, "/software?tab=remotes", http.StatusSeeOther)
}

var errRemoteNotHTTPS = &userError{http.StatusUnprocessableEntity, "Only remotes with an https URL can be allowed."}

// catalogRemoteOp allows, blocks, switches the catalog filter of (filter),
// or stops managing (unmanage) a remote; pgx.ErrNoRows when unknown.
func (s *Server) catalogRemoteOp(ctx context.Context, actor, name, op string) error {
	q := map[string]string{
		// only https remotes may be allowed; a blocked one may have any URL
		"allow":    `UPDATE catalog_remotes SET state='allowed', updated_at=now() WHERE name=$1 AND (url LIKE 'https://%' OR url LIKE 'oci+https://%')`,
		"block":    `UPDATE catalog_remotes SET state='blocked', updated_at=now() WHERE name=$1`,
		"filter":   `UPDATE catalog_remotes SET catalog_only=NOT catalog_only, updated_at=now() WHERE name=$1`,
		"unmanage": `DELETE FROM catalog_remotes WHERE name=$1`,
	}[op]
	if q == "" {
		return pgx.ErrNoRows
	}
	if op == "allow" {
		var u string
		if err := s.db.QueryRow(ctx, `SELECT url FROM catalog_remotes WHERE name=$1`, name).Scan(&u); err == nil &&
			!strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "oci+https://") {
			return errRemoteNotHTTPS
		}
	}
	return s.auditAction(ctx, actor, "catalog.remote."+op, name, "", func(tx pgx.Tx) error {
		if err := s.catalogRemoteIntact(ctx, tx, name); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, q, name)
		if err == nil && tag.RowsAffected() == 0 {
			err = pgx.ErrNoRows
		}
		if err == nil {
			err = s.signCatalogRemote(ctx, tx, name)
		}
		return err
	})
}

// flathubAdd puts a Flathub app into the catalog with its name, summary,
// category and icon, then opens it for editing.
func (s *Server) flathubAdd(w http.ResponseWriter, r *http.Request, sess session) {
	id := strings.TrimSpace(r.FormValue("id"))
	if !api.ValidFlatpakID(id) {
		http.NotFound(w, r)
		return
	}
	slug, pending, err := s.addFlathubApp(r.Context(), sess, id, r.FormValue("mode"))
	switch {
	case errors.Is(err, errFlathubDown):
		s.renderApp(w, r, sess, catalogRow{CatalogApp: api.CatalogApp{Mode: api.AppAvailable}, Enabled: true}, true, "Flathub did not answer; try again later.")
	case errors.Is(err, errAppExists):
		http.Redirect(w, r, "/software", http.StatusSeeOther)
	case err != nil:
		s.fail(w, err)
	case pending:
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/software/apps/"+slug, http.StatusSeeOther)
	}
}

var errFlathubDown = &userError{http.StatusBadGateway, "Flathub did not answer; try again later."}

// addFlathubApp puts a Flathub app into the catalog with its name, summary,
// category and icon (mode request or required, else available); a required
// app goes to four eyes approval first (pending). errAppExists when the
// catalog has the Flatpak already.
func (s *Server) addFlathubApp(ctx context.Context, sess session, id, mode string) (string, bool, error) {
	app, icon, err := s.flathubApp(ctx, id)
	if err != nil {
		s.log.Warn("flathub app lookup failed") // no details: they carry the requested ID
		return "", false, errFlathubDown
	}
	if mode == api.AppOnRequest || mode == api.AppRequired {
		app.Mode = mode
	}
	if s.appNeedsApproval(app) { // four eyes for a required app (foureyes.go)
		err := func() error {
			tx, err := s.db.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_apps a, jsonb_array_elements(a.sources) src WHERE src->>'flatpak'=$1)`, id).Scan(&exists); err != nil || exists {
				return errors.Join(err, errAppExists)
			}
			if app.ID, err = s.slugFor(ctx, tx, app.Name); err != nil {
				return err
			}
			if err := app.Validate(); err != nil {
				return err
			}
			_, err = s.requestApproval(ctx, sess, "catalog.save", app.ID, catalogApproval{App: catalogRow{CatalogApp: app, Enabled: true}, New: true}, "")
			return err
		}()
		return app.ID, err == nil, err
	}
	var slug string
	err = s.auditActionFn(ctx, func(tx pgx.Tx) (string, string, string, string, error) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_apps a, jsonb_array_elements(a.sources) src WHERE src->>'flatpak'=$1)`, id).Scan(&exists); err != nil || exists {
			return "", "", "", "", errAppExists
		}
		var err error
		if slug, err = s.slugFor(ctx, tx, app.Name); err != nil {
			return "", "", "", "", err
		}
		app.ID = slug
		if err := app.Validate(); err != nil {
			return "", "", "", "", err
		}
		doc, _ := json.Marshal(app.Sources)
		_, err = tx.Exec(ctx, `INSERT INTO catalog_apps(slug, name, summary, category, mode, sources, icon, icon_tried) VALUES ($1,$2,$3,$4,$5,$6,$7,now())`,
			slug, app.Name, app.Summary, app.Category, app.Mode, doc, icon)
		if err == nil {
			err = s.signCatalogApp(ctx, tx, slug)
		}
		return sess.Email, "catalog.save", slug, "from Flathub " + id, err
	})
	return slug, false, err
}
