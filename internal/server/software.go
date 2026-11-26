package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Console pages of the software catalog.

// foundRemote is a remote on devices that IT does not manage yet.
type foundRemote struct {
	Name, URL, Title string
	Devices          int
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
