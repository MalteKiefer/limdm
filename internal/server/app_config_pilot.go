package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Pilot rollout of a blueprint change. The changed map goes into a copy of
// the blueprint ("<name>.pilot", same parent), and a few of its devices get
// the copy set explicitly; blueprint_pilots remembers what they had set
// before. Promote saves the map into the blueprint, abort drops it; both
// put the devices back and delete the copy. Every step runs through the
// shared blueprint functions with their validation, versions and audit.

func init() {
	for k, v := range map[string]string{"blueprint.pilot": "Pilot rollout started", "blueprint.pilot_end": "Pilot rollout ended"} {
		auditActions[k] = v
	}
	deCatalog["Pilot rollout started"] = "Pilot Rollout gestartet"
	deCatalog["Pilot rollout ended"] = "Pilot Rollout beendet"
}

type apiPilot struct {
	ID      int64     `json:"id"`      // the pilot copy
	Devices []string  `json:"devices"` // device IDs on the pilot
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// pilots lists the running pilots by the blueprint they test.
func (s *Server) pilots(ctx context.Context) (map[int64]apiPilot, error) {
	rows, err := s.db.Query(ctx, `SELECT blueprint_id, pilot_id, array_agg(device_id ORDER BY device_id), min(created_by), min(created_at)
		FROM blueprint_pilots GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]apiPilot{}
	for rows.Next() {
		var bp int64
		var p apiPilot
		if err := rows.Scan(&bp, &p.ID, &p.Devices, &p.By, &p.At); err != nil {
			return nil, err
		}
		out[bp] = p
	}
	return out, rows.Err()
}

func (s *Server) apiConfigPilotStart(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Tree    []api.Node `json:"tree"`
		Devices []string   `json:"devices"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !s.tenantOwns(ctx, c.sess(), "blueprints", id, false) {
		problem(w, http.StatusNotFound, "blueprint not found")
		return
	}
	bp, err := scanBlueprint(s.db.QueryRow(ctx, `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, id))
	if err != nil {
		s.apiFail(w, err)
		return
	}
	running, err := s.pilots(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if _, ok := running[id]; ok || strings.HasSuffix(bp.Name, ".pilot") {
		problem(w, http.StatusConflict, "a pilot of this blueprint is running already")
		return
	}
	// only devices whose effective blueprint is this one: devices of a child
	// blueprint would lose the child's own map on the copy
	cond, args := tenantDevices(ctx, 1)
	devs, err := s.listDevicesWhere(ctx, `NOT d.retired AND `+cond+` AND `+effectiveBlueprintSQL+` = $1`, append([]any{id}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if len(in.Devices) == 0 || len(in.Devices) > 1000 || slices.ContainsFunc(in.Devices, func(d string) bool {
		return !slices.ContainsFunc(devs, func(x deviceRow) bool { return x.ID == d })
	}) {
		s.apiFail(w, invalid("devices", errors.New("pick 1 to 1000 devices that use this blueprint")))
		return
	}
	name := bp.Name
	if len(name) > 58 {
		name = name[:58]
	}
	pilot := blueprintRec{Name: name + ".pilot", Desc: truncate("Pilot of "+bp.Name, 300), Parent: bp.Parent, Tree: in.Tree}
	if err := s.saveBlueprint(ctx, c.actor(), &pilot); err != nil {
		s.apiFail(w, err)
		return
	}
	err = s.auditAction(ctx, c.actor(), "blueprint.pilot", bp.Name, strings.Join(in.Devices, " "), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO blueprint_pilots(pilot_id, blueprint_id, device_id, prev_blueprint_id, created_by)
			SELECT $1, $2, d.id, d.blueprint_id, $4 FROM devices d WHERE d.id = ANY($3)`, pilot.ID, id, in.Devices, c.actor()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET blueprint_id=$1 WHERE id = ANY($2)`, pilot.ID, in.Devices)
		return err
	})
	if err != nil {
		_ = s.deleteBlueprint(ctx, c.actor(), pilot.ID)
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, apiPilot{ID: pilot.ID, Devices: in.Devices, By: c.actor(), At: time.Now()})
}

// apiConfigPilotEnd promotes (op promote) or aborts (op abort) the pilot of
// a blueprint.
func (s *Server) apiConfigPilotEnd(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	op := r.PathValue("op")
	if op != "promote" && op != "abort" {
		problem(w, http.StatusNotFound, "unknown operation")
		return
	}
	if !s.tenantOwns(ctx, c.sess(), "blueprints", id, false) {
		problem(w, http.StatusNotFound, "blueprint not found")
		return
	}
	running, err := s.pilots(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	p, ok := running[id]
	if !ok {
		problem(w, http.StatusNotFound, "no pilot of this blueprint is running")
		return
	}
	if op == "promote" {
		bp, err := scanBlueprint(s.db.QueryRow(ctx, `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, id))
		if err == nil {
			var pilot blueprintRec
			if pilot, err = scanBlueprint(s.db.QueryRow(ctx, `SELECT `+blueprintCols+` FROM blueprints WHERE id=$1`, p.ID)); err == nil {
				bp.Tree = pilot.Tree
				err = s.saveBlueprint(ctx, c.actor(), &bp)
			}
		}
		if err != nil {
			s.apiFail(w, err)
			return
		}
	}
	err = s.auditAction(ctx, c.actor(), "blueprint.pilot_end", strconv.FormatInt(id, 10), op, func(tx pgx.Tx) error {
		// back to what the devices had set; a blueprint deleted meanwhile falls back
		if _, err := tx.Exec(ctx, `UPDATE devices d SET blueprint_id = (SELECT b.id FROM blueprints b WHERE b.id = p.prev_blueprint_id)
			FROM blueprint_pilots p WHERE p.pilot_id=$1 AND d.id=p.device_id AND d.blueprint_id=$1`, p.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM blueprint_pilots WHERE pilot_id=$1`, p.ID)
		return err
	})
	if err == nil {
		err = s.deleteBlueprint(ctx, c.actor(), p.ID)
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "status": op})
}
