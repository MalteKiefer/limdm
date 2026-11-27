package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Containers and VMs per device (workloads). The agent reports them with
// its status; the server keeps the latest inventory per device and checks
// every workload_action against it, the device's policy (com.limdm.agent
// workload_control), the role (admin, helpdesk when Settings allow it) and
// four eyes for stop and restart. The agent checks again.

func (s *Server) appWorkloadsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/devices/{id}/workloads", s.need("read", s.apiDeviceWorkloads))
	m.HandleFunc("GET /api/v1/workloads", s.need("read", s.apiWorkloads))
}

// workloadPolicyOff is the answer when the device's policy does not allow
// workload actions.
const workloadPolicyOff = "starting, stopping and restarting containers and VMs is not allowed by this device's policy: switch on Workload control in the Agent settings of its blueprint"

// storeWorkloads keeps the latest workload inventory of a device; nil (no
// tool, or an agent without workloads) removes it.
func storeWorkloads(ctx context.Context, tx pgx.Tx, id string, w *api.Workloads) error {
	if w == nil {
		_, err := tx.Exec(ctx, `DELETE FROM device_workloads WHERE device_id=$1`, id)
		return err
	}
	if len(w.Tools) > len(api.WorkloadKinds) {
		w.Tools = w.Tools[:len(api.WorkloadKinds)]
	}
	if len(w.Items) > len(api.WorkloadKinds)*api.MaxWorkloads {
		w.Items, w.Truncated = w.Items[:len(api.WorkloadKinds)*api.MaxWorkloads], true
	}
	if len(w.Errors) > len(api.WorkloadKinds) {
		w.Errors = w.Errors[:len(api.WorkloadKinds)]
	}
	for i := range w.Errors {
		w.Errors[i] = truncate(w.Errors[i], 300)
	}
	for i := range w.Tools {
		w.Tools[i].Kind, w.Tools[i].Version = truncate(w.Tools[i].Kind, 16), truncate(w.Tools[i].Version, 64)
	}
	for i := range w.Items {
		it := &w.Items[i]
		it.Kind, it.ID, it.Name, it.Type, it.State = truncate(it.Kind, 16), truncate(it.ID, 128), truncate(it.Name, 200), truncate(it.Type, 16), truncate(it.State, 32)
		it.Image, it.ImageID, it.Restart = truncate(it.Image, 300), truncate(it.ImageID, 100), truncate(it.Restart, 32)
		it.Project, it.Service = truncate(it.Project, 200), truncate(it.Service, 200)
		if len(it.Ports) > 50 {
			it.Ports = it.Ports[:50]
		}
		for j := range it.Ports {
			it.Ports[j] = truncate(it.Ports[j], 100)
		}
	}
	doc := jsonb(w)
	sum := sha256.Sum256([]byte(doc))
	_, err := tx.Exec(ctx, `INSERT INTO device_workloads(device_id, inventory, hash) VALUES ($1, $2, $3)
		ON CONFLICT (device_id) DO UPDATE SET inventory=EXCLUDED.inventory, hash=EXCLUDED.hash, updated_at=now()
		WHERE device_workloads.hash <> EXCLUDED.hash`, id, doc, hex.EncodeToString(sum[:]))
	return err
}

// deviceWorkloads loads the stored inventory; nil when there is none.
func (s *Server) deviceWorkloads(ctx context.Context, id string) (*api.Workloads, time.Time, error) {
	var raw []byte
	var at time.Time
	err := s.db.QueryRow(ctx, `SELECT inventory, updated_at FROM device_workloads WHERE device_id=$1`, id).Scan(&raw, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, at, nil
	}
	if err != nil {
		return nil, at, err
	}
	var w api.Workloads
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, at, err
	}
	return &w, at, nil
}

// devicePolicy composes the resolved policy of a device.
func devicePolicy(ctx context.Context, s *Server, id string) (api.Policy, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return api.Policy{}, err
	}
	defer tx.Rollback(ctx) // read only
	res, err := resolveDevice(ctx, tx, id)
	if err != nil {
		return api.Policy{}, err
	}
	pol, _ := api.Compose(res.Decls)
	return pol, nil
}

// mayControlWorkloads: admins, and the helpdesk role when Settings allow it.
func (s *Server) mayControlWorkloads(role string) bool {
	return role == "admin" || role == "helpdesk" && s.settings().WorkloadsHelpdesk
}

// workloadNeedsApproval: stop and restart wait for a second admin when
// four eyes covers workloads; start never does.
func (s *Server) workloadNeedsApproval(payload string) bool {
	var w api.WorkloadAction
	return s.settings().FourEyesWorkloads && (json.Unmarshal([]byte(payload), &w) != nil || w.Action != "start")
}

// workloadCommandPayload checks a workload_action from the console form
// (kind, id, action) and builds its payload: the workload must be in the
// device's last inventory, matched exactly, and the policy must allow it.
func (s *Server) workloadCommandPayload(r *http.Request, id string) (string, int, string) {
	w := api.WorkloadAction{Kind: r.FormValue("kind"), ID: r.FormValue("id"), Action: r.FormValue("action")}
	if err := w.Validate(); err != nil {
		return "", http.StatusBadRequest, err.Error()
	}
	inv, _, err := s.deviceWorkloads(r.Context(), id)
	if err != nil {
		return "", http.StatusInternalServerError, "workload inventory unavailable"
	}
	if _, ok := inv.Find(w.Kind, w.ID); !ok {
		return "", http.StatusBadRequest, "unknown workload: it is not in the device's last inventory"
	}
	pol, err := devicePolicy(r.Context(), s, id)
	if err != nil {
		return "", http.StatusInternalServerError, "policy unavailable"
	}
	if !pol.WorkloadControl {
		return "", http.StatusConflict, workloadPolicyOff
	}
	b, _ := json.Marshal(w)
	return string(b), 0, ""
}

type apiWorkloadControl struct {
	Policy   bool `json:"policy"`    // the device's policy allows actions (com.limdm.agent workload_control)
	Allowed  bool `json:"allowed"`   // the caller's role may send them
	FourEyes bool `json:"four_eyes"` // stop and restart wait for a second admin
}

type apiDeviceWorkloads struct {
	Reports   bool               `json:"reports"` // the device has reported workloads
	UpdatedAt *time.Time         `json:"updated_at"`
	Inventory api.Workloads      `json:"inventory"`
	Control   apiWorkloadControl `json:"control"`
}

func (s *Server) apiDeviceWorkloads(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if _, ok := s.deviceFound(w, r, c, id); !ok {
		return
	}
	inv, at, err := s.deviceWorkloads(r.Context(), id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	pol, err := devicePolicy(r.Context(), s, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := apiDeviceWorkloads{Control: apiWorkloadControl{Policy: pol.WorkloadControl, Allowed: s.mayControlWorkloads(c.Role) && c.can("helpdesk"),
		FourEyes: s.settings().FourEyesWorkloads}}
	if inv != nil {
		out.Reports, out.UpdatedAt, out.Inventory = true, &at, *inv
	}
	out.Inventory.Tools, out.Inventory.Items = nonNilSlice(out.Inventory.Tools), nonNilSlice(out.Inventory.Items)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, out)
}

type apiFleetWorkload struct {
	DeviceID string       `json:"device_id"`
	Hostname string       `json:"hostname"`
	Workload api.Workload `json:"workload"`
}

// apiWorkloads lists the workloads of the fleet in the caller's scope,
// filtered by kind, state and image (substring), at most 2000.
func (s *Server) apiWorkloads(w http.ResponseWriter, r *http.Request, c apiCaller) {
	q := r.URL.Query()
	kind, state, image := q.Get("kind"), strings.ToLower(q.Get("state")), q.Get("image")
	if kind != "" && !slices.Contains(api.WorkloadKinds, kind) {
		problemField(w, http.StatusUnprocessableEntity, "kind", "unknown workload kind")
		return
	}
	scope, args := scopeCond(c.sess(), 4)
	rows, err := s.db.Query(r.Context(), `SELECT d.id, d.hostname, it FROM device_workloads x JOIN devices d ON d.id = x.device_id,
		jsonb_array_elements(x.inventory->'items') it
		WHERE NOT d.retired AND ($1 = '' OR it->>'kind' = $1) AND ($2 = '' OR it->>'state' = $2) AND ($3 = '' OR strpos(lower(it->>'image'), lower($3)) > 0) AND `+scope+`
		ORDER BY d.hostname, it->>'kind', it->>'name' LIMIT 2000`, append([]any{kind, state, image}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (apiFleetWorkload, error) {
		var f apiFleetWorkload
		var raw []byte
		if err := row.Scan(&f.DeviceID, &f.Hostname, &raw); err != nil {
			return f, err
		}
		return f, json.Unmarshal(raw, &f.Workload)
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, listPage{Items: nonNilSlice(list)})
}
