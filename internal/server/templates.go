package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Device templates of com.limdm.files and com.limdm.firewall: the server
// renders them per device right before the merge, so the declarations
// token changes with the values and the agent never sees the template
// (api.RenderPayload).

// deviceTemplateVars loads the values a template of the device can use.
func deviceTemplateVars(ctx context.Context, q querier, deviceID string) (api.TemplateVars, error) {
	v := api.TemplateVars{ID: deviceID}
	err := q.QueryRow(ctx, `SELECT d.hostname, d.tags, d.attributes, coalesce(t.name, ''), coalesce(u.email, ''),
			coalesce(d.inventory->>'serial', ''), coalesce(d.inventory->'hostname_info'->>'mac', ''),
			coalesce(d.inventory->>'vendor', ''), coalesce(d.inventory->>'model', '')
		FROM devices d LEFT JOIN tenants t ON t.id = d.tenant_id LEFT JOIN dir_users u ON u.id = d.primary_user_id
		WHERE d.id = $1`, deviceID).Scan(&v.Hostname, &v.Tags, &v.Attributes, &v.Tenant, &v.PrimaryUser, &v.Serial, &v.MAC, &v.Vendor, &v.Model)
	if v.Tags == nil {
		v.Tags = []string{}
	}
	if api.PlaceholderDMI(v.Serial) {
		v.Serial = ""
	}
	return v, err
}

// hasTemplate reports whether an item needs rendering.
func hasTemplate(it api.LibraryItem) bool {
	return (it.Type == api.TypeFiles || it.Type == api.TypeFirewall) && strings.Contains(string(it.Payload), `"template":true`) ||
		it.Type == api.TypeHostname && api.IsTemplate(string(it.Payload))
}

// renderItems returns items with their templates rendered for the device.
// Items that fail keep their payload marked (the agent leaves them alone);
// the reasons go to errs.
func renderItems(ctx context.Context, q querier, deviceID string, items []api.LibraryItem, errs *[]string) ([]api.LibraryItem, error) {
	out := items
	var vars *api.TemplateVars
	for i, it := range items {
		if !hasTemplate(it) {
			continue
		}
		if vars == nil {
			v, err := deviceTemplateVars(ctx, q, deviceID)
			if err != nil {
				return nil, err
			}
			vars, out = &v, append([]api.LibraryItem(nil), items...)
		}
		p, err := api.RenderPayload(it.Type, it.Payload, *vars)
		if err != nil {
			*errs = append(*errs, it.Name+": "+err.Error())
		}
		out[i].Payload = p
	}
	return out, nil
}

// apiConfigItemRender renders a files, firewall or hostname payload, as
// edited, for one device: the preview of the item editor. device is an ID or a
// hostname in the caller's scope.
func (s *Server) apiConfigItemRender(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	var body struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
		Device  string          `json:"device"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := (api.LibraryItem{Name: "preview", Type: body.Type, Payload: body.Payload}).Validate(); err != nil {
		s.apiFail(w, invalid("payload", err))
		return
	}
	cond, args := scopeCond(c.sess(), 2)
	var id string
	err := s.db.QueryRow(ctx, `SELECT d.id FROM devices d WHERE (d.id = $1 OR lower(d.hostname) = lower($1)) AND NOT d.retired AND `+cond+`
		ORDER BY d.id = $1 DESC, d.last_seen DESC NULLS LAST LIMIT 1`, append([]any{strings.TrimSpace(body.Device)}, args...)...).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		problemField(w, http.StatusUnprocessableEntity, "device", "device not found")
		return
	}
	if err != nil {
		s.apiFail(w, err)
		return
	}
	vars, err := deviceTemplateVars(ctx, s.db, id)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out, rerr := api.RenderPayload(body.Type, body.Payload, vars)
	res := struct {
		Payload  json.RawMessage  `json:"payload"`
		Error    string           `json:"error,omitempty"`
		Vars     api.TemplateVars `json:"vars"`
		Hostname *hostnamePreview `json:"hostname,omitempty"` // com.limdm.hostname: the name it computes (hostname.go)
	}{Payload: out, Vars: vars}
	if rerr != nil {
		res.Error = rerr.Error()
	}
	if body.Type == api.TypeHostname {
		if res.Hostname, err = previewHostname(ctx, s.db, id, out); err != nil {
			s.apiFail(w, err)
			return
		}
	}
	writeJSON(w, res)
}

func tailLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(l[max(len(l)-n, 0):], "\n")
}

// apiConfigScriptResults is the last run of a recurring script on each
// device in scope that reported one.
func (s *Server) apiConfigScriptResults(w http.ResponseWriter, r *http.Request, c apiCaller) {
	name := r.URL.Query().Get("name")
	if name == "" || len(name) > 64 {
		problemField(w, http.StatusUnprocessableEntity, "name", "script name required")
		return
	}
	cond, args := scopeCond(c.sess(), 2)
	rows, err := s.db.Query(r.Context(), `SELECT DISTINCT ON (x.device_id) x.device_id, d.hostname, x.exit_code, x.started_at, x.ended_at, x.stdout, x.stderr
		FROM script_results x JOIN devices d ON d.id = x.device_id
		WHERE x.name = $1 AND x.command_id IS NULL AND NOT d.retired AND `+cond+`
		ORDER BY x.device_id, x.id DESC LIMIT 1000`, append([]any{name}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	type result struct {
		DeviceID string    `json:"device_id"`
		Hostname string    `json:"hostname"`
		ExitCode int       `json:"exit_code"`
		Start    time.Time `json:"start"`
		End      time.Time `json:"end"`
		Output   string    `json:"output"` // last lines of stdout and stderr
	}
	items := []result{}
	for rows.Next() {
		var x result
		var stdout, stderr string
		if err := rows.Scan(&x.DeviceID, &x.Hostname, &x.ExitCode, &x.Start, &x.End, &stdout, &stderr); err != nil {
			rows.Close()
			s.apiFail(w, err)
			return
		}
		x.Output = truncate(strings.TrimSpace(tailLines(stdout, 5)+"\n"+tailLines(stderr, 5)), 2000)
		items = append(items, x)
	}
	if err := rows.Err(); err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"items": items})
}
