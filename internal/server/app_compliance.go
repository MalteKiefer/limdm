package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Compliance endpoints of the console app: the fleet aggregation of the
// compliance page, one check with the devices that report it, the heatmap
// of check areas, the history at a date, the compliance and custom check
// library items, and the evidence exports. Risk exceptions keep their
// admin API routes (adminapi_admin.go).

func (s *Server) appComplianceRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/compliance", s.need("read", s.apiCompliance))
	m.HandleFunc("GET /api/v1/compliance/checks/{id}", s.need("read", s.apiComplianceCheck))
	m.HandleFunc("GET /api/v1/compliance/heatmap", s.need("read", s.apiComplianceHeatmap))
	m.HandleFunc("GET /api/v1/compliance/history", s.need("read", s.apiComplianceHistory))
	m.HandleFunc("GET /api/v1/compliance/policies", s.need("read", s.apiCompliancePolicies))
	m.HandleFunc("GET /api/v1/exports/{kind}", s.need("audit", s.apiExport))
}

type appCheck struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Level        int      `json:"level"`
	Severity     string   `json:"severity,omitempty"`
	Refs         api.Refs `json:"refs"`
	Pass         int      `json:"pass"`
	Fail         int      `json:"fail"`
	NA           int      `json:"na"`
	Excepted     int      `json:"excepted"`
	FailingHosts []string `json:"failing_hosts"`
}

type appControl struct {
	Framework string   `json:"framework"` // bsi, cis or iso
	Control   string   `json:"control"`
	Checks    []string `json:"checks"`
	Pass      int      `json:"pass"`
	Fail      int      `json:"fail"`
}

type appCompliance struct {
	Total        int          `json:"total"`
	Compliant    int          `json:"compliant"`
	NonCompliant int          `json:"noncompliant"`
	Stale        int          `json:"stale"`
	Pending      int          `json:"pending"`
	StaleHours   int          `json:"stale_hours"`
	Checks       []appCheck   `json:"checks"`
	Controls     []appControl `json:"controls"`
}

func toAppCheck(lang string, a *checkAgg) appCheck {
	return appCheck{ID: a.ID, Title: translate(lang, a.Title), Level: a.Level, Severity: a.Severity, Refs: a.Refs,
		Pass: a.Pass, Fail: a.Fail, NA: a.NA, Excepted: a.Excepted, FailingHosts: append([]string{}, a.FailingHosts...)}
}

// apiCompliance is the data of the console's compliance page: device
// states, every reported check with its counts and the framework controls.
func (s *Server) apiCompliance(w http.ResponseWriter, r *http.Request, c apiCaller) {
	fc, err := s.fleetComplianceFor(r.Context(), c.sess())
	if err != nil {
		s.apiFail(w, err)
		return
	}
	lang := requestLang(r)
	out := appCompliance{Total: fc.Total, Compliant: fc.Compliant, NonCompliant: fc.Noncompl, Stale: fc.Stale, Pending: fc.Pending,
		StaleHours: s.settings().StaleHours, Checks: make([]appCheck, len(fc.Checks)), Controls: make([]appControl, len(fc.Controls))}
	for i, a := range fc.Checks {
		out.Checks[i] = toAppCheck(lang, a)
	}
	ids := map[string]string{}
	for _, f := range frameworkIDs {
		ids[f.Name] = f.ID
	}
	for i, ctl := range fc.Controls {
		out.Controls[i] = appControl{Framework: ids[ctl.Framework], Control: ctl.Control, Checks: ctl.Checks, Pass: ctl.Pass, Fail: ctl.Fail}
	}
	writeJSON(w, out)
}

type appCheckDevice struct {
	ID         string     `json:"id"`
	Hostname   string     `json:"hostname"`
	Blueprint  string     `json:"blueprint"`
	Status     string     `json:"status"`
	Detail     string     `json:"detail"`
	Remediated bool       `json:"remediated"`
	LastSeen   *time.Time `json:"last_seen"`
}

type appCheckDetail struct {
	appCheck
	Devices   []appCheckDevice `json:"devices"`
	Truncated bool             `json:"truncated"` // more devices than listed; the counts cover all
}

// maxCheckDevices limits the device list of one check; failing ones come first.
const maxCheckDevices = 500

// apiComplianceCheck is one check with the result of every device in scope
// that reports it, failing devices first.
func (s *Server) apiComplianceCheck(w http.ResponseWriter, r *http.Request, c apiCaller) {
	id := r.PathValue("id")
	if !identOK(id) {
		problem(w, http.StatusNotFound, "check not found")
		return
	}
	scope, sargs := scopeCond(c.sess(), 1)
	rows, err := s.db.Query(r.Context(), `SELECT d.id, d.hostname, coalesce(b.name, 'default'), d.last_seen, x`+deviceFrom+`
		CROSS JOIN LATERAL jsonb_array_elements(d.checks) x
		WHERE NOT d.retired AND x->>'id' = $1 AND `+scope+` ORDER BY (x->>'status' = 'fail') DESC, d.hostname, d.id`, append([]any{id}, sargs...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	lang := requestLang(r)
	out := appCheckDetail{Devices: []appCheckDevice{}}
	agg := checkAgg{ID: id}
	n := 0
	defer rows.Close()
	for rows.Next() {
		var d appCheckDevice
		var raw []byte
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Blueprint, &d.LastSeen, &raw); err != nil {
			s.apiFail(w, err)
			return
		}
		var res api.CheckResult
		if err := json.Unmarshal(raw, &res); err != nil {
			s.apiFail(w, err)
			return
		}
		if n == 0 {
			agg.Title, agg.Level, agg.Severity, agg.Refs = res.Title, res.Level, res.Severity, res.Refs
		}
		n++
		switch res.Status {
		case "pass":
			agg.Pass++
		case "fail":
			agg.Fail++
		case "excepted":
			agg.Excepted++
		default:
			agg.NA++
		}
		if len(out.Devices) == maxCheckDevices {
			out.Truncated = true
			continue
		}
		d.Status, d.Detail, d.Remediated = res.Status, res.Detail, res.Remediated
		out.Devices = append(out.Devices, d)
	}
	if err := rows.Err(); err != nil {
		s.apiFail(w, err)
		return
	}
	if n == 0 {
		problem(w, http.StatusNotFound, "no device in scope reports this check")
		return
	}
	out.appCheck = toAppCheck(lang, &agg)
	writeJSON(w, out)
}

type appHeatCell struct {
	Column string `json:"column"`
	Area   string `json:"area"` // the check ID up to the first dot: ssh, kernel, custom ...
	Pass   int    `json:"pass"`
	Fail   int    `json:"fail"`
}

// apiComplianceHeatmap counts passed and failed results per check area and
// blueprint, or per tenant (group=tenant, global view of several tenants).
func (s *Server) apiComplianceHeatmap(w http.ResponseWriter, r *http.Request, c apiCaller) {
	sess := c.sess()
	col := `coalesce(b.name, 'default')`
	group := r.URL.Query().Get("group")
	switch group {
	case "", "blueprint":
		group = "blueprint"
	case "tenant":
		if sess.Tenant != 0 || !s.cfg.MultiTenant {
			problem(w, http.StatusBadRequest, "group=tenant needs the global view of several tenants")
			return
		}
		col = `(SELECT t.name FROM tenants t WHERE t.id = d.tenant_id)`
	default:
		problem(w, http.StatusBadRequest, "group: blueprint or tenant")
		return
	}
	scope, sargs := scopeCond(sess, 0)
	rows, err := s.db.Query(r.Context(), `SELECT `+col+`, split_part(x->>'id', '.', 1),
		count(*) FILTER (WHERE x->>'status' = 'pass'), count(*) FILTER (WHERE x->>'status' = 'fail')`+deviceFrom+`
		CROSS JOIN LATERAL jsonb_array_elements(d.checks) x
		WHERE NOT d.retired AND `+scope+` GROUP BY 1, 2 ORDER BY 1, 2`, sargs...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	cells, err := pgx.CollectRows(rows, pgx.RowToStructByPos[appHeatCell])
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, map[string]any{"group": group, "cells": cells})
}

type appHistoryDevice struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Other    int    `json:"other"`
}

type appHistoryRow struct {
	CheckID string    `json:"check_id"`
	Status  string    `json:"status"`
	Detail  string    `json:"detail"`
	Since   time.Time `json:"since"`
	Catalog string    `json:"catalog_version"`
}

// apiComplianceHistory is the state at the end of a day (at, default
// today) of every device, or of one device (device) with its changes.
func (s *Server) apiComplianceHistory(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	sess := c.sess()
	cutoff, device, ok := historyParams(r.URL.Query())
	if !ok {
		problem(w, http.StatusBadRequest, "at must be a date (YYYY-MM-DD)")
		return
	}
	if device != "" && !s.inScope(ctx, sess, device) {
		problem(w, http.StatusNotFound, "device not found")
		return
	}
	devices, state, changes, err := s.historyState(ctx, sess, cutoff, device)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	rowsOut := func(in []historyRow) []appHistoryRow {
		out := make([]appHistoryRow, len(in))
		for i, h := range in {
			out[i] = appHistoryRow{h.CheckID, h.Status, h.Detail, h.Since, h.Catalog}
		}
		return out
	}
	out := struct {
		At      string             `json:"at"`
		Device  string             `json:"device"`
		Devices []appHistoryDevice `json:"devices"`
		State   []appHistoryRow    `json:"state"`   // one device only
		Changes []appHistoryRow    `json:"changes"` // one device only, newest first
	}{At: cutoff.AddDate(0, 0, -1).Format(time.DateOnly), Device: device, Devices: make([]appHistoryDevice, len(devices)),
		State: []appHistoryRow{}, Changes: rowsOut(changes)}
	for i, d := range devices {
		out.Devices[i] = appHistoryDevice{d.ID, d.Hostname, d.Pass, d.Fail, d.Other}
	}
	if device != "" {
		out.State = rowsOut(state)
	}
	writeJSON(w, out)
}

type appPolicy struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	Blueprints []string `json:"blueprints"`
	api.Compliance
}

type appCustomCheck struct {
	ItemID     int64    `json:"item_id"`
	ItemName   string   `json:"item_name"`
	Blueprints []string `json:"blueprints"`
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Level      int      `json:"level"`
	Refs       api.Refs `json:"refs"`
	Test       string   `json:"test"` // query, file, sysctl, package or service
}

// apiCompliancePolicies lists the compliance policies (com.limdm.compliance)
// and the custom checks (com.limdm.customchecks) of the library with the
// blueprints that use them.
func (s *Server) apiCompliancePolicies(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	items, err := s.allItems(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	use, err := s.itemUsage(ctx)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := struct {
		Policies     []appPolicy      `json:"policies"`
		CustomChecks []appCustomCheck `json:"custom_checks"`
	}{[]appPolicy{}, []appCustomCheck{}}
	for _, it := range items {
		bps := append([]string{}, use[it.ID]...)
		slices.Sort(bps)
		switch it.Type {
		case api.TypeCompliance:
			p := appPolicy{ID: it.ID, Name: it.Name, Blueprints: bps}
			if err := json.Unmarshal(it.Payload, &p.Compliance); err != nil {
				continue // a broken item shows on the library page
			}
			out.Policies = append(out.Policies, p)
		case api.TypeCustomChecks:
			var cc struct {
				Checks []api.CustomCheck `json:"checks"`
			}
			if err := json.Unmarshal(it.Payload, &cc); err != nil {
				continue
			}
			for _, ch := range cc.Checks {
				out.CustomChecks = append(out.CustomChecks, appCustomCheck{ItemID: it.ID, ItemName: it.Name, Blueprints: bps,
					ID: ch.ID, Title: ch.Title, Severity: ch.Severity, Level: ch.Level, Refs: ch.Refs, Test: customTest(ch)})
			}
		}
	}
	writeJSON(w, out)
}

func customTest(c api.CustomCheck) string {
	switch {
	case c.Query != nil:
		return "query"
	case c.File != nil:
		return "file"
	case c.Sysctl != nil:
		return "sysctl"
	case c.Package != nil:
		return "package"
	case c.Service != nil:
		return "service"
	}
	return ""
}

// exportKinds are the exports of the console (export in web.go).
var exportKinds = []string{"compliance.csv", "compliance-history.csv", "exceptions.csv", "inventory.csv", "packages.csv", "audit.csv", "audit.jsonl"}

// apiExport streams an export exactly as the console does, with the same
// scope and the two audit entries (export, export.done with the SHA-256).
func (s *Server) apiExport(w http.ResponseWriter, r *http.Request, c apiCaller) {
	kind := r.PathValue("kind")
	if !slices.Contains(exportKinds, kind) {
		problem(w, http.StatusNotFound, "unknown export")
		return
	}
	if kind == "compliance-history.csv" {
		if _, _, ok := historyParams(r.URL.Query()); !ok {
			problem(w, http.StatusBadRequest, "at must be a date (YYYY-MM-DD)")
			return
		}
	}
	s.export(w, r, c.sess())
}
