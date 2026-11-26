package server

import (
	"net/http"
	"slices"
)

// The reports area of the console app: the compliance state at a date and
// the evidence exports of the console (/export/{kind}) through the API,
// with the same roles (admins and auditors), scope and two audit entries
// per file (streamExport).

func (s *Server) appReportsRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/compliance/history", s.need("read", s.apiComplianceHistory))
	m.HandleFunc("GET /api/v1/exports/{kind}", s.need("audit", s.apiExport))
}

// exportKinds are the files export writes.
var exportKinds = []string{"compliance.csv", "compliance-history.csv", "inventory.csv", "packages.csv", "audit.csv", "audit.jsonl", "exceptions.csv"}

func (s *Server) apiExport(w http.ResponseWriter, r *http.Request, c apiCaller) {
	kind := r.PathValue("kind")
	if !slices.Contains(exportKinds, kind) {
		problem(w, http.StatusNotFound, "unknown export")
		return
	}
	if _, _, ok := historyParams(r.URL.Query()); kind == "compliance-history.csv" && !ok {
		problemField(w, http.StatusBadRequest, "at", "at must be a date (YYYY-MM-DD)")
		return
	}
	s.export(w, r, c.sess())
}

type complianceHistory struct {
	At      string           `json:"at"`
	Device  string           `json:"device"`
	Devices []*historyDevice `json:"devices"`
	State   []historyRow     `json:"state"`   // one device only
	Changes []historyRow     `json:"changes"` // one device only, newest first
}

// apiComplianceHistory is the console's compliance history: the state at
// the end of a day for all devices in scope, or per check of one device.
func (s *Server) apiComplianceHistory(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	cutoff, device, ok := historyParams(r.URL.Query())
	if !ok {
		problemField(w, http.StatusBadRequest, "at", "at must be a date (YYYY-MM-DD)")
		return
	}
	sess := c.sess()
	if device != "" && !s.inScope(ctx, sess, device) {
		problem(w, http.StatusNotFound, "device not found")
		return
	}
	state, devices, changes, err := s.historyAt(ctx, sess, cutoff, device)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out := complianceHistory{At: cutoff.AddDate(0, 0, -1).Format("2006-01-02"), Device: device,
		Devices: nonNilSlice(devices), State: []historyRow{}, Changes: nonNilSlice(changes)}
	if device != "" {
		out.State = nonNilSlice(state)
	}
	writeJSON(w, out)
}

func nonNilSlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
