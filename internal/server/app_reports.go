package server

import "net/http"

// The reports area of the console app: scheduled report presets. The
// compliance history and the exports it uses are the compliance area's
// /api/v1/compliance/history and /api/v1/exports/{kind} (app_compliance.go).

func (s *Server) appReportsRoutes(m *http.ServeMux) {
	s.appReportScheduleRoutes(m)
}

func nonNilSlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
