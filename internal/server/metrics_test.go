package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPromLabelEscaping(t *testing.T) {
	var p promWriter
	p.sample("m", 2, "version", "1\"\n\\x")
	if got := p.String(); got != "m{version=\"1\\\"\\n\\\\x\"} 2\n" {
		t.Fatalf("%q", got)
	}
}

// Every answer carries a request id: the proxy's when it is well formed,
// else a new one; the duration lands in the histogram.
func TestRequestIDAndLatency(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{AccessLog: true}}
	var seen string
	h := s.countRequests("test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = requestID(w) }))
	call := func(id string) string {
		r := httptest.NewRequest("GET", "/x", nil)
		if id != "" {
			r.Header.Set("X-Request-ID", id)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Header().Get("X-Request-ID")
	}
	if got := call("abc-123"); got != "abc-123" || seen != "abc-123" {
		t.Fatalf("proxy id not kept: %q %q", got, seen)
	}
	if got := call("bad id\n"); got == "" || got == "bad id\n" {
		t.Fatalf("malformed id kept: %q", got)
	}
	if a, b := call(""), call(""); a == "" || a == b {
		t.Fatalf("ids not unique: %q %q", a, b)
	}
	httpLatency.Lock()
	n := httpLatency.m["test"].n
	httpLatency.Unlock()
	if n != 4 {
		t.Fatalf("histogram count %d", n)
	}
}

func TestAuditRead(t *testing.T) {
	s := &Server{}
	get := func(pattern string) *http.Request {
		r := httptest.NewRequest("GET", "/api/v1/x", nil)
		r.Pattern = pattern
		return r
	}
	for mode, want := range map[string][3]bool{"sensitive": {true, true, false}, "all": {true, true, true}, "off": {false, false, false}} {
		s.cfg.AuditAPIReads = mode
		got := [3]bool{s.auditRead(get("GET /api/v1/audit"), "audit"), s.auditRead(get("GET /api/v1/devices/{id}"), "read"), s.auditRead(get("GET /api/v1/tags"), "read")}
		if got != want {
			t.Errorf("%s: %v", mode, got)
		}
	}
	s.cfg.AuditAPIReads = "all"
	if s.auditRead(httptest.NewRequest("POST", "/api/v1/x", nil), "admin") {
		t.Error("writes audit themselves")
	}
}
