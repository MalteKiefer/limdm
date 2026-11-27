package server

import "testing"

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "/app/",
		"/app/":                      "/app/",
		"/app/settings?s=users":      "/app/settings?s=users",
		"/devices/d1":                "/app/",
		"/app/devices/d1":            "/app/devices/d1",
		"/app//evil.example":         "/app/evil.example",
		"/application":               "/app/",
		"//evil.example":             "/app/",
		"/\\evil.example":            "/app/",
		"https://evil.example/app/":  "/app/",
		"app/":                       "/app/",
		"/login?next=/x":             "/app/",
		"/logout":                    "/app/",
		"/auth/callback":             "/app/",
		"/api/v1/me":                 "/app/",
		"/app/%0d%0aSet-Cookie:x":    "/app/%0d%0aSet-Cookie:x",
		"/app/\nx":                   "/app/",
		"/app/../login":              "/app/",
		"javascript:alert(1)":        "/app/",
		"/%2f%2fevil.example":        "/app/",
		"/app/?q=" + string(rune(7)): "/app/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
