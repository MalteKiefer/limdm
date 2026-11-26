package server

import "testing"

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "/",
		"/app/":                      "/app/",
		"/app/settings?s=users":      "/app/settings?s=users",
		"/devices/d1":                "/devices/d1",
		"//evil.example":             "/",
		"/\\evil.example":            "/",
		"https://evil.example/app/":  "/",
		"app/":                       "/",
		"/login?next=/x":             "/",
		"/logout":                    "/",
		"/auth/callback":             "/",
		"/api/v1/me":                 "/",
		"/app/%0d%0aSet-Cookie:x":    "/app/%0d%0aSet-Cookie:x",
		"/app/\nx":                   "/",
		"/app/../login":              "/",
		"javascript:alert(1)":        "/",
		"/%2f%2fevil.example":        "/",
		"/app/?q=" + string(rune(7)): "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
