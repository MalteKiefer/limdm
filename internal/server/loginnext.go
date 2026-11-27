package server

import (
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// defaultNext is where a sign in without a (valid) next target lands.
const defaultNext = "/app/"

// safeNext returns the page a sign in returns to: a path of this origin in
// the console app (/app/) or the classic console, never another host, a
// scheme relative URL, the sign in pages themselves or the API. Anything
// else gives defaultNext, so the parameter is no open redirect.
func safeNext(v string) string {
	if v == "" || len(v) > 2000 || v[0] != '/' || (len(v) > 1 && (v[1] == '/' || v[1] == '\\')) ||
		strings.ContainsAny(v, `\`) || strings.ContainsFunc(v, unicode.IsControl) {
		return defaultNext
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return defaultNext
	}
	p := u.Path
	if strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || strings.HasPrefix(p, "//") {
		return defaultNext
	}
	for _, deny := range []string{"/login", "/logout", "/auth/", "/api/", "/scim/", "/network/crl.pem"} {
		if p == strings.TrimSuffix(deny, "/") || strings.HasPrefix(p, deny) {
			return defaultNext
		}
	}
	// a path on this host: always "/" plus the checked path and query
	return "/" + strings.TrimPrefix(u.RequestURI(), "/")
}

// oneLine keeps a value from a request on one log line.
func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}

// toLogin sends a request without a session to the sign in page; a page
// request keeps its own address as the next target.
func toLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if r.Method == http.MethodGet {
		if next := safeNext(r.URL.RequestURI()); next != defaultNext {
			target += "?next=" + url.QueryEscape(next)
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}
