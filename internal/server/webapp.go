package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// The console app: the React build of web/ (docs/development.md), committed
// to webapp/dist and embedded, so `go build` needs no Node. It is served
// under /app/ behind the console network list (consoleFilter) and the
// login; it talks to the admin API with the session (sessionCaller).

//go:embed webapp/dist
var webappFiles embed.FS

// webappRoutes serves the console app: hashed assets with a year of
// immutable caching (a missing one is a 404, so a tab of an older build
// reloads instead of running HTML as a script), every other path the app's
// index.html, revalidated on each load, for signed in users only.
func (s *Server) webappRoutes(mux *http.ServeMux) {
	dist, err := fs.Sub(webappFiles, "webapp/dist")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	index, _ := fs.ReadFile(dist, "index.html")
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /app/assets/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/app/")
		if fi, err := fs.Stat(dist, name); err != nil || fi.IsDir() {
			http.NotFound(w, r)
			return
		}
		// the public build of the open source app: no session needed
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeFileFS(w, r, dist, name) //nolint:gosec // an embedded fs.FS: io/fs refuses paths outside it
	})
	mux.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(w, r); !ok {
			toLogin(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/app/")
		if fi, err := fs.Stat(dist, name); name != "" && name != "index.html" && err == nil && !fi.IsDir() {
			w.Header().Set("Cache-Control", "no-cache") // favicon and the like: not hashed
			http.ServeFileFS(w, r, dist, name)          //nolint:gosec // an embedded fs.FS: io/fs refuses paths outside it
			return
		}
		if index == nil {
			http.Error(w, "the console app is not built: run make web", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(index)
	})
}
