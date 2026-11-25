package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Flathub search for the software catalog (console and desktop app). The
// server asks Flathub's API; devices never talk to it for searching.

const flathubAPI = "https://flathub.org/api/v2"

type flathubHit struct {
	AppID          string `json:"app_id"`
	Name           string `json:"name"`
	Summary        string `json:"summary"`
	Icon           string `json:"icon"`
	DeveloperName  string `json:"developer_name"`
	MainCategories any    `json:"main_categories"` // a string or a list, depending on the entry
}

func (h flathubHit) category() string {
	switch v := h.MainCategories.(type) {
	case string:
		return catalogCategory(v)
	case []any:
		for _, c := range v {
			if s, ok := c.(string); ok {
				return catalogCategory(s)
			}
		}
	}
	return ""
}

// catalogCategory maps freedesktop and Flathub categories to the catalog's.
func catalogCategory(c string) string {
	switch strings.ToLower(c) {
	case "audiovideo", "audio", "video", "player", "music":
		return "Multimedia"
	case "development", "ide", "debugger":
		return "Development"
	case "graphics", "2dgraphics", "3dgraphics", "photography", "rastergraphics", "vectorgraphics":
		return "Graphics"
	case "network", "webbrowser":
		return "Internet"
	case "chat", "instantmessaging", "email", "videoconference", "telephony":
		return "Communication"
	case "office", "wordprocessor", "spreadsheet", "presentation":
		return "Office"
	case "game", "games":
		return "Games"
	case "education", "science":
		return "Education"
	case "security":
		return "Security"
	case "system", "utility", "utilities":
		return "Utilities"
	}
	return ""
}

var flathubClient = &http.Client{Timeout: 20 * time.Second}

// flathubCache keeps search results and icons for an hour, so devices and
// the console cannot make the server hammer Flathub (which would block the
// server's address for everybody).
type cacheEntry struct {
	val []byte
	at  time.Time
}

var (
	flathubMu    sync.Mutex
	flathubCache = map[string]cacheEntry{}
)

func cached(key string, fetch func() ([]byte, error)) ([]byte, error) {
	flathubMu.Lock()
	if e, ok := flathubCache[key]; ok && time.Since(e.at) < time.Hour {
		flathubMu.Unlock()
		return e.val, nil
	}
	flathubMu.Unlock()
	b, err := fetch()
	if err != nil {
		return nil, err
	}
	flathubMu.Lock()
	defer flathubMu.Unlock()
	if len(flathubCache) > 2000 { // bounded: drop everything older than an hour, else all
		for k, e := range flathubCache {
			if time.Since(e.at) >= time.Hour {
				delete(flathubCache, k)
			}
		}
		if len(flathubCache) > 2000 {
			flathubCache = map[string]cacheEntry{}
		}
	}
	flathubCache[key] = cacheEntry{val: b, at: time.Now()}
	return b, nil
}

func flathubJSON(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, flathubAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "limdm-server")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := flathubClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("flathub %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// flathubSearch finds apps on Flathub, without those the catalog has already.
func (s *Server) flathubSearch(ctx context.Context, query string) ([]api.FlatpakHit, error) {
	query = strings.TrimSpace(query)
	if len(query) < 2 || len(query) > 80 {
		return nil, errors.New("search: 2 to 80 characters")
	}
	var res struct {
		Hits []flathubHit `json:"hits"`
	}
	raw, err := cached("search:"+strings.ToLower(query), func() ([]byte, error) {
		var r json.RawMessage
		err := flathubJSON(ctx, http.MethodPost, "/search", map[string]any{"query": query, "hits_per_page": 24, "page": 1}, &r)
		return r, err
	})
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	known := map[string]bool{}
	rows, err := s.db.Query(ctx, `SELECT src->>'flatpak' FROM catalog_apps a, jsonb_array_elements(a.sources) src WHERE src->>'flatpak' IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			known[id] = true
		}
	}
	rows.Close()
	hits := []api.FlatpakHit{} // never JSON null: the console script reads .length
	for _, h := range res.Hits {
		if !api.ValidFlatpakID(h.AppID) || known[h.AppID] {
			continue
		}
		hits = append(hits, api.FlatpakHit{ID: h.AppID, Name: truncate(h.Name, 80), Summary: truncate(h.Summary, 300), Remote: "flathub",
			Icon: flathubIconURL(h.Icon), Category: h.category(), Developer: truncate(h.DeveloperName, 80)})
	}
	return hits, nil
}

var flathubIconPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,300}\.png$`)

// flathubIconURL keeps icon links to Flathub's own media server only and
// rebuilds them on the fixed host.
func flathubIconURL(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host != "dl.flathub.org" || p.RawQuery != "" || p.User != nil ||
		!flathubIconPath.MatchString(p.Path) || strings.Contains(p.Path, "..") {
		return ""
	}
	return "https://dl.flathub.org/" + strings.TrimPrefix(p.Path, "/")
}

// flathubApp reads an app's metadata for the catalog: name, summary,
// category and icon.
func (s *Server) flathubApp(ctx context.Context, id string) (api.CatalogApp, []byte, error) {
	var a struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Summary    string   `json:"summary"`
		Icon       string   `json:"icon"`
		Categories []string `json:"categories"`
	}
	if err := flathubJSON(ctx, http.MethodGet, "/appstream/"+url.PathEscape(id), nil, &a); err != nil {
		return api.CatalogApp{}, nil, err
	}
	if a.ID != id || a.Name == "" {
		return api.CatalogApp{}, nil, fmt.Errorf("flathub has no app %s", id)
	}
	app := api.CatalogApp{Name: truncate(a.Name, 80), Summary: truncate(a.Summary, 300), Mode: api.AppAvailable,
		Sources: []api.AppSource{{Kind: "flatpak", Flatpak: id}}}
	for _, c := range a.Categories {
		if app.Category = catalogCategory(c); app.Category != "" {
			break
		}
	}
	var icon []byte
	if u := flathubIconURL(a.Icon); u != "" {
		if b, err := getBytes(ctx, u, maxLogo); err == nil && validLogo(b) == nil {
			icon = b
		}
	}
	return app, icon, nil
}

// flathubIcon serves a Flathub icon through the server (the console's CSP
// allows no foreign images, devices only talk to the server). Only
// dl.flathub.org URLs and PNG icons pass.
func (s *Server) flathubIcon(w http.ResponseWriter, r *http.Request) {
	u := flathubIconURL(r.URL.Query().Get("u"))
	if u == "" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	b, err := cached("icon:"+u, func() ([]byte, error) {
		b, err := getBytes(ctx, u, maxLogo)
		if err == nil {
			err = validLogo(b)
		}
		return b, err
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(b)
}

// flathubSearchPage shows search results on the "add app" page.
func (s *Server) flathubSearchJSON(w http.ResponseWriter, r *http.Request) {
	hits, err := s.flathubSearch(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.log.Warn("flathub search", "err", err)
		hits = []api.FlatpakHit{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(hits)
}
