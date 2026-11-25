package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Software catalog: apps users install themselves from the desktop app.

// SoftwareSettings are the store wide switches (settings key "software").
type SoftwareSettings struct {
	RestrictFlathub bool `json:"restrict_flathub"` // Flathub offers only catalog apps
	StoresReadOnly  bool `json:"stores_read_only"` // GNOME Software and KDE Discover cannot install
}

func fp(id string) api.AppSource { return api.AppSource{Kind: "flatpak", Flatpak: id} }
func pkg(debian, fedora string) api.AppSource {
	return api.AppSource{Kind: "package", Debian: debian, Fedora: fedora}
}

// defaultCatalog are the apps a new installation starts with: Flatpak
// first (sandboxed, same version everywhere), distribution packages where
// they exist. Detect lists further package names that already count.
var defaultCatalog = []api.CatalogApp{
	{ID: "firefox", Name: "Firefox", Category: "Internet", Summary: "Web browser by Mozilla", Sources: []api.AppSource{fp("org.mozilla.firefox"), pkg("firefox-esr", "firefox")}, Detect: []string{"firefox", "firefox-esr"}},
	{ID: "thunderbird", Name: "Thunderbird", Category: "Office", Summary: "Email, calendar and contacts", Sources: []api.AppSource{fp("org.mozilla.Thunderbird"), pkg("thunderbird", "thunderbird")}},
	{ID: "chromium", Name: "Chromium", Category: "Internet", Summary: "Open source web browser", Sources: []api.AppSource{fp("org.chromium.Chromium"), pkg("chromium", "chromium")}, Detect: []string{"chromium-browser"}},
	{ID: "google-chrome", Name: "Google Chrome", Category: "Internet", Summary: "Web browser by Google", Sources: []api.AppSource{fp("com.google.Chrome")}, Detect: []string{"google-chrome-stable"}},
	{ID: "libreoffice", Name: "LibreOffice", Category: "Office", Summary: "Documents, spreadsheets and presentations", Sources: []api.AppSource{fp("org.libreoffice.LibreOffice"), pkg("libreoffice", "libreoffice")}, Detect: []string{"libreoffice-core", "libreoffice-writer"}},
	{ID: "gimp", Name: "GIMP", Category: "Graphics", Summary: "Image editor", Sources: []api.AppSource{fp("org.gimp.GIMP"), pkg("gimp", "gimp")}},
	{ID: "inkscape", Name: "Inkscape", Category: "Graphics", Summary: "Vector graphics editor", Sources: []api.AppSource{fp("org.inkscape.Inkscape"), pkg("inkscape", "inkscape")}},
	{ID: "vlc", Name: "VLC", Category: "Multimedia", Summary: "Media player", Sources: []api.AppSource{fp("org.videolan.VLC"), pkg("vlc", "vlc")}},
	{ID: "vscode", Name: "Visual Studio Code", Category: "Development", Summary: "Code editor by Microsoft", Sources: []api.AppSource{fp("com.visualstudio.code")}, Detect: []string{"code"}},
	{ID: "slack", Name: "Slack", Category: "Communication", Summary: "Team chat", Sources: []api.AppSource{fp("com.slack.Slack")}, Detect: []string{"slack-desktop", "slack"}},
	{ID: "zoom", Name: "Zoom", Category: "Communication", Summary: "Video meetings", Sources: []api.AppSource{fp("us.zoom.Zoom")}, Detect: []string{"zoom"}},
	{ID: "spotify", Name: "Spotify", Category: "Multimedia", Summary: "Music streaming", Sources: []api.AppSource{fp("com.spotify.Client")}, Detect: []string{"spotify-client"}},
	{ID: "discord", Name: "Discord", Category: "Communication", Summary: "Voice and text chat", Sources: []api.AppSource{fp("com.discordapp.Discord")}, Detect: []string{"discord"}},
	{ID: "signal", Name: "Signal", Category: "Communication", Summary: "Private messenger", Sources: []api.AppSource{fp("org.signal.Signal")}, Detect: []string{"signal-desktop"}},
	{ID: "telegram", Name: "Telegram", Category: "Communication", Summary: "Messenger", Sources: []api.AppSource{fp("org.telegram.desktop"), pkg("telegram-desktop", "")}},
	{ID: "keepassxc", Name: "KeePassXC", Category: "Security", Summary: "Password manager", Sources: []api.AppSource{fp("org.keepassxc.KeePassXC"), pkg("keepassxc", "keepassxc")}},
	{ID: "bitwarden", Name: "Bitwarden", Category: "Security", Summary: "Password manager", Sources: []api.AppSource{fp("com.bitwarden.desktop")}, Detect: []string{"bitwarden"}},
	{ID: "obs-studio", Name: "OBS Studio", Category: "Multimedia", Summary: "Screen recording and streaming", Sources: []api.AppSource{fp("com.obsproject.Studio"), pkg("obs-studio", "obs-studio")}},
	{ID: "audacity", Name: "Audacity", Category: "Multimedia", Summary: "Audio editor", Sources: []api.AppSource{fp("org.audacityteam.Audacity"), pkg("audacity", "audacity")}},
	{ID: "blender", Name: "Blender", Category: "Graphics", Summary: "3D creation suite", Sources: []api.AppSource{fp("org.blender.Blender"), pkg("blender", "blender")}},
	{ID: "remmina", Name: "Remmina", Category: "Utilities", Summary: "Remote desktop client", Sources: []api.AppSource{fp("org.remmina.Remmina"), pkg("remmina", "remmina")}},
	{ID: "filezilla", Name: "FileZilla", Category: "Utilities", Summary: "FTP and SFTP client", Sources: []api.AppSource{fp("org.filezillaproject.Filezilla"), pkg("filezilla", "filezilla")}},
	{ID: "nextcloud", Name: "Nextcloud", Category: "Office", Summary: "File sync client", Sources: []api.AppSource{fp("com.nextcloud.desktopclient.nextcloud"), pkg("nextcloud-desktop", "nextcloud-client")}},
	{ID: "element", Name: "Element", Category: "Communication", Summary: "Matrix messenger", Sources: []api.AppSource{fp("im.riot.Riot")}, Detect: []string{"element-desktop"}},
	{ID: "postman", Name: "Postman", Category: "Development", Summary: "API client", Sources: []api.AppSource{fp("com.getpostman.Postman")}},
}

// seedCatalog adds the default apps once (migration 5); apps an admin
// deletes stay deleted.
func seedCatalog(ctx context.Context, tx pgx.Tx) error {
	for _, a := range defaultCatalog {
		src, _ := json.Marshal(a.Sources)
		if _, err := tx.Exec(ctx, `INSERT INTO catalog_apps(slug, name, summary, category, mode, sources, detect)
			VALUES ($1,$2,$3,$4,'available',$5,$6) ON CONFLICT (slug) DO NOTHING`,
			a.ID, a.Name, a.Summary, a.Category, src, append([]string{}, a.Detect...)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) softwareSettings(ctx context.Context, q querier) (SoftwareSettings, error) {
	var v SoftwareSettings
	var raw []byte
	err := q.QueryRow(ctx, `SELECT value FROM settings WHERE key='software'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(raw, &v)
}

type catalogRow struct {
	api.CatalogApp
	Enabled  bool
	Scope    []int64
	HasIcon  bool
	Updated  time.Time
	Installs int
}

const catalogCols = `slug, name, summary, category, mode, sources, detect, enabled, scope, icon IS NOT NULL,
	coalesce(encode(sha256(icon), 'hex'), ''), updated_at`

func scanCatalog(row pgx.CollectableRow) (catalogRow, error) {
	var r catalogRow
	var src []byte
	err := row.Scan(&r.ID, &r.Name, &r.Summary, &r.Category, &r.Mode, &src, &r.Detect, &r.Enabled, &r.Scope, &r.HasIcon, &r.IconHash, &r.Updated)
	if err == nil {
		err = json.Unmarshal(src, &r.Sources)
	}
	return r, err
}

func (s *Server) catalogApps(ctx context.Context, q querier, where string, args ...any) ([]catalogRow, error) {
	rows, err := q.Query(ctx, `SELECT `+catalogCols+` FROM catalog_apps `+where+` ORDER BY lower(name)`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCatalog)
}

// deviceCatalog is the catalog a device gets: enabled apps whose scope is
// empty or contains one of its blueprints, with the device's requests.
func (s *Server) deviceCatalog(ctx context.Context, tx pgx.Tx, deviceID string, chain []blueprintRec) (*api.Catalog, error) {
	set, err := s.softwareSettings(ctx, tx)
	if err != nil {
		return nil, err
	}
	apps, err := s.catalogApps(ctx, tx, `WHERE enabled`)
	if err != nil {
		return nil, err
	}
	reqs := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (app) app, status FROM catalog_requests WHERE device_id=$1 ORDER BY app, created_at DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var app, st string
		if err := rows.Scan(&app, &st); err != nil {
			rows.Close()
			return nil, err
		}
		reqs[app] = st
	}
	rows.Close()
	c := &api.Catalog{Apps: []api.CatalogApp{}, RestrictFlathub: set.RestrictFlathub, StoresReadOnly: set.StoresReadOnly}
	for _, a := range apps {
		if len(a.Scope) > 0 && !slices.ContainsFunc(chain, func(b blueprintRec) bool { return slices.Contains(a.Scope, b.ID) }) {
			continue
		}
		app := a.CatalogApp
		app.Request = reqs[app.ID]
		c.Apps = append(c.Apps, app)
	}
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	c.Hash = hex.EncodeToString(sum[:16])
	return c, nil
}

// recordAppRequests stores users' requests for "request" apps from a check
// in; an open or approved request is not duplicated.
func recordAppRequests(ctx context.Context, tx pgx.Tx, deviceID string, reqs []api.AppRequest, catalog *api.Catalog) error {
	for _, r := range reqs {
		allowed := slices.ContainsFunc(catalog.Apps, func(a api.CatalogApp) bool { return a.ID == r.App && a.Mode == api.AppOnRequest })
		if !allowed || len(r.User) > 64 || len(r.Note) > 500 {
			continue
		}
		var open bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_requests WHERE device_id=$1 AND app=$2 AND status IN ('pending','approved'))`,
			deviceID, r.App).Scan(&open); err != nil {
			return err
		}
		if open {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO catalog_requests(device_id, app, username, note) VALUES ($1,$2,$3,$4)`,
			deviceID, r.App, r.User, r.Note); err != nil {
			return err
		}
		if err := audit(ctx, tx, "device:"+deviceID, "catalog.request", deviceID, r.App+" for "+r.User+": "+truncate(r.Note, 200)); err != nil {
			return err
		}
	}
	return nil
}

// ---- icons ----

// iconLoop fetches icons of Flatpak apps from Flathub's appstream data.
func (s *Server) iconLoop(ctx context.Context) {
	for {
		s.fetchIcons(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

func (s *Server) fetchIcons(ctx context.Context) {
	apps, err := s.catalogApps(ctx, s.db, `WHERE icon IS NULL AND (icon_tried IS NULL OR icon_tried < now() - interval '1 day')`)
	if err != nil {
		s.log.Warn("catalog icons", "err", err)
		return
	}
	for _, a := range apps {
		for _, src := range a.Sources {
			if src.Kind != "flatpak" {
				continue
			}
			png, err := getBytes(ctx, "https://dl.flathub.org/repo/appstream/x86_64/icons/128x128/"+src.Flatpak+".png", maxLogo)
			if err == nil && validLogo(png) == nil {
				_, _ = s.db.Exec(ctx, `UPDATE catalog_apps SET icon=$2, icon_tried=now() WHERE slug=$1 AND icon IS NULL`, a.ID, png)
				break
			}
		}
		_, _ = s.db.Exec(ctx, `UPDATE catalog_apps SET icon_tried=now() WHERE slug=$1`, a.ID)
	}
}

// catalogIcon serves an app icon (console and agents).
func (s *Server) catalogIcon(w http.ResponseWriter, r *http.Request) {
	var png []byte
	if err := s.db.QueryRow(r.Context(), `SELECT icon FROM catalog_apps WHERE slug=$1 AND icon IS NOT NULL`, r.PathValue("id")).Scan(&png); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(png)
}

func appSourcesText(src []api.AppSource) string {
	var parts []string
	for _, s := range src {
		switch s.Kind {
		case "flatpak":
			parts = append(parts, "Flatpak "+s.Flatpak)
		case "package":
			var p []string
			if s.Debian != "" {
				p = append(p, "deb "+s.Debian)
			}
			if s.Fedora != "" {
				p = append(p, "rpm "+s.Fedora)
			}
			parts = append(parts, strings.Join(p, ", "))
		}
	}
	return strings.Join(parts, " · ")
}
