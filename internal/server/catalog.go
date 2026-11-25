package server

import (
	"context"
	"crypto/sha256"
	"embed"
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
	RestrictFlathub    bool `json:"restrict_flathub"`     // remotes marked catalog only offer only catalog apps
	StoresReadOnly     bool `json:"stores_read_only"`     // GNOME Software and KDE Discover cannot install
	OnlyManagedRemotes bool `json:"only_managed_remotes"` // every other Flatpak remote is disabled
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

//go:embed vendorkeys
var vendorKeys embed.FS

// vendorIcons are icons of seeded apps that are not on Flathub, named by slug.
//
//go:embed vendoricons
var vendorIcons embed.FS

// seedVendorIcons sets them where the app has no icon yet (migration 8).
func seedVendorIcons(ctx context.Context, tx pgx.Tx) error {
	files, err := vendorIcons.ReadDir("vendoricons")
	if err != nil {
		return err
	}
	for _, f := range files {
		png, err := vendorIcons.ReadFile("vendoricons/" + f.Name())
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE catalog_apps SET icon=$2 WHERE slug=$1 AND icon IS NULL`, strings.TrimSuffix(f.Name(), ".png"), png); err != nil {
			return err
		}
	}
	return nil
}

func vendorKey(name string) string {
	b, err := vendorKeys.ReadFile("vendorkeys/" + name + ".asc")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// vendorPkg is a package source from the vendor's own repositories.
func vendorPkg(debian, fedora string, repos ...api.Repository) api.AppSource {
	src := pkg(debian, fedora)
	src.Repos = repos
	return src
}

// moreCatalog came with migration 7: 50 further apps and VPN clients from
// their vendors' repositories (they need a system service, so no Flatpak).
var moreCatalog = append([]api.CatalogApp{
	{ID: "mullvad-vpn", Name: "Mullvad VPN", Category: "Security", Summary: "VPN client by Mullvad", Sources: []api.AppSource{vendorPkg("mullvad-vpn", "mullvad-vpn",
		api.Repository{Name: "mullvad", Family: "debian", URL: "https://repository.mullvad.net/deb/stable", Suites: "stable", Components: "main", Key: vendorKey("mullvad")},
		api.Repository{Name: "mullvad", Family: "fedora", URL: "https://repository.mullvad.net/rpm/stable/$basearch", Key: vendorKey("mullvad")})}},
	// ponytail: one Debian suite for every Debian family distribution; Tailscale's
	// packages are static and identical across suites. Per codename suites if that changes.
	{ID: "tailscale", Name: "Tailscale", Category: "Security", Summary: "Mesh VPN based on WireGuard", Sources: []api.AppSource{vendorPkg("tailscale", "tailscale",
		api.Repository{Name: "tailscale", Family: "debian", URL: "https://pkgs.tailscale.com/stable/debian", Suites: "bookworm", Components: "main", Key: vendorKey("tailscale")},
		api.Repository{Name: "tailscale", Family: "fedora", URL: "https://pkgs.tailscale.com/stable/fedora/$basearch", Key: vendorKey("tailscale")})}},
	{ID: "netbird", Name: "NetBird", Category: "Security", Summary: "Mesh VPN based on WireGuard, with tray app", Sources: []api.AppSource{vendorPkg("netbird netbird-ui", "netbird netbird-ui",
		api.Repository{Name: "netbird", Family: "debian", URL: "https://pkgs.netbird.io/debian", Suites: "stable", Components: "main", Key: vendorKey("netbird-debian")},
		api.Repository{Name: "netbird", Family: "fedora", URL: "https://pkgs.netbird.io/yum/", Key: vendorKey("netbird-fedora"), SignedMetadata: true})}, Detect: []string{"netbird"}},
}, []api.CatalogApp{
	{ID: "anydesk", Name: "AnyDesk", Category: "Utilities", Summary: "Remote desktop", Sources: []api.AppSource{fp("com.anydesk.Anydesk")}},
	{ID: "brave", Name: "Brave", Category: "Internet", Summary: "Web browser with ad blocking", Sources: []api.AppSource{fp("com.brave.Browser")}},
	{ID: "calibre", Name: "calibre", Category: "Office", Summary: "E-book library and reader", Sources: []api.AppSource{fp("com.calibre_ebook.calibre"), pkg("calibre", "calibre")}},
	{ID: "cryptomator", Name: "Cryptomator", Category: "Security", Summary: "Encryption for cloud storage", Sources: []api.AppSource{fp("org.cryptomator.Cryptomator")}},
	{ID: "darktable", Name: "darktable", Category: "Graphics", Summary: "Photo workflow and raw developer", Sources: []api.AppSource{fp("org.darktable.Darktable"), pkg("darktable", "darktable")}},
	{ID: "dbeaver", Name: "DBeaver Community", Category: "Development", Summary: "Database tool", Sources: []api.AppSource{fp("io.dbeaver.DBeaverCommunity")}},
	{ID: "deja-dup", Name: "Déjà Dup", Category: "Utilities", Summary: "Backups", Sources: []api.AppSource{fp("org.gnome.DejaDup"), pkg("deja-dup", "deja-dup")}},
	{ID: "drawio", Name: "draw.io", Category: "Office", Summary: "Diagrams", Sources: []api.AppSource{fp("com.jgraph.drawio.desktop")}},
	{ID: "evince", Name: "Document Viewer", Category: "Office", Summary: "PDF and document viewer", Sources: []api.AppSource{fp("org.gnome.Evince"), pkg("evince", "evince")}},
	{ID: "flameshot", Name: "Flameshot", Category: "Utilities", Summary: "Screenshots with annotations", Sources: []api.AppSource{fp("org.flameshot.Flameshot"), pkg("flameshot", "flameshot")}},
	{ID: "freecad", Name: "FreeCAD", Category: "Graphics", Summary: "Parametric 3D CAD", Sources: []api.AppSource{fp("org.freecad.FreeCAD"), pkg("freecad", "freecad")}},
	{ID: "github-desktop", Name: "GitHub Desktop", Category: "Development", Summary: "Git client for GitHub", Sources: []api.AppSource{fp("io.github.shiftey.Desktop")}},
	{ID: "gnome-boxes", Name: "Boxes", Category: "Utilities", Summary: "Virtual machines", Sources: []api.AppSource{fp("org.gnome.Boxes"), pkg("gnome-boxes", "gnome-boxes")}},
	{ID: "handbrake", Name: "HandBrake", Category: "Multimedia", Summary: "Video transcoder", Sources: []api.AppSource{fp("fr.handbrake.ghb"), pkg("handbrake", "")}},
	{ID: "intellij-idea", Name: "IntelliJ IDEA", Category: "Development", Summary: "Java and Kotlin IDE", Sources: []api.AppSource{fp("com.jetbrains.IntelliJ-IDEA-Community")}},
	{ID: "jitsi-meet", Name: "Jitsi Meet", Category: "Communication", Summary: "Video meetings", Sources: []api.AppSource{fp("org.jitsi.jitsi-meet")}},
	{ID: "joplin", Name: "Joplin", Category: "Office", Summary: "Notes and to-dos", Sources: []api.AppSource{fp("net.cozic.joplin_desktop")}},
	{ID: "kate", Name: "Kate", Category: "Development", Summary: "Text editor", Sources: []api.AppSource{fp("org.kde.kate"), pkg("kate", "kate")}},
	{ID: "kdenlive", Name: "Kdenlive", Category: "Multimedia", Summary: "Video editor", Sources: []api.AppSource{fp("org.kde.kdenlive"), pkg("kdenlive", "kdenlive")}},
	{ID: "kicad", Name: "KiCad", Category: "Development", Summary: "Schematic and circuit board design", Sources: []api.AppSource{fp("org.kicad.KiCad"), pkg("kicad", "kicad")}},
	{ID: "krita", Name: "Krita", Category: "Graphics", Summary: "Digital painting", Sources: []api.AppSource{fp("org.kde.krita"), pkg("krita", "krita")}},
	{ID: "localsend", Name: "LocalSend", Category: "Utilities", Summary: "Share files with nearby devices", Sources: []api.AppSource{fp("org.localsend.localsend_app")}},
	{ID: "mattermost", Name: "Mattermost", Category: "Communication", Summary: "Team chat", Sources: []api.AppSource{fp("com.mattermost.Desktop")}},
	{ID: "meld", Name: "Meld", Category: "Development", Summary: "Compare and merge files", Sources: []api.AppSource{fp("org.gnome.meld"), pkg("meld", "meld")}},
	{ID: "microsoft-edge", Name: "Microsoft Edge", Category: "Internet", Summary: "Web browser by Microsoft", Sources: []api.AppSource{fp("com.microsoft.Edge")}},
	{ID: "mpv", Name: "mpv", Category: "Multimedia", Summary: "Media player", Sources: []api.AppSource{fp("io.mpv.Mpv"), pkg("mpv", "mpv")}},
	{ID: "mullvad-browser", Name: "Mullvad Browser", Category: "Internet", Summary: "Privacy focused web browser", Sources: []api.AppSource{fp("net.mullvad.MullvadBrowser")}},
	{ID: "obsidian", Name: "Obsidian", Category: "Office", Summary: "Markdown knowledge base", Sources: []api.AppSource{fp("md.obsidian.Obsidian")}},
	{ID: "okular", Name: "Okular", Category: "Office", Summary: "Document viewer with annotations", Sources: []api.AppSource{fp("org.kde.okular"), pkg("okular", "okular")}},
	{ID: "onlyoffice", Name: "ONLYOFFICE", Category: "Office", Summary: "Documents, spreadsheets and presentations", Sources: []api.AppSource{fp("org.onlyoffice.desktopeditors")}},
	{ID: "pdfarranger", Name: "PDF Arranger", Category: "Office", Summary: "Merge, sort and crop PDFs", Sources: []api.AppSource{fp("com.github.jeromerobert.pdfarranger"), pkg("pdfarranger", "pdfarranger")}},
	{ID: "podman-desktop", Name: "Podman Desktop", Category: "Development", Summary: "Containers and Kubernetes", Sources: []api.AppSource{fp("io.podman_desktop.PodmanDesktop")}},
	{ID: "proton-pass", Name: "Proton Pass", Category: "Security", Summary: "Password manager", Sources: []api.AppSource{fp("me.proton.Pass")}},
	{ID: "proton-vpn", Name: "Proton VPN", Category: "Security", Summary: "VPN client", Sources: []api.AppSource{fp("com.protonvpn.www")}},
	{ID: "pycharm", Name: "PyCharm", Category: "Development", Summary: "Python IDE", Sources: []api.AppSource{fp("com.jetbrains.PyCharm-Community")}},
	{ID: "rocketchat", Name: "Rocket.Chat", Category: "Communication", Summary: "Team chat", Sources: []api.AppSource{fp("chat.rocket.RocketChat")}},
	{ID: "rustdesk", Name: "RustDesk", Category: "Utilities", Summary: "Remote desktop", Sources: []api.AppSource{fp("com.rustdesk.RustDesk")}},
	{ID: "teams-for-linux", Name: "Teams for Linux", Category: "Communication", Summary: "Unofficial Microsoft Teams client", Sources: []api.AppSource{fp("com.github.IsmaelMartinez.teams_for_linux")}},
	{ID: "tor-browser", Name: "Tor Browser", Category: "Internet", Summary: "Anonymous web browser", Sources: []api.AppSource{fp("org.torproject.torbrowser-launcher"), pkg("torbrowser-launcher", "torbrowser-launcher")}},
	{ID: "trayscale", Name: "Trayscale", Category: "Utilities", Summary: "Tray app for Tailscale", Sources: []api.AppSource{fp("dev.deedles.Trayscale")}},
	{ID: "virt-manager", Name: "Virtual Machine Manager", Category: "Utilities", Summary: "Manage KVM virtual machines", Sources: []api.AppSource{fp("org.virt_manager.virt-manager"), pkg("virt-manager", "virt-manager")}},
	{ID: "vivaldi", Name: "Vivaldi", Category: "Internet", Summary: "Web browser", Sources: []api.AppSource{fp("com.vivaldi.Vivaldi")}},
	{ID: "vscodium", Name: "VSCodium", Category: "Development", Summary: "Code editor without telemetry", Sources: []api.AppSource{fp("com.vscodium.codium")}, Detect: []string{"codium"}},
	{ID: "wireshark", Name: "Wireshark", Category: "Development", Summary: "Network protocol analyzer", Sources: []api.AppSource{fp("org.wireshark.Wireshark"), pkg("wireshark", "wireshark")}},
	{ID: "xournalpp", Name: "Xournal++", Category: "Office", Summary: "Handwritten notes and PDF annotation", Sources: []api.AppSource{fp("com.github.xournalpp.xournalpp"), pkg("xournalpp", "xournalpp")}},
	{ID: "zotero", Name: "Zotero", Category: "Education", Summary: "Research and citations", Sources: []api.AppSource{fp("org.zotero.Zotero")}},
	{ID: "zulip", Name: "Zulip", Category: "Communication", Summary: "Team chat", Sources: []api.AppSource{fp("org.zulip.Zulip")}},
	{ID: "bruno", Name: "Bruno", Category: "Development", Summary: "API client", Sources: []api.AppSource{fp("com.usebruno.Bruno")}},
	{ID: "shotcut", Name: "Shotcut", Category: "Multimedia", Summary: "Video editor", Sources: []api.AppSource{fp("org.shotcut.Shotcut")}},
	{ID: "scribus", Name: "Scribus", Category: "Graphics", Summary: "Desktop publishing", Sources: []api.AppSource{fp("net.scribus.Scribus"), pkg("scribus", "scribus")}},
}...)

// seedCatalog adds the default apps once (migration 5); apps an admin
// deletes stay deleted.
func seedCatalog(ctx context.Context, tx pgx.Tx) error { return seedApps(ctx, tx, defaultCatalog) }

func seedApps(ctx context.Context, tx pgx.Tx, apps []api.CatalogApp) error {
	for _, a := range apps {
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
// A store policy declaration of the device overrides the console default.
func (s *Server) deviceCatalog(ctx context.Context, tx pgx.Tx, deviceID string, chain []blueprintRec, policy *api.SoftwareStore) (*api.Catalog, error) {
	set, err := s.softwareSettings(ctx, tx)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		set = SoftwareSettings{RestrictFlathub: policy.RestrictFlathub, StoresReadOnly: policy.StoresReadOnly, OnlyManagedRemotes: policy.OnlyManagedRemotes}
	}
	remotes, err := s.catalogRemotes(ctx, tx)
	if err != nil {
		return nil, err
	}
	apps, err := s.catalogApps(ctx, tx, `WHERE enabled`)
	if err != nil {
		return nil, err
	}
	reqs := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (app) app, status FROM catalog_requests WHERE device_id=$1 AND app IS NOT NULL AND flatpak=''
		ORDER BY app, created_at DESC`, deviceID)
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
	c := &api.Catalog{Apps: []api.CatalogApp{}, RestrictFlathub: set.RestrictFlathub, StoresReadOnly: set.StoresReadOnly,
		Remotes: remotes, OnlyManagedRemotes: set.OnlyManagedRemotes}
	rows, err = tx.Query(ctx, `SELECT DISTINCT ON (flatpak) flatpak, app_name, status, coalesce(app, '') FROM catalog_requests
		WHERE device_id=$1 AND flatpak <> '' AND created_at > now() - interval '90 days' ORDER BY flatpak, created_at DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	if c.Requests, err = pgx.CollectRows(rows, pgx.RowToStructByPos[api.RequestState]); err != nil {
		return nil, err
	}
	for _, r := range c.Requests { // an approved request makes the new app this device's approved app
		if r.Status == "approved" && r.App != "" {
			reqs[r.App] = "approved"
		}
	}
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
		if len(r.User) > 64 || len(r.Note) > 500 || len(r.Name) > 80 {
			continue
		}
		if r.App == "" && r.Flatpak != "" {
			if err := recordNewAppRequest(ctx, tx, deviceID, r, catalog); err != nil {
				return err
			}
			continue
		}
		allowed := slices.ContainsFunc(catalog.Apps, func(a api.CatalogApp) bool { return a.ID == r.App && a.Mode == api.AppOnRequest })
		if !allowed {
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

// fetchIcons completes catalog apps from Flathub's appstream data: icon,
// and summary and category when empty (taken over Flatpaks, older
// entries). Admins' own texts and icons stay. Each app is tried once a day.
func (s *Server) fetchIcons(ctx context.Context) {
	apps, err := s.catalogApps(ctx, s.db, `WHERE (icon IS NULL OR summary = '' OR category = '')
		AND (icon_tried IS NULL OR icon_tried < now() - interval '1 day')`)
	if err != nil {
		s.log.Warn("catalog icons", "err", err)
		return
	}
	for _, a := range apps {
		for _, src := range a.Sources {
			if src.Kind != "flatpak" {
				continue
			}
			meta, icon, err := s.flathubApp(ctx, src.Flatpak)
			if err != nil { // not on Flathub with metadata; the icon may still be in the repository
				meta = api.CatalogApp{}
				if png, err := getBytes(ctx, "https://dl.flathub.org/repo/appstream/x86_64/icons/128x128/"+src.Flatpak+".png", maxLogo); err == nil && validLogo(png) == nil {
					icon = png
				}
			}
			if icon == nil && meta.Summary == "" && meta.Category == "" {
				continue
			}
			_, _ = s.db.Exec(ctx, `UPDATE catalog_apps SET icon = coalesce(icon, $2),
				summary = CASE WHEN summary = '' THEN $3 ELSE summary END,
				category = CASE WHEN category = '' THEN $4 ELSE category END WHERE slug = $1`, a.ID, icon, meta.Summary, meta.Category)
			break
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

func (s *Server) catalogRemotes(ctx context.Context, q querier) ([]api.CatalogRemote, error) {
	rows, err := q.Query(ctx, `SELECT name, url, title, state, catalog_only FROM catalog_remotes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[api.CatalogRemote])
}

// recordNewAppRequest stores a request for a Flatpak outside the catalog,
// from Flathub or another allowed remote. Apps already in the catalog and
// open requests are not recorded again.
func recordNewAppRequest(ctx context.Context, tx pgx.Tx, deviceID string, r api.AppRequest, catalog *api.Catalog) error {
	remote := r.Remote
	if remote == "" {
		remote = "flathub"
	}
	if !api.ValidFlatpakID(r.Flatpak) || !api.ValidRemoteName(remote) {
		return nil
	}
	allowed := remote == "flathub" && len(catalog.Remotes) == 0
	for _, rem := range catalog.Remotes {
		allowed = allowed || (rem.Name == remote && rem.State == "allowed")
	}
	if !allowed || slices.Contains(catalog.Flatpaks(remote), r.Flatpak) {
		return nil
	}
	var open bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_requests WHERE device_id=$1 AND flatpak=$2 AND status='pending')`,
		deviceID, r.Flatpak).Scan(&open); err != nil || open {
		return err
	}
	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = r.Flatpak
	}
	if _, err := tx.Exec(ctx, `INSERT INTO catalog_requests(device_id, flatpak, remote, app_name, username, note) VALUES ($1,$2,$3,$4,$5,$6)`,
		deviceID, r.Flatpak, remote, name, r.User, r.Note); err != nil {
		return err
	}
	return audit(ctx, tx, "device:"+deviceID, "catalog.request", deviceID, r.Flatpak+" ("+remote+") for "+r.User+": "+truncate(r.Note, 200))
}
