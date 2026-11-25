package agent

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Software catalog (self service). Users pick an app in the desktop app;
// the agent installs only apps the catalog offers this device, from the
// first source that works. An app counts as installed when any of its
// sources or further names is installed, however it got there, so an app
// installed as a distribution package is never installed again as Flatpak.

const (
	flathubURL      = "https://dl.flathub.org/repo/flathub.flatpakrepo"
	flathubFilter   = "/etc/flatpak/limdm-flathub.filter"
	storeReadOnly   = "/etc/polkit-1/rules.d/60-limdm-store-readonly.rules"
	catalogIconsDir = "/var/cache/limdm/catalog"
	appRetry        = time.Hour // a failed required or approved app is tried again after this
)

// appJob is a running or failed install or removal.
type appJob struct {
	Action string // install | remove
	Err    string
	At     time.Time
}

type store struct {
	mu   sync.Mutex
	jobs map[string]*appJob // app ID -> job
}

func (s *store) job(id string) *appJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j := s.jobs[id]; j != nil {
		c := *j
		return &c
	}
	return nil
}

func (s *store) start(id, action string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j := s.jobs[id]; j != nil && j.Err == "" {
		return false // already running
	}
	s.jobs[id] = &appJob{Action: action, At: time.Now()}
	return true
}

func (s *store) finish(id string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.jobs, id)
		return
	}
	s.jobs[id] = &appJob{Err: err.Error(), At: time.Now()}
}

func familyPackages(src api.AppSource, family string) []string {
	if family == "debian" {
		return strings.Fields(src.Debian)
	}
	return strings.Fields(src.Fedora)
}

// installedFlatpaks are the Flatpak IDs installed system wide or for any user.
func installedFlatpaks(apps []api.FlatpakApp) map[string]string {
	m := map[string]string{}
	for _, a := range apps {
		if _, ok := m[a.ID]; !ok || a.Installation == "system" {
			m[a.ID] = a.Installation
		}
	}
	return m
}

// appState tells whether and how an app is installed.
func (a *Agent) appState(app api.CatalogApp, flatpaks map[string]string) api.AppState {
	st := api.AppState{ID: app.ID}
	for _, src := range app.Sources {
		switch src.Kind {
		case "flatpak":
			if _, ok := flatpaks[src.Flatpak]; ok {
				st.Installed, st.Via = true, "flatpak"
				return st
			}
		case "package":
			names := familyPackages(src, a.host.family)
			if len(names) > 0 && a.host.isInstalled(names[0]) {
				st.Installed, st.Via = true, "package"
				return st
			}
		}
	}
	for _, d := range app.Detect {
		if a.host.isInstalled(d) {
			st.Installed, st.Via = true, "package"
			return st
		}
	}
	if j := a.store.job(app.ID); j != nil && j.Err != "" {
		st.Error = j.Err
	}
	return st
}

func (a *Agent) catalogStates(flatpaks []api.FlatpakApp) []api.AppState {
	c := a.state.Catalog
	if c == nil {
		return nil
	}
	fl := installedFlatpaks(flatpaks)
	out := make([]api.AppState, 0, len(c.Apps))
	for _, app := range c.Apps {
		out = append(out, a.appState(app, fl))
	}
	return out
}

func (a *Agent) catalogApp(id string) (api.CatalogApp, bool) {
	if a.state.Catalog == nil {
		return api.CatalogApp{}, false
	}
	for _, app := range a.state.Catalog.Apps {
		if app.ID == id {
			return app, true
		}
	}
	return api.CatalogApp{}, false
}

// ensureFlathub adds the Flathub remote to the system installation.
func (a *Agent) ensureFlathub() error {
	if !hasCmd("flatpak") {
		if err := a.host.install("flatpak"); err != nil {
			return err
		}
	}
	_, err := flatpakCmd(nil, 5*time.Minute, "remote-add", "--if-not-exists", "flathub", flathubURL)
	return err
}

// installApp installs from the first source that works.
func (a *Agent) installApp(app api.CatalogApp) error {
	var errs []error
	for _, src := range app.Sources {
		switch src.Kind {
		case "flatpak":
			if err := a.ensureFlathub(); err != nil {
				errs = append(errs, err)
				continue
			}
			if _, err := flatpakCmd(nil, time.Hour, "install", "-y", "--noninteractive", "flathub", src.Flatpak); err != nil {
				errs = append(errs, fmt.Errorf("flatpak: %w", err))
				continue
			}
			a.event("installed %s (Flatpak %s)", app.Name, src.Flatpak)
			return nil
		case "package":
			names := familyPackages(src, a.host.family)
			if len(names) == 0 {
				continue
			}
			if err := a.host.install(names...); err != nil {
				errs = append(errs, fmt.Errorf("packages: %w", err))
				continue
			}
			a.event("installed %s (packages %s)", app.Name, strings.Join(names, " "))
			return nil
		}
	}
	if len(errs) == 0 {
		return errors.New("no source for this distribution")
	}
	return errors.Join(errs...)
}

// removeApp removes what installed the app (system Flatpak or packages).
func (a *Agent) removeApp(app api.CatalogApp, flatpaks map[string]string) error {
	for _, src := range app.Sources {
		switch src.Kind {
		case "flatpak":
			inst, ok := flatpaks[src.Flatpak]
			if !ok {
				continue
			}
			if inst != "system" {
				return errors.New("installed by the user in their own Flatpak installation")
			}
			if _, err := flatpakCmd(nil, 30*time.Minute, "uninstall", "-y", "--noninteractive", src.Flatpak); err != nil {
				return err
			}
			a.event("removed %s (Flatpak %s)", app.Name, src.Flatpak)
			return nil
		case "package":
			names := familyPackages(src, a.host.family)
			if len(names) == 0 || !a.host.isInstalled(names[0]) {
				continue
			}
			if err := a.host.remove(names...); err != nil {
				return err
			}
			a.event("removed %s (packages %s)", app.Name, strings.Join(names, " "))
			return nil
		}
	}
	return errors.New("installed outside the catalog sources; ask IT to remove it")
}

// applyCatalog installs required apps and approved requests, and sets the
// Flathub filter and the store lock. Failed apps wait appRetry.
func (a *Agent) applyCatalog(flatpaks []api.FlatpakApp) {
	c := a.state.Catalog
	if c == nil {
		return
	}
	a.applyFlathubFilter(c)
	a.applyStoreLock(c.StoresReadOnly)
	fl := installedFlatpaks(flatpaks)
	var due []api.CatalogApp
	for _, app := range c.Apps {
		wanted := app.Mode == api.AppRequired || (app.Mode == api.AppOnRequest && app.Request == "approved")
		if !wanted || a.appState(app, fl).Installed {
			continue
		}
		if j := a.store.job(app.ID); j != nil && (j.Err == "" || time.Since(j.At) < appRetry) {
			continue
		}
		if a.store.start(app.ID, "install") {
			due = append(due, app)
		}
	}
	if len(due) > 0 {
		go func() { // large installs must not hold up the check in
			for _, app := range due {
				err := a.installApp(app)
				a.store.finish(app.ID, err)
				if err != nil {
					a.event("installing %s failed: %v", app.Name, err)
				}
			}
			a.kickCheckin()
		}()
	}
	a.cacheCatalogIcons(c)
}

// applyFlathubFilter limits Flathub to the catalog's Flatpaks (runtimes stay
// allowed), for the system and for user installations.
func (a *Agent) applyFlathubFilter(c *api.Catalog) {
	if !hasCmd("flatpak") {
		return
	}
	accts, _ := nssAccounts()
	users := flatpakUsers(accts, false)
	if !c.RestrictFlathub {
		if exists(flathubFilter) {
			_, _ = flatpakCmd(nil, time.Minute, "remote-modify", "--no-filter", "flathub")
			for _, u := range users {
				_, _ = flatpakCmd(&u, time.Minute, "remote-modify", "--no-filter", "flathub")
			}
			_ = os.Remove(flathubFilter)
		}
		return
	}
	ids := c.Flatpaks()
	changed, err := writeIfChanged(flathubFilter, flathubFilterContent(ids), 0o644)
	if err != nil {
		a.event("Flathub filter: %v", err)
		return
	}
	if !changed && exists(flathubFilter) {
		return
	}
	_, _ = flatpakCmd(nil, time.Minute, "remote-modify", "--filter="+flathubFilter, "flathub")
	for _, u := range users {
		_, _ = flatpakCmd(&u, time.Minute, "remote-modify", "--filter="+flathubFilter, "flathub")
	}
	a.event("Flathub limited to %d catalog apps", len(ids))
}

const storeLockRule = `// Managed by LiMDM: software is installed through the LiMDM catalog only.
polkit.addRule(function(action, subject) {
    var denied = [
        "org.freedesktop.packagekit.package-install",
        "org.freedesktop.packagekit.package-install-untrusted",
        "org.freedesktop.packagekit.package-remove",
        "org.freedesktop.packagekit.system-update",
        "org.freedesktop.packagekit.upgrade-system",
        "org.freedesktop.packagekit.repair-system",
        "org.freedesktop.packagekit.system-sources-configure",
        "org.freedesktop.Flatpak.app-install",
        "org.freedesktop.Flatpak.runtime-install",
        "org.freedesktop.Flatpak.app-uninstall",
        "org.freedesktop.Flatpak.runtime-uninstall",
        "org.freedesktop.Flatpak.modify-repo",
        "org.freedesktop.Flatpak.configure-remote",
        "org.freedesktop.Flatpak.configure"
    ];
    if (denied.indexOf(action.id) >= 0 && subject.user != "root") {
        return polkit.Result.NO;
    }
});
`

// applyStoreLock makes GNOME Software and KDE Discover read only.
func (a *Agent) applyStoreLock(on bool) {
	content := ""
	if on {
		content = storeLockRule
	}
	if changed, err := writeOrRemove(storeReadOnly, content, 0o644); err != nil {
		a.event("store lock: %v", err)
	} else if changed {
		a.event("software stores read only: %v", on)
	}
}

// cacheCatalogIcons fetches app icons for the desktop app (readable by users).
func (a *Agent) cacheCatalogIcons(c *api.Catalog) {
	if err := os.MkdirAll(catalogIconsDir, 0o755); err != nil { //nolint:gosec // icons are read by the user's desktop app
		return
	}
	_ = os.Chmod(catalogIconsDir, 0o755) //nolint:gosec // see above
	for _, app := range c.Apps {
		if app.IconHash == "" {
			continue
		}
		f := catalogIconsDir + "/" + app.ID + ".png"
		stamp := f + "." + app.IconHash[:12]
		if exists(stamp) {
			continue
		}
		var png []byte
		if err := a.getBytes("/api/v1/catalog/icons/"+app.ID, 512<<10, &png); err != nil {
			continue
		}
		if _, err := writeIfChanged(f, string(png), 0o644); err == nil {
			_ = os.WriteFile(stamp, nil, 0o644) //nolint:gosec // marker next to a public icon
		}
	}
}

// ---- desktop socket operations ----

// DesktopApp is a catalog entry as the desktop app shows it.
type DesktopApp struct {
	api.CatalogApp
	Installed bool   `json:"installed"`
	Via       string `json:"via,omitempty"`
	Busy      string `json:"busy,omitempty"` // install | remove while running
	Error     string `json:"error,omitempty"`
	Icon      string `json:"icon,omitempty"` // cached icon file
}

func (a *Agent) desktopCatalog(flatpaks []api.FlatpakApp) []DesktopApp {
	c := a.state.Catalog
	if c == nil {
		return nil
	}
	fl := installedFlatpaks(flatpaks)
	out := make([]DesktopApp, 0, len(c.Apps))
	for _, app := range c.Apps {
		st := a.appState(app, fl)
		d := DesktopApp{CatalogApp: app, Installed: st.Installed, Via: st.Via, Error: st.Error}
		if f := catalogIconsDir + "/" + app.ID + ".png"; exists(f) {
			d.Icon = f
		}
		out = append(out, d)
	}
	return out
}

// storeAction runs an install, removal or request a user asked for.
func (a *Agent) storeAction(op, id, user, note string) DesktopResponse {
	app, ok := a.catalogApp(id)
	if !ok {
		return DesktopResponse{Error: "not in the catalog"}
	}
	switch op {
	case "request":
		if app.Mode != api.AppOnRequest {
			return DesktopResponse{Error: "this app needs no request"}
		}
		a.evMu.Lock()
		if !slices.ContainsFunc(a.state.AppRequests, func(r api.AppRequest) bool { return r.App == id }) {
			a.state.AppRequests = append(a.state.AppRequests, api.AppRequest{App: id, User: user, Note: truncateString(note, 500)})
		}
		a.evMu.Unlock()
		a.kickCheckin()
		return DesktopResponse{OK: true}
	case "install":
		if app.Mode == api.AppOnRequest && app.Request != "approved" {
			return DesktopResponse{Error: "this app needs approval by IT"}
		}
	case "remove":
		if app.Mode != api.AppAvailable {
			return DesktopResponse{Error: "IT manages this app"}
		}
	default:
		return DesktopResponse{Error: "unknown operation"}
	}
	if !a.store.start(id, op) {
		return DesktopResponse{Error: "already in progress"}
	}
	go func() {
		accts, _ := nssAccounts()
		apps, _ := flatpakInventory(accts)
		var err error
		if op == "install" {
			err = a.installApp(app)
		} else {
			err = a.removeApp(app, installedFlatpaks(apps))
		}
		a.store.finish(id, err)
		if err != nil {
			a.event("%s of %s requested by %s failed: %v", op, app.Name, user, err)
		} else {
			a.event("%s of %s requested by %s", op, app.Name, user)
		}
		a.kickCheckin() // report the new state
	}()
	return DesktopResponse{OK: true}
}

func (a *Agent) kickCheckin() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// flathubFilterContent allows runtimes and the catalog's apps, nothing else.
func flathubFilterContent(ids []string) string {
	var b strings.Builder
	b.WriteString("# Managed by LiMDM: Flathub offers only the software catalog.\ndeny *\nallow runtime/*\n")
	ids = slices.Clone(ids)
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		b.WriteString("allow app/" + id + "\n")
	}
	return b.String()
}
