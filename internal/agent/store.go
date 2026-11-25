package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	storeReadOnly   = "/etc/polkit-1/rules.d/60-limdm-store-readonly.rules"
	catalogIconsDir = "/var/cache/limdm/catalog"
	searchIconsDir  = "/var/cache/limdm/search"
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

// installApp installs from the first source that works.
func (a *Agent) installApp(app api.CatalogApp) error {
	var errs []error
	for _, src := range app.Sources {
		switch src.Kind {
		case "flatpak":
			if err := a.ensureRemote(src.RemoteOf()); err != nil {
				errs = append(errs, err)
				continue
			}
			if _, err := flatpakCmd(nil, time.Hour, "install", "-y", "--noninteractive", src.RemoteOf(), src.Flatpak); err != nil {
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
			if err := a.setAppRepos(src, false); err != nil {
				errs = append(errs, fmt.Errorf("package source: %w", err))
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
			if err := a.setAppRepos(src, true); err != nil {
				a.event("removing the package source of %s: %v", app.Name, err)
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
	a.applyRemotes(c)
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

// applyRemotes manages Flatpak remotes in the system and in users'
// installations: allowed remotes exist and are enabled (system), blocked
// ones and, with OnlyManagedRemotes, unmanaged ones are disabled, and remotes
// marked catalog only get the catalog filter while RestrictFlathub is on.
// It runs every cycle, so a user's changes do not last.
func (a *Agent) applyRemotes(c *api.Catalog) {
	if !hasCmd("flatpak") {
		return
	}
	managed := map[string]api.CatalogRemote{}
	for _, r := range c.Remotes {
		managed[r.Name] = r
	}
	if len(c.Remotes) == 0 { // server before 0.10.1: Flathub, catalog only
		managed["flathub"] = api.CatalogRemote{Name: "flathub", URL: flathubURL, State: "allowed", CatalogOnly: true}
	}
	accts, _ := nssAccounts()
	installs := []*api.Account{nil}
	for _, u := range flatpakUsers(accts, false) {
		installs = append(installs, &u)
	}
	for _, inst := range installs {
		out, _ := flatpakCmd(inst, time.Minute, "remotes", "--show-disabled", "--columns=name,url,title,options")
		present := map[string]api.FlatpakRemoteInfo{}
		for _, r := range parseFlatpakRemotes(out, "") {
			present[r.Name] = r
		}
		for name, r := range present {
			m, ok := managed[name]
			switch {
			case ok && m.State == "blocked", !ok && c.OnlyManagedRemotes:
				if !r.Disabled {
					if _, err := flatpakCmd(inst, time.Minute, "remote-modify", "--disable", name); err == nil {
						a.event("disabled Flatpak remote %s (%s)", name, installName(inst))
					}
				}
			case ok && r.Disabled:
				if _, err := flatpakCmd(inst, time.Minute, "remote-modify", "--enable", name); err == nil {
					a.event("enabled Flatpak remote %s (%s)", name, installName(inst))
				}
			}
		}
		if inst == nil { // allowed remotes are set up system wide
			for name, m := range managed {
				if _, ok := present[name]; !ok && m.State == "allowed" {
					if _, err := flatpakCmd(nil, 5*time.Minute, "remote-add", "--if-not-exists", name, m.URL); err != nil {
						a.event("adding Flatpak remote %s failed: %v", name, err)
					} else {
						a.event("added Flatpak remote %s", name)
						present[name] = api.FlatpakRemoteInfo{Name: name}
					}
				}
			}
		}
		for name := range present {
			m := managed[name]
			file := "/etc/flatpak/limdm-" + name + ".filter"
			if c.RestrictFlathub && m.CatalogOnly && m.State == "allowed" {
				if _, err := writeIfChanged(file, flathubFilterContent(c.Flatpaks(name)), 0o644); err == nil {
					_, _ = flatpakCmd(inst, time.Minute, "remote-modify", "--filter="+file, name)
				}
			} else if exists(file) {
				_, _ = flatpakCmd(inst, time.Minute, "remote-modify", "--no-filter", name)
			}
		}
	}
	// filter files of remotes that no longer need one
	files, _ := filepath.Glob("/etc/flatpak/limdm-*.filter")
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "limdm-"), ".filter")
		if m := managed[name]; !c.RestrictFlathub || !m.CatalogOnly || m.State != "allowed" {
			_ = os.Remove(f)
		}
	}
}

func installName(inst *api.Account) string {
	if inst == nil {
		return "system"
	}
	return inst.Name
}

// ensureRemote makes the remote of a Flatpak source available system wide.
func (a *Agent) ensureRemote(name string) error {
	if !hasCmd("flatpak") {
		if err := a.host.install("flatpak"); err != nil {
			return err
		}
	}
	url := ""
	if c := a.state.Catalog; c != nil {
		for _, r := range c.Remotes {
			if r.Name == name {
				if r.State != "allowed" {
					return fmt.Errorf("remote %s is blocked", name)
				}
				url = r.URL
			}
		}
	}
	if url == "" && name == "flathub" {
		url = flathubURL
	}
	if url == "" {
		return fmt.Errorf("remote %s is not managed", name)
	}
	if _, err := flatpakCmd(nil, 5*time.Minute, "remote-add", "--if-not-exists", name, url); err != nil {
		return err
	}
	_, err := flatpakCmd(nil, time.Minute, "remote-modify", "--enable", name)
	return err
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
	// explicit chmod of both levels: the agent runs with UMask=0077, and the
	// desktop app reads the icons as the user
	if err := os.MkdirAll(catalogIconsDir, 0o755); err != nil { //nolint:gosec // icons are read by the user's desktop app
		return
	}
	_ = os.Chmod(brandingDir, 0o755)     //nolint:gosec // see above
	_ = os.Chmod(catalogIconsDir, 0o755) //nolint:gosec // see above
	for _, app := range c.Apps {
		if app.IconHash == "" {
			continue
		}
		f := catalogIconsDir + "/" + app.ID + ".png"
		stamp := f + "." + app.IconHash[:12]
		if exists(stamp) {
			_ = os.Chmod(f, 0o644) //nolint:gosec // repairs icons cached before the permission fix
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

// flathubFilterContent allows runtimes and the catalog's apps of a remote, nothing else.
func flathubFilterContent(ids []string) string {
	var b strings.Builder
	b.WriteString("# Managed by LiMDM: this remote offers only the software catalog.\ndeny *\nallow runtime/*\n")
	ids = slices.Clone(ids)
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		b.WriteString("allow app/" + id + "\n")
	}
	return b.String()
}

// ---- apps outside the catalog ----

// DesktopHit is a search result; Icon is a cached file the app can read.
type DesktopHit struct {
	api.FlatpakHit
	Icon string `json:"icon,omitempty"`
}

// searchApps asks the server (which asks Flathub) and caches the icons.
func (a *Agent) searchApps(q string) DesktopResponse {
	q = strings.TrimSpace(q)
	if len(q) < 2 || len(q) > 80 {
		return DesktopResponse{Error: "search: 2 to 80 characters"}
	}
	var body []byte
	if err := a.getBytes("/api/v1/catalog/search?q="+url.QueryEscape(q), 1<<20, &body); err != nil {
		return DesktopResponse{Error: "the server did not answer the search"}
	}
	var hits []api.FlatpakHit
	if err := json.Unmarshal(body, &hits); err != nil {
		return DesktopResponse{Error: "the server did not answer the search"}
	}
	if err := os.MkdirAll(searchIconsDir, 0o755); err == nil { //nolint:gosec // icons are read by the user's desktop app
		_ = os.Chmod(searchIconsDir, 0o755) //nolint:gosec // see above, the agent runs with UMask=0077
	}
	out := make([]DesktopHit, 0, len(hits))
	for _, h := range hits {
		if !api.ValidFlatpakID(h.ID) {
			continue
		}
		d := DesktopHit{FlatpakHit: h}
		if h.Icon != "" {
			f := searchIconsDir + "/" + h.ID + ".png"
			var png []byte
			if exists(f) {
				d.Icon = f
			} else if a.getBytes("/api/v1/catalog/flathub-icon?u="+url.QueryEscape(h.Icon), 512<<10, &png) == nil &&
				bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
				if _, err := writeIfChanged(f, string(png), 0o644); err == nil {
					d.Icon = f
				}
			}
		}
		out = append(out, d)
	}
	return DesktopResponse{OK: true, Hits: out}
}

// requestNewApp queues a request for an app outside the catalog; IT decides
// in the console.
func (a *Agent) requestNewApp(r api.AppRequest) DesktopResponse {
	if !api.ValidFlatpakID(r.Flatpak) || (r.Remote != "" && !api.ValidRemoteName(r.Remote)) {
		return DesktopResponse{Error: "invalid app"}
	}
	r.Name, r.Note = truncateString(strings.TrimSpace(r.Name), 80), truncateString(r.Note, 500)
	a.evMu.Lock()
	switch {
	case slices.ContainsFunc(a.state.AppRequests, func(q api.AppRequest) bool { return q.Flatpak == r.Flatpak }):
	case len(a.state.AppRequests) >= 20:
		a.evMu.Unlock()
		return DesktopResponse{Error: "too many open requests, wait for the next check in"}
	default:
		a.state.AppRequests = append(a.state.AppRequests, r)
	}
	a.evMu.Unlock()
	a.kickCheckin()
	return DesktopResponse{OK: true}
}

// withQueued adds requests not yet sent to the server as pending.
func (a *Agent) withQueued(reqs []api.RequestState) []api.RequestState {
	out := slices.Clone(reqs)
	a.evMu.Lock()
	defer a.evMu.Unlock()
	for _, q := range a.state.AppRequests {
		if q.Flatpak != "" && !slices.ContainsFunc(out, func(r api.RequestState) bool { return r.Flatpak == q.Flatpak }) {
			out = append(out, api.RequestState{Flatpak: q.Flatpak, Name: q.Name, Status: "pending"})
		}
	}
	return out
}
