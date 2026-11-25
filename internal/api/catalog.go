package api

import (
	"fmt"
	"regexp"
)

// Software catalog (self service). The console keeps a catalog of apps; the
// server sends each device the entries for its blueprints. Users install
// from the desktop app: it hands the agent an app ID, never a package name,
// and the agent installs only what the catalog allows. No user needs admin
// rights.

// App modes.
const (
	AppAvailable = "available" // users install and remove it themselves
	AppRequired  = "required"  // installed on every device that gets it
	AppOnRequest = "request"   // users ask, an admin approves in the console
)

// CatalogApp is one entry. Sources are tried in order; the first one usable
// on the device installs it. The app counts as installed when any source,
// or any name in Detect, is installed, whatever way it got there.
type CatalogApp struct {
	ID       string      `json:"id"` // slug, e.g. "firefox"
	Name     string      `json:"name"`
	Summary  string      `json:"summary,omitempty"`
	Category string      `json:"category,omitempty"`
	Mode     string      `json:"mode"`
	Sources  []AppSource `json:"sources"`
	Detect   []string    `json:"detect,omitempty"` // further package names that mean "installed" (firefox-esr, code)
	IconHash string      `json:"icon_hash,omitempty"`
	Request  string      `json:"request,omitempty"` // this device's request: pending | approved | denied
}

// AppSource is a way to install an app.
type AppSource struct {
	Kind    string `json:"kind"`              // flatpak | package
	Flatpak string `json:"flatpak,omitempty"` // application ID on Flathub
	Debian  string `json:"debian,omitempty"`  // package name(s), space separated
	Fedora  string `json:"fedora,omitempty"`
}

// Catalog is what a device receives in the check in.
type Catalog struct {
	Apps            []CatalogApp `json:"apps"`
	RestrictFlathub bool         `json:"restrict_flathub"` // Flathub only offers catalog apps (remote filter)
	StoresReadOnly  bool         `json:"stores_read_only"` // GNOME Software and KDE Discover cannot install
	Hash            string       `json:"hash"`
}

// AppRequest is a user's request for a "request" app, sent with the check in.
type AppRequest struct {
	App  string `json:"app"`
	User string `json:"user"`
	Note string `json:"note,omitempty"`
}

// AppState is the catalog state of one app on a device (inventory).
type AppState struct {
	ID        string `json:"id"`
	Installed bool   `json:"installed"`
	Via       string `json:"via,omitempty"` // flatpak | package
	Error     string `json:"error,omitempty"`
}

var (
	appIDRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	flatpakIDRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){2,}$`)
	pkgListRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]*( [a-z0-9][a-z0-9+._-]*)*$`)
)

// Validate checks an app before it is stored or installed.
func (a CatalogApp) Validate() error {
	switch {
	case !appIDRe.MatchString(a.ID):
		return fmt.Errorf("app id %q: lower case letters, digits and dashes", a.ID)
	case a.Name == "" || len(a.Name) > 80 || len(a.Summary) > 300 || len(a.Category) > 40:
		return fmt.Errorf("app %s: name up to 80, summary up to 300, category up to 40 characters", a.ID)
	case a.Mode != AppAvailable && a.Mode != AppRequired && a.Mode != AppOnRequest:
		return fmt.Errorf("app %s: mode is available, required or request", a.ID)
	case len(a.Sources) == 0:
		return fmt.Errorf("app %s: at least one source", a.ID)
	}
	for _, s := range a.Sources {
		switch s.Kind {
		case "flatpak":
			if !flatpakIDRe.MatchString(s.Flatpak) {
				return fmt.Errorf("app %s: invalid Flatpak ID %q", a.ID, s.Flatpak)
			}
		case "package":
			if s.Debian == "" && s.Fedora == "" {
				return fmt.Errorf("app %s: a package source needs a Debian or Fedora package", a.ID)
			}
			for _, p := range []string{s.Debian, s.Fedora} {
				if p != "" && !pkgListRe.MatchString(p) {
					return fmt.Errorf("app %s: invalid package list %q", a.ID, p)
				}
			}
		default:
			return fmt.Errorf("app %s: source kind is flatpak or package", a.ID)
		}
	}
	for _, d := range a.Detect {
		if !pkgListRe.MatchString(d) || len(d) > 64 {
			return fmt.Errorf("app %s: invalid detect name %q", a.ID, d)
		}
	}
	return nil
}

// Flatpaks returns the Flatpak IDs of the catalog, for the Flathub filter.
func (c Catalog) Flatpaks() []string {
	var ids []string
	for _, a := range c.Apps {
		for _, s := range a.Sources {
			if s.Kind == "flatpak" {
				ids = append(ids, s.Flatpak)
			}
		}
	}
	return ids
}

// SoftwareStore is the store policy of a device (com.limdm.softwarestore).
type SoftwareStore struct {
	RestrictFlathub bool `json:"restrict_flathub"` // Flathub offers only catalog apps
	StoresReadOnly  bool `json:"stores_read_only"` // GNOME Software and KDE Discover cannot install
}
