package api

import (
	"fmt"
	"regexp"
	"strings"
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
	// Signature is the command key's signature over CatalogAppSigned.
	Signature string `json:"signature,omitempty"`
}

// AppSource is a way to install an app.
type AppSource struct {
	Kind    string `json:"kind"`              // flatpak | package
	Flatpak string `json:"flatpak,omitempty"` // application ID
	Remote  string `json:"remote,omitempty"`  // Flatpak remote, flathub when empty
	Debian  string `json:"debian,omitempty"`  // package name(s), space separated
	Fedora  string `json:"fedora,omitempty"`
	// Repos are vendor package repositories the packages come from, at
	// most one per family; the agent adds it before installing.
	Repos []Repository `json:"repos,omitempty"`
}

// Catalog is what a device receives in the check in.
type Catalog struct {
	Apps []CatalogApp `json:"apps"`
	// RestrictFlathub limits every remote marked CatalogOnly (Flathub by
	// default) to the catalog's apps with a remote filter.
	RestrictFlathub    bool            `json:"restrict_flathub"`
	StoresReadOnly     bool            `json:"stores_read_only"` // GNOME Software and KDE Discover cannot install
	Remotes            []CatalogRemote `json:"remotes,omitempty"`
	OnlyManagedRemotes bool            `json:"only_managed_remotes,omitempty"` // other remotes are disabled, also users'
	Requests           []RequestState  `json:"requests,omitempty"`             // this device's requests for apps outside the catalog
	Hash               string          `json:"hash"`
}

// CatalogRemote is a Flatpak remote IT manages for all devices.
type CatalogRemote struct {
	Name        string `json:"name"`
	URL         string `json:"url"` // .flatpakrepo file, repository or oci+https URL
	Title       string `json:"title,omitempty"`
	State       string `json:"state"`               // allowed | blocked
	CatalogOnly bool   `json:"catalog_only"`        // with RestrictFlathub only catalog apps
	Signature   string `json:"signature,omitempty"` // command key signature over CatalogRemoteSigned
}

var remoteNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate checks a remote before it is stored.
func (r CatalogRemote) Validate() error {
	switch {
	case !remoteNameRe.MatchString(r.Name):
		return fmt.Errorf("remote name %q: letters, digits, dots, dashes", r.Name)
	// a blocked remote is matched by name and never used: an insecure one
	// (http, file) must be blockable
	case r.State != "blocked" && !strings.HasPrefix(r.URL, "https://") && !strings.HasPrefix(r.URL, "oci+https://"):
		return fmt.Errorf("remote %s: URL must start with https:// or oci+https://", r.Name)
	case len(r.URL) > 512 || strings.ContainsAny(r.URL, " \n\x00") || len(r.Title) > 80:
		return fmt.Errorf("remote %s: URL up to 512 characters without spaces, title up to 80", r.Name)
	case r.State != "allowed" && r.State != "blocked":
		return fmt.Errorf("remote %s: state is allowed or blocked", r.Name)
	}
	return nil
}

// RemoteOf is the remote a Flatpak source installs from.
func (s AppSource) RemoteOf() string {
	if s.Remote == "" {
		return "flathub"
	}
	return s.Remote
}

// AppRequest is a user's request, sent with the check in: for a catalog app
// in "request" mode (App), or for a Flatpak that is not in the catalog yet
// (Flatpak, Remote, Name).
type AppRequest struct {
	App     string `json:"app,omitempty"`
	Flatpak string `json:"flatpak,omitempty"`
	Remote  string `json:"remote,omitempty"`
	Name    string `json:"name,omitempty"`
	User    string `json:"user"`
	Note    string `json:"note,omitempty"`
}

// RequestState is a device's request for an app outside the catalog.
type RequestState struct {
	Flatpak string `json:"flatpak"`
	Name    string `json:"name"`
	Status  string `json:"status"`        // pending | approved | denied
	App     string `json:"app,omitempty"` // catalog app created on approval
}

// FlatpakHit is a search result for apps outside the catalog.
type FlatpakHit struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Summary   string `json:"summary,omitempty"`
	Remote    string `json:"remote"`
	Icon      string `json:"icon,omitempty"` // https URL on dl.flathub.org
	Category  string `json:"category,omitempty"`
	Developer string `json:"developer,omitempty"`
}

// ValidFlatpakID reports whether id is a Flatpak application ID.
func ValidFlatpakID(id string) bool { return flatpakIDRe.MatchString(id) }

// ValidRemoteName reports whether name is a Flatpak remote name.
func ValidRemoteName(name string) bool { return remoteNameRe.MatchString(name) }

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
			if s.Remote != "" && !remoteNameRe.MatchString(s.Remote) {
				return fmt.Errorf("app %s: invalid remote %q", a.ID, s.Remote)
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
			fams := map[string]bool{}
			for _, r := range s.Repos {
				if err := r.Validate(); err != nil {
					return fmt.Errorf("app %s: %w", a.ID, err)
				}
				if fams[r.Family] {
					return fmt.Errorf("app %s: one repository per family", a.ID)
				}
				fams[r.Family] = true
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

// Flatpaks returns the Flatpak IDs the catalog installs from a remote.
func (c Catalog) Flatpaks(remote string) []string {
	var ids []string
	for _, a := range c.Apps {
		for _, s := range a.Sources {
			if s.Kind == "flatpak" && s.RemoteOf() == remote {
				ids = append(ids, s.Flatpak)
			}
		}
	}
	return ids
}

// SoftwareStore is the store policy of a device (com.limdm.softwarestore).
type SoftwareStore struct {
	RestrictFlathub    bool `json:"restrict_flathub"`               // remotes marked catalog only offer only catalog apps
	StoresReadOnly     bool `json:"stores_read_only"`               // GNOME Software and KDE Discover cannot install
	OnlyManagedRemotes bool `json:"only_managed_remotes,omitempty"` // every other Flatpak remote is disabled
}
