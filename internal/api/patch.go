package api

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Patch management (docs/patching.md): update rules per source, update
// rings, the pending update list and the outcome of the last run per source.

// Update sources.
const (
	SourceOSSecurity = "os_security" // security updates of the distribution
	SourceOSAll      = "os_all"      // every update of the distribution
	SourceFlatpak    = "flatpak"     // system wide Flatpak apps and runtimes
	SourceThirdParty = "third_party" // vendor repositories (apt sources, dnf and zypper repos) other than the distribution's
)

// UpdateSources lists the sources in the order the agent runs them.
var UpdateSources = []string{SourceOSSecurity, SourceOSAll, SourceThirdParty, SourceFlatpak}

// UpdateRule is the policy of one update source. Window and Days default
// to the declaration's. With Rings the agent installs only once a new wave
// of its update ring is open (UpdateGate).
type UpdateRule struct {
	Source string   `json:"source"`
	Mode   string   `json:"mode"` // off | notify | install
	Window string   `json:"window,omitempty"`
	Days   []string `json:"days,omitempty"`
	Rings  bool     `json:"rings,omitempty"`
	// Repos limits third_party to these repositories: dnf and zypper repo
	// IDs, apt origins as apt-get prints them (shell glob). Empty is every
	// third party repository.
	Repos []string `json:"repos,omitempty"`
}

var repoPatternRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/*?+-]{0,99}$`)

func (r UpdateRule) validate(seen []string) error {
	if !slices.Contains(UpdateSources, r.Source) || slices.Contains(seen, r.Source) {
		return fmt.Errorf("rules: source %q must be one of os_security, os_all, third_party, flatpak (each once)", r.Source)
	}
	switch r.Mode {
	case "off", "notify", "install":
	default:
		return errors.New("rules: mode must be off, notify or install")
	}
	if r.Window != "" && !windowRe.MatchString(r.Window) {
		return errors.New("rules: window must be HH:MM-HH:MM")
	}
	if err := validDays(r.Days); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	if len(r.Repos) > 0 && r.Source != SourceThirdParty {
		return errors.New("rules: repos apply to third_party only")
	}
	if len(r.Repos) > 50 {
		return errors.New("rules: at most 50 repos")
	}
	for _, p := range r.Repos {
		if !repoPatternRe.MatchString(p) {
			return fmt.Errorf("rules: invalid repo %q", p)
		}
	}
	return nil
}

func validDays(days []string) error {
	for i, d := range days {
		if !slices.Contains(Weekdays, d) || slices.Contains(days[:i], d) {
			return fmt.Errorf("days: %q is not one of mon, tue, wed, thu, fri, sat, sun (each once)", d)
		}
	}
	return nil
}

// EffectiveRules are the rules the agent follows. Without rules the mode
// maps to them: security installs OS security updates, all installs every
// source (what "all" always did: apt and dnf upgrade every repository, and
// Flatpak). Empty windows and days are the declaration's.
func (u Updates) EffectiveRules() []UpdateRule {
	rules := u.Rules
	if len(rules) == 0 {
		switch u.Mode {
		case "security":
			rules = []UpdateRule{{Source: SourceOSSecurity, Mode: "install"}}
		case "all":
			rules = []UpdateRule{{Source: SourceOSAll, Mode: "install"}, {Source: SourceThirdParty, Mode: "install"}, {Source: SourceFlatpak, Mode: "install"}}
		}
	}
	out := make([]UpdateRule, 0, len(rules))
	for _, s := range UpdateSources { // run order
		for _, r := range rules {
			if r.Source == s {
				if r.Window == "" {
					r.Window, r.Days = u.Window, firstNonNil(r.Days, u.Days)
				}
				out = append(out, r)
			}
		}
	}
	return out
}

func firstNonNil(a, b []string) []string {
	if a != nil {
		return a
	}
	return b
}

// Installs reports whether a rule installs OS updates (the check
// updates.auto).
func (u Updates) Installs() bool {
	for _, r := range u.EffectiveRules() {
		if r.Mode == "install" && (r.Source == SourceOSSecurity || r.Source == SourceOSAll) {
			return true
		}
	}
	return false
}

// UpdateGate is the server's answer for the device's update ring: Open
// while the ring is not paused, Wave counts the waves that reached it. A
// rule with Rings installs once per wave. No gate (nil) means the device is
// in no ring and installs in every window.
type UpdateGate struct {
	Ring string `json:"ring"`
	Wave int    `json:"wave"`
	Open bool   `json:"open"`
}

// PendingUpdate is one available update as the device's package manager
// reports it.
type PendingUpdate struct {
	Name      string   `json:"name"`
	Current   string   `json:"current,omitempty"`
	Candidate string   `json:"candidate"`
	Origin    string   `json:"origin,omitempty"` // apt origin, dnf or zypper repo ID, Flatpak remote
	Source    string   `json:"source"`           // os_all | third_party | flatpak (os_all includes security updates)
	Security  bool     `json:"security,omitempty"`
	Severity  string   `json:"severity,omitempty"` // as the advisory states it (Important, moderate …)
	CVEs      []string `json:"cves,omitempty"`
	Patch     bool     `json:"patch,omitempty"` // a zypper patch, not a package
}

// UpdateRun is the outcome of the last run of one source.
type UpdateRun struct {
	Source string    `json:"source"`
	At     time.Time `json:"at"`
	Result string    `json:"result"` // installed | no_updates | failed | unsupported
	Count  int       `json:"count,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Wave   int       `json:"wave,omitempty"` // ring wave the run belonged to
}

// UpdateStatus is the patch part of the status report.
type UpdateStatus struct {
	Pending      []PendingUpdate `json:"pending"`
	PendingError string          `json:"pending_error,omitempty"`
	Runs         []UpdateRun     `json:"runs,omitempty"`
	Ring         string          `json:"ring,omitempty"`
	// SecuritySince is when security updates were first seen pending
	// without a break (the check updates.security_age).
	SecuritySince *time.Time `json:"security_since,omitempty"`
}

// PackageHold is the payload of package_hold: keep a package at its
// installed version, or release it again.
type PackageHold struct {
	Name    string `json:"name"`
	Release bool   `json:"release,omitempty"`
}

// PackageDowngrade is the payload of package_downgrade. An empty version
// takes the highest available one below the installed version.
type PackageDowngrade struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

var pkgVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)

func (p PackageHold) Validate() error {
	if !pkgNameRe.MatchString(p.Name) {
		return errors.New("invalid package name")
	}
	return nil
}

func (p PackageDowngrade) Validate() error {
	if !pkgNameRe.MatchString(p.Name) {
		return errors.New("invalid package name")
	}
	if p.Version != "" && !pkgVersionRe.MatchString(p.Version) {
		return errors.New("invalid version")
	}
	return nil
}

func sourcesOf(rules []UpdateRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Source
	}
	return out
}
