package agent

import (
	"encoding/xml"
	"errors"
	"io"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// The pending update list: what the package managers already know, no
// extra downloads beyond their own metadata refresh. Security flags,
// severities and CVE IDs come from the distribution's advisories where the
// package manager has them (dnf updateinfo, zypper patches); apt knows only
// whether an update comes from a security archive.

const maxPending = 1000

// pendingList lists available updates; cached for an hour because it hits
// the mirrors.
func (h *host) pendingList() ([]api.PendingUpdate, error) {
	if time.Since(h.pending.at) < time.Hour {
		return h.pending.list, h.pending.err
	}
	list, err := h.fetchPending()
	if len(list) > maxPending {
		list = list[:maxPending]
	}
	h.pending = pendingCache{at: time.Now(), list: list, err: err}
	return list, err
}

// pendingUpdates counts the pending OS updates and the security updates
// among them. Rolling releases have no separate security channel: every
// pending update can carry security fixes.
func (h *host) pendingUpdates() (all, security int, err error) {
	list, err := h.pendingList()
	for _, p := range list {
		switch {
		case p.Source == api.SourceFlatpak:
		case p.Patch:
			security++ // SUSE: needed security patches
		default:
			all++
			if p.Security {
				security++
			}
		}
	}
	if h.family == "arch" || h.family == "alpine" || h.rolling() {
		security = all
	}
	return all, security, err
}

func (h *host) fetchPending() ([]api.PendingUpdate, error) {
	var list []api.PendingUpdate
	var err error
	switch h.family {
	case "arch":
		// checkupdates (pacman-contrib) uses its own database copy; pacman -Sy would
		// leave the system in a partial upgrade state
		if !hasCmd("checkupdates") {
			return nil, errors.New("checkupdates (pacman-contrib) missing")
		}
		out, cerr := run(10*time.Minute, "checkupdates")
		var ee *exec.ExitError
		if cerr != nil && (!errors.As(cerr, &ee) || ee.ExitCode() != 2) { // 2: nothing to update
			return nil, cerr
		}
		list = parseCheckupdates(out)
	case "alpine":
		if _, err = run(10*time.Minute, "apk", "update", "-q"); err != nil {
			return nil, err
		}
		out, verr := run(5*time.Minute, "apk", "version", "-l", "<")
		if verr != nil {
			return nil, verr
		}
		list = parseApkVersion(out)
	case "suse":
		list, err = h.zypperPending()
	case "debian":
		h.pkgMu.Lock()
		err = h.aptUpdate()
		h.pkgMu.Unlock()
		if err != nil {
			return nil, err
		}
		var out string
		if out, err = aptSim(aptUpgradeVerb()...); err != nil {
			return nil, err
		}
		list = parseAptPending(out, h.ID)
		if onPVE() { // on a Proxmox VE node its own repositories are the distribution's
			for i := range list {
				if strings.EqualFold(list[i].Origin, "proxmox") {
					list[i].Source = api.SourceOSAll
				}
			}
		}
	default:
		list, err = h.dnfPending()
	}
	if pkgs, _, perr := h.installedPackages(); perr == nil {
		installed := make(map[string]string, len(pkgs))
		for _, p := range pkgs {
			installed[p.Name] = p.Version
		}
		for i := range list {
			if list[i].Current == "" && !list[i].Patch {
				list[i].Current = installed[list[i].Name]
			}
		}
	}
	if err != nil {
		return list, err
	}
	return append(list, flatpakPending()...), nil
}

// aptDistroOrigins are the apt origins of the distributions themselves;
// every other origin is a third party repository. The host's os-release ID
// counts too (derivatives: pop, zorin, kali, neon, tuxedo), and so do the
// Launchpad PPAs elementary OS ships its own packages in.
var aptDistroOrigins = []string{"debian", "debian-security", "debian backports", "ubuntu", "ubuntuesm", "ubuntuesmapps", "raspbian", "raspberry pi foundation", "linuxmint"}

const elementaryPPA = "lp-ppa-elementary-os"

// parseAptPending reads apt-get -s upgrade: "Inst name [current]
// (candidate Origin:Version/Archive, Origin:… [arch])"; new packages have
// no current version.
func parseAptPending(out, osID string) []api.PendingUpdate {
	var list []api.PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "Inst ")
		if !ok {
			continue
		}
		name, rest, _ := strings.Cut(rest, " ")
		p := api.PendingUpdate{Name: name, Source: api.SourceOSAll}
		if cur, after, ok := strings.Cut(rest, "] "); ok && strings.HasPrefix(cur, "[") {
			p.Current, rest = strings.TrimPrefix(cur, "["), after
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")")
		if i := strings.LastIndex(inner, " ["); i >= 0 {
			inner = inner[:i]
		}
		p.Candidate, inner, _ = strings.Cut(inner, " ")
		origin, _, _ := strings.Cut(inner, ":")
		p.Origin = strings.TrimSpace(origin)
		p.Security = strings.Contains(strings.ToLower(inner), "-security")
		o := strings.ToLower(p.Origin)
		if !slices.Contains(aptDistroOrigins, o) && !strings.HasPrefix(o, elementaryPPA) && (osID == "" || !strings.HasPrefix(o, strings.ToLower(osID))) {
			p.Source = api.SourceThirdParty
		}
		list = append(list, p)
	}
	return list
}

// dnfDistroRepo reports whether a repo ID belongs to the distribution
// (Fedora, RHEL and its rebuilds); EPEL and vendor repos are third party.
func dnfDistroRepo(id string) bool {
	id = strings.ToLower(id)
	switch id {
	case "fedora", "updates", "updates-testing", "fedora-cisco-openh264", "baseos", "appstream", "extras", "crb", "powertools",
		"highavailability", "resilientstorage", "rt", "nfv", "sap", "saphana", "plus":
		return true
	}
	return strings.HasPrefix(id, "rhel-") || strings.HasPrefix(id, "fedora-") || strings.HasPrefix(id, "updates-") || oracleRepoRe.MatchString(id)
}

var oracleRepoRe = regexp.MustCompile(`^ol[0-9]+_`) // Oracle Linux: ol9_baseos_latest

func (h *host) dnfPending() ([]api.PendingUpdate, error) {
	// dnf check-update exits 100 when updates exist.
	out, err := run(10*time.Minute, "dnf", "-q", "check-update", "--refresh")
	var ee *exec.ExitError
	if err != nil && (!errors.As(err, &ee) || ee.ExitCode() != 100) {
		return nil, err
	}
	list := parseDnfCheckUpdate(out)
	sec, err := run(10*time.Minute, "dnf", "-q", "updateinfo", "list", "--security")
	if err != nil {
		return list, err
	}
	cves, _ := run(10*time.Minute, "dnf", "-q", "updateinfo", "list", "--security", "--with-cve") // optional
	markDnfSecurity(list, sec, cves)
	return list, nil
}

// parseDnfCheckUpdate reads "name.arch version repo" lines.
func parseDnfCheckUpdate(out string) []api.PendingUpdate {
	var list []api.PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || !strings.Contains(f[0], ".") || strings.HasSuffix(line, ":") {
			continue
		}
		name := f[0][:strings.LastIndex(f[0], ".")]
		p := api.PendingUpdate{Name: name, Candidate: f[1], Origin: f[2], Source: api.SourceOSAll}
		if !dnfDistroRepo(f[2]) {
			p.Source = api.SourceThirdParty
		}
		list = append(list, p)
	}
	return list
}

// advisoryRe matches the advisory ID that starts every package line of
// "dnf updateinfo list" (dnf4: ID, severity, package) and of dnf5's
// "advisory list" table (ID, type, severity, package, issued).
var advisoryRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z][A-Z0-9]*)*-[0-9]{4}[:-][0-9A-Za-z]+`) // FEDORA-, FEDORA-EPEL-, RHSA- …

// dnfAdvisoryLine splits an updateinfo line into ID, severity and package
// name (dnf4 "ID Important/Sec. nevra", dnf5 "ID security Important nevra issued").
func dnfAdvisoryLine(line string) (id, severity, name string, ok bool) {
	f := strings.Fields(line)
	if len(f) < 3 || !advisoryRe.MatchString(f[0]) {
		return "", "", "", false
	}
	nevra := f[2]
	severity = strings.TrimSuffix(f[1], "/Sec.")
	if len(f) >= 4 && f[1] == "security" {
		severity, nevra = f[2], f[3]
	}
	return f[0], severity, nevraName(nevra), true
}

// nevraName strips ".arch" and "-version-release" from a NEVRA.
func nevraName(nevra string) string {
	if i := strings.LastIndex(nevra, "."); i > 0 {
		nevra = nevra[:i]
	}
	for range 2 {
		if i := strings.LastIndex(nevra, "-"); i > 0 {
			nevra = nevra[:i]
		}
	}
	return nevra
}

func markDnfSecurity(list []api.PendingUpdate, sec, cves string) {
	idx := map[string]int{}
	for i, p := range list {
		idx[p.Name] = i
	}
	for _, line := range strings.Split(sec, "\n") {
		if _, sev, name, ok := dnfAdvisoryLine(line); ok {
			if i, found := idx[name]; found {
				list[i].Security = true
				if list[i].Severity == "" || severityRank(sev) > severityRank(list[i].Severity) {
					list[i].Severity = sev
				}
			}
		}
	}
	for _, line := range strings.Split(cves, "\n") {
		if id, _, name, ok := dnfAdvisoryLine(line); ok && strings.HasPrefix(id, "CVE-") {
			if i, found := idx[name]; found && !slices.Contains(list[i].CVEs, id) && len(list[i].CVEs) < 50 {
				list[i].CVEs = append(list[i].CVEs, id)
			}
		}
	}
}

// severityRank orders the severities of Red Hat, Fedora and SUSE advisories.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "important":
		return 3
	case "moderate":
		return 2
	case "low":
		return 1
	}
	return 0
}

// parseCheckupdates reads "name current -> candidate".
func parseCheckupdates(out string) []api.PendingUpdate {
	var list []api.PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[2] == "->" {
			list = append(list, api.PendingUpdate{Name: f[0], Current: f[1], Candidate: f[3], Source: api.SourceOSAll})
		}
	}
	return list
}

// parseApkVersion reads "name-version-rN < candidate" after a header line.
func parseApkVersion(out string) []api.PendingUpdate {
	var list []api.PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "<" {
			continue
		}
		p, _ := parseApkInfo(f[0], nil)
		if len(p) == 1 {
			list = append(list, api.PendingUpdate{Name: p[0].Name, Current: p[0].Version, Candidate: f[2], Source: api.SourceOSAll})
		}
	}
	return list
}

// flatpakPending lists updates of system wide Flatpaks; the remote's
// summary is all it fetches.
func flatpakPending() []api.PendingUpdate {
	if !hasCmd("flatpak") {
		return nil
	}
	out, err := run(5*time.Minute, "flatpak", "remote-ls", "--updates", "--system", "--columns=application,version,origin")
	if err != nil {
		return nil
	}
	var list []api.PendingUpdate
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := flatpakColumns(line, 3); f[0] != "" && f[0] != "Application ID" {
			list = append(list, api.PendingUpdate{Name: f[0], Candidate: f[1], Origin: f[2], Source: api.SourceFlatpak})
		}
	}
	return list
}

// zypperDistroRepo: the repositories of openSUSE and SUSE themselves;
// OBS home and project repositories and vendor repositories are third party.
func zypperDistroRepo(alias, url string) bool {
	if strings.Contains(url, "/repositories/") {
		return false
	}
	a := strings.ToLower(alias)
	for _, p := range []string{"repo-", "opensuse", "sle", "suse", "basesystem", "server-applications", "desktop-applications"} {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return strings.Contains(url, "download.opensuse.org") || strings.Contains(url, "cdn.opensuse.org") || strings.Contains(url, "updates.suse.com")
}

func (h *host) zypperPending() ([]api.PendingUpdate, error) {
	args := []string{"--xmlout", "list-updates"}
	if h.rolling() {
		args = append(args, "--dup")
	}
	out, err := zypper(10*time.Minute, args...)
	if err != nil {
		return nil, err
	}
	list, err := parseZypperUpdates(out)
	if err != nil || h.rolling() {
		return list, err // rolling release: no patches
	}
	out, err = zypper(10*time.Minute, "--xmlout", "list-patches", "--category", "security")
	if err != nil {
		return list, err
	}
	patches, err := parseZypperUpdates(out)
	return append(list, patches...), err
}

// parseZypperUpdates reads the <update> elements of zypper's XML output:
// packages of list-updates, patches of list-patches (with severity and the
// CVE IDs of their issue list).
func parseZypperUpdates(out string) ([]api.PendingUpdate, error) {
	d := xml.NewDecoder(strings.NewReader(out))
	var list []api.PendingUpdate
	var cur *api.PendingUpdate
	for {
		t, err := d.Token()
		if errors.Is(err, io.EOF) {
			return list, nil
		}
		if err != nil {
			return list, err
		}
		switch se := t.(type) {
		case xml.StartElement:
			attr := func(n string) string {
				for _, a := range se.Attr {
					if a.Name.Local == n {
						return a.Value
					}
				}
				return ""
			}
			switch se.Name.Local {
			case "update":
				list = append(list, api.PendingUpdate{Name: attr("name"), Current: attr("edition-old"), Candidate: attr("edition"), Source: api.SourceOSAll})
				cur = &list[len(list)-1]
				if attr("kind") == "patch" {
					cur.Patch, cur.Security, cur.Severity = true, attr("category") == "security", attr("severity")
				}
			case "source":
				if cur != nil {
					cur.Origin = attr("alias")
					if !zypperDistroRepo(cur.Origin, attr("url")) {
						cur.Source = api.SourceThirdParty
					}
				}
			case "issue":
				if id := attr("id"); cur != nil && attr("type") == "cve" && id != "" && len(cur.CVEs) < 50 {
					if !strings.HasPrefix(id, "CVE-") {
						id = "CVE-" + id
					}
					cur.CVEs = append(cur.CVEs, id)
				}
			}
		case xml.EndElement:
			if se.Name.Local == "update" {
				cur = nil
			}
		}
	}
}

// matchRepo reports whether origin matches one of the patterns (shell
// glob); no patterns match everything.
func matchRepo(patterns []string, origin string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := path.Match(p, origin); ok || p == origin {
			return true
		}
	}
	return false
}

// sourceName is the source package of a Debian package ("openssl", or
// "glibc (2.36-9)" as osquery shows it), empty when it is the package itself.
func sourceName(name, source string) string {
	source, _, _ = strings.Cut(strings.TrimSpace(source), " ")
	if source == name {
		return ""
	}
	return source
}

// sourceVersion is the version of a Debian package's source when it
// differs from the package's own version: dpkg's ${source:Version}, or the
// "(278+deb13u1)" osquery shows after the source name.
func sourceVersion(version, source, srcVersion string) string {
	if srcVersion == "" {
		if _, v, ok := strings.Cut(strings.TrimSpace(source), " ("); ok {
			srcVersion = strings.TrimSuffix(v, ")")
		}
	}
	if srcVersion = strings.TrimSpace(srcVersion); srcVersion == version {
		return ""
	}
	return srcVersion
}
