package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// syncManaged makes dir contain exactly the desired files among those matching
// prefix*suffix: missing ones are written, stale ones removed. keep lists names
// owned by other parts of the agent (e.g. the osquery repository).
func syncManaged(dir, prefix, suffix string, desired map[string]string, keep ...string) (bool, error) {
	return syncManagedMode(dir, prefix, suffix, 0o644, desired, keep...) // public config and keys
}

// syncManagedMode is syncManaged with the file mode of the written files.
func syncManagedMode(dir, prefix, suffix string, mode os.FileMode, desired map[string]string, keep ...string) (bool, error) {
	changed := false
	var errs []error
	for name, content := range desired {
		c, err := writeIfChanged(filepath.Join(dir, name), content, mode)
		changed = changed || c
		errs = append(errs, err)
	}
	existing, _ := filepath.Glob(filepath.Join(dir, prefix+"*"+suffix))
	for _, f := range existing {
		base := filepath.Base(f)
		if _, ok := desired[base]; ok || slices.Contains(keep, base) {
			continue
		}
		errs = append(errs, os.Remove(f))
		changed = true
	}
	return changed, errors.Join(errs...)
}

// writeOrRemove keeps a single managed drop-in in sync with content ("" removes it).
func writeOrRemove(path, content string, mode os.FileMode) (bool, error) {
	if content == "" {
		if err := os.Remove(path); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
		return false, nil
	}
	return writeIfChanged(path, content, mode)
}

func (a *Agent) applyExtra() {
	x := a.pol.Extra
	run := func(typ string, err error) {
		if err != nil {
			a.problem(typ, "%s: %v", strings.TrimPrefix(typ, "com.limdm."), err)
		}
	}
	run(api.TypeRepositories, a.applyRepositories(x.Repositories))
	run(api.TypeRepositories, a.applyRepoDisable(x.RepoDisable))
	run(api.TypeCertificates, a.applyCertificates(x.Certificates))
	run(api.TypeSysctl, applySysctlCustom(x.Sysctl))
	run(api.TypeKernelModules, applyModulesCustom(x.KernelModules))
	run(api.TypeSSH, applySSHCustom(x.SSH))
	run(api.TypeBanner, applyBanner(x.Banner))
	run(api.TypeDNS, applyDNS(x.DNS))
	run(api.TypeNTP, applyNTP(x.NTP))
	run(api.TypeProxy, a.applyProxy(x.Proxy))
	run(api.TypeFlatpak, a.applyFlatpak(x.Flatpak))
	run(api.TypeScripts, a.applyScripts(x.Scripts))
	run(api.TypeDconf, applyDconf(x.Dconf))
	run(api.TypePolkit, applyPolkit(x.Polkit))
	run(api.TypeSudo, applySudo(x.Sudo))
	run(api.TypeBootloader, a.applyBootloader(x.Bootloader))
	run(api.TypeNetwork, a.applyNetwork(x.Network))
	run(api.TypePrinters, a.applyPrinters(x.Printers))
	run(api.TypeArtifacts, a.applyArtifacts(x.Artifacts))
	run(api.TypeHostname, a.applyHostname(x.Hostname))
	a.ensureDependencies()
	a.notifyEscrow()
}

// repoFiles renders a repository for this host's family: key file name and
// content (none with KeyFile) and source file name and content. prefix is
// limdm- for declarations and limdm-app- for catalog apps.
func (h *host) repoFiles(prefix string, r api.Repository) (keyName, key, srcName, src string) {
	if h.family == "debian" {
		keyPath := r.KeyFile
		if keyPath == "" {
			keyName, key = prefix+r.Name+".asc", r.Key
			keyPath = "/etc/apt/keyrings/" + keyName
		}
		return keyName, key, prefix + r.Name + ".sources", managedHeader + "Types: deb\nURIs: " + r.URL + "\nSuites: " + r.Suites +
			"\nComponents: " + r.Components + "\nSigned-By: " + keyPath + "\n"
	}
	keyPath := r.KeyFile
	if keyPath == "" {
		keyName, key = "RPM-GPG-KEY-"+prefix+r.Name, r.Key
		keyPath = "/etc/pki/rpm-gpg/" + keyName
	}
	check := "gpgcheck=1\nrepo_gpgcheck=0"
	if r.SignedMetadata {
		check = "gpgcheck=0\nrepo_gpgcheck=1"
	}
	if h.family == "suse" {
		check += "\nautorefresh=1\ntype=rpm-md"
	}
	return keyName, key, prefix + r.Name + ".repo", managedHeader + "[" + prefix + r.Name + "]\nname=" + r.Name + "\nbaseurl=" + r.URL +
		"\nenabled=1\n" + check + "\ngpgkey=file://" + keyPath + "\n"
}

// repoDirs are the key and source directories of this host's family.
func (h *host) repoDirs() (keyDir, srcDir string) {
	if h.family == "debian" {
		return "/etc/apt/keyrings", "/etc/apt/sources.list.d"
	}
	if h.family == "suse" {
		return "/etc/pki/rpm-gpg", "/etc/zypp/repos.d"
	}
	return "/etc/pki/rpm-gpg", "/etc/yum.repos.d"
}

func (a *Agent) applyRepositories(repos []api.Repository) error {
	keys, sources := map[string]string{}, map[string]string{}
	for _, r := range repos {
		if r.Family != a.host.family {
			continue
		}
		kn, k, sn, src := a.host.repoFiles("limdm-", r)
		if kn != "" {
			keys[kn] = k
		}
		sources[sn] = src
	}
	keyDir, srcDir := a.host.repoDirs()
	// osquery's source and catalog app sources have their own owners
	keyKeep, srcKeep := appRepoFiles(keyDir), appRepoFiles(srcDir)
	var c1, c2 bool
	var err1, err2 error
	if a.host.family == "debian" {
		c1, err1 = syncManaged(keyDir, "limdm-", ".asc", keys, append(keyKeep, "limdm-osquery.asc")...)
		c2, err2 = syncManaged(srcDir, "limdm-", ".sources", sources, append(srcKeep, "limdm-osquery.sources")...)
	} else {
		c1, err1 = syncManaged(keyDir, "RPM-GPG-KEY-limdm-", "", keys, append(keyKeep, "RPM-GPG-KEY-limdm-osquery")...)
		c2, err2 = syncManaged(srcDir, "limdm-", ".repo", sources, append(srcKeep, "limdm-osquery.repo")...)
	}
	var err3 error
	if c1 {
		var paths []string
		for kn := range keys {
			paths = append(paths, filepath.Join(keyDir, kn))
		}
		err3 = a.host.trustKeys(paths...)
	}
	if c1 || c2 {
		a.host.aptStale.Store(true) // refresh package lists with the new sources
		a.event("package sources updated")
	}
	return errors.Join(err1, err2, err3)
}

// appRepoFiles lists the catalog apps' repository files in dir.
func appRepoFiles(dir string) []string {
	var names []string
	for _, pat := range []string{"limdm-app-*", "RPM-GPG-KEY-limdm-app-*"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, f := range m {
			names = append(names, filepath.Base(f))
		}
	}
	return names
}

// setAppRepos adds (or with remove, deletes) the vendor repository of a
// catalog app's package source for this host.
func (a *Agent) setAppRepos(src api.AppSource, remove bool) error {
	keyDir, srcDir := a.host.repoDirs()
	var errs []error
	for _, r := range src.Repos {
		// the catalog has Debian and Fedora sources; an rpm-md repository works with zypper too
		if r.Family != a.host.family && (r.Family != "fedora" || a.host.family != "suse") {
			continue
		}
		kn, k, sn, s := a.host.repoFiles("limdm-app-", r)
		if remove {
			k, s = "", ""
		}
		if kn != "" {
			c, err := writeOrRemove(filepath.Join(keyDir, kn), k, 0o644)
			errs = append(errs, err)
			if c && !remove {
				errs = append(errs, a.host.trustKeys(filepath.Join(keyDir, kn)))
			}
		}
		c, err := writeOrRemove(filepath.Join(srcDir, sn), s, 0o644)
		errs = append(errs, err)
		if c && !remove {
			a.host.aptStale.Store(true)
			a.event("added package source %s", r.Name)
		}
	}
	return errors.Join(errs...)
}

// caAnchors is where this family keeps local CA certificates and the
// command that rebuilds the trust store.
func (h *host) caAnchors() (dir, ext, update string) {
	switch h.family {
	case "fedora":
		return "/etc/pki/ca-trust/source/anchors", ".pem", "update-ca-trust"
	case "suse":
		return "/etc/pki/trust/anchors", ".pem", "update-ca-certificates"
	case "arch":
		return "/etc/ca-certificates/trust-source/anchors", ".crt", "update-ca-trust"
	}
	return "/usr/local/share/ca-certificates", ".crt", "update-ca-certificates" // Debian family, Alpine
}

func (a *Agent) applyCertificates(certs []api.Certificate) error {
	desired := map[string]string{}
	dir, ext, update := a.host.caAnchors()
	for _, c := range certs {
		desired["limdm-"+c.Name+ext] = strings.TrimSpace(c.PEM) + "\n"
	}
	changed, err := syncManaged(dir, "limdm-", ext, desired)
	if err != nil || !changed {
		return err
	}
	if _, err := sh(update); err != nil {
		return err
	}
	a.event("trusted CA certificates updated (%d managed)", len(certs))
	return nil
}

func applySysctlCustom(set map[string]string) error {
	const f = "/etc/sysctl.d/70-limdm-custom.conf"
	content := ""
	if len(set) > 0 {
		var b strings.Builder
		b.WriteString(managedHeader)
		for _, k := range sortedKeys(set) {
			fmt.Fprintf(&b, "%s = %s\n", k, set[k])
		}
		content = b.String()
	}
	changed, err := writeOrRemove(f, content, 0o644)
	if err != nil || !changed || content == "" {
		return err
	}
	_, err = sh("sysctl", "-q", "-e", "-p", f)
	return err
}

func applyModulesCustom(mods []string) error {
	content := ""
	if len(mods) > 0 {
		var b strings.Builder
		b.WriteString(managedHeader)
		for _, m := range slices.Sorted(slices.Values(mods)) {
			fmt.Fprintf(&b, "install %s /bin/false\nblacklist %s\n", m, m)
		}
		content = b.String()
	}
	_, err := writeOrRemove("/etc/modprobe.d/70-limdm-custom.conf", content, 0o644)
	return err
}

// applySSHCustom adds allowed sshd options after the compliance drop-in
// (sshd keeps the first value, so the baseline cannot be overridden).
func applySSHCustom(opts map[string]string) error {
	bin := sshdBinary()
	if bin == "" {
		if len(opts) > 0 {
			return errors.New("no SSH server installed")
		}
		return nil
	}
	const f = "/etc/ssh/sshd_config.d/02-limdm-custom.conf"
	content := ""
	if len(opts) > 0 {
		var b strings.Builder
		b.WriteString(managedHeader)
		for _, k := range sortedKeys(opts) {
			fmt.Fprintf(&b, "%s %s\n", k, opts[k])
		}
		content = b.String()
	}
	old, readErr := os.ReadFile(f)
	changed, err := writeOrRemove(f, content, 0o600)
	if err != nil || !changed {
		return err
	}
	if _, err := sh(bin, "-t"); err != nil {
		if readErr == nil {
			err = errors.Join(err, os.WriteFile(f, old, 0o600)) //nolint:gosec // constant path, restoring the previous file
		} else {
			err = errors.Join(err, os.Remove(f))
		}
		return err
	}
	for _, unit := range []string{"ssh", "sshd"} {
		_ = svc("reload-or-restart", unit)
	}
	return nil
}

func applyBanner(b *api.Banner) error {
	if b == nil {
		return nil
	}
	var errs []error
	if b.Issue != "" {
		text := strings.TrimRight(b.Issue, "\n") + "\n"
		_, e1 := writeIfChanged("/etc/issue", text, 0o644)
		_, e2 := writeIfChanged("/etc/issue.net", text, 0o644)
		errs = append(errs, e1, e2)
	}
	if b.Motd != "" {
		_, err := writeIfChanged("/etc/motd", strings.TrimRight(b.Motd, "\n")+"\n", 0o644)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func applyDNS(d *api.DNS) error {
	const f = "/etc/systemd/resolved.conf.d/60-limdm.conf"
	content := ""
	if d != nil {
		if !unitActive("systemd-resolved") {
			return errors.New("systemd-resolved is not active")
		}
		sec := "allow-downgrade"
		if d.DNSSEC {
			sec = "yes"
		}
		content = managedHeader + "[Resolve]\nDNS=" + strings.Join(d.Servers, " ") + "\nDomains=" + strings.Join(d.Domains, " ") + "\nDNSSEC=" + sec + "\n"
	}
	changed, err := writeOrRemove(f, content, 0o644)
	if err != nil || !changed {
		return err
	}
	err = svc("try-restart", "systemd-resolved")
	return err
}

func applyNTP(n *api.NTP) error {
	timesyncd := "/etc/systemd/timesyncd.conf.d/60-limdm.conf"
	chrony := "/etc/chrony/sources.d/limdm.sources"
	if n == nil {
		_, e1 := writeOrRemove(timesyncd, "", 0o644)
		_, e2 := writeOrRemove(chrony, "", 0o644)
		return errors.Join(e1, e2)
	}
	switch {
	case unitActive("systemd-timesyncd"):
		changed, err := writeIfChanged(timesyncd, managedHeader+"[Time]\nNTP="+strings.Join(n.Servers, " ")+"\n", 0o644)
		if err != nil || !changed {
			return err
		}
		err = svc("restart", "systemd-timesyncd")
		return err
	case exists("/etc/chrony/sources.d"):
		var b strings.Builder
		b.WriteString(managedHeader)
		for _, s := range n.Servers {
			fmt.Fprintf(&b, "server %s iburst\n", s)
		}
		changed, err := writeIfChanged(chrony, b.String(), 0o644)
		if err != nil || !changed {
			return err
		}
		_, err = sh("chronyc", "reload", "sources")
		return err
	}
	return errors.New("no supported time service (systemd-timesyncd, or chrony with /etc/chrony/sources.d)")
}

func (a *Agent) applyFlatpak(f *api.Flatpak) error {
	if f == nil || (len(f.Remotes) == 0 && len(f.Install) == 0 && len(f.Remove) == 0) {
		return nil
	}
	if !hasCmd("flatpak") {
		if err := a.host.install("flatpak"); err != nil {
			return err
		}
	}
	var errs []error
	sysRemotes, userRemotes := []api.FlatpakRemote{}, []api.FlatpakRemote{}
	for _, r := range f.Remotes {
		if r.InstallationScope() == "user" {
			userRemotes = append(userRemotes, r)
		} else {
			sysRemotes = append(sysRemotes, r)
		}
	}
	if len(sysRemotes) > 0 {
		out, _ := flatpakCmd(nil, time.Minute, "remotes", "--show-disabled", "--columns=name,url,title,options")
		existing := parseFlatpakRemotes(out, "system")
		for _, r := range sysRemotes {
			if err := applyRemote(nil, r, existing); err != nil {
				errs = append(errs, fmt.Errorf("remote %s: %w", r.Name, err))
			}
		}
	}
	if len(userRemotes) > 0 {
		accts, _ := nssAccounts()
		for _, u := range flatpakUsers(accts, true) {
			out, _ := flatpakCmd(&u, time.Minute, "remotes", "--show-disabled", "--columns=name,url,title,options")
			existing := parseFlatpakRemotes(out, u.Name)
			for _, r := range userRemotes {
				if err := applyRemote(&u, r, existing); err != nil {
					errs = append(errs, fmt.Errorf("remote %s for %s: %w", r.Name, u.Name, err))
				}
			}
		}
	}
	out, _ := sh("flatpak", "list", "--system", "--app", "--columns=application")
	installed := strings.Fields(out)
	for _, app := range f.Install {
		if !slices.Contains(installed, app) {
			if _, err := run(30*time.Minute, "flatpak", "install", "-y", "--system", "--noninteractive", app); err != nil {
				errs = append(errs, err)
			} else {
				a.event("installed flatpak %s", app)
			}
		}
	}
	for _, app := range f.Remove {
		if slices.Contains(installed, app) {
			if _, err := run(10*time.Minute, "flatpak", "uninstall", "-y", "--system", "--noninteractive", app); err != nil {
				errs = append(errs, err)
			} else {
				a.event("removed flatpak %s", app)
			}
		}
	}
	return errors.Join(errs...)
}

// applyScripts runs recurring scripts when due; devices must allow scripts.
func (a *Agent) applyScripts(scripts []api.Script) error {
	if len(scripts) == 0 {
		return nil
	}
	if !a.cfg.AllowScripts {
		return errors.New("scripts are disabled on this device (enroll with --allow-scripts)")
	}
	if a.state.ScriptRuns == nil {
		a.state.ScriptRuns = map[string]time.Time{}
	}
	if a.state.ScriptSums == nil {
		a.state.ScriptSums = map[string]string{}
	}
	var errs []error
	for _, sc := range scripts {
		now := time.Now().Round(0) // wall clock, suspend included
		sum := scriptSum(sc)
		if a.state.ScriptSums[sc.Name] == "" && !a.state.ScriptRuns[sc.Name].IsZero() {
			a.state.ScriptSums[sc.Name] = sum // ran before agents kept sums: not a change
		}
		if !scriptDue(sc, a.state.ScriptRuns[sc.Name], a.state.ScriptSums[sc.Name], sum, now, scriptJitter(a.cfg.DeviceID, sc)) {
			if _, seen := a.state.ScriptRuns[sc.Name]; !seen {
				a.state.ScriptRuns[sc.Name] = now // a new schedule waits for its next slot
			}
			continue
		}
		a.state.ScriptRuns[sc.Name], a.state.ScriptSums[sc.Name] = now, sum
		res, err := runScript(sc.Body, sc.Params, sc.TimeoutMinutes)
		res.Name = sc.Name
		if len(a.state.ScriptResults) >= 50 { // bounded while offline: the oldest go first
			a.state.ScriptResults = a.state.ScriptResults[1:]
		}
		a.state.ScriptResults = append(a.state.ScriptResults, res)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sc.Name, err))
		}
	}
	return errors.Join(errs...)
}
