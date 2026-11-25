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
	changed := false
	var errs []error
	for name, content := range desired {
		c, err := writeIfChanged(filepath.Join(dir, name), content, 0o644) // public config and keys
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
}

func (a *Agent) applyRepositories(repos []api.Repository) error {
	keys, sources := map[string]string{}, map[string]string{}
	for _, r := range repos {
		if r.Family != a.host.family {
			continue
		}
		if a.host.family == "debian" {
			key := "limdm-" + r.Name + ".asc"
			keys[key] = r.Key
			sources["limdm-"+r.Name+".sources"] = managedHeader + "Types: deb\nURIs: " + r.URL + "\nSuites: " + r.Suites +
				"\nComponents: " + r.Components + "\nSigned-By: /etc/apt/keyrings/" + key + "\n"
		} else {
			key := "RPM-GPG-KEY-limdm-" + r.Name
			keys[key] = r.Key
			sources["limdm-"+r.Name+".repo"] = managedHeader + "[limdm-" + r.Name + "]\nname=" + r.Name + "\nbaseurl=" + r.URL +
				"\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=0\ngpgkey=file:///etc/pki/rpm-gpg/" + key + "\n"
		}
	}
	var c1, c2 bool
	var err1, err2 error
	if a.host.family == "debian" {
		c1, err1 = syncManaged("/etc/apt/keyrings", "limdm-", ".asc", keys, "limdm-osquery.asc")
		c2, err2 = syncManaged("/etc/apt/sources.list.d", "limdm-", ".sources", sources, "limdm-osquery.sources")
	} else {
		c1, err1 = syncManaged("/etc/pki/rpm-gpg", "RPM-GPG-KEY-limdm-", "", keys, "RPM-GPG-KEY-limdm-osquery")
		c2, err2 = syncManaged("/etc/yum.repos.d", "limdm-", ".repo", sources, "limdm-osquery.repo")
	}
	if c1 || c2 {
		a.host.aptUpdated = time.Time{} // refresh package lists with the new sources
		a.event("package sources updated")
	}
	return errors.Join(err1, err2)
}

func (a *Agent) applyCertificates(certs []api.Certificate) error {
	desired := map[string]string{}
	dir, ext, update := "/usr/local/share/ca-certificates", ".crt", "update-ca-certificates"
	if a.host.family != "debian" {
		dir, ext, update = "/etc/pki/ca-trust/source/anchors", ".pem", "update-ca-trust"
	}
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
		_, _ = sh("systemctl", "try-reload-or-restart", unit)
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
	_, err = sh("systemctl", "try-restart", "systemd-resolved")
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
		_, err = sh("systemctl", "restart", "systemd-timesyncd")
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

func (a *Agent) applyProxy(p *api.Proxy) error {
	var profile, envd, apt, dnf string
	if p != nil {
		var b, e strings.Builder
		b.WriteString(managedHeader)
		e.WriteString(managedHeader)
		for k, v := range map[string]string{"http_proxy": p.HTTP, "https_proxy": p.HTTPS, "no_proxy": p.NoProxy} {
			if v != "" {
				q := "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" // single quotes: no shell expansion
				fmt.Fprintf(&b, "export %s=%s\nexport %s=%s\n", k, q, strings.ToUpper(k), q)
				fmt.Fprintf(&e, "%s=%s\n%s=%s\n", k, v, strings.ToUpper(k), v)
			}
		}
		profile, envd = b.String(), e.String()
		if a.host.family == "debian" {
			apt = managedHeader
			if p.HTTP != "" {
				apt += fmt.Sprintf("Acquire::http::Proxy %q;\n", p.HTTP)
			}
			if p.HTTPS != "" {
				apt += fmt.Sprintf("Acquire::https::Proxy %q;\n", p.HTTPS)
			}
		} else if proxy := firstNonEmpty(p.HTTPS, p.HTTP); proxy != "" {
			dnf = managedHeader + "[main]\nproxy=" + proxy + "\n"
		}
	}
	_, e1 := writeOrRemove("/etc/profile.d/limdm-proxy.sh", profile, 0o644)
	_, e2 := writeOrRemove("/etc/environment.d/60-limdm-proxy.conf", envd, 0o644)
	var e3 error
	if a.host.family == "debian" {
		_, e3 = writeOrRemove("/etc/apt/apt.conf.d/60limdm-proxy", apt, 0o644)
	} else {
		_, e3 = writeOrRemove("/etc/dnf/libdnf5.conf.d/60-limdm-proxy.conf", dnf, 0o644)
	}
	return errors.Join(e1, e2, e3)
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
	for _, r := range f.Remotes {
		if _, err := run(5*time.Minute, "flatpak", "remote-add", "--system", "--if-not-exists", r.Name, r.URL); err != nil {
			errs = append(errs, err)
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
	var errs []error
	for _, sc := range scripts {
		if time.Since(a.state.ScriptRuns[sc.Name]) < time.Duration(sc.IntervalHours)*time.Hour {
			continue
		}
		a.state.ScriptRuns[sc.Name] = time.Now()
		out, err := runScript(sc.Body)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sc.Name, err))
			continue
		}
		a.event("script %s ran: %s", sc.Name, lastLines(out, 2))
	}
	return errors.Join(errs...)
}
