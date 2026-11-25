package agent

import (
	"os/exec"
	"strings"
	"time"
)

// The agent does not rely on what a device happens to have installed: the
// packages declare the core tools as dependencies, and every day the agent
// installs whatever is missing (a package may have been removed, or the
// agent was installed from the tarball). Desktop tools are only installed on
// devices with a desktop.

type dependency struct {
	cmd            string // program the agent calls
	debian, fedora string // package providing it
	desktop        bool   // only on devices with a desktop
}

var dependencies = []dependency{
	{cmd: "cryptsetup", debian: "cryptsetup-bin", fedora: "cryptsetup"},
	{cmd: "findmnt", debian: "util-linux", fedora: "util-linux"},
	{cmd: "lsblk", debian: "util-linux", fedora: "util-linux"},
	{cmd: "runuser", debian: "util-linux", fedora: "util-linux"},
	{cmd: "ip", debian: "iproute2", fedora: "iproute"},
	{cmd: "sysctl", debian: "procps", fedora: "procps-ng"},
	{cmd: "modprobe", debian: "kmod", fedora: "kmod"},
	{cmd: "gpg", debian: "gpg", fedora: "gnupg2"},
	{cmd: "nft", debian: "nftables", fedora: "nftables"},
	{cmd: "auditctl", debian: "auditd", fedora: "audit"},
	{cmd: "notify-send", debian: "libnotify-bin", fedora: "libnotify", desktop: true},
	{cmd: "dconf", debian: "dconf-cli", fedora: "dconf", desktop: true},
}

var depsChecked time.Time

// missingPackages lists the packages to install for absent tools.
func missingPackages(family string, desktopPresent, kde bool, has func(string) bool) []string {
	var pkgs []string
	add := func(p string) {
		for _, x := range pkgs {
			if x == p {
				return
			}
		}
		pkgs = append(pkgs, p)
	}
	for _, d := range dependencies {
		if (d.desktop && !desktopPresent) || has(d.cmd) {
			continue
		}
		if family == "debian" {
			add(d.debian)
		} else {
			add(d.fedora)
		}
	}
	// dialogs for the desktop helper: kdialog on KDE Plasma, zenity elsewhere
	if desktopPresent && !has("zenity") && !has("kdialog") {
		if kde {
			add("kdialog")
		} else {
			add("zenity")
		}
	}
	return pkgs
}

// ensureDependencies installs missing tools, at most once a day.
func (a *Agent) ensureDependencies() {
	if time.Since(depsChecked) < 24*time.Hour {
		return
	}
	depsChecked = time.Now()
	env, dm := desktop()
	pkgs := missingPackages(a.host.family, env != "" || dm != "", strings.HasPrefix(env, "KDE"), func(c string) bool {
		_, err := exec.LookPath(c)
		return err == nil
	})
	if len(pkgs) == 0 {
		return
	}
	if err := a.host.install(pkgs...); err != nil {
		a.event("installing missing tools %v failed: %v", pkgs, err)
		return
	}
	a.event("installed missing tools %v", pkgs)
}
