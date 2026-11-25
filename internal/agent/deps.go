package agent

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The agent does not rely on what a device happens to have installed: the
// packages declare the core tools as dependencies, and every day the agent
// installs whatever is missing (a package may have been removed, or the
// agent was installed from the tarball). Desktop tools are only installed on
// devices with a desktop.

type dependency struct {
	cmd            string   // program the agent calls, or a file pattern (contains "/")
	debian, fedora string   // package providing it
	desktop        bool     // only on devices with a desktop
	with           []string // only if one of these programs is installed
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
	// the GTK 4 desktop app (packaging/limdm-desktop-ui)
	{cmd: "python3", debian: "python3", fedora: "python3", desktop: true},
	{cmd: "/usr/lib*/python3*/*-packages/gi/__init__.py", debian: "python3-gi", fedora: "python3-gobject", desktop: true},
	{cmd: "/usr/lib*/*/girepository-1.0/Gtk-4.0.typelib", debian: "gir1.2-gtk-4.0", fedora: "gtk4", desktop: true},
	{cmd: "/usr/lib*/*/girepository-1.0/Adw-1.typelib", debian: "gir1.2-adw-1", fedora: "libadwaita", desktop: true},
	// idle screen lock for compositors and window managers (screenlock.go)
	{cmd: "swayidle", debian: "swayidle", fedora: "swayidle", desktop: true, with: waylandCompositors},
	{cmd: "swaylock", debian: "swaylock", fedora: "swaylock", desktop: true, with: waylandCompositors},
	{cmd: "xss-lock", debian: "xss-lock", fedora: "xss-lock", desktop: true, with: x11WindowManagers},
	{cmd: "i3lock", debian: "i3lock", fedora: "i3lock", desktop: true, with: x11WindowManagers},
	{cmd: "xset", debian: "x11-xserver-utils", fedora: "xset", desktop: true, with: x11WindowManagers},
	{cmd: "xfce4-screensaver", debian: "xfce4-screensaver", fedora: "xfce4-screensaver", desktop: true, with: []string{"xfce4-session"}},
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
		if (d.desktop && !desktopPresent) || has(d.cmd) || (d.with != nil && !slices.ContainsFunc(d.with, has)) {
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
	pkgs := missingPackages(a.host.family, env != "" || dm != "", strings.HasPrefix(env, "KDE"), present)
	if len(pkgs) == 0 {
		return
	}
	if err := a.host.install(pkgs...); err != nil {
		a.event("installing missing tools %v failed: %v", pkgs, err)
		return
	}
	a.event("installed missing tools %v", pkgs)
}

// present reports whether a program is on PATH, or a file matching a pattern exists.
func present(c string) bool {
	if strings.Contains(c, "/") {
		m, _ := filepath.Glob(c)
		if len(m) == 0 && strings.HasPrefix(c, "/usr/lib*/*/") { // Fedora: /usr/lib64/girepository-1.0
			m, _ = filepath.Glob(strings.Replace(c, "/usr/lib*/*/", "/usr/lib*/", 1))
		}
		return len(m) > 0
	}
	_, err := exec.LookPath(c)
	return err == nil
}
