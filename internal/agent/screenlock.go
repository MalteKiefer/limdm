package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Screen lock and login screen privacy on every desktop.
//
// Desktop environments get locked system defaults users cannot change:
// dconf for GNOME, Budgie, Cinnamon and MATE, kscreenlockerrc with kiosk
// immutability for KDE Plasma, xfconf with locked properties for Xfce.
// Compositors without such settings (sway, Hyprland, river, labwc, niri,
// Wayfire) get swayidle with swaylock, i3 and other X11 window managers
// xss-lock with i3lock; the agent starts these in every such session and
// restarts them within a minute when they are ended. Login managers (GDM,
// SDDM, LightDM) lose automatic login and, if declared, the user list.

const (
	dconfSettings = "/etc/dconf/db/local.d/60-limdm"
	dconfLocks    = "/etc/dconf/db/local.d/locks/60-limdm"
	gdmProfile    = "/etc/dconf/profile/gdm"
	gdmSettings   = "/etc/dconf/db/gdm.d/60-limdm"
	kdeLock       = "/etc/xdg/kscreenlockerrc"
	xfceLock      = "/etc/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-screensaver.xml"
	swayLock      = "/etc/sway/config.d/60-limdm-lock.conf"
	sddmConf      = "/etc/sddm.conf.d/99-limdm.conf"
	lightdmConf   = "/etc/lightdm/lightdm.conf.d/99-limdm.conf"
)

func lockMinutes(seconds int) int { return max(1, (seconds+59)/60) }

// dconfLockFiles covers GNOME (also Budgie), Cinnamon and MATE in one
// database; keys of absent desktops are ignored.
func dconfLockFiles(seconds int) (settings, locks string) {
	settings = managedHeader + fmt.Sprintf(`[org/gnome/desktop/session]
idle-delay=uint32 %[1]d

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
ubuntu-lock-on-suspend=true

[org/cinnamon/desktop/session]
idle-delay=uint32 %[1]d

[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/mate/screensaver]
idle-activation-enabled=true
lock-enabled=true
lock-delay=0

[org/mate/desktop/session]
idle-delay=%[2]d
`, seconds, lockMinutes(seconds))
	locks = managedHeader + `/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/cinnamon/desktop/session/idle-delay
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/screensaver/lock-delay
/org/mate/screensaver/idle-activation-enabled
/org/mate/screensaver/lock-enabled
/org/mate/screensaver/lock-delay
/org/mate/desktop/session/idle-delay
`
	return
}

// kdeLockFile: [$i] makes the group immutable (KDE kiosk).
func kdeLockFile(seconds int) string {
	return managedHeader + fmt.Sprintf("[Daemon][$i]\nAutolock=true\nLockOnResume=true\nLockGrace=0\nTimeout=%d\n", lockMinutes(seconds))
}

// xfceLockFile: locked="*" keeps users from changing the properties.
func xfceLockFile(seconds int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!-- Managed by LiMDM. Local changes are overwritten. -->
<channel name="xfce4-screensaver" version="1.0">
  <property name="saver" type="empty">
    <property name="enabled" type="bool" value="true" locked="*"/>
    <property name="idle-activation" type="empty">
      <property name="enabled" type="bool" value="true" locked="*"/>
      <property name="delay" type="int" value="%d" locked="*"/>
    </property>
  </property>
  <property name="lock" type="empty">
    <property name="enabled" type="bool" value="true" locked="*"/>
    <property name="saver-activation" type="empty">
      <property name="enabled" type="bool" value="true" locked="*"/>
      <property name="delay" type="int" value="0" locked="*"/>
    </property>
    <property name="sleep-activation" type="bool" value="true" locked="*"/>
  </property>
</channel>
`, lockMinutes(seconds))
}

// swayIdleArgs locks after the idle time and before suspend.
func swayIdleArgs(seconds int) []string {
	return []string{"-w", "timeout", strconv.Itoa(seconds), "swaylock -f -c 000000",
		"before-sleep", "swaylock -f -c 000000", "lock", "swaylock -f -c 000000"}
}

func swayLockFile(seconds int) string {
	return managedHeader + "exec swayidle " + strings.Join([]string{"-w", "timeout", strconv.Itoa(seconds),
		"'swaylock -f -c 000000'", "before-sleep", "'swaylock -f -c 000000'", "lock", "'swaylock -f -c 000000'"}, " ") + "\n"
}

func gdmFiles(hideUsers bool) (profile, settings string) {
	profile = "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n"
	settings = managedHeader + fmt.Sprintf("[org/gnome/login-screen]\ndisable-user-list=%t\n", hideUsers)
	return
}

func sddmFile(sl screenLockPolicy) string {
	s := managedHeader
	if !sl.allowAutologin {
		s += "[Autologin]\nUser=\nSession=\nRelogin=false\n\n"
	}
	if sl.hideUsers {
		s += "[Users]\nRememberLastUser=false\nRememberLastSession=false\n"
	}
	return s
}

func lightdmFile(sl screenLockPolicy) string {
	s := managedHeader + "[Seat:*]\nallow-guest=false\n"
	if !sl.allowAutologin {
		s += "autologin-user=\nautologin-guest=false\n"
	}
	if sl.hideUsers {
		s += "greeter-hide-users=true\ngreeter-show-manual-login=true\n"
	}
	return s
}

type screenLockPolicy struct {
	seconds                   int
	hideUsers, allowAutologin bool
}

func (a *Agent) screenLockPolicy() screenLockPolicy {
	return screenLockPolicy{a.pol.ScreenLockSeconds, a.pol.ScreenLock.HideUsers, a.pol.ScreenLock.AllowAutologin}
}

// lockTargets is every managed file this device needs, by what is installed.
func lockTargets(sl screenLockPolicy) map[string]string {
	t := map[string]string{}
	if hasCmd("dconf") {
		t[dconfSettings], t[dconfLocks] = dconfLockFiles(sl.seconds)
	}
	if hasCmd("plasmashell") || exists("/usr/bin/kscreenlocker_greet") || exists("/usr/libexec/kscreenlocker_greet") {
		t[kdeLock] = kdeLockFile(sl.seconds)
	}
	if hasCmd("xfce4-session") {
		t[xfceLock] = xfceLockFile(sl.seconds)
	}
	if hasCmd("sway") {
		t[swayLock] = swayLockFile(sl.seconds)
	}
	if hasCmd("gdm") || hasCmd("gdm3") || exists("/usr/sbin/gdm") || exists("/usr/sbin/gdm3") {
		t[gdmProfile], t[gdmSettings] = gdmFiles(sl.hideUsers)
	}
	if hasCmd("sddm") {
		t[sddmConf] = sddmFile(sl)
	}
	if hasCmd("lightdm") {
		t[lightdmConf] = lightdmFile(sl)
	}
	return t
}

// gdmAutologinFile is GDM's daemon configuration (Fedora, Debian/Ubuntu).
func gdmAutologinFile() string {
	for _, f := range []string{"/etc/gdm/custom.conf", "/etc/gdm3/custom.conf", "/etc/gdm3/daemon.conf"} {
		if exists(f) {
			return f
		}
	}
	return ""
}

func runScreenLock(a *Agent) (string, string) {
	env, dm := desktop()
	if env == "" && dm == "" {
		return na, "no desktop"
	}
	sl := a.screenLockPolicy()
	if sl.seconds == 0 {
		return fail, "screen lock not declared"
	}
	var missing []string
	for f, want := range lockTargets(sl) {
		if readFile(f) != want {
			missing = append(missing, f)
		}
	}
	if f := gdmAutologinFile(); f != "" && !sl.allowAutologin && strings.EqualFold(iniValue(readFile(f), "daemon", "AutomaticLoginEnable"), "true") {
		missing = append(missing, f+" (automatic login)")
	}
	if exists(dconfSettings) && !strings.Contains(readFile("/etc/dconf/profile/user"), "system-db:local") {
		missing = append(missing, "/etc/dconf/profile/user")
	}
	for _, s := range idleSessions() {
		if !s.locked {
			missing = append(missing, s.user+": no idle lock running in the "+s.kind+" session")
		}
	}
	if len(missing) > 0 {
		return fail, "not enforced: " + strings.Join(missing, ", ")
	}
	return pass, fmt.Sprintf("locks after %d s on every desktop, users cannot change it", sl.seconds)
}

func fixScreenLock(a *Agent) error {
	sl := a.screenLockPolicy()
	if sl.seconds == 0 {
		return errors.New("screen lock not declared")
	}
	var errs []error
	dconfChanged := false
	for f, want := range lockTargets(sl) {
		changed, err := writeIfChanged(f, want, 0o644)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if changed && strings.HasPrefix(f, "/etc/dconf/") {
			dconfChanged = true
		}
	}
	if exists(dconfSettings) {
		profile := readFile("/etc/dconf/profile/user")
		if !strings.Contains(profile, "system-db:local") {
			if profile == "" {
				profile = "user-db:user\n"
			}
			if _, err := writeIfChanged("/etc/dconf/profile/user", strings.TrimRight(profile, "\n")+"\nsystem-db:local\n", 0o644); err != nil {
				errs = append(errs, err)
			}
			dconfChanged = true
		}
	}
	if dconfChanged {
		if _, err := sh("dconf", "update"); err != nil {
			errs = append(errs, err)
		}
	}
	if f := gdmAutologinFile(); f != "" && !sl.allowAutologin {
		if s := readFile(f); strings.EqualFold(iniValue(s, "daemon", "AutomaticLoginEnable"), "true") {
			if _, err := writeIfChanged(f, setINIValue(s, "daemon", "AutomaticLoginEnable", "false"), 0o644); err != nil {
				errs = append(errs, err)
			}
		}
	}
	a.ensureIdleLocks()
	return errors.Join(errs...)
}

// ---- idle lock for compositors and window managers ----

type idleSession struct {
	user, uid, kind string // kind: wayland (wlroots style) or x11
	env             []string
	locked          bool
}

// compositors that need an external idle locker
var (
	waylandCompositors = []string{"sway", "Hyprland", "river", "labwc", "niri", "wayfire"}
	x11WindowManagers  = []string{"i3", "bspwm", "openbox", "awesome", "herbstluftwm"}
	idleLockers        = []string{"swayidle", "hypridle", "xss-lock", "xautolock"}
)

// idleSessions lists graphical sessions of compositors and window managers
// without a screen locker of their own, and whether a locker runs there.
func idleSessions() []idleSession {
	procs := map[string]map[string]bool{} // uid -> process names
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, err := os.ReadFile(d + "/comm")
		if err != nil {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(d, &st) != nil {
			continue
		}
		uid := strconv.FormatUint(uint64(st.Uid), 10)
		if procs[uid] == nil {
			procs[uid] = map[string]bool{}
		}
		procs[uid][strings.TrimSpace(string(comm))] = true
	}
	var res []idleSession
	for _, s := range graphicalSessions() {
		p := procs[s.uid]
		kind := ""
		for _, c := range waylandCompositors {
			if p[c] {
				kind = "wayland"
			}
		}
		for _, c := range x11WindowManagers {
			if p[c] {
				kind = "x11"
			}
		}
		if kind == "" {
			continue // a desktop environment with its own locker, configured above
		}
		is := idleSession{user: s.user, uid: s.uid, kind: kind, env: s.env}
		for _, l := range idleLockers {
			is.locked = is.locked || p[l]
		}
		res = append(res, is)
	}
	return res
}

// ensureIdleLocks starts the idle locker in sessions that lack one; run
// every minute so ending it does not help.
func (a *Agent) ensureIdleLocks() {
	seconds := a.pol.ScreenLockSeconds
	if seconds == 0 {
		return
	}
	for _, s := range idleSessions() {
		if s.locked {
			continue
		}
		var argv []string
		switch {
		case s.kind == "wayland" && hasCmd("swayidle") && hasCmd("swaylock"):
			argv = append([]string{"swayidle"}, swayIdleArgs(seconds)...)
		case s.kind == "x11" && hasCmd("xss-lock") && hasCmd("i3lock"):
			// the X screensaver timeout drives xss-lock
			_, _ = run(10*time.Second, "runuser", append(append([]string{"-u", s.user, "--", "env"}, s.env...), "xset", "s", strconv.Itoa(seconds), strconv.Itoa(seconds))...)
			argv = []string{"xss-lock", "--transfer-sleep-lock", "--", "i3lock", "-n", "-c", "000000"}
		default:
			continue // tools missing: ensureDependencies installs them
		}
		args := []string{"--user", "--machine=" + s.user + "@.host", "--collect", "--quiet", "--unit=limdm-idle-lock"}
		for _, kv := range s.env {
			args = append(args, "--setenv="+kv)
		}
		if _, err := run(30*time.Second, "systemd-run", append(args, argv...)...); err != nil {
			a.log.Warn("starting the idle lock failed", "user", s.user, "err", err)
			continue
		}
		a.event("started the idle screen lock for %s (%s session)", s.user, s.kind)
	}
}

// ---- small INI helpers (GDM's custom.conf) ----

func iniValue(s, section, key string) string {
	cur := ""
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = t[1 : len(t)-1]
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok && cur == section && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// setINIValue sets key in section, adding the section or key if needed.
func setINIValue(s, section, key, value string) string { //nolint:unparam // a general INI helper, today only for GDM
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	cur, inserted := "", false
	sectionEnd := -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			if cur == section && sectionEnd < 0 {
				sectionEnd = i
			}
			cur = t[1 : len(t)-1]
			continue
		}
		if k, _, ok := strings.Cut(t, "="); ok && cur == section && strings.TrimSpace(k) == key {
			lines[i] = key + "=" + value
			inserted = true
		}
	}
	if !inserted {
		switch {
		case cur == section && sectionEnd < 0:
			lines = append(lines, key+"="+value)
		case sectionEnd >= 0:
			lines = append(lines[:sectionEnd], append([]string{key + "=" + value}, lines[sectionEnd:]...)...)
		default:
			lines = append(lines, "", "["+section+"]", key+"="+value)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
