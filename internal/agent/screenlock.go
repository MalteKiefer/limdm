package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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

func gdmFiles() (profile, settings string) {
	profile = "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n"
	settings = managedHeader + "[org/gnome/login-screen]\ndisable-user-list=true\n"
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

// screenLockPolicy: the login screen is only touched when the declaration
// has one of its keys (manageLogin); existing declarations keep greeters as
// they are.
type screenLockPolicy struct {
	seconds                                int
	manageLogin, hideUsers, allowAutologin bool
}

func (a *Agent) screenLockPolicy() screenLockPolicy {
	l := a.pol.ScreenLock
	return screenLockPolicy{seconds: a.pol.ScreenLockSeconds, manageLogin: l.ManageLogin, hideUsers: l.HideUsers, allowAutologin: l.AllowAutologin || !l.ManageLogin}
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
	if !sl.manageLogin {
		return t
	}
	if sl.hideUsers && (hasCmd("gdm") || hasCmd("gdm3") || exists("/usr/sbin/gdm") || exists("/usr/sbin/gdm3")) {
		t[gdmProfile], t[gdmSettings] = gdmFiles()
	}
	if hasCmd("sddm") && (sl.hideUsers || !sl.allowAutologin) {
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

// autologinSetting is a key in a login manager's main file that turns on
// automatic login. Main files are read after the conf.d drop-ins and win,
// so they are checked and fixed directly.
type autologinSetting struct {
	file, section, key string
	off                string // the value that switches it off
	on                 func(string) bool
}

func truthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "true" || v == "1" || v == "yes"
}

func notEmpty(v string) bool { return strings.TrimSpace(v) != "" }

func autologinSettings() []autologinSetting {
	var s []autologinSetting
	if f := gdmAutologinFile(); f != "" {
		s = append(s, autologinSetting{f, "daemon", "AutomaticLoginEnable", "false", truthy},
			autologinSetting{f, "daemon", "TimedLoginEnable", "false", truthy})
	}
	if exists("/etc/sddm.conf") {
		s = append(s, autologinSetting{"/etc/sddm.conf", "Autologin", "User", "", notEmpty})
	}
	if exists("/etc/lightdm/lightdm.conf") {
		s = append(s, autologinSetting{"/etc/lightdm/lightdm.conf", "Seat:*", "autologin-user", "", notEmpty},
			autologinSetting{"/etc/lightdm/lightdm.conf", "SeatDefaults", "autologin-user", "", notEmpty})
	}
	return s
}

// unenforced names desktops installed here that no mechanism above covers.
func unenforced(env string) []string {
	var out []string
	switch {
	case strings.HasPrefix(env, "COSMIC"), strings.HasPrefix(env, "LXQt"):
		out = append(out, "no screen lock enforcement for "+env)
	}
	if hasCmd("xfce4-session") && !hasCmd("xfce4-screensaver") {
		out = append(out, "xfce4-screensaver not installed")
	}
	return out
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
	missing := unenforced(env)
	for f, want := range lockTargets(sl) {
		if readFile(f) != want {
			missing = append(missing, f)
		}
	}
	if !sl.allowAutologin {
		for _, s := range autologinSettings() {
			if s.on(iniValue(readFile(s.file), s.section, s.key)) {
				missing = append(missing, s.file+" ("+s.key+")")
			}
		}
	}
	if exists(dconfSettings) && !strings.Contains(readFile("/etc/dconf/profile/user"), "system-db:local") {
		missing = append(missing, "/etc/dconf/profile/user")
	}
	for _, s := range idleSessions() {
		switch {
		case !s.locked:
			missing = append(missing, s.user+": no idle lock running in the "+s.kind+" session")
		case s.kind == "x11" && xTimeout(s) != sl.seconds:
			missing = append(missing, s.user+": X screensaver timeout is not "+strconv.Itoa(sl.seconds)+" s")
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
	if !sl.allowAutologin {
		for _, s := range autologinSettings() {
			content := readFile(s.file)
			if s.on(iniValue(content, s.section, s.key)) {
				if _, err := writeIfChanged(s.file, setINIValue(content, s.section, s.key, s.off), 0o644); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	if hasCmd("xfce4-session") && !hasCmd("xfce4-screensaver") {
		if err := a.host.install("xfce4-screensaver"); err != nil {
			errs = append(errs, err)
		}
	}
	a.ensureIdleLocks()
	return errors.Join(errs...)
}

// ---- idle lock for compositors and window managers ----

type idleSession struct {
	user, uid, kind string // kind: wayland (wlroots style) or x11
	env             []string
	locked          bool // the agent's own idle locker runs in this session
	screenLocked    bool // a screen locker shows right now
}

// compositors that need an external idle locker
var (
	waylandCompositors = []string{"sway", "Hyprland", "river", "labwc", "niri", "wayfire"}
	x11WindowManagers  = []string{"i3", "bspwm", "openbox", "awesome", "herbstluftwm"}
)

// idleFallback holds lockers started directly where systemd-run --user
// could not reach the user's service manager (uid -> process).
var (
	idleMu       sync.Mutex
	idleFallback = map[string]*os.Process{}
)

// ownLockerRuns: only the agent's own locker counts, never a process that
// merely has a locker's name.
func ownLockerRuns(s graphicalSession) bool {
	if _, err := run(10*time.Second, "systemctl", "--user", "--machine="+s.user+"@.host", "is-active", "--quiet", "limdm-idle-lock"); err == nil {
		return true
	}
	idleMu.Lock()
	defer idleMu.Unlock()
	p := idleFallback[s.uid]
	if p == nil {
		return false
	}
	if p.Signal(syscall.Signal(0)) != nil {
		delete(idleFallback, s.uid)
		return false
	}
	return true
}

// userProcs maps uid to the names of its running processes.
func userProcs() map[string]map[string]bool {
	procs := map[string]map[string]bool{}
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
	return procs
}

// idleSessions lists graphical sessions of compositors and window managers
// without a screen locker of their own, and whether the agent's locker runs.
func idleSessions() []idleSession {
	procs := userProcs()
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
		res = append(res, idleSession{user: s.user, uid: s.uid, kind: kind, env: s.env, locked: ownLockerRuns(s), screenLocked: lockerRunning(p)})
	}
	return res
}

// xTimeout reads the X screensaver timeout of a session (seconds, 0 = off).
func xTimeout(s idleSession) int {
	out, err := run(10*time.Second, "runuser", append(append([]string{"-u", s.user, "--", "env"}, s.env...), "xset", "q")...)
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "timeout:" {
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return -1
}

// remediatesScreenLock: the idle locker is a change on the device, so it
// follows the same rules as every other remediation.
func (a *Agent) remediatesScreenLock() bool {
	pol := a.policy()
	p := pol.Compliance
	return pol.ScreenLockSeconds > 0 && p.Remediate && p.Level >= 1 && !slices.Contains(p.Exclude, "desktop.screenlock")
}

// ensureIdleLocks starts the agent's locker in sessions that lack it and
// sets the X screensaver timeout; run every minute so ending it does not help.
func (a *Agent) ensureIdleLocks() {
	if !a.remediatesScreenLock() {
		return
	}
	seconds := a.policy().ScreenLockSeconds
	for _, s := range idleSessions() {
		if s.kind == "x11" && hasCmd("xset") && xTimeout(s) != seconds {
			// xss-lock follows the X screensaver timeout; a user's "xset s off" is undone here
			_, _ = run(10*time.Second, "runuser", append(append([]string{"-u", s.user, "--", "env"}, s.env...), "xset", "s", strconv.Itoa(seconds), strconv.Itoa(seconds))...)
		}
		if s.locked {
			continue
		}
		var argv []string
		switch {
		case s.kind == "wayland" && hasCmd("swayidle") && hasCmd("swaylock"):
			argv = append([]string{"swayidle"}, swayIdleArgs(seconds)...)
		case s.kind == "x11" && hasCmd("xss-lock") && hasCmd("i3lock"):
			argv = []string{"xss-lock", "--transfer-sleep-lock", "--", "i3lock", "-n", "-c", "000000"}
		default:
			continue // tools missing: ensureDependencies installs them
		}
		args := []string{"--user", "--machine=" + s.user + "@.host", "--collect", "--quiet", "--unit=limdm-idle-lock"}
		for _, kv := range s.env {
			args = append(args, "--setenv="+kv)
		}
		if _, err := run(30*time.Second, "systemd-run", append(args, argv...)...); err != nil {
			// like the desktop helper: start it directly when the user manager is out of reach
			proc, err2 := startInSession(0, s.user, s.env, argv[0], argv[1:]...)
			if err2 != nil {
				a.log.Warn("starting the idle lock failed", "user", s.user, "err", errors.Join(err, err2))
				continue
			}
			idleMu.Lock()
			idleFallback[s.uid] = proc
			idleMu.Unlock()
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
func setINIValue(s, section, key, value string) string {
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
