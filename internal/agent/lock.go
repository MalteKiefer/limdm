package agent

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Remote lock on every desktop.
//
// A lock has three parts, because each alone leaves a way in:
//   - /etc/nologin refuses new logins (pam_nologin, also SSH).
//   - The local passwords of all people's accounts are locked, so neither a
//     new login nor the screen locker accepts them. The accounts LiMDM
//     locked are remembered; unlock only releases those.
//   - Terminal and SSH sessions of people cannot be locked, so they end;
//     root's stay, like /etc/nologin lets root in.
//   - Running graphical sessions are locked, not ended (like Windows and
//     macOS, unsaved work stays): desktop environments through logind
//     (loginctl lock-sessions); compositors and window managers without a
//     logind aware locker (labwc, sway, Hyprland, i3 …) get swaylock or
//     i3lock started directly, again every minute while the device stays
//     locked.

const deviceLockUsers = stateDir + "/device-lock-users.json"

// peopleAccounts are local accounts of people: UID 1000 to 59999 with a
// login shell.
func peopleAccounts() []string { return parsePeople(readFile("/etc/passwd")) }

func parsePeople(accountDB string) []string {
	var users []string
	for _, l := range strings.Split(accountDB, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || uid < 1000 || uid >= 60000 || strings.HasSuffix(f[6], "nologin") || strings.HasSuffix(f[6], "/false") {
			continue
		}
		users = append(users, f[0])
	}
	return users
}

// lockAfterLost records a lock sent during lost mode.
const lockAfterLost = stateDir + "/lock-after-lost"

// While the device is locked or lost, the lock screen of GNOME, Cinnamon
// and MATE cannot be switched off by the user: disable-lock-screen in the
// user's own settings makes these shells ignore logind's lock request, and
// lockSessions trusts them to lock. A system setting with a dconf lock
// overrides it; removed again on unlock.
const (
	lockdownSettings = "/etc/dconf/db/local.d/50-limdm-device-lock"
	lockdownLocks    = "/etc/dconf/db/local.d/locks/50-limdm-device-lock"
)

// lockdownDirs hold disable-lock-screen (keys of absent desktops are ignored).
var lockdownDirs = []string{"org/gnome/desktop/lockdown", "org/cinnamon/desktop/lockdown", "org/mate/lockdown"}

func lockdownFiles() (settings, locks string) {
	settings, locks = managedHeader, managedHeader
	for _, dir := range lockdownDirs {
		settings += "\n[" + dir + "]\ndisable-lock-screen=false\n"
		locks += "/" + dir + "/disable-lock-screen\n"
	}
	return settings, locks
}

// setLockdown writes (on) or removes the lock screen lockdown.
func setLockdown(on bool) error {
	if !hasCmd("dconf") {
		return nil
	}
	settings, locks := "", ""
	if on {
		settings, locks = lockdownFiles()
	}
	c1, e1 := writeOrRemove(lockdownSettings, settings, 0o644)
	c2, e2 := writeOrRemove(lockdownLocks, locks, 0o644)
	if err := errors.Join(e1, e2); err != nil || !c1 && !c2 {
		return err
	}
	return dconfUpdate(true, on)
}

func readLockUsers() []string {
	var users []string
	_ = json.Unmarshal([]byte(readFile(deviceLockUsers)), &users)
	return users
}

func (a *Agent) lockDevice() (string, error) {
	if inLostMode() {
		// remembered: "found" ends lost mode into this lock, not into a free device
		if err := os.WriteFile(lockAfterLost, nil, 0o600); err != nil {
			return "", err
		}
		return "device is in lost mode; it stays locked after Found as well", nil
	}
	if _, err := writeIfChanged(nologinFile, nologinText, 0o644); err != nil {
		return "", err
	}
	if err := setLockdown(true); err != nil { // before the lock request, or the shell may ignore it
		a.event("keeping the lock screen enabled: %v", err)
	}
	locked, err := lockPasswords()
	ended := endConsoleSessions()
	n := a.lockSessions()
	return "logins blocked, local passwords of " + strings.Join(locked, ", ") + " locked, " + strconv.Itoa(n) +
		" sessions locked, terminal and SSH sessions ended: " + strings.Join(ended, ", "), err
}

func (a *Agent) unlockDevice() (string, error) {
	if inLostMode() {
		// only "found" ends lost mode; an unlock (also the automatic one of the
		// compliance policy) must not release its password locks
		return "", errors.New("device is in lost mode; use Found to unlock it")
	}
	if readFile(nologinFile) == nologinText {
		if err := os.Remove(nologinFile); err != nil {
			return "", err
		}
	}
	_ = os.Remove(lockAfterLost)
	if err := setLockdown(false); err != nil {
		a.event("removing the lock screen lockdown: %v", err)
	}
	released, err := a.releasePasswords()
	return "logins allowed again, local passwords released: " + strings.Join(released, ", ") + "; users unlock their screen with their password", err
}

// lockPasswords locks the local passwords of all people's accounts and
// remembers which ones LiMDM locked (device lock, lost mode).
func lockPasswords() ([]string, error) {
	locked := readLockUsers()
	var errs []error
	for _, u := range peopleAccounts() {
		if passwordLocked(u) {
			continue // locked before (by IT or the SSO rules); a release leaves it so
		}
		if _, err := sh("usermod", "-L", u); err != nil {
			errs = append(errs, err)
			continue
		}
		if !slices.Contains(locked, u) {
			locked = append(locked, u)
		}
	}
	b, _ := json.Marshal(locked)
	if err := os.WriteFile(deviceLockUsers, b, 0o600); err != nil {
		errs = append(errs, err)
	}
	return locked, errors.Join(errs...)
}

// releasePasswords unlocks what lockPasswords locked; the SSO rules may keep
// managed users locked.
func (a *Agent) releasePasswords() ([]string, error) {
	var errs []error
	var released, failed []string
	for _, u := range readLockUsers() {
		if !passwordLocked(u) || a.state.UserLocked[u] {
			continue // locked by IT with user_lock: stays locked
		}
		if _, err := sh("usermod", "-U", u); err != nil {
			errs = append(errs, err)
			failed = append(failed, u) // kept, so the next unlock retries it
			continue
		}
		released = append(released, u)
	}
	if len(failed) > 0 {
		b, _ := json.Marshal(failed)
		if err := os.WriteFile(deviceLockUsers, b, 0o600); err != nil {
			errs = append(errs, err)
		}
	} else if err := os.Remove(deviceLockUsers); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	a.syncPasswordLocks()
	return released, errors.Join(errs...)
}

// enforceDeviceLock keeps sessions locked while the device is locked; run
// every minute, so ending the locker does not help.
func (a *Agent) enforceDeviceLock() {
	locked := readFile(nologinFile) == nologinText
	if err := setLockdown(locked || inLostMode()); err != nil {
		a.event("lock screen lockdown: %v", err)
	}
	if locked {
		if ended := endConsoleSessions(); len(ended) > 0 {
			a.event("device locked: ended %s", strings.Join(ended, ", "))
		}
		a.lockSessions()
	}
}

// consoleSession: a person's session without a screen to lock (terminal,
// or remote as with SSH).
func consoleSession(l loginSession) bool {
	if !l.person() || (!l.Remote && l.Type != "tty" && l.Type != "unspecified") {
		return false
	}
	if !l.Remote { // a compositor started from the console is graphical: locked, not ended
		if env, _ := sessionDisplay(l); env != nil {
			return false
		}
		// without an audit session ID the session cannot be told apart: when
		// the user has a display anywhere, keep it rather than end a desktop
		if (l.Audit == "" || l.Audit == "0" || l.Audit == "4294967295") && graphicalEnv(l.UID, "") != nil {
			return false
		}
	}
	return true
}

// endConsoleSessions ends terminal and SSH sessions of people; they have
// no screen locker.
func endConsoleSessions() []string {
	if !hasCmd("loginctl") {
		return endTTYs() // systems without systemd-logind
	}
	var ended []string
	for _, l := range loginSessions() {
		if !consoleSession(l) {
			continue
		}
		if _, err := sh("loginctl", "terminate-session", l.ID); err == nil {
			ended = append(ended, l.User+" (session "+l.ID+")")
		}
	}
	return ended
}

// endTTYs ends people's terminal and SSH logins from utmp (who): every
// process on their terminal gets SIGHUP, then SIGKILL.
func endTTYs() []string {
	people := peopleAccounts()
	ttys := map[string]string{} // tty -> user
	out, _ := sh("who")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] == "root" || !userRe.MatchString(f[0]) || !strings.HasPrefix(f[1], "pts/") && !strings.HasPrefix(f[1], "tty") {
			continue
		}
		if slices.Contains(people, f[0]) {
			ttys[f[1]] = f[0]
		}
	}
	// musl systems (Alpine) often keep no utmp, so who lists nobody: the
	// terminals people's processes run on count as well
	for tty, user := range procTTYs(people) {
		ttys[tty] = user
	}
	var ended []string
	for tty, user := range ttys {
		_, _ = sh("pkill", "-HUP", "-t", tty)
		_, _ = sh("pkill", "-KILL", "-t", tty)
		ended = append(ended, user+" ("+tty+")")
	}
	slices.Sort(ended)
	return ended
}

// procTTYs maps the terminals people's sessions control to the user, from
// /proc: musl systems keep no utmp. Graphical sessions stay (they are locked,
// not ended): a virtual console a verified compositor or X server runs on,
// and a pseudo terminal only when every session on it was started by such a
// compositor (terminal emulators). Every other terminal ends, SSH included.
// Per session leader, not per process: a process a user hangs onto an SSH
// terminal from the desktop does not make it graphical. Names and parents a
// user can fake are not trusted, only verified compositor binaries.
func procTTYs(people []string) map[string]string {
	uids := map[uint32]string{}
	for _, p := range people {
		if u, err := user.Lookup(p); err == nil {
			if id, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
				uids[uint32(id)] = p
			}
		}
	}
	type ttyInfo struct {
		user                string
		compositor, foreign bool // compositor on this VT; a session not started by one
	}
	ttys := map[string]*ttyInfo{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		var st syscall.Stat_t
		if syscall.Stat(d, &st) != nil {
			continue
		}
		name, ok := uids[st.Uid]
		if !ok {
			continue
		}
		pid := filepath.Base(d)
		f := strings.Fields(afterComm(readFile(d + "/stat")))
		if len(f) < 5 {
			continue
		}
		tty := ttyName(f[4]) // controlling terminal
		if tty == "" {
			continue
		}
		info := ttys[tty]
		if info == nil {
			info = &ttyInfo{user: name}
			ttys[tty] = info
		}
		if !strings.HasPrefix(tty, "pts/") && verifiedCompositor(pid) {
			info.compositor = true
		}
		if f[3] == pid && !underCompositor(pid) { // a session leader on its own
			info.foreign = true
		}
	}
	out := map[string]string{}
	for tty, info := range ttys {
		if strings.HasPrefix(tty, "pts/") && info.foreign || !strings.HasPrefix(tty, "pts/") && !info.compositor {
			out[tty] = info.user
		}
	}
	return out
}

// ttyName turns the tty_nr of /proc/PID/stat into ttyN or pts/N; "" when
// the process has no controlling terminal or another kind.
func ttyName(nr string) string {
	n, err := strconv.ParseUint(nr, 10, 32)
	if err != nil || n == 0 {
		return ""
	}
	major, minor := (n>>8)&0xfff, (n&0xff)|((n>>12)&0xfff00)
	switch {
	case major == 4 && minor >= 1 && minor < 64:
		return "tty" + strconv.FormatUint(minor, 10)
	case major >= 136 && major <= 143:
		return "pts/" + strconv.FormatUint((major-136)*256+minor, 10)
	}
	return ""
}

// underCompositor reports whether pid or one of its ancestors runs a
// verified compositor or X server.
func underCompositor(pid string) bool {
	for range 32 {
		if verifiedCompositor(pid) {
			return true
		}
		f := strings.Fields(afterComm(readFile("/proc/" + pid + "/stat")))
		if len(f) < 2 || f[1] == "0" || f[1] == "1" {
			return false
		}
		pid = f[1] // the parent
	}
	return false
}

// afterComm drops "pid (comm) " from a /proc stat line; comm may contain
// spaces and parentheses, the last ")" ends it.
func afterComm(stat string) string {
	if i := strings.LastIndexByte(stat, ')'); i >= 0 {
		return stat[i+1:]
	}
	return ""
}

// trustedExe: the process runs one of the named binaries, owned by root
// and not writable by others, in a system directory (a renamed or copied
// user program fails).
func trustedExe(pid string, names map[string]bool) bool {
	exe, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil || !names[filepath.Base(exe)] {
		return false
	}
	if dir := filepath.Dir(exe); !slices.Contains([]string{"/usr/bin", "/usr/local/bin", "/usr/libexec", "/usr/lib/xorg", "/bin"}, dir) {
		return false
	}
	var st syscall.Stat_t
	return syscall.Stat(exe, &st) == nil && st.Uid == 0 && st.Mode&0o022 == 0
}

// verifiedCompositor: the process runs a known compositor or X server binary
// (trustedExe) on a virtual console.
func verifiedCompositor(pid string) bool {
	if !trustedExe(pid, graphicalExe) {
		return false
	}
	// started at the device: a compositor run headless over SSH has a
	// pseudo terminal, not a virtual console
	t, err := os.Readlink("/proc/" + pid + "/fd/0")
	return err == nil && vtRe.MatchString(t)
}

// graphicalExe are compositors and X servers started from a console.
var graphicalExe = map[string]bool{"sway": true, "Hyprland": true, "Xorg": true, "Xorg.wrap": true, "X": true, "xinit": true,
	"weston": true, "labwc": true, "river": true, "wayfire": true, "niri": true, "cage": true, "gnome-shell": true,
	"kwin_wayland": true, "dwl": true, "Xwayland": true}

// logindLocks: desktops whose shell locks itself on loginctl lock-sessions,
// by logind's Desktop property, which the display manager sets at login and
// the user cannot change. LockedHint is not used: the session owner sets it.
func logindLocks(desktop string) bool {
	d := strings.ToLower(desktop)
	for _, n := range []string{"gnome", "ubuntu", "plasma", "kde", "cinnamon", "mate"} {
		if strings.Contains(d, n) {
			return true
		}
	}
	return false
}

// lockSessions locks every graphical session: through logind first (the
// desktop's own locker), then, unless the session's desktop locks itself on
// logind's request, with swaylock or i3lock started in the session
// (compositors and window managers without a logind aware locker, LXQt,
// LXDE …). A locker that seems to run already is not trusted: its name,
// environment and display are the user's to choose. Starting a second
// locker on a locked session fails harmlessly (swaylock finds the session
// lock taken, i3lock cannot grab the keyboard). Returns the sessions
// locked that way.
func (a *Agent) lockSessions() int {
	sessions := graphicalSessions()
	if len(sessions) == 0 {
		return 0
	}
	desktops := map[string]string{}
	if hasCmd("loginctl") {
		_, _ = sh("loginctl", "lock-sessions")
		time.Sleep(3 * time.Second) // give lockers time to show
		for _, l := range loginSessions() {
			desktops[l.ID] = l.Desktop
		}
	}
	n := 0
	for _, s := range sessions {
		if logindLocks(desktops[s.id]) {
			continue
		}
		var argv []string
		switch {
		case s.kind == "wayland" && hasCmd("swaylock"):
			argv = []string{"swaylock", "-f", "-c", "000000"}
		case s.kind == "x11" && hasCmd("i3lock"):
			argv = []string{"i3lock", "-c", "000000"}
		default:
			a.event("cannot lock the %s session of %s: no logind aware locker and no swaylock or i3lock", s.kind, s.user)
			continue
		}
		if _, err := startInSession(0, s.user, s.env, argv[0], argv[1:]...); err != nil {
			a.event("locking the session of %s failed: %v", s.user, err)
			continue
		}
		n++
	}
	return n
}

// lockerRunning: a screen locker process of the session's user.
func lockerRunning(procs map[string]bool) bool {
	for _, n := range []string{"swaylock", "i3lock", "hyprlock", "gtklock", "waylock", "slock", "xsecurelock"} {
		if procs[n] {
			return true
		}
	}
	return false
}
