package agent

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
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

func parsePeople(passwd string) []string {
	var users []string
	for _, l := range strings.Split(passwd, "\n") {
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

func readLockUsers() []string {
	var users []string
	_ = json.Unmarshal([]byte(readFile(deviceLockUsers)), &users)
	return users
}

func (a *Agent) lockDevice() (string, error) {
	if _, err := writeIfChanged(nologinFile, nologinText, 0o644); err != nil {
		return "", err
	}
	locked, err := lockPasswords()
	ended := endConsoleSessions()
	n := a.lockSessions()
	return "logins blocked, local passwords of " + strings.Join(locked, ", ") + " locked, " + strconv.Itoa(n) +
		" sessions locked, terminal and SSH sessions ended: " + strings.Join(ended, ", "), err
}

func (a *Agent) unlockDevice() (string, error) {
	if readFile(nologinFile) == nologinText {
		if err := os.Remove(nologinFile); err != nil {
			return "", err
		}
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
	var released []string
	for _, u := range readLockUsers() {
		if !passwordLocked(u) {
			continue
		}
		if _, err := sh("usermod", "-U", u); err != nil {
			errs = append(errs, err)
			continue
		}
		released = append(released, u)
	}
	if err := os.Remove(deviceLockUsers); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	a.syncPasswordLocks()
	return released, errors.Join(errs...)
}

// enforceDeviceLock keeps sessions locked while the device is locked; run
// every minute, so ending the locker does not help.
func (a *Agent) enforceDeviceLock() {
	if readFile(nologinFile) == nologinText {
		if ended := endConsoleSessions(); len(ended) > 0 {
			a.event("device locked: ended %s", strings.Join(ended, ", "))
		}
		a.lockSessions()
	}
}

// consoleSession: a person's session without a screen to lock (terminal,
// or remote as with SSH).
func consoleSession(l loginSession) bool {
	return l.person() && (l.Remote || l.Type == "tty" || l.Type == "unspecified")
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
	out, err := sh("who")
	if err != nil {
		return nil
	}
	var ended []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] == "root" || !userRe.MatchString(f[0]) || !(strings.HasPrefix(f[1], "pts/") || strings.HasPrefix(f[1], "tty")) {
			continue
		}
		if !slices.Contains(peopleAccounts(), f[0]) {
			continue
		}
		_, _ = sh("pkill", "-HUP", "-t", f[1])
		_, _ = sh("pkill", "-KILL", "-t", f[1])
		ended = append(ended, f[0]+" ("+f[1]+")")
	}
	return ended
}

// lockSessions locks every graphical session: through logind first (the
// desktop's own locker), then, where after a few seconds neither logind
// reports the session locked nor a locker process runs (compositors and
// window managers without a logind aware locker, LXQt, LXDE …), with
// swaylock or i3lock started in the session. Returns the sessions locked
// that way.
func (a *Agent) lockSessions() int {
	sessions := graphicalSessions()
	if len(sessions) == 0 {
		return 0
	}
	if hasCmd("loginctl") {
		_, _ = sh("loginctl", "lock-sessions")
		time.Sleep(3 * time.Second) // lockers set LockedHint once they show
	}
	locked := map[string]bool{}
	for _, l := range loginSessions() {
		locked[l.ID] = l.Locked
	}
	procs := userProcs()
	n := 0
	for _, s := range sessions {
		if locked[s.id] || lockerRunning(procs[s.uid]) {
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
