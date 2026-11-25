package agent

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Remote lock on every desktop.
//
// A lock has three parts, because each alone leaves a way in:
//   - /etc/nologin refuses new logins (pam_nologin, also SSH).
//   - The local passwords of all people's accounts are locked, so neither a
//     new login nor the screen locker accepts them. The accounts LiMDM
//     locked are remembered; unlock only releases those.
//   - Running sessions are locked: desktop environments through logind
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
	n := a.lockSessions()
	return "logins blocked, local passwords of " + strings.Join(locked, ", ") + " locked, " + strconv.Itoa(n) + " sessions locked", err
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

// lockSessions locks every running graphical session and returns how many
// compositor or window manager sessions needed a locker of their own.
func (a *Agent) lockSessions() int {
	_, _ = sh("loginctl", "lock-sessions") // desktop environments
	n := 0
	for _, s := range idleSessions() {
		if s.screenLocked {
			continue
		}
		var argv []string
		switch {
		case s.kind == "wayland" && hasCmd("swaylock"):
			argv = []string{"swaylock", "-f", "-c", "000000"}
		case s.kind == "x11" && hasCmd("i3lock"):
			argv = []string{"i3lock", "-c", "000000"}
		default:
			a.event("cannot lock the %s session of %s: no screen locker installed", s.kind, s.user)
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

// enforceDeviceLock keeps sessions locked while the device is locked; run
// every minute, so ending the locker does not help.
func (a *Agent) enforceDeviceLock() {
	if readFile(nologinFile) == nologinText {
		a.lockSessions()
	}
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
