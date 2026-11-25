package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Local password after SSO (api.Login.LocalPassword).
//
// pam_exec runs `limdm-agent pam-auth` with expose_authtok before pam_unix, so
// the hook receives the password the user typed:
//   - SSO confirmed within reverify_hours: the hook steps aside and pam_unix
//     checks the local password (offline, lock screen).
//   - otherwise: the hook runs the SSO device flow; on success the typed
//     password becomes the local password and the confirmation time is stored.
//
// The agent enforces the limits independently of the hook: it locks the local
// password of managed users whose confirmation is overdue, of every managed
// user when the server was unreachable for offline_lock_hours (then the whole
// device is locked through /etc/nologin), and always in pure SSO mode.

const (
	ssoFile     = stateDir + "/sso-verified.json" // username -> last SSO confirmation
	offlineText = "This device is locked because it could not reach the LiMDM server for too long.\n" +
		"Connect it to the network; it unlocks automatically once the server is reachable.\n"
	minLocalPassword = 14
)

// pamPolicy is what the PAM hook reads (root only file).
type pamPolicy struct {
	api.Login
	OfflineLockHours int `json:"offline_lock_hours,omitempty"`
}

func readPAMPolicy() (pamPolicy, bool) {
	var p pamPolicy
	b, err := os.ReadFile(loginFile)
	if err != nil || json.Unmarshal(b, &p) != nil || !p.Enabled {
		return p, false
	}
	return p, true
}

func readSSO() map[string]time.Time {
	m := map[string]time.Time{}
	if b, err := os.ReadFile(ssoFile); err == nil {
		_ = json.Unmarshal(b, &m) // corrupt file: everybody needs SSO again
	}
	return m
}

// forgetSSO drops the confirmation of a removed user.
func forgetSSO(user string) {
	m := readSSO()
	if _, ok := m[user]; !ok {
		return
	}
	delete(m, user)
	if b, err := json.Marshal(m); err == nil {
		_, _ = writeIfChanged(ssoFile, string(b), 0o600)
	}
}

// deviceLocked: locked from the console or by the compliance policy. Local
// passwords are locked too, so screen lockers and sudo without pam_nologin
// cannot be used to get back in.
func deviceLocked() bool {
	s := readFile(nologinFile)
	return s == nologinText || strings.HasPrefix(s, lostPrefix)
}

func inLostMode() bool { return strings.HasPrefix(readFile(nologinFile), lostPrefix) }

func recordSSO(user string, at time.Time) error {
	m := readSSO()
	m[user] = at.UTC()
	b, _ := json.Marshal(m)
	_, err := writeIfChanged(ssoFile, string(b), 0o600)
	return err
}

// ssoDue reports whether user needs an SSO confirmation before the local password works.
func ssoDue(p pamPolicy, user string, now time.Time) bool {
	t, ok := readSSO()[user]
	return ssoDueAt(p, t, ok, serverOffline(now), now)
}

// ssoDueAt: a confirmation is due without one, after ReverifyHours, and
// offline (the server unreachable) only after the grace period on top, so
// travellers and login screens without network are not locked out.
func ssoDueAt(p pamPolicy, last time.Time, confirmed, offline bool, now time.Time) bool {
	if !p.LocalPassword || !confirmed {
		return true
	}
	age, reverify := now.Sub(last), time.Duration(p.ReverifyHours)*time.Hour
	if age <= reverify {
		return false
	}
	return !offline || age > reverify+p.Grace()
}

// ssoLockWanted: the local password of a managed user must be locked, so
// only an SSO confirmation at the login screen lets them in. Session mode:
// never confirmed, or overdue beyond the grace period while the device is
// online. Login mode: whenever a confirmation is due.
func ssoLockWanted(p pamPolicy, user string, now time.Time) bool {
	if !p.Session() {
		return ssoDue(p, user, now)
	}
	t, ok := readSSO()[user]
	return sessionLock(p, t, ok, serverOffline(now), now)
}

func sessionLock(p pamPolicy, last time.Time, confirmed, offline bool, now time.Time) bool {
	if !confirmed {
		return true
	}
	return !offline && now.Sub(last) > time.Duration(p.ReverifyHours+p.GraceHours)*time.Hour
}

// sessionDue: the desktop app should ask for a confirmation in the session.
func sessionDue(p pamPolicy, last time.Time, now time.Time) bool {
	return now.Sub(last) > time.Duration(p.ReverifyHours)*time.Hour
}

// serverOffline: the agent has not reached the LiMDM server for 30 minutes.
func serverOffline(now time.Time) bool {
	var st struct {
		LastContact time.Time `json:"last_contact"`
	}
	b, err := os.ReadFile(stateFile)
	if err != nil || json.Unmarshal(b, &st) != nil || st.LastContact.IsZero() {
		return false // unknown: no grace
	}
	return now.Sub(st.LastContact) > 30*time.Minute
}

// lastContactOverdue reads the agent state; used by the hook before the agent
// had a chance to lock after a long time switched off.
func lastContactOverdue(p pamPolicy, now time.Time) bool {
	if p.OfflineLockHours <= 0 {
		return false
	}
	var st struct {
		LastContact time.Time `json:"last_contact"`
	}
	b, err := os.ReadFile(stateFile)
	if err != nil || json.Unmarshal(b, &st) != nil || st.LastContact.IsZero() {
		return false
	}
	return now.Sub(st.LastContact) > time.Duration(p.OfflineLockHours)*time.Hour
}

func checkLocalPassword(user, pw string) error {
	switch {
	case len(pw) < minLocalPassword:
		return fmt.Errorf("choose a password with at least %d characters", minLocalPassword)
	case strings.ContainsAny(pw, "\n\x00"):
		return fmt.Errorf("the password contains invalid characters")
	case strings.Contains(strings.ToLower(pw), strings.ToLower(user)):
		return fmt.Errorf("the password must not contain the user name")
	}
	return nil
}

func setLocalPassword(user, pw string) error {
	cmd := commandWithStdin(user + ":" + pw + "\n")
	out, err := cmd("chpasswd")
	if err != nil {
		return fmt.Errorf("chpasswd: %s", lastLines(out, 1))
	}
	return nil
}

// readAuthtok reads what pam_exec expose_authtok writes to stdin (NUL terminated).
func readAuthtok() string {
	s, _ := bufio.NewReader(os.Stdin).ReadString(0)
	return strings.TrimRight(s, "\x00\r\n")
}

// passwordLocked reports whether the shadow entry of user is locked ("!").
func passwordLocked(user string) bool {
	for _, f := range shadowEntries() {
		if f[0] == user {
			return strings.HasPrefix(f[1], "!") || f[1] == "*"
		}
	}
	return false
}

// syncPasswordLocks applies the rules above to every managed user.
func (a *Agent) syncPasswordLocks() {
	p, ok := readPAMPolicy()
	if !ok {
		return
	}
	now := time.Now()
	for user := range readUsers() {
		if a.state.UserLocked[user] {
			continue // locked by IT; only user_unlock releases it
		}
		want := a.state.OfflineLocked || deviceLocked() || ssoLockWanted(p, user, now)
		has := passwordLocked(user)
		switch {
		case want && !has:
			if _, err := sh("usermod", "-L", user); err == nil {
				a.event("local password of %s locked until the next SSO confirmation", user)
			}
		case !want && has:
			// fails for accounts that never had a password; they keep needing SSO
			if _, err := sh("usermod", "-U", user); err == nil {
				a.event("local password of %s unlocked", user)
			}
		}
	}
}

// enforceOffline locks the device after offline_lock_hours without server
// contact and unlocks it once a check in succeeds.
func (a *Agent) enforceOffline(contact bool) {
	now := time.Now().UTC()
	if contact || a.state.LastContact.IsZero() {
		a.state.LastContact = now // zero: first start with this feature, do not lock right away
	}
	h := a.pol.OfflineLockHours
	overdue := h > 0 && now.Sub(a.state.LastContact) > time.Duration(h)*time.Hour
	switch {
	case overdue && !a.state.OfflineLocked:
		a.state.OfflineLocked = true
		if !deviceLocked() { // a manual lock and lost mode keep their own message
			if _, err := writeIfChanged(nologinFile, offlineText, 0o644); err != nil {
				a.event("offline lock: %v", err)
			}
		}
		_, _ = sh("loginctl", "lock-sessions")
		a.event("device locked: no server contact for more than %d hours", h)
	case !overdue && a.state.OfflineLocked:
		a.state.OfflineLocked = false
		if readFile(nologinFile) == offlineText {
			os.Remove(nologinFile)
		}
		a.event("device unlocked: server reachable again")
	}
	a.syncPasswordLocks()
}

// annotateSSO marks managed accounts in the inventory.
func annotateSSO(accts []api.Account) {
	users, seen := readUsers(), readSSO()
	for i := range accts {
		if _, ok := users[accts[i].Name]; !ok {
			continue
		}
		accts[i].SSO = true
		if t, ok := seen[accts[i].Name]; ok {
			accts[i].LastSSO = &t
		}
		accts[i].PwdLocked = passwordLocked(accts[i].Name)
	}
}
