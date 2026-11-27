package agent

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	// Keys live outside the home: root never writes into a directory the
	// user controls (a symlinked ~/.ssh would redirect the write).
	keysDir    = "/etc/ssh/limdm_authorized_keys"
	keysDropin = "/etc/ssh/sshd_config.d/00-limdm-keys.conf" // first: sshd keeps the first AuthorizedKeysFile
)

// localUserState is what LiMDM did to a declared account, so that only its
// own changes are undone.
type localUserState struct {
	Groups []string `json:"groups,omitempty"` // supplementary groups the declaration added
	Locked bool     `json:"locked,omitempty"` // locked by the declaration
}

// applyLocalUsers creates the declared accounts and keeps shell, groups,
// lock and SSH keys in line. Accounts dropped from the declaration are
// locked, never deleted; the imperative user_* commands keep working.
func (a *Agent) applyLocalUsers(users []api.LocalUser) error {
	if len(users) == 0 && len(a.state.LocalUsers) == 0 {
		return nil
	}
	if a.state.LocalUsers == nil {
		a.state.LocalUsers = map[string]localUserState{}
	}
	var errs []error
	keys := map[string]string{}
	for _, u := range users {
		if err := a.applyLocalUser(u); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u.Name, err))
			continue
		}
		if len(u.AuthorizedKeys) > 0 {
			keys[u.Name] = managedHeader + strings.Join(u.AuthorizedKeys, "\n") + "\n"
		}
	}
	for name, st := range a.state.LocalUsers {
		if slices.ContainsFunc(users, func(u api.LocalUser) bool { return u.Name == name }) {
			continue
		}
		if _, err := user.Lookup(name); err == nil && !st.Locked {
			if _, err := sh("usermod", "-L", "-e", "1", name); err != nil {
				errs = append(errs, err)
				continue
			}
			a.event("locked local user %s (no longer declared)", name)
		}
		delete(a.state.LocalUsers, name)
	}
	errs = append(errs, a.syncAuthorizedKeys(keys))
	return errors.Join(errs...)
}

func (a *Agent) applyLocalUser(u api.LocalUser) error {
	shell := firstNonEmpty(u.Shell, "/bin/bash")
	if !exists(shell) {
		return fmt.Errorf("shell %s does not exist", shell)
	}
	st := a.state.LocalUsers[u.Name]
	acct, err := user.Lookup(u.Name)
	if err != nil {
		args := []string{"-m", "-s", shell}
		if u.UID > 0 {
			args = append(args, "-u", strconv.Itoa(u.UID))
		}
		if u.FullName != "" {
			args = append(args, "-c", u.FullName)
		}
		if _, err := sh("useradd", append(args, "--", u.Name)...); err != nil {
			return err
		}
		a.event("created local user %s (declared)", u.Name)
		if acct, err = user.Lookup(u.Name); err != nil {
			return err
		}
	} else if u.UID > 0 && acct.Uid != strconv.Itoa(u.UID) {
		a.event("local user %s has uid %s, declared %d: not renumbered", u.Name, acct.Uid, u.UID)
	}
	if cur := passwdShell(readFile("/etc/passwd"), u.Name); cur != "" && cur != shell {
		if _, err := sh("usermod", "-s", shell, u.Name); err != nil {
			return err
		}
		a.event("shell of %s set to %s", u.Name, shell)
	}
	// groups: add the declared ones, remove only those an earlier declaration added
	have, _ := acct.GroupIds()
	var names []string
	for _, gid := range have {
		if g, err := user.LookupGroupId(gid); err == nil {
			names = append(names, g.Name)
		}
	}
	for _, g := range u.Groups {
		if !slices.Contains(names, g) {
			if _, err := sh("usermod", "-aG", g, u.Name); err != nil {
				return err
			}
			a.event("added %s to group %s", u.Name, g)
		}
	}
	for _, g := range st.Groups {
		if !slices.Contains(u.Groups, g) && slices.Contains(names, g) {
			if _, err := sh("gpasswd", "-d", u.Name, g); err != nil {
				return err
			}
			a.event("removed %s from group %s", u.Name, g)
		}
	}
	st.Groups = slices.Clone(u.Groups)
	switch {
	case u.Locked && !st.Locked:
		if _, err := sh("usermod", "-L", "-e", "1", u.Name); err != nil {
			return err
		}
		_, _ = sh("loginctl", "terminate-user", u.Name)
		st.Locked = true
		a.event("locked local user %s (declared)", u.Name)
	case !u.Locked && st.Locked:
		if _, err := sh("usermod", "-e", "", u.Name); err != nil {
			return err
		}
		_, _ = sh("usermod", "-U", u.Name) // fails without a password: key only accounts stay password locked
		st.Locked = false
		a.event("unlocked local user %s (declared)", u.Name)
	}
	a.state.LocalUsers[u.Name] = st
	return nil
}

// passwdShell is the login shell of name in /etc/passwd content.
func passwdShell(accountDB, name string) string {
	for _, l := range strings.Split(accountDB, "\n") {
		if f := strings.Split(l, ":"); len(f) == 7 && f[0] == name {
			return f[6]
		}
	}
	return ""
}

// syncAuthorizedKeys keeps one root owned key file per declared user and
// the sshd drop in that reads them besides the users' own files.
func (a *Agent) syncAuthorizedKeys(keys map[string]string) error {
	if len(keys) == 0 && !exists(keysDir) && !exists(keysDropin) {
		return nil
	}
	_, e1 := syncManaged(keysDir, "", "", keys)
	dropin := ""
	if len(keys) > 0 {
		dropin = managedHeader + "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 " + keysDir + "/%u\n"
	} else {
		if exists(keysDir) {
			e1 = errors.Join(e1, os.Remove(keysDir))
		}
	}
	changed, e2 := writeOrRemove(keysDropin, dropin, 0o600)
	if e2 == nil && changed && sshdBinary() != "" {
		if _, err := sh(sshdBinary(), "-t"); err != nil {
			_, _ = writeOrRemove(keysDropin, "", 0o600)
			return errors.Join(e1, err)
		}
		for _, unit := range []string{"ssh", "sshd"} {
			_ = svc("reload-or-restart", unit)
		}
	}
	return errors.Join(e1, e2)
}
