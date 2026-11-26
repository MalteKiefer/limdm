package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Local accounts IT manages remotely: create (optionally as admin), grant
// and revoke admin rights, lock, unlock, reset the password and delete.
// They work with or without SSO. Accounts managed through the device's
// desktop user list are changed there, not with these commands, because the
// list is applied again at every check in.

func (a *Agent) userCommand(typ, payload string) (string, error) {
	var u api.UserCommand
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		return "", err
	}
	if err := u.Validate(typ); err != nil {
		return "", err
	}
	if _, managed := readUsers()[u.Username]; managed && a.policy().Login.Enabled && typ != "user_lock" && typ != "user_unlock" {
		return "", errors.New(u.Username + " is managed through the device's desktop user list; change it there")
	}
	lu, lookupErr := user.Lookup(u.Username)
	exists := lookupErr == nil
	if typ != "user_create" && !exists {
		return "", errors.New("no local account " + u.Username)
	}
	// an account with uid 0 is root under another name; commands of the
	// helpdesk role (NoAdmin, signed by the server) never touch accounts
	// that can reach root
	if why := privileged(u.Username); typ != "user_create" && why != "" && (u.NoAdmin || lu.Uid == "0") {
		return "", errors.New("refused: " + why + "; accounts with admin rights are changed by an admin")
	}
	switch typ {
	case "user_create":
		if exists {
			return "", errors.New("account " + u.Username + " exists already")
		}
		if _, err := sh("useradd", "-m", "-s", "/bin/bash", "-c", u.FullName, u.Username); err != nil {
			return "", err
		}
		if err := setPassword(u.Username, u.Password); err != nil {
			return "", err
		}
		out := "created " + u.Username + "; the password must be changed at the first login"
		if u.Admin {
			if _, err := sh("usermod", "-aG", a.host.adminGroup(), u.Username); err != nil {
				return out, err
			}
			out += ", admin rights granted"
		}
		a.event("created local user %s (admin %v)", u.Username, u.Admin)
		return out, nil
	case "user_admin":
		if u.Admin {
			if _, err := sh("usermod", "-aG", a.host.adminGroup(), u.Username); err != nil {
				return "", err
			}
			a.event("granted admin to %s", u.Username)
			return "admin rights granted to " + u.Username, nil
		}
		var removed []string
		for _, g := range adminGroups {
			if slices.Contains(groupMembers(g), u.Username) {
				if _, err := sh("gpasswd", "-d", u.Username, g); err != nil {
					return "", err
				}
				removed = append(removed, g)
			}
		}
		out := "admin rights revoked from " + u.Username + " (groups: " + strings.Join(removed, ", ") + ")"
		if rules := sudoersMentions(u.Username); len(rules) > 0 {
			out += "; still named in " + strings.Join(rules, ", ") + ", edit these with a script"
		}
		a.event("revoked admin from %s", u.Username)
		return out, nil
	case "user_lock":
		if _, err := sh("usermod", "-L", "-e", "1", u.Username); err != nil {
			return "", err
		}
		if a.state.UserLocked == nil {
			a.state.UserLocked = map[string]bool{}
		}
		a.state.UserLocked[u.Username] = true
		_, _ = sh("loginctl", "terminate-user", u.Username)
		a.event("locked user %s", u.Username)
		return "account " + u.Username + " locked and its sessions ended", nil
	case "user_unlock":
		if _, err := sh("usermod", "-U", "-e", "", u.Username); err != nil {
			return "", err
		}
		delete(a.state.UserLocked, u.Username)
		a.syncPasswordLocks() // the SSO rules may keep a managed user's password locked
		a.event("unlocked user %s", u.Username)
		return "account " + u.Username + " unlocked", nil
	case "user_password":
		if err := setPassword(u.Username, u.Password); err != nil {
			return "", err
		}
		a.event("password of %s reset", u.Username)
		return "password of " + u.Username + " reset; it must be changed at the next login", nil
	case "user_delete":
		_, _ = sh("loginctl", "terminate-user", u.Username)
		args := []string{u.Username}
		if !u.KeepHome {
			args = []string{"-r", u.Username}
		}
		if _, err := sh("userdel", args...); err != nil {
			return "", err
		}
		forgetSSO(u.Username)
		delete(a.state.UserLocked, u.Username)
		a.event("deleted user %s (home kept %v)", u.Username, u.KeepHome)
		return "account " + u.Username + " deleted", nil
	}
	return "", errors.New("unknown user command")
}

// setPassword sets a password through chpasswd's standard input (never in
// argv) and makes the user choose a new one at the next login.
func setPassword(name, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "chpasswd")
	cmd.Stdin = strings.NewReader(name + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New("chpasswd: " + strings.TrimSpace(string(out)))
	}
	_, err := sh("chage", "-d", "0", name)
	return err
}

// sudoersMentions lists sudoers files that name the user or, as %group,
// one of the given groups.
func sudoersMentions(name string, groups ...string) []string {
	var files []string
	for _, f := range append([]string{"/etc/sudoers"}, sudoersFiles()...) {
		if sudoersNames(readFile(f), name, groups...) {
			files = append(files, f)
		}
	}
	return files
}

// sudoersNames reports whether a sudoers text names the user (in a user
// list, alias or Defaults:user) or %group of one of the groups.
func sudoersNames(text, name string, groups ...string) bool {
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		for _, w := range strings.FieldsFunc(t, func(r rune) bool { return strings.ContainsRune(" \t,:=!()\\", r) }) {
			if w == name || (strings.HasPrefix(w, "%") && slices.Contains(groups, w[1:])) {
				return true
			}
		}
	}
	return false
}

// rootEquivalentGroups reach root without sudo: a container or VM daemon
// that mounts / for its members, or raw access to the disks.
var rootEquivalentGroups = []string{"docker", "lxd", "incus-admin", "libvirt", "disk"}

// privileged says why an account can reach root: uid 0, membership in an
// admin or root equivalent group or a sudoers rule for the account or one of its groups (which
// covers NOPASSWD rules). Empty means none of these.
func privileged(name string) string {
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	if u.Uid == "0" {
		return name + " has uid 0"
	}
	var groups []string
	if ids, err := u.GroupIds(); err == nil {
		for _, id := range ids {
			if g, err := user.LookupGroupId(id); err == nil {
				groups = append(groups, g.Name)
			}
		}
	}
	for _, g := range slices.Concat(adminGroups, rootEquivalentGroups) {
		if slices.Contains(groups, g) || slices.Contains(groupMembers(g), name) {
			return name + " is a member of " + g
		}
	}
	if files := sudoersMentions(name, groups...); len(files) > 0 {
		return name + " has sudo rules in " + strings.Join(files, ", ")
	}
	return ""
}

func sudoersFiles() []string {
	m, _ := filepath.Glob("/etc/sudoers.d/*")
	return m
}
