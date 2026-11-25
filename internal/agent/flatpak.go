package agent

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Flatpak exists in two kinds of installations: the system one and one per
// user (~/.local/share/flatpak). User installations are read and changed by
// running flatpak as that user.

// flatpakUsers are the regular accounts with a user installation, or with a
// home if all is set (to add remotes for everyone).
func flatpakUsers(accts []api.Account, all bool) []api.Account {
	var res []api.Account
	for _, a := range accts {
		if a.System || a.UID < 1000 || !userRe.MatchString(a.Name) || !filepath.IsAbs(a.Home) {
			continue
		}
		if st, err := os.Stat(a.Home); err != nil || !st.IsDir() {
			continue
		}
		if !all {
			if _, err := os.Stat(filepath.Join(a.Home, ".local/share/flatpak")); err != nil {
				continue
			}
		}
		res = append(res, a)
	}
	return res
}

// flatpakCmd runs flatpak for the system installation (user nil) or as a user.
func flatpakCmd(user *api.Account, timeout time.Duration, args ...string) (string, error) {
	if user == nil {
		return run(timeout, "flatpak", append([]string{"--system"}, args...)...)
	}
	argv := append([]string{"-u", user.Name, "--", "env", "HOME=" + user.Home, "XDG_RUNTIME_DIR=/run/user/" + itoa(uint32(user.UID)), //nolint:gosec // uid >= 1000
		"flatpak", "--user"}, args...)
	return run(timeout, "runuser", argv...)
}

func flatpakInventory(accts []api.Account) ([]api.FlatpakApp, []api.FlatpakRemoteInfo) {
	if !hasCmd("flatpak") {
		return nil, nil
	}
	var apps []api.FlatpakApp
	var remotes []api.FlatpakRemoteInfo
	collect := func(user *api.Account, installation string) {
		if out, err := flatpakCmd(user, time.Minute, "list", "--app", "--columns=application,name,version,branch,origin"); err == nil {
			apps = append(apps, parseFlatpakApps(out, installation)...)
		}
		if out, err := flatpakCmd(user, time.Minute, "remotes", "--show-disabled", "--columns=name,url,title,options"); err == nil {
			remotes = append(remotes, parseFlatpakRemotes(out, installation)...)
		}
	}
	collect(nil, "system")
	for _, u := range flatpakUsers(accts, false) {
		collect(&u, u.Name)
	}
	return apps, remotes
}

func flatpakColumns(line string, n int) []string {
	f := strings.Split(line, "\t")
	for len(f) < n {
		f = append(f, "")
	}
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

func parseFlatpakApps(out, installation string) []api.FlatpakApp {
	var res []api.FlatpakApp
	for _, l := range strings.Split(out, "\n") {
		f := flatpakColumns(l, 5)
		if f[0] == "" || f[0] == "Application ID" {
			continue
		}
		res = append(res, api.FlatpakApp{ID: f[0], Name: f[1], Version: f[2], Branch: f[3], Origin: f[4], Installation: installation})
	}
	return res
}

func parseFlatpakRemotes(out, installation string) []api.FlatpakRemoteInfo {
	var res []api.FlatpakRemoteInfo
	for _, l := range strings.Split(out, "\n") {
		f := flatpakColumns(l, 4)
		if f[0] == "" || f[0] == "Name" {
			continue
		}
		res = append(res, api.FlatpakRemoteInfo{Name: f[0], URL: f[1], Title: f[2], Installation: installation,
			Disabled: strings.Contains(","+f[3]+",", ",disabled,")})
	}
	return res
}

// applyRemote adds or updates a remote in one installation.
func applyRemote(user *api.Account, r api.FlatpakRemote, existing []api.FlatpakRemoteInfo) error {
	var cur *api.FlatpakRemoteInfo
	for i := range existing {
		if existing[i].Name == r.Name {
			cur = &existing[i]
		}
	}
	if cur == nil {
		if _, err := flatpakCmd(user, 5*time.Minute, "remote-add", "--if-not-exists", r.Name, r.URL); err != nil {
			return err
		}
	} else if !strings.HasSuffix(r.URL, ".flatpakrepo") && strings.TrimSuffix(cur.URL, "/") != strings.TrimSuffix(r.URL, "/") {
		if _, err := flatpakCmd(user, time.Minute, "remote-modify", "--url="+r.URL, r.Name); err != nil {
			return err
		}
	}
	if cur == nil || cur.Disabled != r.Disabled {
		flag := "--enable"
		if r.Disabled {
			flag = "--disable"
		}
		if _, err := flatpakCmd(user, time.Minute, "remote-modify", flag, r.Name); err != nil {
			return err
		}
	}
	return nil
}
