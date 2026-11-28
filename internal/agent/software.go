package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// ---- snaps and AppImages in the inventory ----

func snapInventory() []api.SnapApp {
	if !hasCmd("snap") {
		return nil
	}
	out, err := sh("snap", "list", "--unicode=never", "--color=never")
	if err != nil {
		return nil
	}
	return parseSnapList(out)
}

// parseSnapList reads "Name Version Rev Tracking Publisher Notes".
func parseSnapList(out string) []api.SnapApp {
	var res []api.SnapApp
	for i, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 5 {
			continue
		}
		s := api.SnapApp{Name: f[0], Version: f[1], Publisher: strings.TrimSuffix(f[4], "*")}
		if len(f) > 5 && f[5] != "-" {
			s.Notes = f[5]
		}
		res = append(res, s)
	}
	return res
}

// appImageInventory finds AppImage files where people keep them: below each
// home (four levels), /opt (three) and /usr/local/bin. Bounded to 200.
func appImageInventory() []api.AppImage {
	var res []api.AppImage
	roots := map[string]int{"/opt": 3, "/usr/local/bin": 1}
	homes, _ := filepath.Glob("/home/*")
	for _, h := range append(homes, "/root") {
		roots[h] = 4
	}
	for root, depth := range roots {
		base := strings.Count(root, "/")
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || len(res) >= 200 {
				return filepath.SkipDir
			}
			if d.IsDir() {
				if strings.Count(p, "/")-base >= depth || (p != root && strings.HasPrefix(d.Name(), ".") && d.Name() != ".local") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".appimage") || d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			ai := api.AppImage{Path: p, SizeMB: info.Size() >> 20}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil {
					ai.Owner = u.Username
				}
			}
			res = append(res, ai)
			return nil
		})
	}
	return res
}

// ---- software_remove ----

// removeSoftware removes a package, snap, Flatpak (system or a user's) or
// AppImage file that IT picked in the console.
func (a *Agent) removeSoftware(payload string) (string, error) {
	var r api.SoftwareRemove
	if err := json.Unmarshal([]byte(payload), &r); err != nil {
		return "", err
	}
	if err := r.Validate(); err != nil {
		return "", err
	}
	switch r.Kind {
	case "package":
		if !a.host.isInstalled(r.Name) {
			return "", fmt.Errorf("package %s is not installed", r.Name)
		}
		if protectedPackage(r.Name) {
			return "", fmt.Errorf("%s is needed by LiMDM or the system and is not removed", r.Name)
		}
		if err := a.host.remove(r.Name); err != nil {
			return "", err
		}
	case "snap":
		if _, err := run(30*time.Minute, "snap", "remove", "--purge", r.Name); err != nil {
			return "", err
		}
	case "flatpak":
		if r.Installation == "system" {
			if _, err := flatpakCmd(nil, 30*time.Minute, "uninstall", "-y", "--noninteractive", "--system", r.Name); err != nil {
				return "", err
			}
		} else if _, err := run(30*time.Minute, "runuser", "-u", r.Installation, "--", "flatpak", "uninstall", "-y", "--noninteractive", "--user", r.Name); err != nil {
			return "", err
		}
	case "appimage":
		info, err := os.Lstat(r.Name)
		if err != nil || !info.Mode().IsRegular() {
			return "", errors.New("no such AppImage file")
		}
		if err := os.Remove(r.Name); err != nil {
			return "", err
		}
	}
	a.event("removed %s %s on IT's request", r.Kind, r.Name)
	return "removed " + r.Kind + " " + r.Name, nil
}

// archKernel matches the kernel packages of Arch and its derivatives:
// linux, linux-lts, linux-zen, linux-hardened, linux-rt, Manjaro's linux612
// and CachyOS' linux-cachyos with its variants (not headers or modules).
var archKernel = regexp.MustCompile(`^linux(\d{2,3}|-lts|-zen|-hardened|-rt|-cachyos(-(lts|bore|eevdf|bmq|rc|rt-bore|server|hardened|deckify))?)?$`)

// protectedPackage: removing these would take down the agent or the system.
func protectedPackage(name string) bool {
	switch name {
	case "limdm-agent", "systemd", "dpkg", "apt", "rpm", "dnf", "pacman", "bash", "coreutils", "sudo", "openssh-server", "openssh", "linux-image-generic", "kernel", "kernel-core", "glibc", "libc6", "osquery", "cryptsetup":
		return true
	}
	return archKernel.MatchString(name)
}
