package agent

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	dnf5Hold   = "/etc/dnf/libdnf5.conf.d/60-limdm-hold.conf"
	pacmanConf = "/etc/pacman.conf"
)

// updateDay reports whether now belongs to one of days (empty: every day).
// A window across midnight belongs to the day it started on.
func updateDay(now time.Time, window string, days []string) bool {
	if len(days) == 0 {
		return true
	}
	if from, to, ok := strings.Cut(window, "-"); ok && from > to && now.Format("15:04") < to {
		now = now.AddDate(0, 0, -1) // after midnight in a window that started yesterday
	}
	return slices.Contains(days, api.Weekdays[now.Weekday()])
}

// updateGap is how long pending security updates are tolerated after the
// last run: until the next window, which is a week away at most with days.
func updateGap(u api.Updates) time.Duration {
	if len(u.Days) > 0 {
		return 8 * 24 * time.Hour
	}
	return 48 * time.Hour
}

// applyHolds keeps the declared packages at their version and releases the
// ones LiMDM held before. Alpine is left out: apk pins are versions in
// /etc/apk/world, not holds.
func (a *Agent) applyHolds(hold []string) error {
	hold = slices.Sorted(slices.Values(hold))
	switch a.host.family {
	case "debian":
		if len(hold) == 0 && len(a.state.Held) == 0 {
			return nil
		}
		out, err := sh("apt-mark", "showhold")
		if err != nil {
			return err
		}
		cur := strings.Fields(out)
		var add, drop []string
		for _, n := range hold {
			if !slices.Contains(cur, n) && a.host.isInstalled(n) {
				add = append(add, n)
			}
		}
		for _, n := range a.state.Held {
			if !slices.Contains(hold, n) && slices.Contains(cur, n) {
				drop = append(drop, n)
			}
		}
		var errs []error
		if len(add) > 0 {
			_, err := sh("apt-mark", append([]string{"hold", "--"}, add...)...)
			errs = append(errs, err)
			if err == nil {
				a.event("packages held: %v", add)
			}
		}
		if len(drop) > 0 {
			_, err := sh("apt-mark", append([]string{"unhold", "--"}, drop...)...)
			errs = append(errs, err)
			if err == nil {
				a.event("packages released: %v", drop)
			}
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
		a.state.Held = hold
	case "fedora":
		content := ""
		if len(hold) > 0 {
			content = managedHeader + "[main]\nexcludepkgs=" + strings.Join(hold, ",") + "\n"
		}
		_, e1 := writeOrRemove(dnf5Hold, content, 0o644)
		var e2 error
		if exists(dnfConf) {
			var owned string
			if owned, e2 = syncINIKey(dnfConf, "main", "excludepkgs", strings.Join(hold, ","), a.state.DNFExclude); e2 == nil {
				a.state.DNFExclude = owned
			}
		}
		return errors.Join(e1, e2)
	case "arch":
		if !exists(pacmanConf) {
			return nil
		}
		owned, err := syncINIKey(pacmanConf, "options", "IgnorePkg", strings.Join(hold, " "), a.state.PacmanIgnore)
		if err == nil {
			a.state.PacmanIgnore = owned
		}
		return err
	case "alpine":
		if len(hold) > 0 {
			return errors.New("hold is not supported on Alpine; pin versions in /etc/apk/world")
		}
	}
	return nil
}

// autoremove removes packages nothing depends on any more, old kernels
// included (apt keeps the running and the newest kernel, dnf keeps
// installonly_limit kernels).
func (h *host) autoremove() (string, error) {
	h.pkgMu.Lock()
	defer h.pkgMu.Unlock()
	switch h.family {
	case "debian":
		return run(30*time.Minute, "apt-get", "autoremove", "--purge", "-y", "-q", "-o", "DPkg::Lock::Timeout=300")
	case "fedora":
		return run(30*time.Minute, "dnf", "autoremove", "-y", "-q")
	case "arch":
		orphans, err := run(time.Minute, "pacman", "-Qdtq")
		if err != nil || strings.TrimSpace(orphans) == "" {
			return "", nil // pacman -Qdtq exits 1 when there are none
		}
		return run(30*time.Minute, "pacman", append([]string{"-Rns", "--noconfirm", "--"}, strings.Fields(orphans)...)...)
	}
	return "", nil // apk removes unneeded dependencies itself
}

// snapTimer turns the update window into a snapd refresh.timer value:
// "02:00-05:00" or "mon,02:00-05:00,,fri,02:00-05:00".
func snapTimer(u api.Updates) string {
	if len(u.Days) == 0 {
		return u.Window
	}
	parts := make([]string, 0, len(u.Days))
	for _, d := range u.Days {
		parts = append(parts, d+","+u.Window)
	}
	return strings.Join(parts, ",,")
}

// applySnapRefresh holds snap refreshes or moves them into the window, and
// undoes what LiMDM set when the declaration no longer asks for it.
func (a *Agent) applySnapRefresh(u api.Updates) error {
	if !hasCmd("snap") {
		return nil
	}
	want := ""
	switch u.SnapRefresh {
	case "hold":
		want = "hold"
	case "window":
		want = "timer=" + snapTimer(u)
	}
	if want == a.state.SnapRefresh {
		return nil
	}
	var err error
	switch prev := a.state.SnapRefresh; {
	case prev == "hold":
		_, err = sh("snap", "refresh", "--unhold")
	case strings.HasPrefix(prev, "timer="):
		_, err = sh("snap", "unset", "system", "refresh.timer")
	}
	if err != nil {
		return err
	}
	switch {
	case want == "hold":
		_, err = sh("snap", "refresh", "--hold")
	case want != "":
		_, err = sh("snap", "set", "system", "refresh."+want)
	}
	if err != nil {
		a.state.SnapRefresh = ""
		return err
	}
	a.state.SnapRefresh = want
	a.event("snap refresh: %s", firstNonEmpty(want, "default"))
	return nil
}
