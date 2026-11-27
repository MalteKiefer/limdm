package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// errUnsupported: the distribution has no such update source or action.
var errUnsupported = errors.New("not supported on this distribution")

// maintenance runs every update rule in its window: once a day, or with
// rings once per wave of the device's ring. A run that changed nothing is
// logged as "no updates", never as installed.
func (a *Agent) maintenance(now time.Time) {
	u := a.pol.Updates
	if a.state.UpdateRuns == nil {
		a.state.UpdateRuns = map[string]api.UpdateRun{}
	}
	installed, inWin := false, false
	for _, r := range u.EffectiveRules() {
		if r.Mode != "install" || !inWindow(now, r.Window) || !updateDay(now, r.Window, r.Days) {
			continue
		}
		inWin = true
		last := a.state.UpdateRuns[r.Source]
		if last.At.IsZero() {
			last.At = a.state.LastUpdateRun // the run before rules existed
		}
		due, wave := runDue(r, last, a.state.UpdateGate, now)
		if !due {
			continue
		}
		run := a.runSource(r, now, wave)
		a.state.UpdateRuns[r.Source] = run
		a.state.LastUpdateRun = run.At
		installed = installed || run.Result == "installed"
	}
	if installed && u.Autoremove {
		if out, err := a.host.autoremove(); err != nil {
			a.problem(api.TypeUpdates, "autoremove failed: %v", err)
		} else if strings.TrimSpace(out) != "" {
			a.event("autoremove: %s", lastLines(out, 3))
		}
	}
	// Schedule once: a new shutdown call would replace and postpone the pending one.
	if inWin && u.Reboot && !a.rebootPending(now) && a.host.rebootRequired() {
		if err := a.scheduleReboot(now, u.RebootDefer); err != nil {
			a.problem(api.TypeUpdates, "reboot after updates: %v", err)
		}
	}
}

// runDue decides whether a rule runs now (inside its window): once a day,
// or with rings once per wave of an open ring, a failed run again a day
// later. It returns the wave the run belongs to.
func runDue(r api.UpdateRule, last api.UpdateRun, g *api.UpdateGate, now time.Time) (bool, int) {
	daily := now.Sub(last.At) > 20*time.Hour
	if !r.Rings || g == nil { // no ring: no gate
		return daily, 0
	}
	return g.Open && (last.Wave < g.Wave || last.Result == "failed" && daily), g.Wave
}

// runSource installs one source and tells honestly what happened: the
// package versions before and after decide between installed and no
// updates, not the exit code.
func (a *Agent) runSource(r api.UpdateRule, now time.Time, wave int) api.UpdateRun {
	run := api.UpdateRun{Source: r.Source, At: now.Round(0), Wave: wave} // wall clock: the monotonic one stops during suspend
	before := a.host.pkgVersions()
	out, err := a.host.installSource(r)
	out = cleanUpgradeOutput(out)
	switch {
	case errors.Is(err, errUnsupported):
		run.Result, run.Detail = "unsupported", r.Source+" updates are "+err.Error()
		a.event("updates (%s): %s", r.Source, run.Detail)
	case err != nil:
		run.Result, run.Detail = "failed", truncate(strings.TrimSpace(lastLines(out, 3)+"\n"+err.Error()), 500)
		a.problem(api.TypeUpdates, "updates (%s) failed: %v", r.Source, err)
	default:
		if r.Source == api.SourceFlatpak {
			run.Count = len(flatpakDoneRe.FindAllString(out, -1))
		} else {
			run.Count = changedPackages(before, a.host.pkgVersions())
		}
		run.Result = "no_updates"
		if run.Count > 0 {
			run.Result = "installed"
		}
		run.Detail = truncate(lastLines(out, 3), 500)
		if run.Count > 0 {
			a.event("updates (%s): %d updated", r.Source, run.Count)
		} else {
			a.event("updates (%s): no updates", r.Source)
		}
	}
	return run
}

// flatpakDoneRe matches the numbered lines of flatpak update ("1. [✓] org.x …").
var flatpakDoneRe = regexp.MustCompile(`(?m)^\s*[0-9]+\.\s+\[`)

// mailNoiseRe: unattended-upgrade complains when it cannot mail its report.
var mailNoiseRe = regexp.MustCompile(`(?i)(send mail|sendmail|mailx|/usr/bin/mail)`)

// cleanUpgradeOutput drops the mail noise of unattended-upgrade.
func cleanUpgradeOutput(out string) string {
	lines := strings.Split(out, "\n")
	return strings.Join(slices.DeleteFunc(lines, mailNoiseRe.MatchString), "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// pkgVersions maps "name arch" to the installed version.
func (h *host) pkgVersions() map[string]string {
	pkgs, _, err := h.installedPackages()
	if err != nil {
		return nil
	}
	m := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		m[p.Name+" "+p.Arch] = p.Version
	}
	return m
}

// changedPackages counts packages that are new or have another version.
func changedPackages(before, after map[string]string) int {
	if before == nil || after == nil {
		return 0
	}
	n := 0
	for k, v := range after {
		if old, ok := before[k]; !ok || old != v {
			n++
		}
	}
	return n
}

// installSource installs the updates of one source. OS updates use the
// plain full upgrade unless third party updates are pending; then only the
// distribution's packages (apt: name=version, dnf and zypper: their repos).
// Arch, Alpine and rolling openSUSE have no third party source the agent
// can separate.
func (h *host) installSource(r api.UpdateRule) (string, error) {
	switch r.Source {
	case api.SourceOSSecurity:
		return h.upgrade(true)
	case api.SourceFlatpak:
		if !hasCmd("flatpak") {
			return "", errors.New("flatpak is not installed")
		}
		return flatpakUpgrade()
	}
	if h.family == "arch" || h.family == "alpine" || h.rolling() {
		if r.Source == api.SourceThirdParty {
			return "", errUnsupported
		}
		return h.upgrade(false)
	}
	pending, err := h.pendingList()
	if err != nil {
		return "", err
	}
	var third bool
	var sel []api.PendingUpdate
	for _, p := range pending {
		if p.Patch || p.Source == api.SourceFlatpak {
			continue
		}
		third = third || p.Source == api.SourceThirdParty
		if p.Source == r.Source && (r.Source != api.SourceThirdParty || matchRepo(r.Repos, p.Origin)) {
			sel = append(sel, p)
		}
	}
	if r.Source == api.SourceOSAll && !third {
		return h.upgrade(false) // nothing third party pending: the plain full upgrade
	}
	if len(sel) == 0 {
		return "", nil
	}
	return h.upgradeSelected(sel)
}

// upgradeSelected upgrades the listed pending updates only.
func (h *host) upgradeSelected(sel []api.PendingUpdate) (string, error) {
	h.pkgMu.Lock()
	defer h.pkgMu.Unlock()
	h.pending = pendingCache{}
	var repos []string
	for _, p := range sel {
		if p.Origin != "" && !slices.Contains(repos, p.Origin) {
			repos = append(repos, p.Origin)
		}
	}
	switch h.family {
	case "debian":
		args := []string{"install", "--only-upgrade", "-y", "-q", "-o", "DPkg::Lock::Timeout=900",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
		for _, p := range sel {
			args = append(args, p.Name+"="+p.Candidate)
		}
		return run(2*time.Hour, "apt-get", args...)
	case "suse":
		return h.zypperUpgrade(false, repos)
	}
	args := []string{"upgrade", "-y", "-q", "--refresh"}
	for _, r := range repos {
		args = append(args, "--repo="+r)
	}
	return run(2*time.Hour, "dnf", args...)
}

// securitySince tracks since when security updates are pending without a
// break.
func (a *Agent) securitySince(sec int, now time.Time) time.Time {
	switch {
	case sec == 0:
		a.state.SecuritySince = time.Time{}
	case a.state.SecuritySince.IsZero():
		a.state.SecuritySince = now.Round(0)
	}
	return a.state.SecuritySince
}

func runSecurityAge(a *Agent) (string, string) {
	_, sec, err := a.host.pendingUpdates()
	if err != nil {
		return fail, "update status unknown: " + err.Error()
	}
	since := a.securitySince(sec, time.Now())
	if sec == 0 {
		return pass, "no security updates pending"
	}
	days := a.pol.Updates.SecurityMaxDays
	if days == 0 {
		days = 14
	}
	// a date, not a running duration: the detail would change the status every hour
	detail := fmt.Sprintf("security updates pending since %s, at most %d days allowed", since.UTC().Format("2006-01-02"), days)
	if time.Since(since) > time.Duration(days)*24*time.Hour {
		return fail, detail
	}
	return pass, detail
}

// updateStatus is the patch part of the status report.
func (a *Agent) updateStatus() *api.UpdateStatus {
	list, err := a.host.pendingList()
	st := &api.UpdateStatus{Pending: list}
	if st.Pending == nil {
		st.Pending = []api.PendingUpdate{}
	}
	if err != nil {
		st.PendingError = truncate(err.Error(), 300)
	}
	for _, s := range api.UpdateSources {
		if r, ok := a.state.UpdateRuns[s]; ok {
			st.Runs = append(st.Runs, r)
		}
	}
	if g := a.state.UpdateGate; g != nil {
		st.Ring = g.Ring
	}
	if t := a.state.SecuritySince; !t.IsZero() {
		st.SecuritySince = &t
	}
	return st
}

// rulesSummary describes the effective rules for the check updates.auto.
func rulesSummary(u api.Updates) string {
	var parts []string
	for _, r := range u.EffectiveRules() {
		s := r.Source + " " + r.Mode
		if r.Mode != "off" {
			s += " " + r.Window
		}
		if r.Rings {
			s += " (rings)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// packageHold keeps a package at its installed version or releases it:
// apt-mark, dnf versionlock (dnf4 needs its plugin), zypper locks.
func (a *Agent) packageHold(payload string) (string, error) {
	var p api.PackageHold
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return "", err
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	if !a.host.isInstalled(p.Name) && !p.Release {
		return "", fmt.Errorf("%s is not installed", p.Name)
	}
	return a.host.hold(p.Name, !p.Release)
}

func (h *host) hold(name string, on bool) (string, error) {
	h.pkgMu.Lock()
	defer h.pkgMu.Unlock()
	switch h.family {
	case "debian":
		return sh("apt-mark", map[bool]string{true: "hold", false: "unhold"}[on], "--", name)
	case "fedora":
		return sh("dnf", "versionlock", map[bool]string{true: "add", false: "delete"}[on], name)
	case "suse":
		return zypper(time.Minute, map[bool]string{true: "addlock", false: "removelock"}[on], name)
	}
	return "", errUnsupported
}

// packageDowngrade installs an older version (the given one, or the
// highest available below the installed one) and holds the package there,
// or the next update run would upgrade it again. Debian family and dnf
// only: zypper, pacman and apk keep no older versions in their
// repositories.
func (a *Agent) packageDowngrade(payload string) (string, error) {
	var p api.PackageDowngrade
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return "", err
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	h := a.host
	if !h.isInstalled(p.Name) {
		return "", fmt.Errorf("%s is not installed", p.Name)
	}
	var out string
	var err error
	h.pkgMu.Lock()
	switch h.family {
	case "debian":
		v := p.Version
		if v == "" {
			v, err = aptPreviousVersion(p.Name)
		}
		if err == nil {
			out, err = run(30*time.Minute, "apt-get", "install", "-y", "-q", "--allow-downgrades", "-o", "DPkg::Lock::Timeout=300",
				"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", p.Name+"="+v)
		}
	case "fedora":
		target := p.Name
		if p.Version != "" {
			target += "-" + p.Version
		}
		out, err = run(30*time.Minute, "dnf", "downgrade", "-y", "-q", target)
	default:
		err = errUnsupported
	}
	h.pending = pendingCache{}
	h.pkgMu.Unlock()
	if err != nil {
		return out, err
	}
	hout, err := h.hold(p.Name, true)
	return out + "\n" + hout, err
}

// aptPreviousVersion is the highest version apt knows below the installed one.
func aptPreviousVersion(name string) (string, error) {
	cur, err := run(time.Minute, "dpkg-query", "-W", "-f", "${Version}", "--", name)
	if err != nil {
		return "", err
	}
	out, err := run(time.Minute, "apt-cache", "madison", name)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") { // newest first
		f := strings.Split(line, "|")
		if len(f) < 2 {
			continue
		}
		v := strings.TrimSpace(f[1])
		if _, err := run(time.Minute, "dpkg", "--compare-versions", v, "lt", strings.TrimSpace(cur)); err == nil {
			return v, nil
		}
	}
	return "", errors.New("no older version in the configured repositories")
}

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
