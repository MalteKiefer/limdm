package agent

import (
	"errors"
	"os/exec"
	"time"
)

// SUSE family: openSUSE Leap, Tumbleweed, SLES and SLED, all with zypper.
// Transactional systems (MicroOS, SL Micro) are not supported: their root
// file system is read only and needs transactional-update.

const (
	zypperRebootNeeded  = 102 // ZYPPER_EXIT_INF_REBOOT_NEEDED: success, reboot required
	zypperRestartNeeded = 103 // ZYPPER_EXIT_INF_RESTART_NEEDED: zypper updated itself first
)

// rolling reports a rolling release, which has no separate security channel.
func (h *host) rolling() bool {
	return h.ID == "opensuse-tumbleweed" || h.ID == "opensuse-slowroll"
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}

// zypper runs one non interactive zypper command. Exit 103 means zypper
// updated itself and stopped; the command then runs a second time. 102 and
// 103 are successful outcomes.
func zypper(timeout time.Duration, args ...string) (string, error) {
	full := append([]string{"--non-interactive"}, args...)
	out, err := run(timeout, "zypper", full...)
	if exitCode(err) == zypperRestartNeeded {
		var more string
		more, err = run(timeout, "zypper", full...)
		out += more
	}
	if c := exitCode(err); c == zypperRebootNeeded || c == zypperRestartNeeded {
		err = nil
	}
	return out, err
}

// zypperInstallArgs builds the install command; recommends stay out like
// apt's --no-install-recommends.
func zypperInstallArgs(pkgs []string) []string {
	return append([]string{"install", "--no-recommends", "--auto-agree-with-licenses", "--"}, pkgs...)
}

// zypperUpgradeArgs: security patches only, or every update. Rolling
// releases always do a distribution upgrade (zypper dup), as zypper update
// is not supported there.
func zypperUpgradeArgs(securityOnly, rolling bool) []string {
	switch {
	case rolling:
		return []string{"dup", "--auto-agree-with-licenses"}
	case securityOnly:
		return []string{"patch", "--category", "security", "--auto-agree-with-licenses"}
	}
	return []string{"update", "--auto-agree-with-licenses"}
}

func (h *host) zypperInstall(pkgs []string) error {
	if h.aptStale.Swap(false) { // new or changed sources: fetch their metadata first
		if _, err := zypper(10*time.Minute, "refresh"); err != nil {
			h.aptStale.Store(true)
			return err
		}
	}
	_, err := zypper(30*time.Minute, zypperInstallArgs(pkgs)...)
	return err
}

// zypperUpgrade installs updates, limited to repos (aliases) when given.
func (h *host) zypperUpgrade(securityOnly bool, repos []string) (string, error) {
	if _, err := zypper(10*time.Minute, "refresh"); err != nil {
		return "", err
	}
	args := zypperUpgradeArgs(securityOnly, h.rolling())
	for _, r := range repos {
		args = append(args, "--repo", r)
	}
	return zypper(2*time.Hour, args...)
}

// zypperRebootRequired: libzypp marks /run/reboot-needed after updates that
// need one; zypper needs-rebooting exits 102 when core libraries changed.
func zypperRebootRequired() bool {
	if exists("/run/reboot-needed") {
		return true
	}
	_, err := run(5*time.Minute, "zypper", "needs-rebooting")
	return exitCode(err) == zypperRebootNeeded
}

// trustKeys imports repository signing keys into the rpm database. zypper
// would otherwise ask whether to trust a new key, which a non interactive
// run answers with no.
func (h *host) trustKeys(paths ...string) error {
	if h.family != "suse" {
		return nil
	}
	var errs []error
	for _, p := range paths {
		if exists(p) {
			if out, err := sh("rpm", "--import", p); err != nil {
				errs = append(errs, errors.New("rpm --import "+p+": "+lastLines(out, 2)))
			}
		}
	}
	return errors.Join(errs...)
}
