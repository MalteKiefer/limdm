package agent

import (
	"encoding/xml"
	"errors"
	"io"
	"os/exec"
	"strings"
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

func (h *host) zypperUpgrade(securityOnly bool) (string, error) {
	if _, err := zypper(10*time.Minute, "refresh"); err != nil {
		return "", err
	}
	out, err := zypper(2*time.Hour, zypperUpgradeArgs(securityOnly, h.rolling())...)
	if !securityOnly || h.rolling() {
		out += flatpakUpgrade()
	}
	return out, err
}

func (h *host) zypperPending() (all, security int, err error) {
	args := []string{"--xmlout", "list-updates"}
	if h.rolling() {
		args = append(args, "--dup")
	}
	out, err := zypper(10*time.Minute, args...)
	if err != nil {
		return 0, 0, err
	}
	if all, err = countZypperUpdates(out); err != nil || h.rolling() {
		return all, all, err // rolling release: every pending update can carry security fixes
	}
	out, err = zypper(10*time.Minute, "--xmlout", "list-patches", "--category", "security")
	if err != nil {
		return all, 0, err
	}
	security, err = countZypperUpdates(out)
	return all, security, err
}

// countZypperUpdates counts the <update> elements of zypper's XML output
// (list-updates lists packages, list-patches the needed patches).
func countZypperUpdates(out string) (int, error) {
	d := xml.NewDecoder(strings.NewReader(out))
	n := 0
	for {
		t, err := d.Token()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if se, ok := t.(xml.StartElement); ok && se.Name.Local == "update" {
			n++
		}
	}
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
