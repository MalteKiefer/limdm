package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// host describes the local system. family is "debian" (Debian, Ubuntu) or "fedora".
type host struct {
	ID, Version, Name, family string

	aptUpdated time.Time
	pending    pendingCache
	pkgs       pkgCache
}

// pkgCache keeps the package list until the package database changes.
type pkgCache struct {
	stamp string // modification times of the package database
	list  []api.Package
	hash  string
	names map[string]bool
}

// pkgDBStamp changes whenever packages are installed, removed or upgraded.
func (h *host) pkgDBStamp() string {
	paths := []string{"/var/lib/dpkg/status"}
	if h.family != "debian" {
		paths = []string{"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite"}
	}
	var b strings.Builder
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", p, st.ModTime().UnixNano(), st.Size())
		}
	}
	return b.String()
}

type pendingCache struct {
	at            time.Time
	all, security int
	err           error
}

func detectHost() (*host, error) {
	osr := parseOSRelease(readFile("/etc/os-release"))
	h := &host{ID: osr["ID"], Version: osr["VERSION_ID"], Name: osr["PRETTY_NAME"]}
	like := " " + osr["ID"] + " " + osr["ID_LIKE"] + " "
	switch {
	case strings.Contains(like, " debian ") || strings.Contains(like, " ubuntu "):
		h.family = "debian"
	case strings.Contains(like, " fedora ") || strings.Contains(like, " rhel "):
		h.family = "fedora"
	default:
		return nil, fmt.Errorf("unsupported distribution %q", h.ID)
	}
	return h, nil
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func readTrim(p string) string { return strings.TrimSpace(readFile(p)) }

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// run executes a command with a timeout and returns combined output.
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, lastLines(string(out), 5))
	}
	return string(out), nil
}

func sh(name string, args ...string) (string, error) { return run(2*time.Minute, name, args...) }

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func unitActive(name string) bool {
	_, err := run(30*time.Second, "systemctl", "is-active", "--quiet", name)
	return err == nil
}

// writeIfChanged writes atomically and reports whether the content changed.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() != mode {
			return true, os.Chmod(path, mode)
		}
		return false, nil
	}
	if dir := filepath.Dir(path); !exists(dir) {
		// explicit chmod: the service runs with UMask=0077, apt and polkitd read these as other users
		if err := errors.Join(os.MkdirAll(dir, 0o755), os.Chmod(dir, 0o755)); err != nil { //nolint:gosec // system config dirs (/etc/*.d) are world readable by design
			return false, err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".limdm-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

// ---- package management ----

func (h *host) installedPackages() ([]api.Package, string, error) {
	stamp := h.pkgDBStamp()
	if stamp != "" && stamp == h.pkgs.stamp {
		return h.pkgs.list, h.pkgs.hash, nil
	}
	pkgs, err := h.osqueryPackages()
	if err != nil || len(pkgs) == 0 {
		if pkgs, err = h.nativePackages(); err != nil {
			return nil, "", err
		}
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	sum := sha256.New()
	names := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		fmt.Fprintf(sum, "%s=%s=%s\n", p.Name, p.Version, p.Arch)
		names[p.Name] = true
	}
	h.pkgs = pkgCache{stamp: stamp, list: pkgs, hash: hex.EncodeToString(sum.Sum(nil)), names: names}
	return pkgs, h.pkgs.hash, nil
}

func (h *host) nativePackages() ([]api.Package, error) {
	var out string
	var err error
	if h.family == "debian" {
		out, err = run(time.Minute, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n")
	} else {
		out, err = run(time.Minute, "rpm", "-qa", "--qf", "ii \t%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	}
	if err != nil {
		return nil, err
	}
	var pkgs []api.Package
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 4 && strings.HasPrefix(f[0], "ii") {
			pkgs = append(pkgs, api.Package{Name: f[1], Version: f[2], Arch: f[3]})
		}
	}
	return pkgs, nil
}

func (h *host) isInstalled(name string) bool {
	// answered from the cached list while the package database is unchanged
	if stamp := h.pkgDBStamp(); stamp != "" && stamp == h.pkgs.stamp {
		return h.pkgs.names[name]
	}
	if h.family == "debian" {
		out, err := run(30*time.Second, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}", name)
		return err == nil && strings.HasPrefix(out, "ii")
	}
	_, err := run(30*time.Second, "rpm", "-q", "--quiet", name)
	return err == nil
}

func (h *host) aptUpdate() error {
	if h.family != "debian" || time.Since(h.aptUpdated) < time.Hour {
		return nil
	}
	if _, err := run(10*time.Minute, "apt-get", "update", "-qq"); err != nil {
		return err
	}
	h.aptUpdated = time.Now()
	return nil
}

func (h *host) install(pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	if h.family == "debian" {
		if err := h.aptUpdate(); err != nil {
			return err
		}
		_, err := run(30*time.Minute, "apt-get", append([]string{"install", "-y", "-q", "--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--"}, pkgs...)...)
		return err
	}
	_, err := run(30*time.Minute, "dnf", append([]string{"install", "-y", "-q", "--"}, pkgs...)...)
	return err
}

func (h *host) remove(pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	if h.family == "debian" {
		_, err := run(30*time.Minute, "apt-get", append([]string{"remove", "-y", "-q", "--"}, pkgs...)...)
		return err
	}
	_, err := run(30*time.Minute, "dnf", append([]string{"remove", "-y", "-q", "--"}, pkgs...)...)
	return err
}

// upgrade installs updates. securityOnly uses unattended-upgrades on Debian
// family (security origins by default) and dnf's security filter on Fedora.
func (h *host) upgrade(securityOnly bool) (string, error) {
	h.pending = pendingCache{}
	if h.family == "debian" {
		h.aptUpdated = time.Time{}
		if err := h.aptUpdate(); err != nil {
			return "", err
		}
		if securityOnly {
			if !hasCmd("unattended-upgrade") {
				if err := h.install("unattended-upgrades"); err != nil {
					return "", err
				}
			}
			return run(2*time.Hour, "unattended-upgrade", "-v")
		}
		return run(2*time.Hour, "apt-get", "upgrade", "-y", "-q", "--with-new-pkgs",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")
	}
	args := []string{"upgrade", "-y", "-q", "--refresh"}
	if securityOnly {
		args = append(args, "--security")
	}
	return run(2*time.Hour, "dnf", args...)
}

// pendingUpdates counts available updates; cached for an hour because it hits the mirrors.
func (h *host) pendingUpdates() (all, security int, err error) {
	if time.Since(h.pending.at) < time.Hour {
		return h.pending.all, h.pending.security, h.pending.err
	}
	defer func() { h.pending = pendingCache{at: time.Now(), all: all, security: security, err: err} }()
	if h.family == "debian" {
		if err = h.aptUpdate(); err != nil {
			return
		}
		var out string
		if out, err = run(5*time.Minute, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade", "--with-new-pkgs"); err != nil {
			return
		}
		all, security = countAptPending(out)
		return
	}
	// dnf check-update exits 100 when updates exist.
	out, cerr := run(10*time.Minute, "dnf", "-q", "check-update", "--refresh")
	var ee *exec.ExitError
	if cerr != nil && (!errors.As(cerr, &ee) || ee.ExitCode() != 100) {
		return 0, 0, cerr
	}
	all = countDnfLines(out)
	sec, serr := run(10*time.Minute, "dnf", "-q", "updateinfo", "list", "--security")
	if serr != nil {
		return all, 0, serr
	}
	security = countDnfLines(sec)
	return
}

func countAptPending(out string) (all, security int) {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Inst ") {
			all++
			if strings.Contains(strings.ToLower(line), "-security") {
				security++
			}
		}
	}
	return
}

func countDnfLines(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && !strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "Obsoleting") {
			n++
		}
	}
	return n
}

func (h *host) rebootRequired() bool {
	if h.family == "debian" {
		return exists("/run/reboot-required")
	}
	if !hasCmd("dnf") {
		return false
	}
	// exit 1 means a reboot is required; any other failure is treated as unknown (false).
	_, err := run(5*time.Minute, "dnf", "-q", "needs-restarting", "-r")
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 1
}

func (h *host) adminGroup() string {
	if h.family == "debian" {
		return "sudo"
	}
	return "wheel"
}

// metrics reads memory, root filesystem usage and load for history charts.
func metrics() *api.Metrics {
	m := &api.Metrics{}
	var total, avail uint64
	for _, line := range strings.Split(readFile("/proc/meminfo"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	m.MemTotalMB, m.MemUsedMB = total/1024, (total-min(avail, total))/1024
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil && st.Blocks > 0 {
		m.RootUsedPct = float64(st.Blocks-st.Bfree) * 100 / float64(st.Blocks)
	}
	if f := strings.Fields(readFile("/proc/loadavg")); len(f) > 0 {
		m.Load1, _ = strconv.ParseFloat(f[0], 64)
	}
	return m
}

// ---- inventory ----

// inventory collects hardware and OS facts. Personal data (IPs, logged in
// users) is only collected when the privacy declaration allows it.
func (h *host) inventory(priv api.Privacy) api.Inventory {
	inv := api.Inventory{
		Source:    "native",
		MachineID: readTrim("/etc/machine-id"), OSID: h.ID, OSVersion: h.Version, OSName: h.Name,
		Kernel: readTrim("/proc/sys/kernel/osrelease"), Arch: runtime.GOARCH,
		Vendor: readTrim("/sys/class/dmi/id/sys_vendor"), Model: readTrim("/sys/class/dmi/id/product_name"),
		Serial: readTrim("/sys/class/dmi/id/product_serial"),
	}
	inv.Hostname, _ = os.Hostname()
	sc := bufio.NewScanner(strings.NewReader(readFile("/proc/cpuinfo")))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
			inv.CPU = strings.TrimSpace(v)
			break
		}
	}
	for _, line := range strings.Split(readFile("/proc/meminfo"), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			inv.MemoryMB = kb / 1024
		}
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		inv.DiskGB = st.Blocks * uint64(st.Bsize) >> 30 //nolint:gosec // block size is a small positive kernel value
	}
	for _, line := range strings.Split(readFile("/proc/stat"), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			inv.BootTime, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil && priv.NetworkInfo {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				inv.IPs = append(inv.IPs, ipn.IP.String())
			}
		}
	}
	inv.Disks, inv.Volumes = nativeDisks(), nativeVolumes()
	inv.Accounts, inv.Groups = nssAccounts()
	annotateSSO(inv.Accounts)
	inv.Repos = h.repos()
	inv.Desktop, inv.DisplayManager = desktop()
	inv.Interfaces, inv.DNS, inv.Routes, inv.VPNs = network(priv)
	if out, err := run(30*time.Second, "who"); err == nil && priv.LoggedInUsers {
		seen := map[string]bool{}
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) > 0 && !seen[f[0]] {
				seen[f[0]] = true
				inv.Users = append(inv.Users, f[0])
			}
		}
	}
	enrichFromOsquery(&inv)
	return inv
}

// commandWithStdin runs a command with input on stdin (secrets never go into argv).
func commandWithStdin(in string) func(name string, args ...string) (string, error) {
	return func(name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		cmd.Stdin = strings.NewReader(in)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
}
