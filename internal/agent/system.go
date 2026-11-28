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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// host describes the local system. family is debian, fedora, suse, arch or alpine (see familyOf).
type host struct {
	ID, Version, Name, family string
	// Like (ID_LIKE) and BaseCodename (UBUNTU_CODENAME, else
	// DEBIAN_CODENAME) let the server match derivatives against the CVE
	// data of their base distribution.
	Like, BaseCodename string

	// pkgMu runs package manager calls one at a time: catalog installs run
	// in the background next to the check in's own installs and upgrades
	pkgMu    sync.Mutex
	cacheMu  sync.Mutex   // guards pkgs
	aptStale atomic.Bool  // new sources: the next install refreshes the lists (set without pkgMu)
	aptWarn  atomic.Value // string: apt-get update failed for one repository only (aptEnterpriseOnly)

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
	paths := map[string][]string{
		"debian": {"/var/lib/dpkg/status"},
		"fedora": {"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite"},
		"arch":   {"/var/lib/pacman/local"},
		"alpine": {"/lib/apk/db/installed"},
		"suse":   {"/usr/lib/sysimage/rpm/Packages.db", "/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"},
	}[h.family]
	var b strings.Builder
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", p, st.ModTime().UnixNano(), st.Size())
		}
	}
	return b.String()
}

type pendingCache struct {
	at   time.Time
	list []api.PendingUpdate
	err  error
}

func detectHost() (*host, error) {
	osr := parseOSRelease(readFile("/etc/os-release"))
	h := &host{ID: osr["ID"], Version: osr["VERSION_ID"], Name: osr["PRETTY_NAME"], Like: osr["ID_LIKE"],
		BaseCodename: firstNonEmpty(osr["UBUNTU_CODENAME"], osr["DEBIAN_CODENAME"])}
	h.family = familyOf(osr)
	if h.family == "" {
		return nil, fmt.Errorf("unsupported distribution %q", h.ID)
	}
	return h, nil
}

// familyOf maps os-release to the package family: debian (apt), fedora
// (dnf: Fedora, CentOS Stream, RHEL, Rocky, Alma), suse (zypper: openSUSE
// Leap, Tumbleweed, SLES), arch (pacman: Arch, Manjaro, EndeavourOS, CachyOS) or
// alpine (apk, OpenRC).
func familyOf(osr map[string]string) string {
	like := " " + osr["ID"] + " " + osr["ID_LIKE"] + " "
	switch {
	case strings.Contains(like, " debian ") || strings.Contains(like, " ubuntu "):
		return "debian"
	case strings.Contains(like, " suse ") || strings.Contains(like, " opensuse ") || strings.Contains(like, " sles "):
		return "suse"
	case strings.Contains(like, " fedora ") || strings.Contains(like, " rhel ") || strings.Contains(like, " centos "):
		return "fedora"
	case strings.Contains(like, " arch ") || strings.Contains(like, " manjaro "): // BigLinux names only Manjaro
		return "arch"
	case strings.Contains(like, " alpine "):
		return "alpine"
	}
	return ""
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
	// a background child (a script starting a daemon) keeps the output pipe
	// open; without a bound, CombinedOutput would wait for it forever
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil // exited fine; a background child it started keeps the output open
	}
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

// mkdirReadable creates dir and every missing parent as 0755. MkdirAll alone
// would leave the parents at 0700: the service runs with UMask=0077, and apt,
// polkitd and dconf read these as other users.
func mkdirReadable(dir string) error {
	if exists(dir) {
		return nil
	}
	if err := mkdirReadable(filepath.Dir(dir)); err != nil {
		return err
	}
	return errors.Join(os.Mkdir(dir, 0o755), os.Chmod(dir, 0o755)) //nolint:gosec // system config dirs (/etc/*.d) are world readable by design
}

// writeIfChanged writes atomically and reports whether the content changed.
func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() != mode {
			return true, os.Chmod(path, mode)
		}
		return false, nil
	}
	if err := mkdirReadable(filepath.Dir(path)); err != nil {
		return false, err
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
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
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
		fmt.Fprintf(sum, "%s=%s=%s=%s=%s\n", p.Name, p.Version, p.Arch, p.Source, p.SourceVersion)
		names[p.Name] = true
	}
	h.pkgs = pkgCache{stamp: stamp, list: pkgs, hash: hex.EncodeToString(sum.Sum(nil)), names: names}
	return pkgs, h.pkgs.hash, nil
}

func (h *host) nativePackages() ([]api.Package, error) {
	var out string
	var err error
	switch h.family {
	case "arch":
		pkgs, err := parsePacmanQ(run(time.Minute, "pacman", "-Q"))
		for i := range pkgs { // the security tracker lists pkgbase for split packages
			pkgs[i].Source = sourceName(pkgs[i].Name, pacmanBase(readFile(filepath.Join(pacmanLocal, pkgs[i].Name+"-"+pkgs[i].Version, "desc"))))
		}
		return pkgs, err
	case "alpine":
		// apk list -I carries the origin (the secdb's package); apk info -v is the fallback
		if pkgs, err := parseApkList(run(time.Minute, "apk", "list", "-I")); err == nil && len(pkgs) > 0 {
			return pkgs, nil
		}
		return parseApkInfo(run(time.Minute, "apk", "info", "-v"))
	}
	if h.family == "debian" {
		out, err = run(time.Minute, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n")
	} else {
		out, err = run(time.Minute, "rpm", "-qa", "--qf", "ii \t%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%|ARCH?{%{ARCH}}|\n")
	}
	if err != nil {
		return nil, err
	}
	var pkgs []api.Package
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 4 && strings.HasPrefix(f[0], "ii") && f[1] != "gpg-pubkey" {
			p := api.Package{Name: f[1], Version: f[2], Arch: f[3]}
			if len(f) > 4 {
				p.Source = sourceName(p.Name, f[4])
			}
			if len(f) > 5 {
				p.SourceVersion = sourceVersion(p.Version, "", f[5])
			}
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}

func (h *host) isInstalled(name string) bool {
	// answered from the cached list while the package database is unchanged
	h.cacheMu.Lock()
	if stamp := h.pkgDBStamp(); stamp != "" && stamp == h.pkgs.stamp {
		ok := h.pkgs.names[name]
		h.cacheMu.Unlock()
		return ok
	}
	h.cacheMu.Unlock()
	switch h.family {
	case "debian":
		out, err := run(30*time.Second, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}", name)
		return err == nil && strings.HasPrefix(out, "ii")
	case "arch":
		_, err := run(30*time.Second, "pacman", "-Q", "--", name)
		return err == nil
	case "alpine":
		_, err := run(30*time.Second, "apk", "info", "-e", "--", name)
		return err == nil
	}
	_, err := run(30*time.Second, "rpm", "-q", "--quiet", name)
	return err == nil
}

func (h *host) aptUpdate() error {
	if h.family != "debian" {
		return nil
	}
	if !h.aptStale.Swap(false) && time.Since(h.aptUpdated) < time.Hour {
		return nil
	}
	out, err := run(10*time.Minute, "apt-get", "update", "-qq")
	warn := ""
	if err != nil {
		if warn = aptEnterpriseOnly(out); warn == "" {
			h.aptStale.Store(true)
			return err
		}
	}
	h.aptWarn.Store(warn)
	h.aptUpdated = time.Now()
	return nil
}

func (h *host) install(pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil // nothing to do: do not wait behind a running catalog install
	}
	h.pkgMu.Lock()
	defer h.pkgMu.Unlock()
	return h.installLocked(pkgs...)
}

func (h *host) installLocked(pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	if h.family == "debian" {
		if err := h.aptUpdate(); err != nil {
			return err
		}
		_, err := aptGet(30*time.Minute, append([]string{"install", "-y", "-q", "--no-install-recommends", "-o", "DPkg::Lock::Timeout=300",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--"}, pkgs...)...)
		return err
	}
	var err error
	switch h.family {
	case "arch": // -Syu: Arch does not support partial upgrades
		_, err = run(30*time.Minute, "pacman", append([]string{"-Syu", "--noconfirm", "--needed", "--"}, pkgs...)...)
	case "alpine":
		_, err = run(30*time.Minute, "apk", append([]string{"add", "--no-interactive", "--"}, pkgs...)...)
	case "suse":
		err = h.zypperInstall(pkgs)
	default:
		_, err = run(30*time.Minute, "dnf", append([]string{"install", "-y", "-q", "--"}, pkgs...)...)
	}
	return err
}

func (h *host) remove(pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	h.pkgMu.Lock()
	defer h.pkgMu.Unlock()
	if h.family == "debian" {
		_, err := aptGet(30*time.Minute, append([]string{"remove", "-y", "-q", "-o", "DPkg::Lock::Timeout=300", "--"}, pkgs...)...)
		return err
	}
	var err error
	switch h.family {
	case "arch":
		_, err = run(30*time.Minute, "pacman", append([]string{"-R", "--noconfirm", "--"}, pkgs...)...)
	case "alpine":
		_, err = run(30*time.Minute, "apk", append([]string{"del", "--no-interactive", "--"}, pkgs...)...)
	case "suse":
		_, err = zypper(30*time.Minute, append([]string{"remove", "--"}, pkgs...)...)
	default:
		_, err = run(30*time.Minute, "dnf", append([]string{"remove", "-y", "-q", "--"}, pkgs...)...)
	}
	return err
}

// upgrade installs OS updates. securityOnly uses unattended-upgrades on
// Debian family (security origins by default), dnf's security filter on
// Fedora and security patches on SUSE. Flatpak is its own source
// (flatpakUpgrade).
func (h *host) upgrade(securityOnly bool) (string, error) {
	h.pkgMu.Lock()
	defer h.pkgMu.Unlock()
	h.pending = pendingCache{}
	switch h.family { // rolling releases have no separate security channel: always everything
	case "arch":
		return run(2*time.Hour, "pacman", "-Syu", "--noconfirm")
	case "alpine":
		return run(2*time.Hour, "apk", "upgrade", "--update-cache", "--no-interactive")
	case "suse":
		return h.zypperUpgrade(securityOnly, nil)
	}
	if h.family == "debian" {
		h.aptUpdated = time.Time{}
		if err := h.aptUpdate(); err != nil {
			return "", err
		}
		if securityOnly {
			if !hasCmd("unattended-upgrade") {
				if err := h.installLocked("unattended-upgrades"); err != nil {
					return "", err
				}
			}
			return run(2*time.Hour, "unattended-upgrade", "-v")
		}
		// wait for dpkg instead of failing while unattended-upgrades or PackageKit holds it
		return aptGet(2*time.Hour, append(aptUpgradeVerb(), "-y", "-q", "-o", "DPkg::Lock::Timeout=900",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")...)
	}
	args := []string{"upgrade", "-y", "-q", "--refresh"}
	if securityOnly {
		args = append(args, "--security")
	}
	return run(2*time.Hour, "dnf", args...)
}

// flatpakUpgrade updates system wide Flatpak apps and runtimes.
func flatpakUpgrade() (string, error) {
	if !hasCmd("flatpak") {
		return "", nil
	}
	return run(time.Hour, "flatpak", "update", "-y", "--noninteractive", "--system")
}

func (h *host) rebootRequired() bool {
	switch h.family {
	case "debian":
		return exists("/run/reboot-required")
	case "arch", "alpine":
		return kernelReplaced()
	case "suse":
		return zypperRebootRequired()
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
	return "wheel" // Fedora and SUSE family, Arch, Alpine
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
		OSLike: h.Like, OSBaseCodename: h.BaseCodename,
		Kernel: readTrim("/proc/sys/kernel/osrelease"), Arch: runtime.GOARCH,
		Vendor: cleanDMI(readTrim("/sys/class/dmi/id/sys_vendor")), Model: cleanDMI(readTrim("/sys/class/dmi/id/product_name")),
		Serial: cleanDMI(readTrim("/sys/class/dmi/id/product_serial")),
	}
	if inv.Model == "" { // ARM boards (Raspberry Pi …) describe themselves in the device tree
		inv.Model = strings.TrimRight(readTrim("/proc/device-tree/model"), "\x00")
	}
	if inv.Serial == "" {
		inv.Serial = strings.TrimRight(readTrim("/proc/device-tree/serial-number"), "\x00")
	}
	inv.Hostname, _ = os.Hostname()
	inv.OSProduct, inv.Proxmox = proxmoxInventory()
	sc := bufio.NewScanner(strings.NewReader(readFile("/proc/cpuinfo")))
	for sc.Scan() { // x86 has "model name"; ARM kernels "Hardware", "Model" or "CPU part"
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok {
			switch strings.TrimSpace(k) {
			case "model name":
				inv.CPU = strings.TrimSpace(v)
			case "Hardware", "Model":
				if inv.CPU == "" {
					inv.CPU = strings.TrimSpace(v)
				}
			}
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
	inv.TPM = tpmInventory()
	inv.Accounts, inv.Groups = nssAccounts()
	annotateSSO(inv.Accounts)
	inv.Repos = h.repos()
	inv.Flatpaks, inv.FlatpakRemotes = flatpakInventory(inv.Accounts)
	inv.Snaps, inv.AppImages = snapInventory(), appImageInventory()
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
		cmd.WaitDelay = 5 * time.Second
		out, err := cmd.CombinedOutput()
		if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
			err = nil
		}
		return string(out), err
	}
}

// kernelReplaced: the running kernel's modules are gone, the package
// manager installed another kernel (Arch and Alpine keep only one).
func kernelReplaced() bool {
	rel := readTrim("/proc/sys/kernel/osrelease")
	return rel != "" && !exists("/lib/modules/"+rel) && !exists("/usr/lib/modules/"+rel)
}

// parsePacmanQ reads "name version" lines of pacman -Q.
func parsePacmanQ(out string, err error) ([]api.Package, error) {
	if err != nil {
		return nil, err
	}
	var pkgs []api.Package
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			pkgs = append(pkgs, api.Package{Name: f[0], Version: f[1]})
		}
	}
	return pkgs, nil
}

// parseApkInfo reads "name-version-rREL" lines of apk info -v.
func parseApkInfo(out string, err error) ([]api.Package, error) {
	if err != nil {
		return nil, err
	}
	var pkgs []api.Package
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		// the version starts at the last dash followed by a digit, before -rN
		i := strings.LastIndex(l, "-r")
		if i <= 0 {
			continue
		}
		j := strings.LastIndex(l[:i], "-")
		if j <= 0 {
			continue
		}
		pkgs = append(pkgs, api.Package{Name: l[:j], Version: l[j+1:]})
	}
	return pkgs, nil
}

// pacmanLocal is pacman's local database, one directory per package.
const pacmanLocal = "/var/lib/pacman/local"

// pacmanBase reads %BASE% of a local database desc file.
func pacmanBase(desc string) string {
	_, rest, ok := strings.Cut(desc, "%BASE%\n")
	if !ok {
		return ""
	}
	base, _, _ := strings.Cut(rest, "\n")
	return strings.TrimSpace(base)
}

// parseApkList reads apk list -I: "name-version-rN arch {origin} (license) [installed]".
func parseApkList(out string, err error) ([]api.Package, error) {
	if err != nil {
		return nil, err
	}
	var pkgs []api.Package
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || !strings.HasPrefix(f[2], "{") || !strings.HasSuffix(f[2], "}") {
			continue
		}
		p, _ := parseApkInfo(f[0], nil)
		if len(p) != 1 {
			continue
		}
		p[0].Arch, p[0].Source = f[1], sourceName(p[0].Name, strings.Trim(f[2], "{}"))
		pkgs = append(pkgs, p[0])
	}
	return pkgs, nil
}
