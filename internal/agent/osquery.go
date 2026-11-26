package agent

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// osquery is mandatory: it is the inventory source. The agent installs it from
// the official repository and trusts only the signing key embedded here
// (fingerprint 1484 120A C4E9 F8A1 A577 AEEE 97A8 0C63 C9D8 B80B, osquery@fb.com,
// same key for deb and rpm). Enforcement and remediation stay in the agent;
// osquery is only queried with osqueryi, no osqueryd daemon is enabled.

var osqueryKey = api.OsqueryKey

const (
	OsqueryKeyFingerprint = "1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B"
	osqueryRepoURL        = "https://pkg.osquerypackages.com"
	osqueryi              = "/usr/bin/osqueryi"
)

func hasOsquery() bool { return exists(osqueryi) }

// ensureOsquery adds the osquery repository with the pinned key and installs osquery.
func (h *host) ensureOsquery() error {
	if hasOsquery() {
		return nil
	}
	if h.family == "arch" || h.family == "alpine" {
		return errors.New("osquery is not packaged for " + h.family + "; the native inventory is used")
	}
	if h.family == "debian" {
		const key = "/etc/apt/keyrings/limdm-osquery.asc"
		if _, err := writeIfChanged(key, osqueryKey, 0o644); err != nil {
			return err
		}
		src := managedHeader + "Types: deb\nURIs: " + osqueryRepoURL + "/deb\nSuites: deb\nComponents: main\n" +
			"Architectures: amd64 arm64\nSigned-By: " + key + "\n"
		if _, err := writeIfChanged("/etc/apt/sources.list.d/limdm-osquery.sources", src, 0o644); err != nil {
			return err
		}
		h.aptStale.Store(true) // pick up the new repository
	} else { // Fedora and SUSE family: the osquery rpm repository works with dnf and zypper
		const key = "/etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery"
		if _, err := writeIfChanged(key, osqueryKey, 0o644); err != nil {
			return err
		}
		if err := h.trustKeys(key); err != nil {
			return err
		}
		_, dir := h.repoDirs()
		repo := managedHeader + "[limdm-osquery]\nname=osquery\nbaseurl=" + osqueryRepoURL + "/rpm/$basearch/\n" +
			"enabled=1\ngpgcheck=1\ngpgkey=file://" + key + "\n"
		changed, err := writeIfChanged(dir+"/limdm-osquery.repo", repo, 0o644)
		if err != nil {
			return err
		}
		if changed {
			h.aptStale.Store(true)
		}
	}
	return h.install("osquery")
}

// osq runs one query; osquery returns every column as a string.
func osq(query string) ([]map[string]string, error) { return osqWithin(time.Minute, query) }

func osqWithin(timeout time.Duration, query string) ([]map[string]string, error) {
	// an explicit database path: osqueryi otherwise writes below $HOME, which
	// is unset or / for a service; events are not needed for single queries
	out, err := run(timeout, osqueryi, "--json", "--database_path="+stateDir+"/osqueryi.db", "--disable_events", "--disable_extensions", query)
	if err != nil {
		return nil, err
	}
	var rows []map[string]string
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, fmt.Errorf("osquery output: %w", err)
	}
	return rows, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atou(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

// osqueryVersion returns e.g. "5.24.1".
func osqueryVersion() string {
	rows, err := osq("SELECT version FROM osquery_info")
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0]["version"]
}

// enrichFromOsquery overlays the native inventory with osquery data. Each
// section falls back to the native value when its query fails.
func enrichFromOsquery(inv *api.Inventory) {
	if !hasOsquery() {
		return
	}
	v := osqueryVersion()
	if v == "" {
		return
	}
	inv.Source = "osquery " + v
	if r, err := osq("SELECT cpu_brand, cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial FROM system_info"); err == nil && len(r) == 1 {
		s := r[0]
		inv.CPU = firstNonEmpty(strings.TrimSpace(s["cpu_brand"]), inv.CPU)
		inv.CPUCores, inv.CPUThreads = atoi(s["cpu_physical_cores"]), atoi(s["cpu_logical_cores"])
		if mem := atou(s["physical_memory"]); mem > 0 {
			inv.MemoryMB = mem >> 20
		}
		inv.Vendor = firstNonEmpty(cleanDMI(s["hardware_vendor"]), inv.Vendor)
		inv.Model = firstNonEmpty(cleanDMI(s["hardware_model"]), inv.Model)
		inv.Serial = firstNonEmpty(cleanDMI(s["hardware_serial"]), inv.Serial)
	}
	if r, err := osq("SELECT name, version, codename FROM os_version"); err == nil && len(r) == 1 {
		inv.OSCodename = r[0]["codename"]
	}
	if r, err := osq("SELECT vendor, version FROM platform_info"); err == nil && len(r) == 1 {
		inv.BIOSVendor, inv.BIOSVersion = cleanDMI(r[0]["vendor"]), cleanDMI(r[0]["version"])
	}
	if r, err := osq("SELECT swap_total FROM memory_info"); err == nil && len(r) == 1 {
		inv.SwapMB = atou(r[0]["swap_total"]) >> 20
	}
	if r, err := osq("SELECT name, model, size, block_size, type FROM block_devices WHERE parent = '' AND name NOT LIKE '/dev/loop%' AND name NOT LIKE '/dev/ram%' AND name NOT LIKE '/dev/zram%' AND name NOT LIKE '/dev/sr%'" +
		" AND name NOT LIKE '/dev/dm-%' AND name NOT LIKE '/dev/nbd%' AND name NOT LIKE '/dev/zd%' AND name NOT LIKE '/dev/mtdblock%' AND name NOT LIKE '/dev/fd%'"); err == nil && len(r) > 0 {
		var disks []api.Disk
		for _, d := range r {
			size := atou(d["size"]) * max(atou(d["block_size"]), 1)
			if size == 0 {
				continue
			}
			disks = append(disks, api.Disk{Name: d["name"], Model: strings.TrimSpace(d["model"]), SizeGB: size >> 30, Type: diskType(d["name"])})
		}
		if disks != nil {
			inv.Disks = disks
		}
	}
}

// cleanDMI drops the placeholders vendors leave in firmware fields.
func cleanDMI(v string) string {
	v = strings.TrimSpace(v)
	switch strings.ToLower(strings.Trim(v, ". ")) {
	case "", "to be filled by o.e.m", "to be filled by oem", "default string", "system serial number", "system product name",
		"system manufacturer", "system version", "not specified", "not applicable", "none", "n/a", "na", "oem", "o.e.m",
		"0", "00000000", "0123456789", "123456789", "chassis serial number", "invalid", "unknown", "xxxxxxxxxxxx":
		return ""
	}
	return v
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// diskType reads the kernel's rotational flag; virtio and xen disks report as virtual.
func diskType(dev string) string {
	name := filepath.Base(dev)
	switch {
	case strings.HasPrefix(name, "nvme"):
		return "nvme"
	case strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd"):
		return "virtual"
	case strings.HasPrefix(name, "mmcblk"): // eMMC or SD card
		if readTrim("/sys/block/"+name+"/device/type") == "SD" {
			return "sd"
		}
		return "emmc"
	}
	switch readTrim("/sys/block/" + name + "/queue/rotational") {
	case "0":
		return "ssd"
	case "1":
		return "hdd"
	}
	return ""
}

// ---- native collectors (also the fallback when osquery is unavailable) ----

type lsblkDev struct {
	Name     string     `json:"name"`
	Path     string     `json:"path"`
	Size     uint64     `json:"size"`
	Model    string     `json:"model"`
	Type     string     `json:"type"`
	Children []lsblkDev `json:"children"`
}

func nativeDisks() []api.Disk {
	out, err := sh("lsblk", "-J", "-b", "-d", "-o", "NAME,PATH,SIZE,MODEL,TYPE")
	if err != nil {
		return nil
	}
	var res struct {
		Devices []lsblkDev `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(out), &res) != nil {
		return nil
	}
	var disks []api.Disk
	for _, d := range res.Devices {
		if d.Type == "disk" && !strings.HasPrefix(d.Name, "zram") {
			disks = append(disks, api.Disk{Name: d.Path, Model: strings.TrimSpace(d.Model), SizeGB: d.Size >> 30, Type: diskType(d.Path)})
		}
	}
	return disks
}

var localFS = map[string]bool{"ext4": true, "ext3": true, "ext2": true, "xfs": true, "btrfs": true, "bcachefs": true, "vfat": true,
	"exfat": true, "ecryptfs": true, "ntfs": true, "ntfs3": true, "f2fs": true, "zfs": true, "jfs": true, "nilfs2": true, "reiserfs": true}

func nativeVolumes() []api.Volume {
	out, err := sh("findmnt", "-J", "-b", "-l", "-o", "SOURCE,TARGET,FSTYPE,SIZE,AVAIL")
	if err != nil {
		return nil
	}
	var res struct {
		FS []struct {
			Source string `json:"source"`
			Target string `json:"target"`
			FSType string `json:"fstype"`
			Size   uint64 `json:"size"`
			Avail  uint64 `json:"avail"`
		} `json:"filesystems"`
	}
	if json.Unmarshal([]byte(out), &res) != nil {
		return nil
	}
	seen := map[string]bool{}
	var vols []api.Volume
	for _, f := range res.FS {
		dev := f.Source
		if i := strings.Index(dev, "["); i > 0 { // btrfs subvolume
			dev = dev[:i]
		}
		if !localFS[f.FSType] || seen[f.Target] || strings.HasPrefix(f.Target, "/snap/") {
			continue
		}
		seen[f.Target] = true
		method := volumeEncryption(dev, f.FSType, f.Target)
		vols = append(vols, api.Volume{Device: dev, Mount: f.Target, FS: f.FSType, SizeGB: f.Size >> 30, FreeGB: f.Avail >> 30,
			Encrypted: method != "", Encryption: method})
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Mount < vols[j].Mount })
	return vols
}

// volumeEncryption names how a mounted file system is encrypted, "" when it
// is not: dm-crypt below it (any layering: LVM on LUKS, LUKS on LVM, RAID),
// native ZFS encryption, eCryptfs. A Btrfs file system spanning several
// devices counts only when every device is encrypted.
func volumeEncryption(src, fstype, target string) string {
	switch fstype {
	case "zfs":
		out, err := sh("zfs", "get", "-H", "-o", "value", "encryption", src)
		if v := strings.TrimSpace(out); err == nil && v != "off" && v != "-" && v != "" {
			return "ZFS native (" + v + ")"
		}
		return ""
	case "ecryptfs":
		return "eCryptfs"
	}
	if !strings.HasPrefix(src, "/dev/") {
		return ""
	}
	devs := []string{src}
	if fstype == "btrfs" && target != "" {
		if out, err := sh("btrfs", "filesystem", "show", target); err == nil {
			if d := btrfsDevices(out); len(d) > 0 {
				devs = d
			}
		}
	}
	method := ""
	for _, d := range devs {
		m := dmCryptType(d)
		if m == "" {
			return "" // one plain device leaves data unencrypted
		}
		method = m
	}
	return method
}

// btrfsDevices reads the "devid … path /dev/x" lines of btrfs filesystem show.
func btrfsDevices(out string) []string {
	var devs []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "devid" && strings.HasPrefix(f[len(f)-1], "/dev/") {
			devs = append(devs, f[len(f)-1])
		}
	}
	return devs
}

// dmCryptType finds the dm-crypt mapping below a device and its type from
// cryptsetup (LUKS1, LUKS2, PLAIN, TCRYPT, BITLK; hw-opal for self
// encrypting drives); "" when the device is not encrypted.
func dmCryptType(dev string) string {
	if !strings.HasPrefix(dev, "/dev/") {
		return ""
	}
	out, err := sh("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", dev)
	if err != nil {
		return ""
	}
	name := ""
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[1] == "crypt" {
			name = f[0]
			break
		}
	}
	if name == "" {
		return ""
	}
	st, err := sh("cryptsetup", "status", name)
	if err != nil {
		return "dm-crypt"
	}
	return cryptTypeOf(st)
}

func cryptTypeOf(status string) string {
	typ, opal := "dm-crypt", false
	for _, l := range strings.Split(status, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		switch {
		case ok && k == "type":
			typ = strings.TrimSpace(v)
			if typ == "PLAIN" {
				typ = "plain dm-crypt"
			}
		case strings.Contains(l, "hw-opal"):
			opal = true
		}
	}
	if opal {
		typ += " hw-opal"
	}
	return typ
}

// desktop reports the desktop in use (the running sessions' XDG_CURRENT_DESKTOP)
// or, without a session, the installed one, and the display manager.
func desktop() (env, dm string) {
	for _, gs := range graphicalSessions() {
		for _, kv := range gs.env {
			if v, ok := strings.CutPrefix(kv, "XDG_CURRENT_DESKTOP="); ok && v != "" {
				env = desktopName(v)
			}
		}
		if env != "" {
			break
		}
	}
	if env == "" {
		env = installedDesktop()
	}
	return strings.TrimSpace(env), displayManager()
}

// desktopName turns XDG_CURRENT_DESKTOP ("ubuntu:GNOME", "labwc:wlroots",
// "X-Cinnamon") into a name, with the version where the desktop reports one.
func desktopName(xdg string) string {
	parts := strings.Split(xdg, ":")
	name := parts[0]
	for _, p := range parts { // "ubuntu:GNOME", "Budgie:GNOME": the first known name wins
		if desktopVersion(p) != "" || knownDesktops[strings.ToLower(p)] != "" {
			name = p
			break
		}
	}
	if v := desktopVersion(name); v != "" {
		return v
	}
	if n := knownDesktops[strings.ToLower(name)]; n != "" {
		return n
	}
	return strings.TrimPrefix(name, "X-")
}

var knownDesktops = map[string]string{
	"x-cinnamon": "Cinnamon", "cinnamon": "Cinnamon", "xfce": "Xfce", "mate": "MATE", "cosmic": "COSMIC", "budgie": "Budgie",
	"lxqt": "LXQt", "lxde": "LXDE", "pantheon": "Pantheon", "deepin": "Deepin", "enlightenment": "Enlightenment",
	"hyprland": "Hyprland", "niri": "niri", "river": "river", "labwc": "labwc", "wayfire": "Wayfire", "i3": "i3",
	"openbox": "Openbox", "awesome": "awesome", "bspwm": "bspwm", "qtile": "Qtile", "dwm": "dwm", "unity": "Unity",
}

// desktopVersion asks the desktops that report a version.
func desktopVersion(name string) string {
	switch strings.ToLower(name) {
	case "gnome":
		if out, err := sh("gnome-shell", "--version"); err == nil {
			return "GNOME " + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "GNOME Shell"))
		}
		return "GNOME"
	case "kde":
		if out, err := sh("plasmashell", "--version"); err == nil {
			return "KDE Plasma " + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "plasmashell"))
		}
		return "KDE Plasma"
	case "sway":
		if out, err := sh("sway", "--version"); err == nil {
			return "Sway " + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "sway version"))
		}
		return "Sway"
	}
	return ""
}

// installedDesktop is the first desktop found installed (servers, no session).
func installedDesktop() string {
	for _, c := range []struct{ cmd, name string }{
		{"gnome-shell", "GNOME"}, {"plasmashell", "KDE"}, {"cinnamon-session", "Cinnamon"}, {"xfce4-session", "Xfce"},
		{"mate-session", "MATE"}, {"cosmic-session", "COSMIC"}, {"budgie-desktop", "Budgie"}, {"lxqt-session", "LXQt"},
		{"gala", "Pantheon"}, {"startdde", "Deepin"}, {"lxsession", "LXDE"}, {"enlightenment", "Enlightenment"},
		{"sway", "sway"}, {"Hyprland", "Hyprland"}, {"niri", "niri"}, {"river", "river"}, {"labwc", "labwc"},
		{"wayfire", "Wayfire"}, {"i3", "i3"}, {"openbox", "Openbox"}, {"awesome", "awesome"}, {"bspwm", "bspwm"}, {"qtile", "Qtile"},
	} {
		if hasCmd(c.cmd) {
			return desktopName(c.name)
		}
	}
	return ""
}

// displayManager reads systemd's display-manager alias, or finds a running one.
func displayManager() string {
	if target, err := os.Readlink("/etc/systemd/system/display-manager.service"); err == nil {
		return strings.TrimSuffix(filepath.Base(target), ".service")
	}
	running := userProcs()["0"]
	for _, dm := range []string{"gdm", "gdm3", "sddm", "lightdm", "greetd", "lxdm", "ly", "slim", "xdm", "cosmic-greeter"} {
		if running[dm] {
			return dm
		}
	}
	return ""
}

// osqueryPackages returns installed packages from osquery.
func (h *host) osqueryPackages() ([]api.Package, error) {
	if !hasOsquery() || (h.family != "debian" && h.family != "fedora" && h.family != "suse") {
		return nil, errors.New("osquery packages unavailable") // pacman and apk lists come from the native collector
	}
	q := "SELECT name, version, arch FROM deb_packages WHERE status LIKE '%installed'"
	if h.family != "debian" {
		// with the epoch as rpm compares versions; gpg-pubkey entries are keys, not packages
		q = "SELECT name, CASE WHEN epoch NOT IN ('', '0') THEN epoch || ':' ELSE '' END || version || '-' || release AS version," +
			" CASE WHEN arch = '(none)' THEN '' ELSE arch END AS arch FROM rpm_packages WHERE name != 'gpg-pubkey'"
	}
	rows, err := osq(q)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("osquery returned no packages") // the native list is used instead
	}
	pkgs := make([]api.Package, 0, len(rows))
	for _, r := range rows {
		pkgs = append(pkgs, api.Package{Name: r["name"], Version: r["version"], Arch: r["arch"]})
	}
	return pkgs, nil
}
