package agent

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
		h.aptUpdated = time.Time{} // pick up the new repository
	} else {
		const key = "/etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-osquery"
		if _, err := writeIfChanged(key, osqueryKey, 0o644); err != nil {
			return err
		}
		repo := managedHeader + "[limdm-osquery]\nname=osquery\nbaseurl=" + osqueryRepoURL + "/rpm/$basearch/\n" +
			"enabled=1\ngpgcheck=1\ngpgkey=file://" + key + "\n"
		if _, err := writeIfChanged("/etc/yum.repos.d/limdm-osquery.repo", repo, 0o644); err != nil {
			return err
		}
	}
	return h.install("osquery")
}

// osq runs one query; osquery returns every column as a string.
func osq(query string) ([]map[string]string, error) {
	out, err := run(time.Minute, osqueryi, "--json", query)
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
func enrichFromOsquery(inv *api.Inventory, priv api.Privacy) {
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
		inv.Vendor = firstNonEmpty(s["hardware_vendor"], inv.Vendor)
		inv.Model = firstNonEmpty(s["hardware_model"], inv.Model)
		inv.Serial = firstNonEmpty(s["hardware_serial"], inv.Serial)
	}
	if r, err := osq("SELECT name, version, codename FROM os_version"); err == nil && len(r) == 1 {
		inv.OSCodename = r[0]["codename"]
	}
	if r, err := osq("SELECT vendor, version FROM platform_info"); err == nil && len(r) == 1 {
		inv.BIOSVendor, inv.BIOSVersion = r[0]["vendor"], r[0]["version"]
	}
	if r, err := osq("SELECT swap_total FROM memory_info"); err == nil && len(r) == 1 {
		inv.SwapMB = atou(r[0]["swap_total"]) >> 20
	}
	if r, err := osq("SELECT name, model, size, block_size, type FROM block_devices WHERE parent = '' AND name NOT LIKE '/dev/loop%' AND name NOT LIKE '/dev/ram%' AND name NOT LIKE '/dev/zram%' AND name NOT LIKE '/dev/sr%'"); err == nil && len(r) > 0 {
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
	{
		if r, err := osq("SELECT d.interface, d.mac, a.address FROM interface_details d LEFT JOIN interface_addresses a USING (interface) WHERE d.interface <> 'lo'"); err == nil {
			byName := map[string]*api.NIC{}
			var order []string
			for _, row := range r {
				n := byName[row["interface"]]
				if n == nil {
					n = &api.NIC{Name: row["interface"], MAC: row["mac"]}
					byName[row["interface"]] = n
					order = append(order, row["interface"])
				}
				if a := row["address"]; priv.NetworkInfo && a != "" && !strings.HasPrefix(a, "fe80:") && !slices.Contains(n.IPs, a) {
					n.IPs = append(n.IPs, a)
				}
			}
			inv.Interfaces = nil
			for _, name := range order {
				inv.Interfaces = append(inv.Interfaces, *byName[name])
			}
		}
	}
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

var localFS = map[string]bool{"ext4": true, "ext3": true, "xfs": true, "btrfs": true, "vfat": true, "f2fs": true, "zfs": true}

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
		vols = append(vols, api.Volume{Device: dev, Mount: f.Target, FS: f.FSType, SizeGB: f.Size >> 30, FreeGB: f.Avail >> 30, Encrypted: onLUKS(dev)})
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Mount < vols[j].Mount })
	return vols
}

// onLUKS reports whether a block device sits on a dm-crypt mapping.
func onLUKS(dev string) bool {
	if !strings.HasPrefix(dev, "/dev/") {
		return false
	}
	out, err := sh("lsblk", "-s", "-n", "-o", "TYPE", dev)
	return err == nil && strings.Contains(" "+strings.Join(strings.Fields(out), " ")+" ", " crypt ")
}

// desktop detects the installed desktop environment and display manager.
func desktop() (env, dm string) {
	switch {
	case hasCmd("gnome-shell"):
		env = "GNOME"
		if out, err := sh("gnome-shell", "--version"); err == nil {
			env = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "GNOME Shell"))
			env = "GNOME " + env
		}
	case hasCmd("plasmashell"):
		env = "KDE Plasma"
		if out, err := sh("plasmashell", "--version"); err == nil {
			env = "KDE Plasma " + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "plasmashell"))
		}
	case hasCmd("cinnamon-session"):
		env = "Cinnamon"
	case hasCmd("xfce4-session"):
		env = "Xfce"
	case hasCmd("mate-session"):
		env = "MATE"
	}
	if target, err := os.Readlink("/etc/systemd/system/display-manager.service"); err == nil {
		dm = strings.TrimSuffix(filepath.Base(target), ".service")
	}
	return strings.TrimSpace(env), dm
}

// osqueryPackages returns installed packages from osquery.
func (h *host) osqueryPackages() ([]api.Package, error) {
	if !hasOsquery() {
		return nil, errors.New("osquery not installed")
	}
	q := "SELECT name, version, arch FROM deb_packages WHERE status LIKE '%installed'"
	if h.family != "debian" {
		q = "SELECT name, version || '-' || release AS version, arch FROM rpm_packages"
	}
	rows, err := osq(q)
	if err != nil {
		return nil, err
	}
	pkgs := make([]api.Package, 0, len(rows))
	for _, r := range rows {
		pkgs = append(pkgs, api.Package{Name: r["name"], Version: r["version"], Arch: r["arch"]})
	}
	return pkgs, nil
}
