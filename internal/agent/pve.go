package agent

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Proxmox VE is Debian with its own kernel, cluster file system and
// firewall. os-release says Debian, so a node is recognised by /etc/pve
// (pmxcfs) or the pveversion command. The rules that keep a node intact
// (full upgrades only, no removal of proxmox-ve, host name and firewall
// left alone, no automatic reboot) are described in docs/proxmox.md.

// pveRoot prefixes every path below; tests point it at a temporary tree.
var pveRoot = ""

// pveVersionCmd runs pveversion; replaced in tests.
var pveVersionCmd = func() (string, error) { return run(30*time.Second, "pveversion") }

// onPVE reports whether this host is a Proxmox VE node.
func onPVE() bool {
	return exists(pveRoot+"/etc/pve") || exists(pveRoot+"/usr/bin/pveversion")
}

// errPVEHostname: renaming a node breaks /etc/pve/nodes/<name> and the cluster.
var errPVEHostname = errors.New("not changed on a Proxmox VE node: the host name names the node in /etc/pve/nodes and the cluster (rename the node by hand as the Proxmox documentation describes)")

// errPVEFirewall: pve-firewall or proxmox-firewall own iptables and nftables.
var errPVEFirewall = errors.New("not enforced on a Proxmox VE node: the host firewall belongs to pve-firewall (Datacenter, Node and VM firewall in the Proxmox web interface)")

// proxmoxInventory reports the product name ("Proxmox VE 8.4") and the
// node facts, or nothing on other hosts.
func proxmoxInventory() (string, *api.ProxmoxInfo) {
	if !onPVE() {
		return "", nil
	}
	out, _ := pveVersionCmd()
	info := &api.ProxmoxInfo{Version: parsePVEVersion(out), Node: pveNode(), Cluster: corosyncCluster(readFile(pveRoot + "/etc/pve/corosync.conf"))}
	return pveProduct(info.Version), info
}

// pveProduct turns the pve-manager version 8.4.1 into "Proxmox VE 8.4".
func pveProduct(version string) string {
	f := strings.SplitN(version, ".", 3)
	if len(f) >= 2 {
		return "Proxmox VE " + f[0] + "." + f[1]
	}
	return strings.TrimSpace("Proxmox VE " + version)
}

// pveNode is the node name: /etc/pve/local links to nodes/<name>.
func pveNode() string {
	if l, err := os.Readlink(pveRoot + "/etc/pve/local"); err == nil {
		return filepath.Base(l)
	}
	h, _ := os.Hostname()
	short, _, _ := strings.Cut(h, ".")
	return short
}

// corosyncCluster reads cluster_name from corosync.conf (totem section);
// empty on a standalone node.
func corosyncCluster(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "cluster_name:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// pveCritical are the packages whose removal takes a node apart.
var pveCritical = []string{"proxmox-ve", "pve-manager"}

// aptSim runs an apt-get transaction as a simulation; replaced in tests.
var aptSim = func(args ...string) (string, error) {
	return run(5*time.Minute, "apt-get", append([]string{"-s", "-o", "Debug::NoLocking=1"}, args...)...)
}

// aptRemovals lists the packages an apt-get -s run removes ("Remv name [version]").
func aptRemovals(sim string) []string {
	var out []string
	for _, line := range strings.Split(sim, "\n") {
		if rest, ok := strings.CutPrefix(line, "Remv "); ok {
			name, _, _ := strings.Cut(rest, " ")
			out = append(out, name)
		}
	}
	return out
}

// aptGuard simulates an apt-get transaction on a Proxmox VE node first and
// refuses it when it would remove proxmox-ve or pve-manager (a held back
// dependency, a conflicting package, a removal that drags them along).
func aptGuard(args ...string) error {
	if !onPVE() {
		return nil
	}
	sim, err := aptSim(args...)
	if err != nil {
		return err
	}
	var bad []string
	for _, p := range aptRemovals(sim) {
		if slices.Contains(pveCritical, p) {
			bad = append(bad, p)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("refused on Proxmox VE: apt-get %s would remove %s", args[0], strings.Join(bad, ", "))
	}
	return nil
}

// aptGet runs apt-get after aptGuard.
func aptGet(timeout time.Duration, args ...string) (string, error) {
	if err := aptGuard(args...); err != nil {
		return "", err
	}
	return run(timeout, "apt-get", args...)
}

// aptUpgradeVerb is the apt-get full upgrade: dist-upgrade on Proxmox VE,
// whose packages need new dependencies and removals that a plain upgrade
// holds back (aptGuard still refuses losing proxmox-ve), else upgrade with
// new packages.
func aptUpgradeVerb() []string {
	if onPVE() {
		return []string{"dist-upgrade"}
	}
	return []string{"upgrade", "--with-new-pkgs"}
}

// aptEnterpriseOnly returns a warning when every error of apt-get update
// comes from the Proxmox enterprise repository (HTTP 401 without a
// subscription): the other lists were refreshed and stay usable.
func aptEnterpriseOnly(out string) string {
	enterprise := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "E: ") {
			continue
		}
		switch {
		case strings.Contains(line, "enterprise.proxmox.com"):
			enterprise = true
		case strings.HasPrefix(line, "E: Some index files failed to download"):
		default:
			return ""
		}
	}
	if !enterprise {
		return ""
	}
	return "the Proxmox enterprise repository refused access (no subscription, HTTP 401); the updates of the other repositories are listed. Disable it or switch to the no-subscription repository."
}

// pveCheck adjusts a catalog check on a Proxmox VE node: a check whose fix
// would break the node is not applicable (NA is the detail), an sshd
// expectation the cluster cannot meet is relaxed (KV, "" drops a key) and
// the result says so (Note).
type pveCheck struct {
	NA, Note string
	KV       map[string]string
}

var pveChecks = map[string]pveCheck{
	"net.forwarding": {NA: "not applicable on a Proxmox VE node: guests in routed, NAT and SDN networks need IP forwarding"},
	"ssh.baseline": {Note: "Proxmox VE node: root login with keys is allowed, the cluster nodes log in to each other as root",
		KV: map[string]string{"permitrootlogin": "prohibit-password|without-password|no"}},
	"ssh.strict": {Note: "Proxmox VE node: TCP forwarding is not checked, migrations tunnel through SSH",
		KV: map[string]string{"allowtcpforwarding": ""}},
}

// pveAdjust returns c as it applies on this host and, when it does not
// apply at all, the reason.
func pveAdjust(c check, pve bool) (check, string) {
	adj, ok := pveChecks[c.ID]
	if !pve || !ok {
		return c, ""
	}
	if adj.NA != "" {
		return c, adj.NA
	}
	kv := maps.Clone(c.KV)
	for k, v := range adj.KV {
		if v == "" {
			delete(kv, k)
		} else {
			kv[k] = v
		}
	}
	c.KV = kv
	return c, ""
}
