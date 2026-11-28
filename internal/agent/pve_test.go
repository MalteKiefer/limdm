package agent

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// fakePVE lays out /etc/pve of a node named pve1 (cluster when corosync is
// set) under a temporary root and feeds pveversion.
func fakePVE(t *testing.T, version, corosync string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/pve/nodes/pve1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nodes/pve1", filepath.Join(root, "etc/pve/local")); err != nil {
		t.Fatal(err)
	}
	if corosync != "" {
		if err := os.WriteFile(filepath.Join(root, "etc/pve/corosync.conf"), []byte(corosync), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pveRoot = root
	pveVersionCmd = func() (string, error) { return version, nil }
	t.Cleanup(func() {
		pveRoot = ""
		pveVersionCmd = func() (string, error) { return run(30*time.Second, "pveversion") }
	})
}

const corosyncConf = `logging {
  debug: off
}
nodelist {
  node {
    name: pve1
    nodeid: 1
    ring0_addr: 10.0.0.1
  }
}
quorum {
  provider: corosync_votequorum
}
totem {
  cluster_name: prod
  config_version: 3
  version: 2
}
`

func TestProxmoxInventory(t *testing.T) {
	if p, info := proxmoxInventory(); p != "" || info != nil {
		t.Fatalf("plain host reported as Proxmox VE: %q %+v", p, info)
	}
	fakePVE(t, "pve-manager/8.4.1/2a5fa54a8503f96d (running kernel: 6.8.12-10-pve)\n", corosyncConf)
	p, info := proxmoxInventory()
	if p != "Proxmox VE 8.4" || info == nil || info.Version != "8.4.1" || info.Node != "pve1" || info.Cluster != "prod" {
		t.Fatalf("PVE 8 cluster node: %q %+v", p, info)
	}
	fakePVE(t, "pve-manager/9.0.6/49c767b70aeb6648 (running kernel: 6.14.8-2-pve)\n", "")
	if p, info = proxmoxInventory(); p != "Proxmox VE 9.0" || info.Cluster != "" || info.Node != "pve1" {
		t.Fatalf("PVE 9 standalone: %q %+v", p, info)
	}
}

func TestAptGuard(t *testing.T) {
	var sims [][]string
	sim := "Inst libpve-common-perl [8.2.9] (8.3.1 Proxmox:8.4/stable [all])\n"
	aptSim = func(args ...string) (string, error) {
		sims = append(sims, args)
		return sim, nil
	}
	t.Cleanup(func() {
		aptSim = func(args ...string) (string, error) {
			return run(5*time.Minute, "apt-get", append([]string{"-s", "-o", "Debug::NoLocking=1"}, args...)...)
		}
	})
	if err := aptGuard("remove", "-y", "--", "corosync"); err != nil || len(sims) != 0 || aptUpgradeVerb()[0] != "upgrade" {
		t.Fatalf("plain Debian: %v %v %v", err, sims, aptUpgradeVerb())
	}
	fakePVE(t, "", "")
	if v := aptUpgradeVerb(); len(v) != 1 || v[0] != "dist-upgrade" {
		t.Fatalf("PVE upgrade verb %v", v)
	}
	if err := aptGuard("dist-upgrade", "-y"); err != nil || len(sims) != 1 || sims[0][0] != "dist-upgrade" {
		t.Fatalf("harmless upgrade: %v %v", err, sims)
	}
	sim = "Remv proxmox-ve [8.4.0]\nRemv pve-manager [8.4.1]\nRemv libfoo [1]\nInst libfoo2 (2 Debian:12.10/stable [amd64])\n"
	if got := aptRemovals(sim); strings.Join(got, ",") != "proxmox-ve,pve-manager,libfoo" {
		t.Fatalf("removals %v", got)
	}
	err := aptGuard("install", "-y", "--", "libfoo2")
	if err == nil || !strings.Contains(err.Error(), "would remove proxmox-ve, pve-manager") {
		t.Fatalf("removal of proxmox-ve not refused: %v", err)
	}
	if _, err := aptGet(time.Minute, "dist-upgrade", "-y"); err == nil {
		t.Fatal("aptGet ran a refused transaction")
	}
}

func TestAptEnterpriseOnly(t *testing.T) {
	enterprise := `E: Failed to fetch https://enterprise.proxmox.com/debian/pve/dists/bookworm/InRelease  401  Unauthorized [IP: 212.224.123.70 443]
E: The repository 'https://enterprise.proxmox.com/debian/pve bookworm InRelease' is not signed.
E: Some index files failed to download. They have been ignored, or old ones used instead.
`
	if aptEnterpriseOnly(enterprise) == "" {
		t.Fatal("enterprise only 401 not recognised")
	}
	if aptEnterpriseOnly(enterprise+"E: Failed to fetch http://deb.debian.org/debian/dists/bookworm/InRelease  Could not resolve\n") != "" {
		t.Fatal("a failing Debian mirror was hidden")
	}
	if aptEnterpriseOnly("E: Could not get lock /var/lib/apt/lists/lock\n") != "" {
		t.Fatal("unrelated error hidden")
	}
}

func TestPVEChecks(t *testing.T) {
	a := &Agent{pol: api.Policy{Compliance: api.Compliance{Level: 2}}}
	if _, ok := a.groupKV("sysctl")["net.ipv4.ip_forward"]; !ok {
		t.Fatal("plain host: ip_forward missing")
	}
	fakePVE(t, "", "")
	if _, ok := a.groupKV("sysctl")["net.ipv4.ip_forward"]; ok {
		t.Fatal("PVE: ip_forward ends up in the sysctl drop-in")
	}
	ssh := a.groupKV("sshd")
	if _, ok := ssh["allowtcpforwarding"]; ok || ssh["passwordauthentication"] != "no" {
		t.Fatalf("PVE sshd: %v", ssh)
	}
	if v := ssh["permitrootlogin"]; !sshValueOK("without-password", v) || !sshValueOK("no", v) || sshValueOK("yes", v) || sshWanted(v) != "prohibit-password" {
		t.Fatalf("PVE permitrootlogin %q", v)
	}
	for _, c := range catalog {
		if c.ID == "net.forwarding" {
			if _, why := pveAdjust(c, true); !strings.Contains(why, "not applicable") {
				t.Fatalf("net.forwarding on PVE: %q", why)
			}
		}
	}
}

func TestHostnameOnPVE(t *testing.T) {
	dir := t.TempDir()
	hostsFile, mailnameFile, hostnameFile = filepath.Join(dir, "hosts"), filepath.Join(dir, "mailname"), filepath.Join(dir, "hostname")
	var cmds []string
	hostCmd = func(_ time.Duration, name string, args ...string) (string, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return "", nil
	}
	mtaProbe = func() (string, string) { return "", "" }
	dnsResolver = stubResolver{}
	t.Cleanup(func() {
		hostsFile, mailnameFile, hostnameFile = "/etc/hosts", "/etc/mailname", "/etc/hostname"
		hostCmd, mtaProbe, dnsResolver = run, mtaHostname, net.DefaultResolver
	})
	hosts := "127.0.0.1 localhost\n10.0.0.1 pve1.lab.example pve1\n"
	if err := os.WriteFile(hostsFile, []byte(hosts), 0o644); err != nil {
		t.Fatal(err)
	}
	fakePVE(t, "", "")
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := a.applyHostname(&api.Hostname{Source: "fixed", Name: "renamed", Domain: "lab.example", Hosts: true})
	if err == nil || a.state.Hostname.Info.Result != "failed" || !strings.Contains(a.state.Hostname.Info.Detail, "Proxmox VE") {
		t.Fatalf("rename on PVE: %v %+v", err, a.state.Hostname.Info)
	}
	if len(cmds) != 0 || readFile(hostsFile) != hosts || exists(hostnameFile) {
		t.Fatalf("PVE node touched: %v %q", cmds, readFile(hostsFile))
	}
}
