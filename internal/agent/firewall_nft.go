package agent

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Alpine: nftables with one table LiMDM owns (inet limdm), rewritten as a
// whole from the declaration and loaded atomically with nft -f. awall would
// add its own policy language on top of iptables; nftables is the kernel's
// current firewall, the stock nftables service loads /etc/nftables.d at
// boot, and the firewall.active check reads the same ruleset.

// nftFile is included by Alpine's /etc/nftables.nft at boot.
var nftFile = "/etc/nftables.d/limdm.nft"

// Boot: the file must be loaded at boot. Where the distribution's main
// configuration includes /etc/nftables.d/*.nft and its nftables service is
// enabled at boot, that does it. Otherwise LiMDM installs its own small
// boot service, limdm-firewall, that loads only its file after nftables.
// The agent never starts, restarts or reloads the nftables service and never
// loads or edits the main configuration: both begin with flush ruleset and
// would drop the tables of Docker, NetBird or CrowdSec at runtime.
var (
	nftMainConfs   = []string{"/etc/nftables.conf", "/etc/nftables.nft", "/etc/sysconfig/nftables.conf"}
	nftEnabled     = []string{"/etc/systemd/system/sysinit.target.wants/nftables.service", "/etc/systemd/system/multi-user.target.wants/nftables.service", "/etc/runlevels/default/nftables", "/etc/runlevels/boot/nftables"}
	nftUnitDir     = "/etc/systemd/system"
	nftInitDir     = "/etc/init.d"
	nftUnitEnabled = []string{"/etc/systemd/system/multi-user.target.wants/limdm-firewall.service", "/etc/runlevels/default/limdm-firewall"}
)

var nftIncludeRe = regexp.MustCompile(`(?m)^\s*include\s+"/etc/nftables\.d/\*(\.nft)?"`)

// nftBootCovered: the main configuration includes nftables.d and the
// nftables service starts at boot (read from files, no command).
func nftBootCovered() bool {
	included := false
	for _, c := range nftMainConfs {
		if nftIncludeRe.MatchString(readFile(c)) {
			included = true
		}
	}
	enabled := false
	for _, e := range nftEnabled {
		enabled = enabled || exists(e)
	}
	return included && enabled
}

// ensureNftBoot makes the LiMDM table load at boot, idempotently.
func ensureNftBoot() error {
	if nftBootCovered() {
		return nil
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	if systemd() {
		unit := "[Unit]\nDescription=LiMDM host firewall table (only inet limdm)\nAfter=nftables.service\nDefaultDependencies=no\nBefore=network-pre.target\nWants=network-pre.target\n\n" +
			"[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=" + nft + " -f " + nftFile + "\n\n[Install]\nWantedBy=multi-user.target\n"
		changed, err := writeIfChanged(filepath.Join(nftUnitDir, "limdm-firewall.service"), unit, 0o644)
		if err != nil {
			return err
		}
		if changed {
			if _, err := sh("systemctl", "daemon-reload"); err != nil {
				return err
			}
		}
		if !exists(nftUnitEnabled[0]) {
			_, err = sh("systemctl", "enable", "limdm-firewall.service") // enable only: the table is loaded already
		}
		return err
	}
	script := "#!/sbin/openrc-run\n# Loads only LiMDM's table (inet limdm); written by the LiMDM agent.\ndescription=\"LiMDM host firewall table\"\n\n" +
		"depend() {\n\tafter nftables\n}\n\nstart() {\n\tebegin \"Loading the LiMDM firewall table\"\n\t" + nft + " -f " + nftFile + "\n\teend $?\n}\n"
	if _, err := writeIfChanged(filepath.Join(nftInitDir, "limdm-firewall"), script, 0o755); err != nil {
		return err
	}
	if exists(nftUnitEnabled[1]) {
		return nil
	}
	_, err = sh("rc-update", "add", "limdm-firewall", "default")
	return err
}

// nftAddr is the match of a source or destination address.
func nftAddr(dir, addr string) string {
	if addr == "" {
		return ""
	}
	fam := "ip"
	if strings.Contains(addr, ":") {
		fam = "ip6"
	}
	return fam + " " + dir + " " + addr + " "
}

// nftPort is the match of a port or range ("" for any).
func nftPort(p string) string {
	if p == "" {
		return ""
	}
	port, proto, _ := strings.Cut(strings.Replace(p, ":", "-", 1), "/")
	return proto + " dport " + port + " "
}

// nftRuleset renders the LiMDM table. Input drops everything not allowed;
// output drops only with outbound deny. Established traffic, loopback,
// ICMP and DHCP replies always pass.
func nftRuleset(rules []fwRule, deny bool) string {
	var in, out strings.Builder
	for _, r := range rules {
		if r.Out {
			fmt.Fprintf(&out, "\t\t%s%saccept\n", nftAddr("daddr", r.To), nftPort(r.Port))
			continue
		}
		iface := ""
		if r.Iface != "" {
			iface = `iifname "` + r.Iface + `" `
		}
		fmt.Fprintf(&in, "\t\t%s%s%saccept\n", iface, nftAddr("saddr", r.From), nftPort(r.Port))
	}
	policy := "accept"
	if deny {
		policy = "drop"
	}
	return "# Written by the LiMDM agent from com.limdm.firewall; changes are overwritten.\n" +
		"table inet limdm {}\ndelete table inet limdm\ntable inet limdm {\n" +
		"\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n" +
		"\t\tct state established,related accept\n\t\tct state invalid drop\n\t\tiifname \"lo\" accept\n" +
		"\t\tmeta l4proto { icmp, ipv6-icmp } accept\n\t\tudp sport { 67, 547 } udp dport { 68, 546 } accept\n" + in.String() + "\t}\n" +
		"\tchain output {\n\t\ttype filter hook output priority 0; policy " + policy + ";\n" +
		"\t\tct state established,related accept\n\t\toifname \"lo\" accept\n\t\tmeta l4proto { icmp, ipv6-icmp } accept\n" +
		out.String() + "\t}\n}\n"
}

// syncNftables writes and loads the LiMDM table when it changed or is not
// loaded (after a manual flush).
func (a *Agent) syncNftables() error {
	if !hasCmd("nft") {
		return nil // applyFirewall installs it first
	}
	deny := egressDeny(a.pol.Firewall)
	var server []fwRule
	if deny {
		var err error
		if server, err = a.serverEgress(); err != nil {
			return err
		}
	}
	changed, err := writeIfChanged(nftFile, nftRuleset(wantRules(a.pol.Firewall, false, server), deny), 0o600)
	if err != nil {
		return err
	}
	if _, err := sh("nft", "list", "table", "inet", "limdm"); err != nil || changed {
		// only LiMDM's table: the file deletes and recreates inet limdm
		if _, err := sh("nft", "-f", nftFile); err != nil {
			return err
		}
		a.event("firewall: nftables table inet limdm loaded")
	}
	return ensureNftBoot()
}
