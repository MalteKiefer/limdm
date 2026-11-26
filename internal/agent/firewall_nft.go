package agent

import (
	"fmt"
	"strings"
)

// Alpine: nftables with one table LiMDM owns (inet limdm), rewritten as a
// whole from the declaration and loaded atomically with nft -f. awall would
// add its own policy language on top of iptables; nftables is the kernel's
// current firewall, the stock nftables service loads /etc/nftables.d at
// boot, and the firewall.active check reads the same ruleset.

// nftFile is included by Alpine's /etc/nftables.nft at boot.
var nftFile = "/etc/nftables.d/limdm.nft"

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
	if _, err := sh("nft", "list", "table", "inet", "limdm"); err == nil && !changed {
		return nil
	}
	if _, err := sh("nft", "-f", nftFile); err != nil {
		return err
	}
	a.event("firewall: nftables table inet limdm loaded")
	return nil
}
