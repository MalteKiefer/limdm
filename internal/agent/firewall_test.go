package agent

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestFirewallRuleArgs(t *testing.T) {
	src := fwRule{Port: "60000:61000/udp", From: "10.0.0.0/8"}
	for _, c := range []struct {
		r    fwRule
		del  bool
		want string
	}{
		{src, true, "delete allow from 10.0.0.0/8 to any port 60000:61000 proto udp"},
		{fwRule{Port: "22/tcp"}, false, "allow 22/tcp"},
		{fwRule{Port: "22/tcp", Iface: "wg0"}, false, "allow in on wg0 to any port 22 proto tcp"},
		{fwRule{Port: "22/tcp", Iface: "wg0", From: "10.0.0.0/8"}, true, "delete allow in on wg0 from 10.0.0.0/8 to any port 22 proto tcp"},
		{fwRule{Out: true, Port: "53/udp"}, false, "allow out 53/udp"},
		{fwRule{Out: true, To: "192.0.2.1", Port: "443/tcp"}, false, "allow out to 192.0.2.1 port 443 proto tcp"},
		{fwRule{Out: true, To: "192.0.2.0/24"}, false, "allow out to 192.0.2.0/24"},
	} {
		if got := strings.Join(ufwArgs(c.r, c.del), " "); got != c.want {
			t.Errorf("ufw %+v: %s", c.r, got)
		}
	}
	for _, c := range []struct {
		r    fwRule
		del  bool
		want string
	}{
		{src, false, `--add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="60000-61000" protocol="udp" accept`},
		{fwRule{Port: "443/tcp", From: "2001:db8::/32"}, true, `--remove-rich-rule=rule family="ipv6" source address="2001:db8::/32" port port="443" protocol="tcp" accept`},
		{fwRule{Port: "22/tcp"}, true, "--remove-port=22/tcp"},
		{fwRule{Zone: "internal", Port: "22/tcp"}, false, "--zone=internal --add-port=22/tcp"},
		{fwRule{Zone: "internal", Iface: "wg0"}, false, "--zone=internal --change-interface=wg0"},
		{fwRule{Zone: "internal", Iface: "wg0"}, true, "--zone=internal --remove-interface=wg0"},
		{fwRule{Zone: "internal", From: "10.0.0.0/8"}, false, "--zone=internal --add-source=10.0.0.0/8"},
		{fwRule{Out: true, Port: "53/udp"}, false, `--policy=limdm-egress --add-rich-rule=rule port port="53" protocol="udp" accept`},
		{fwRule{Out: true, To: "192.0.2.1"}, true, `--policy=limdm-egress --remove-rich-rule=rule family="ipv4" destination address="192.0.2.1" accept`},
	} {
		if got := strings.Join(firewalldArgs(c.r, c.del), " "); got != c.want {
			t.Errorf("firewalld %+v: %s", c.r, got)
		}
	}
}

func TestFirewallWantRules(t *testing.T) {
	f := api.Firewall{Enforce: true, Allow: []string{"22/tcp"},
		Zones:    []api.FirewallZone{{Name: "internal", Interfaces: []string{"wg0"}, Sources: []string{"10.0.0.0/8", "fd00::/8"}, Allow: []string{"5432/tcp"}}},
		Outbound: &api.FirewallOutbound{Policy: "deny", Allow: []api.FirewallEgress{{To: "192.0.2.0/24", Port: "443/tcp"}}}}
	server := []fwRule{{Out: true, To: "198.51.100.7", Port: "8443/tcp"}}
	ufw := wantRules(f, false, server)
	for _, r := range []fwRule{{Port: "22/tcp"}, {Port: "5432/tcp", From: "10.0.0.0/8", Iface: "wg0"}, {Port: "5432/tcp", From: "fd00::/8", Iface: "wg0"},
		{Out: true, To: "192.0.2.0/24", Port: "443/tcp"}, {Out: true, Port: "53/udp"}, server[0]} {
		if !slices.Contains(ufw, r) {
			t.Errorf("ufw misses %+v", r)
		}
	}
	fwd := wantRules(f, true, server)
	for _, r := range []fwRule{{Zone: "internal", Iface: "wg0"}, {Zone: "internal", From: "10.0.0.0/8"}, {Zone: "internal", Port: "5432/tcp"}} {
		if !slices.Contains(fwd, r) {
			t.Errorf("firewalld misses %+v", r)
		}
	}
	f.Outbound.Policy = "allow"
	if slices.ContainsFunc(wantRules(f, false, nil), func(r fwRule) bool { return r.Out }) {
		t.Error("outbound rules without deny")
	}
	nft := nftRuleset(ufw, true)
	for _, want := range []string{"type filter hook input priority 0; policy drop;", "\t\ttcp dport 22 accept\n", `iifname "wg0" ip6 saddr fd00::/8 tcp dport 5432 accept`,
		"policy drop;\n", "ip daddr 192.0.2.0/24 tcp dport 443 accept", "ip daddr 198.51.100.7 tcp dport 8443 accept", "udp dport 53 accept"} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft ruleset misses %q:\n%s", want, nft)
		}
	}
	if !nftDropsInput("table inet limdm {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;") {
		t.Error("check does not see the table")
	}
	// state written by agents before zones still reads
	var st State
	if err := json.Unmarshal([]byte(`{"firewall_rules":[{"port":"22/tcp","from":""}]}`), &st); err != nil || st.FirewallRules[0] != (fwRule{Port: "22/tcp"}) {
		t.Fatal(err, st.FirewallRules)
	}
}

func TestFirewallRulesValidation(t *testing.T) {
	ok := api.LibraryItem{Name: "x", Type: api.TypeFirewall, Payload: []byte(`{"enforce":true,"allow":["22/tcp"],"rules":[{"port":"5432/tcp","from":"10.0.0.0/8"},{"port":"443/tcp","from":"192.0.2.7"}]}`)}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := api.LibraryItem{Name: "x", Type: api.TypeFirewall, Payload: []byte(`{"enforce":true,"allow":[],"rules":[{"port":"22/tcp","from":"10.0.0.0/8 to any"}]}`)}
	if bad.Validate() == nil {
		t.Fatal("invalid source accepted")
	}
}
