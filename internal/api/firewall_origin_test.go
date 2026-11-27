package api

import (
	"strings"
	"testing"
)

func TestVPNAndLiMDMOrigins(t *testing.T) {
	for _, c := range []struct {
		r    FirewallInvRule
		want string
	}{
		{FirewallInvRule{Source: "nftables", Table: "inet ts", Chain: "ts-input", Raw: `iifname "tailscale0" accept`}, OriginSystem},
		{FirewallInvRule{Source: "iptables", Table: "filter", Chain: "INPUT", Raw: `-A INPUT -i ztabcdef12 -j ACCEPT`}, OriginSystem},
		{FirewallInvRule{Source: "nftables", Table: "ip wg-quick-wg0", Chain: "preraw", Raw: `meta mark 0x0000ca6c accept`}, OriginSystem},
		{FirewallInvRule{Source: "nftables", Table: "inet limdm", Chain: "input", Raw: `tcp dport 443 accept`}, OriginManaged},
		{FirewallInvRule{Source: "firewalld", Zone: "limdm-egress", Raw: `--policy=limdm-egress --add-rich-rule=rule accept`}, OriginManaged},
		// names that only look alike stay foreign: a wg0 rule an admin wrote, wt without digits
		{FirewallInvRule{Source: "nftables", Table: "inet filter", Chain: "input", Raw: `iifname "wg0" udp dport 51820 accept`}, OriginForeign},
		{FirewallInvRule{Source: "nftables", Table: "inet filter", Chain: "input", Raw: `iifname "wtx" accept`}, OriginForeign},
	} {
		c.r.Finish()
		if c.r.Origin != c.want {
			t.Errorf("%s: %s, want %s", c.r.Raw, c.r.Origin, c.want)
		}
	}
	if n := ParseBridgeNets([]string{"172.18.0.0/16", "0.0.0.0/0", "fd00::/8", "nonsense", "10.1.2.3/24"}); len(n) != 2 || n[1].String() != "10.1.2.0/24" {
		t.Errorf("bridge nets %v", n)
	}
	r := FirewallInvRule{Source: "nftables", Table: "ip nat", Chain: "POSTROUTING", Raw: "ip saddr 0.0.0.0/0 masquerade"}
	if BridgeRule(r, ParseBridgeNets([]string{"172.18.0.0/16"})) {
		t.Error("a wider network counted as the bridge")
	}
}

func TestFirewallRemoveValidation(t *testing.T) {
	ok := Declaration{Identifier: "f", Type: TypeFirewall, Payload: []byte(`{"remove":["nftables inet filter input: tcp dport 8443 accept"]}`)}
	if err := ok.apply(&Policy{}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"nftables inet limdm_fw input: iif \"lo\" accept", "nftables ip netbird netbird-rt-fwd: iifname \"wt0\" drop", "iptables filter DOCKER-USER: -A DOCKER-USER -j RETURN"} {
		bad := Declaration{Identifier: "f", Type: TypeFirewall, Payload: []byte(`{"remove":["` + strings.ReplaceAll(m, `"`, `\"`) + `"]}`)}
		if bad.apply(&Policy{}) == nil {
			t.Errorf("remove entry accepted: %s", m)
		}
	}
	f, err := RemoveInto(Firewall{Keep: []string{"x"}}, FirewallInvRule{Source: "ufw", Origin: OriginForeign, Match: "x", Raw: "ufw allow 8080/tcp"}, false)
	if err != nil || len(f.Keep) != 0 || len(f.Remove) != 1 {
		t.Fatalf("remove into: %+v %v", f, err)
	}
}
