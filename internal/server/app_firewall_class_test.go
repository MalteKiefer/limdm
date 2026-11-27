package server

import (
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// The server classifies again: an agent that reports LiMDM's legacy table,
// NetBird or Docker NAT rules as foreign (agents of 0.19.0-rc1) does not
// make them actionable, and implausible bridge subnets are dropped.
func TestSanitizeFirewallReclassifies(t *testing.T) {
	inv := api.FirewallInventory{BridgeNets: []string{"172.18.0.0/16", "0.0.0.0/0"}, Rules: []api.FirewallInvRule{
		{Source: "nftables", Origin: "foreign", Table: "inet limdm_fw", Chain: "input", Raw: `iif "lo" accept`},
		{Source: "nftables", Origin: "foreign", Table: "inet filter", Chain: "input", Raw: `iifname "wt0" counter packets 0 bytes 0 accept`},
		{Source: "nftables", Origin: "foreign", Table: "ip nat", Chain: "POSTROUTING", Raw: `ip saddr 172.18.0.6 ip daddr 172.18.0.6 tcp dport 8000 counter masquerade`},
		{Source: "nftables", Origin: "foreign", Table: "inet filter", Chain: "input", Raw: `tcp dport 8443 accept`},
	}}
	sanitizeFirewall(&inv)
	want := []string{api.OriginManaged, api.OriginSystem, api.OriginSystem, api.OriginForeign}
	for i, r := range inv.Rules {
		if r.Origin != want[i] {
			t.Errorf("%s: %s, want %s", r.Raw, r.Origin, want[i])
		}
	}
	if len(inv.BridgeNets) != 1 || inv.BridgeNets[0] != "172.18.0.0/16" {
		t.Errorf("bridge nets %v", inv.BridgeNets)
	}
}
