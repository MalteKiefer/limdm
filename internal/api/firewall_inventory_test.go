package api

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestAdoptAndKeep(t *testing.T) {
	r := FirewallInvRule{Source: "ufw", Direction: "in", Action: "allow", Port: "8080", Proto: "tcp", Raw: "ufw allow 8080/tcp"}
	r.Finish()
	if r.Origin != OriginForeign || len(r.ID) != 16 {
		t.Fatalf("%+v", r)
	}
	item := Firewall{Enforce: true, Allow: []string{"22/tcp"}}
	got, err := AdoptInto(item, r, FirewallInventory{})
	if err != nil || !slices.Equal(got.Allow, []string{"22/tcp", "8080/tcp"}) || !got.Enforce {
		t.Fatalf("adopt: %+v %v", got, err)
	}
	out := FirewallInvRule{Source: "ufw", Direction: "out", Action: "allow", Port: "443", Proto: "tcp", To: "192.0.2.1", Raw: "ufw allow out to 192.0.2.1 port 443 proto tcp"}
	out.Finish()
	if _, err := AdoptInto(item, out, FirewallInventory{}); err == nil {
		t.Fatal("outbound adopted into an item without outbound policy")
	}
	item.Outbound = &FirewallOutbound{Policy: "deny"}
	if got, err := AdoptInto(item, out, FirewallInventory{}); err != nil || got.Outbound.Policy != "deny" || got.Outbound.Allow[0] != (FirewallEgress{To: "192.0.2.1", Port: "443/tcp"}) {
		t.Fatalf("adopt outbound: %+v %v", got.Outbound, err)
	}
	kept, err := KeepInto(item, r)
	if err != nil || !slices.Equal(kept.Keep, []string{r.Match}) {
		t.Fatalf("keep: %+v %v", kept, err)
	}
	b, _ := json.Marshal(kept)
	if err := (Declaration{Identifier: "fw", Type: TypeFirewall, Payload: b}).apply(&Policy{}); err != nil {
		t.Fatalf("kept item invalid: %v", err)
	}
	merged := mergeFirewall(kept, Firewall{Keep: []string{"other", r.Match}})
	if !slices.Equal(merged.Keep, []string{r.Match, "other"}) {
		t.Fatalf("merge keep: %v", merged.Keep)
	}
	if (Firewall{Keep: []string{"a\nb"}}).validate() == nil {
		t.Fatal("multi line exception accepted")
	}
	sys := FirewallInvRule{Source: "iptables", Table: "filter", Chain: "FORWARD", Action: "accept", Iface: "br-3f2a", Direction: "forward", Raw: "-A FORWARD -i br-3f2a -j ACCEPT"}
	sys.Finish()
	if _, err := KeepInto(item, sys); err == nil || sys.Origin != OriginSystem {
		t.Fatal("system rule kept")
	}
}

func TestRuleRisk(t *testing.T) {
	closed := FirewallPolicies{In: "drop", Out: "drop"}
	for _, c := range []struct {
		r    FirewallInvRule
		pol  FirewallPolicies
		want string
	}{
		{FirewallInvRule{Direction: "in", Action: "accept", Port: "22"}, closed, "ssh"},
		{FirewallInvRule{Direction: "in", Action: "accept", Port: "20-30"}, closed, "ssh"},
		{FirewallInvRule{Direction: "in", Action: "accept"}, closed, "ssh"}, // any port, for example ct state established
		{FirewallInvRule{Direction: "in", Action: "accept", Port: "22"}, FirewallPolicies{In: "accept"}, ""},
		{FirewallInvRule{Direction: "in", Action: "drop", Port: "22"}, closed, ""},
		{FirewallInvRule{Direction: "in", Action: "accept", Port: "22", Iface: "lo"}, closed, ""},
		{FirewallInvRule{Direction: "out", Action: "accept", Port: "443"}, closed, "server"},
		{FirewallInvRule{Direction: "out", Action: "accept", Port: "53"}, closed, ""},
	} {
		if got := RuleRisk(c.r, c.pol, 443); got != c.want {
			t.Errorf("%+v: %q", c.r, got)
		}
	}
}
