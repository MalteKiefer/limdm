package agent

import (
	"slices"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestFirewallRuleArgs(t *testing.T) {
	src := api.FirewallRule{Port: "60000:61000/udp", From: "10.0.0.0/8"}
	if got := ufwArgs(src, true); !slices.Equal(got, []string{"delete", "allow", "from", "10.0.0.0/8", "to", "any", "port", "60000:61000", "proto", "udp"}) {
		t.Fatal(got)
	}
	if got := ufwArgs(api.FirewallRule{Port: "22/tcp"}, false); !slices.Equal(got, []string{"allow", "22/tcp"}) {
		t.Fatal(got)
	}
	if got := firewalldArg(src, false); got != `--add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="60000-61000" protocol="udp" accept` {
		t.Fatal(got)
	}
	if got := firewalldArg(api.FirewallRule{Port: "443/tcp", From: "2001:db8::/32"}, true); got != `--remove-rich-rule=rule family="ipv6" source address="2001:db8::/32" port port="443" protocol="tcp" accept` {
		t.Fatal(got)
	}
	if got := firewalldArg(api.FirewallRule{Port: "22/tcp"}, true); got != "--remove-port=22/tcp" {
		t.Fatal(got)
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
