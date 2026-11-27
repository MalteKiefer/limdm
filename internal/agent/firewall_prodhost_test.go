package agent

import (
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// Rules of a real Debian 13 host with Docker (Paperless), NetBird and the
// table of an early LiMDM agent: the texts are the ones `nft -a list
// ruleset` printed there. Nothing of it may be offered for adopt, keep or
// discard except the hand written rule in inet filter.
const prodNftJSON = `{"nftables": [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
{"table": {"family": "inet", "name": "filter", "handle": 1}},
{"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
{"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wt0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 6, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8443}}, {"accept": null}]}},
{"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 7, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wt0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}},
{"table": {"family": "ip", "name": "netbird", "handle": 2}},
{"chain": {"family": "ip", "table": "netbird", "name": "netbird-rt-fwd", "handle": 1}},
{"chain": {"family": "ip", "table": "netbird", "name": "netbird-rt-postrouting", "handle": 2, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
{"chain": {"family": "ip", "table": "netbird", "name": "netbird-acl-input-rules", "handle": 3}},
{"rule": {"family": "ip", "table": "netbird", "chain": "netbird-rt-fwd", "handle": 8, "expr": [{"drop": null}]}},
{"rule": {"family": "ip", "table": "netbird", "chain": "netbird-rt-postrouting", "handle": 9, "expr": [{"masquerade": null}]}},
{"rule": {"family": "ip", "table": "netbird", "chain": "netbird-acl-input-rules", "handle": 10, "expr": [{"accept": null}]}},
{"table": {"family": "ip", "name": "nat", "handle": 3}},
{"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING", "handle": 1, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
{"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 11, "expr": [{"masquerade": null}]}},
{"table": {"family": "inet", "name": "limdm_fw", "handle": 4}},
{"chain": {"family": "inet", "table": "limdm_fw", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": -10, "policy": "drop"}},
{"rule": {"family": "inet", "table": "limdm_fw", "chain": "input", "handle": 12, "expr": [{"accept": null}]}},
{"rule": {"family": "inet", "table": "limdm_fw", "chain": "input", "handle": 13, "expr": [{"drop": null}]}},
{"rule": {"family": "inet", "table": "limdm_fw", "chain": "input", "handle": 14, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": null}]}}
]}`

const prodNftText = `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		iifname "wt0" counter packets 0 bytes 0 accept # handle 5
		tcp dport 8443 accept # handle 6
	}

	chain forward { # handle 2
		type filter hook forward priority filter; policy drop;
		oifname "wt0" ct state established,related counter packets 0 bytes 0 accept # handle 7
	}
}
table ip netbird { # handle 2
	chain netbird-rt-fwd { # handle 1
		iifname "wt0" oifname "wt0" drop # handle 8
	}

	chain netbird-rt-postrouting { # handle 2
		type nat hook postrouting priority srcnat; policy accept;
		meta mark 0x0001bd21 oifname != "lo" counter packets 0 bytes 0 masquerade # handle 9
	}

	chain netbird-acl-input-rules { # handle 3
		ip saddr @nb0000001 accept # handle 10
	}
}
table ip nat { # handle 3
	chain POSTROUTING { # handle 1
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 172.18.0.6 ip daddr 172.18.0.6 tcp dport 8000 counter packets 0 bytes 0 masquerade # handle 11
	}
}
table inet limdm_fw { # handle 4
	chain input { # handle 1
		type filter hook input priority filter - 10; policy drop;
		iif "lo" accept # handle 12
		ct state invalid drop # handle 13
		tcp dport 22 accept # handle 14
	}
}
`

func TestProductionHostClassification(t *testing.T) {
	rules, pol, err := parseNft(prodNftJSON, prodNftText)
	if err != nil {
		t.Fatal(err)
	}
	bridges := api.ParseBridgeNets([]string{"172.17.0.0/16", "172.18.0.0/16"})
	for i := range rules {
		rules[i].Finish(bridges...)
		rules[i].Risk = api.RuleRisk(rules[i], pol, 443)
	}
	want := map[string]string{
		`iifname "wt0" counter`:       api.OriginSystem, // NetBird in inet filter input
		`oifname "wt0" ct state`:      api.OriginSystem, // NetBird in inet filter forward
		`iifname "wt0" oifname "wt0"`: api.OriginSystem, // table ip netbird
		`meta mark 0x0001bd21`:        api.OriginSystem,
		`@nb0000001`:                  api.OriginSystem,  // NetBird set
		`ip saddr 172.18.0.6`:         api.OriginSystem,  // Docker hairpin NAT outside DOCKER chains
		`iif "lo" accept`:             api.OriginManaged, // inet limdm_fw of an early agent
		`ct state invalid drop`:       api.OriginManaged,
		`tcp dport 8443 accept`:       api.OriginForeign, // the one hand written rule
	}
	for sub, origin := range want {
		r := byRaw(t, rules, sub)
		if r.Origin != origin {
			t.Errorf("%q: origin %s, want %s (%s)", sub, r.Origin, origin, r.Match)
		}
		if origin != api.OriginForeign && api.RemovableRule(r, true) == nil {
			t.Errorf("%q: removable", sub)
		}
	}
	if r := byRaw(t, rules, "tcp dport 22"); r.Origin != api.OriginManaged || r.Table != "inet limdm_fw" {
		t.Errorf("ssh rule of inet limdm_fw: %+v", r)
	}
	// without the bridge subnets the NAT rule would look foreign
	nat := byRaw(t, rules, "ip saddr 172.18.0.6")
	nat.Origin = ""
	nat.Finish()
	if nat.Origin != api.OriginForeign {
		t.Errorf("NAT without bridges: %s", nat.Origin)
	}
}
