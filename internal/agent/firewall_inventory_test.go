package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// finish runs what collectFirewall does after parsing.
func finish(rules []api.FirewallInvRule, pol api.FirewallPolicies) []api.FirewallInvRule {
	for i := range rules {
		rules[i].Finish()
		rules[i].Risk = api.RuleRisk(rules[i], pol, 443)
	}
	return rules
}

func byRaw(t *testing.T, rules []api.FirewallInvRule, sub string) api.FirewallInvRule {
	t.Helper()
	for _, r := range rules {
		if strings.Contains(r.Raw, sub) {
			return r
		}
	}
	t.Fatalf("no rule with %q in %+v", sub, rules)
	return api.FirewallInvRule{}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs(`-A INPUT -m comment --comment "allow web \"x\"" -j ACCEPT 'a b'`)
	want := []string{"-A", "INPUT", "-m", "comment", "--comment", `allow web "x"`, "-j", "ACCEPT", "a b"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestParseUFW(t *testing.T) {
	active, pol := parseUFWStatus("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n")
	if !active || pol != (api.FirewallPolicies{In: "deny", Out: "allow", Forward: "disabled"}) {
		t.Fatalf("%v %+v", active, pol)
	}
	added := "Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\nufw allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'db'\n" +
		"ufw allow in on wg0 to any port 8080 proto tcp\nufw deny 23\nufw allow OpenSSH\nufw allow out to 192.0.2.1 port 443 proto tcp\n"
	rules := finish(parseUFWAdded(added, ufwManaged([]fwRule{{Port: "22/tcp"}})), pol)
	if len(rules) != 6 {
		t.Fatalf("%d rules", len(rules))
	}
	ssh := byRaw(t, rules, "22/tcp")
	if ssh.Origin != api.OriginManaged || ssh.Risk != "ssh" {
		t.Fatalf("ssh: %+v", ssh)
	}
	db := byRaw(t, rules, "5432")
	if db.Origin != api.OriginForeign || db.From != "10.0.0.0/8" || db.Port != "5432" || db.Proto != "tcp" || db.Comment != "db" || db.Direction != "in" {
		t.Fatalf("db: %+v", db)
	}
	if f, err := api.AdoptFragment(db, api.FirewallInventory{}); err != nil || !slices.Equal(f.Rules, []api.FirewallRule{{Port: "5432/tcp", From: "10.0.0.0/8"}}) {
		t.Fatalf("adopt db: %+v %v", f, err)
	}
	name, args, err := removeArgs(db)
	if err != nil || name != "ufw" || strings.Join(args, " ") != "--force delete allow from 10.0.0.0/8 to any port 5432 proto tcp" {
		t.Fatalf("remove: %s %q %v", name, args, err)
	}
	wg := byRaw(t, rules, "wg0")
	if f, err := api.AdoptFragment(wg, api.FirewallInventory{}); err != nil || f.Zones[0].Name != "if-wg0" || f.Zones[0].Allow[0] != "8080/tcp" {
		t.Fatalf("adopt wg0: %+v %v", f, err)
	}
	if _, err := api.AdoptFragment(byRaw(t, rules, "deny 23"), api.FirewallInventory{}); err == nil {
		t.Fatal("a deny rule was adoptable")
	}
	out := byRaw(t, rules, "out to")
	if out.Direction != "out" || out.To != "192.0.2.1" || out.Risk != "" { // outbound policy allow
		t.Fatalf("out: %+v", out)
	}
}

const firewalldZones = `docker
  target: ACCEPT
  interfaces: docker0
  sources:
  services:
  ports:
  rich rules:

internal
  target: default
  interfaces: wg0
  sources: 10.8.0.0/24
  services: ssh
  ports: 9100/tcp
  rich rules:

public (default)
  target: default
  icmp-block-inversion: no
  interfaces:
  sources:
  services: dhcpv6-client ssh
  ports: 22/tcp 8080/tcp 60000-61000/udp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
	rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept
	rule family="ipv4" source address="192.0.2.9" reject
`

const firewalldPolicies = `limdm-egress
  priority: -1
  target: REJECT
  ingress-zones: HOST
  egress-zones: ANY
  services:
  ports:
  rich rules:
	rule port port="53" protocol="udp" accept
	rule family="ipv4" destination address="198.51.100.4" port port="443" protocol="tcp" accept
`

func TestParseFirewalld(t *testing.T) {
	applied := []fwRule{{Port: "22/tcp"}, {Zone: "internal", Iface: "wg0"}, {Out: true, Port: "53/udp"}}
	rules, pol := parseFirewalld(firewalldZones, firewalldPolicies, "public", firewalldManaged(applied, "public"))
	if pol.In != "reject" || pol.Out != "reject" {
		t.Fatalf("policy %+v", pol)
	}
	rules = finish(rules, pol)
	for _, r := range rules {
		if r.Zone == "docker" && r.Origin != api.OriginSystem {
			t.Fatalf("docker zone not system: %+v", r)
		}
	}
	for raw, origin := range map[string]string{
		"--zone=public --add-port=22/tcp":                                                 api.OriginManaged,
		"--zone=internal --add-interface=wg0":                                             api.OriginManaged,
		`--policy=limdm-egress --add-rich-rule=rule port port="53" protocol="udp" accept`: api.OriginManaged,
		"--zone=public --add-port=8080/tcp":                                               api.OriginForeign,
		"--zone=docker --add-interface=docker0":                                           api.OriginSystem,
	} {
		if r := byRaw(t, rules, raw); r.Raw != raw || r.Origin != origin {
			t.Errorf("%s: %+v", raw, r)
		}
	}
	rich := byRaw(t, rules, `port="5432"`)
	if rich.From != "10.0.0.0/8" || rich.Port != "5432" || rich.Proto != "tcp" || rich.Action != "accept" || rich.Direction != "in" {
		t.Fatalf("rich: %+v", rich)
	}
	name, args, err := removeArgs(rich)
	if err != nil || name != "firewall-cmd" || args[1] != "--zone=public" || !strings.HasPrefix(args[2], "--remove-rich-rule=rule family") {
		t.Fatalf("remove: %q %v", args, err)
	}
	inv := api.FirewallInventory{DefaultZone: "public", Rules: rules}
	if f, err := api.AdoptFragment(byRaw(t, rules, "9100/tcp"), inv); err != nil || f.Zones[0].Name != "internal" ||
		!slices.Equal(f.Zones[0].Interfaces, []string{"wg0"}) || !slices.Equal(f.Zones[0].Sources, []string{"10.8.0.0/24"}) {
		t.Fatalf("adopt zone port: %+v %v", f, err)
	}
	if f, err := api.AdoptFragment(byRaw(t, rules, "60000-61000"), inv); err != nil || f.Allow[0] != "60000:61000/udp" {
		t.Fatalf("adopt range: %+v %v", f, err)
	}
	if r := byRaw(t, rules, "--zone=public --add-service=ssh"); r.Risk != "ssh" {
		t.Fatalf("ssh service risk: %+v", r)
	}
	if r := byRaw(t, rules, "198.51.100.4"); r.Direction != "out" || r.To != "198.51.100.4" || r.Risk != "server" {
		t.Fatalf("egress: %+v", r)
	}
}

// A Docker host with iptables (legacy or nft): every Docker rule is a
// system rule, nothing of it is adoptable or removable.
const dockerIptables = `# Generated by iptables-save v1.8.9
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.18.0.0/16 ! -o br-3f2a9c1d7e4b -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i br-3f2a9c1d7e4b -p tcp -m tcp --dport 8000 -j DNAT --to-destination 172.18.0.2:8000
COMMIT
*filter
:INPUT DROP [120:9000]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
:f2b-sshd - [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 9090 -m comment --comment "monitoring" -j ACCEPT
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i br-3f2a9c1d7e4b -o br-3f2a9c1d7e4b -j ACCEPT
-A DOCKER -d 172.18.0.2/32 ! -i br-3f2a9c1d7e4b -o br-3f2a9c1d7e4b -p tcp -m tcp --dport 8000 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-USER -j RETURN
-A f2b-sshd -s 203.0.113.7/32 -j REJECT --reject-with icmp-port-unreachable
-A f2b-sshd -j RETURN
COMMIT
`

func TestParseIptablesDockerHost(t *testing.T) {
	rules, pol := parseIptablesSave(dockerIptables, "iptables")
	if pol.In != "drop" || pol.Forward != "drop" || pol.Out != "accept" {
		t.Fatalf("policy %+v", pol)
	}
	rules = finish(rules, pol)
	var foreign []string
	for _, r := range rules {
		if r.Origin != api.OriginSystem {
			foreign = append(foreign, r.Raw)
			continue
		}
		if api.RemovableRule(r, true) == nil {
			t.Errorf("system rule removable: %s", r.Raw)
		}
		if _, err := api.AdoptFragment(r, api.FirewallInventory{}); err == nil {
			t.Errorf("system rule adoptable: %s", r.Raw)
		}
	}
	want := []string{"-A INPUT -i lo -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT", `-A INPUT -p tcp -m tcp --dport 9090 -m comment --comment "monitoring" -j ACCEPT`}
	if !slices.Equal(foreign, want) {
		t.Fatalf("foreign rules:\n%s", strings.Join(foreign, "\n"))
	}
	mon := byRaw(t, rules, "9090")
	if mon.Comment != "monitoring" || mon.Risk != "" || mon.Direction != "in" || mon.Action != "accept" {
		t.Fatalf("9090: %+v", mon)
	}
	if r := byRaw(t, rules, "--dport 22 -j ACCEPT"); r.Risk != "ssh" || api.RemovableRule(r, false) == nil || api.RemovableRule(r, true) != nil {
		t.Fatalf("ssh risk: %+v", r)
	}
	name, args, err := removeArgs(mon)
	if err != nil || name != "iptables" || strings.Join(args, "|") != "-t|filter|-D|INPUT|-p|tcp|-m|tcp|--dport|9090|-m|comment|--comment|monitoring|-j|ACCEPT" {
		t.Fatalf("remove: %s %q %v", name, args, err)
	}
}

// Docker on nftables (iptables-nft): the same, read from nft -j.
const dockerNftJSON = `{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
{"table": {"family": "ip", "name": "filter", "handle": 1}},
{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
{"chain": {"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 3}},
{"chain": {"family": "ip", "table": "filter", "name": "DOCKER", "handle": 4}},
{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 10, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}}, {"counter": {"packets": 3, "bytes": 180}}, {"accept": null}]}},
{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 11, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [22, {"range": [6000, 6010]}]}}}, {"accept": null}]}},
{"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 12, "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER-USER"}}]}},
{"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 13, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"xt": {"type": "match", "name": "conntrack"}}, {"accept": null}]}},
{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER", "handle": 14, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "172.17.0.2"}}, {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 80}}, {"accept": null}]}},
{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 15, "expr": [{"return": null}]}},
{"table": {"family": "ip", "name": "nat", "handle": 2}},
{"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING", "handle": 1, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}},
{"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 5, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "172.17.0.0", "len": 16}}}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"masquerade": null}]}},
{"table": {"family": "inet", "name": "limdm", "handle": 3}},
{"chain": {"family": "inet", "table": "limdm", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
{"rule": {"family": "inet", "table": "limdm", "chain": "input", "handle": 4, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}}, {"accept": null}]}}
]}`

const dockerNftText = `table ip filter { # handle 1
	chain INPUT { # handle 1
		type filter hook input priority filter; policy drop;
		tcp dport 8080 counter packets 3 bytes 180 accept # handle 10
		ip saddr 10.0.0.0/8 tcp dport { 22, 6000-6010 } accept # handle 11
	}

	chain FORWARD { # handle 2
		type filter hook forward priority filter; policy drop;
		counter packets 0 bytes 0 jump DOCKER-USER # handle 12
		oifname "docker0" xt match "conntrack" accept # handle 13
	}

	chain DOCKER-USER { # handle 3
		return # handle 15
	}

	chain DOCKER { # handle 4
		ip daddr 172.17.0.2 iifname != "docker0" tcp dport 80 accept # handle 14
	}
}
table ip nat { # handle 2
	chain POSTROUTING { # handle 1
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 172.17.0.0/16 oifname != "docker0" masquerade # handle 5
	}
}
table inet limdm { # handle 3
	set blocked { # handle 2
		type ipv4_addr
		elements = { 192.0.2.1 }
	}
	chain input { # handle 1
		type filter hook input priority filter; policy drop;
		tcp dport 443 accept # handle 4
	}
}
`

func TestParseNftDockerHost(t *testing.T) {
	rules, pol, err := parseNft(dockerNftJSON, dockerNftText)
	if err != nil {
		t.Fatal(err)
	}
	if pol.In != "drop" || pol.Forward != "drop" || pol.Out != "accept" {
		t.Fatalf("policy %+v", pol)
	}
	rules = finish(rules, pol)
	if len(rules) != 8 {
		t.Fatalf("%d rules", len(rules))
	}
	for _, r := range rules {
		if r.Chain == "DOCKER" || r.Chain == "DOCKER-USER" || strings.Contains(r.Raw, "docker0") {
			if r.Origin != api.OriginSystem || api.RemovableRule(r, true) == nil {
				t.Errorf("docker rule not system: %+v", r)
			}
			if _, err := api.AdoptFragment(r, api.FirewallInventory{}); err == nil {
				t.Errorf("docker rule adoptable: %+v", r)
			}
		}
	}
	web := byRaw(t, rules, "dport 8080")
	if web.Origin != api.OriginForeign || web.Port != "8080" || web.Proto != "tcp" || web.Direction != "in" || web.Handle != "10" ||
		!strings.Contains(web.Match, "counter accept") || web.Risk != "" {
		t.Fatalf("8080: %+v", web)
	}
	set := byRaw(t, rules, "6000-6010")
	if set.Port != "22,6000-6010" || set.From != "10.0.0.0/8" || set.Risk != "ssh" {
		t.Fatalf("set: %+v", set)
	}
	if f, err := api.AdoptFragment(set, api.FirewallInventory{}); err != nil || len(f.Rules) != 2 || f.Rules[1].Port != "6000:6010/tcp" {
		t.Fatalf("adopt set: %+v %v", f, err)
	}
	if r := byRaw(t, rules, "dport 443"); r.Origin != api.OriginManaged {
		t.Fatalf("limdm table: %+v", r)
	}
	name, args, err := removeArgs(web)
	if err != nil || name != "nft" || strings.Join(args, " ") != "delete rule ip filter INPUT handle 10" {
		t.Fatalf("remove: %q %v", args, err)
	}
	// counters change, the identity stays
	again, _, _ := parseNft(dockerNftJSON, strings.Replace(dockerNftText, "packets 3 bytes 180", "packets 9 bytes 999", 1))
	again = finish(again, pol)
	if byRaw(t, again, "dport 8080").ID != web.ID {
		t.Fatal("ID changed with the counters")
	}
}

func TestRemovePayload(t *testing.T) {
	if (api.FirewallRemoveRule{ID: "0123456789abcdef", Raw: "ufw allow 1/tcp"}).Validate() != nil {
		t.Fatal("valid payload refused")
	}
	for _, p := range []api.FirewallRemoveRule{{ID: "x", Raw: "a"}, {ID: "0123456789abcdef"}, {ID: "0123456789abcdef", Raw: "a\nb"}} {
		if p.Validate() == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	if _, _, err := removeArgs(api.FirewallInvRule{Source: "firewalld", Raw: "--zone=public; rm -rf /"}); err == nil {
		t.Fatal("bad firewalld text accepted")
	}
}
