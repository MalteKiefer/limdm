package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// fwRule is one rule LiMDM manages on the host firewall. The state keeps
// the applied ones so rules no longer declared can be deleted. Entries of
// agents before zones (port and from only) read as inbound rules of the
// default zone.
type fwRule struct {
	Port  string `json:"port,omitempty"`
	From  string `json:"from,omitempty"`
	Zone  string `json:"zone,omitempty"`  // firewalld zone, empty is the default zone
	Iface string `json:"iface,omitempty"` // ufw: inbound interface; firewalld: interface bound to Zone (no port)
	To    string `json:"to,omitempty"`    // outbound destination
	Out   bool   `json:"out,omitempty"`
}

// errUnrendered: a firewall template the server could not render for this
// device reaches the agent still marked; the firewall stays as it is.
var errUnrendered = errors.New("template could not be rendered on the server (see the preview in the console); firewall left as it is")

// egressPolicy is the name of the firewalld policy for outbound filtering.
const egressPolicy = "limdm-egress"

// egressBase is what outbound deny always allows besides the LiMDM server:
// DNS, DHCP (v4 and v6) and NTP (certificates need the right time).
var egressBase = []fwRule{{Out: true, Port: "53/udp"}, {Out: true, Port: "53/tcp"}, {Out: true, Port: "67/udp"}, {Out: true, Port: "547/udp"}, {Out: true, Port: "123/udp"}}

func or1(l []string) []string {
	if len(l) == 0 {
		return []string{""}
	}
	return l
}

// wantRules expands the declaration into the rules of one backend: ufw and
// nftables match interface and source per rule, firewalld binds them to the
// zone. server are the outbound rules that keep the LiMDM server reachable.
func wantRules(f api.Firewall, firewalld bool, server []fwRule) []fwRule {
	var out []fwRule
	add := func(r fwRule) {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	for _, r := range f.FirewallRules() {
		add(fwRule{Port: r.Port, From: r.From})
	}
	for _, z := range f.Zones {
		if firewalld {
			for _, i := range z.Interfaces {
				add(fwRule{Zone: z.Name, Iface: i})
			}
			for _, s := range z.Sources {
				add(fwRule{Zone: z.Name, From: s})
			}
			for _, p := range z.Allow {
				add(fwRule{Zone: z.Name, Port: p})
			}
			continue
		}
		for _, p := range z.Allow {
			for _, i := range or1(z.Interfaces) {
				for _, s := range or1(z.Sources) {
					add(fwRule{Port: p, From: s, Iface: i})
				}
			}
		}
	}
	if egressDeny(f) {
		for _, e := range f.Outbound.Allow {
			add(fwRule{Out: true, To: e.To, Port: e.Port})
		}
		for _, r := range slices.Concat(egressBase, server) {
			add(r)
		}
	}
	return out
}

func egressDeny(f api.Firewall) bool { return f.Outbound != nil && f.Outbound.Policy == "deny" }

// serverEgress are the outbound rules to the LiMDM server, or to the proxy
// the agent reaches it through.
func (a *Agent) serverEgress() ([]fwRule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Server, nil)
	if err != nil {
		return nil, err
	}
	u := req.URL
	if p, err := agentProxy(req); err == nil && p != nil {
		u = p
	}
	port := u.Port()
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[u.Scheme == "https"]
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("outbound deny needs the server address: %w", err)
	}
	var out []fwRule
	for _, ip := range ips {
		out = append(out, fwRule{Out: true, To: ip, Port: port + "/tcp"})
	}
	return out, nil
}

// ufwArgs are the ufw arguments that add (or, with del, delete) a rule.
func ufwArgs(r fwRule, del bool) []string {
	var args []string
	if del {
		args = []string{"delete"}
	}
	port, proto, _ := strings.Cut(r.Port, "/")
	switch {
	case r.Out && r.To == "":
		return append(args, "allow", "out", r.Port)
	case r.Out:
		args = append(args, "allow", "out", "to", r.To)
		if r.Port != "" {
			args = append(args, "port", port, "proto", proto)
		}
		return args
	case r.Iface != "":
		args = append(args, "allow", "in", "on", r.Iface)
		if r.From != "" {
			args = append(args, "from", r.From)
		}
		return append(args, "to", "any", "port", port, "proto", proto)
	case r.From == "":
		return append(args, "allow", r.Port)
	}
	return append(args, "allow", "from", r.From, "to", "any", "port", port, "proto", proto)
}

// family is the rich rule address family of an address or network.
func family(addr string) string {
	if strings.Contains(addr, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// richPort is the port part of a rich rule ("" without a port).
func richPort(p string) string {
	if p == "" {
		return ""
	}
	port, proto, _ := strings.Cut(strings.Replace(p, ":", "-", 1), "/")
	return ` port port="` + port + `" protocol="` + proto + `"`
}

// firewalldArgs are the firewall-cmd options (after --permanent) that add
// or remove a rule: a port, a rich rule for a source network, a zone
// binding or an outbound rule of the LiMDM policy.
func firewalldArgs(r fwRule, del bool) []string {
	verb := "--add-"
	if del {
		verb = "--remove-"
	}
	if r.Out {
		rule := "rule"
		if r.To != "" {
			rule += ` family="` + family(r.To) + `" destination address="` + r.To + `"`
		}
		return []string{"--policy=" + egressPolicy, verb + "rich-rule=" + rule + richPort(r.Port) + " accept"}
	}
	var args []string
	if r.Zone != "" {
		args = []string{"--zone=" + r.Zone}
	}
	switch {
	case r.Iface != "" && del:
		return append(args, "--remove-interface="+r.Iface)
	case r.Iface != "":
		return append(args, "--change-interface="+r.Iface) // moves it from the zone it is in
	case r.Port == "":
		return append(args, verb+"source="+r.From)
	case r.From == "":
		port, proto, _ := strings.Cut(strings.Replace(r.Port, ":", "-", 1), "/")
		return append(args, verb+"port="+port+"/"+proto)
	}
	return append(args, verb+`rich-rule=rule family="`+family(r.From)+`" source address="`+r.From+`"`+richPort(r.Port)+" accept")
}

// firewalldPrepare creates the zones the rules name and the outbound policy
// (deny), or deletes the policy when outbound deny is no longer declared.
// It returns the applied rules without those the deleted policy took along.
func firewalldPrepare(want, applied []fwRule, deny bool) ([]fwRule, bool, error) {
	changed := false
	zones, _ := sh("firewall-cmd", "--permanent", "--get-zones")
	have := strings.Fields(zones)
	var errs []error
	for _, r := range want {
		if r.Zone != "" && !slices.Contains(have, r.Zone) {
			_, err := sh("firewall-cmd", "--permanent", "--new-zone="+r.Zone)
			errs = append(errs, err)
			have = append(have, r.Zone)
			changed = true
		}
	}
	_, infoErr := sh("firewall-cmd", "--permanent", "--info-policy="+egressPolicy)
	switch {
	case deny && infoErr != nil:
		for _, args := range [][]string{{"--new-policy=" + egressPolicy}, {"--policy=" + egressPolicy, "--add-ingress-zone=HOST"},
			{"--policy=" + egressPolicy, "--add-egress-zone=ANY"}, {"--policy=" + egressPolicy, "--set-target=REJECT"}} {
			if _, err := sh("firewall-cmd", append([]string{"--permanent"}, args...)...); err != nil {
				return applied, changed, fmt.Errorf("outbound policy (firewalld 0.9 or newer): %w", err)
			}
		}
		changed = true
	case !deny && infoErr == nil:
		if _, err := sh("firewall-cmd", "--permanent", "--delete-policy="+egressPolicy); err != nil {
			return applied, changed, err
		}
		changed = true
		fallthrough
	case !deny:
		applied = slices.DeleteFunc(slices.Clone(applied), func(r fwRule) bool { return r.Out })
	}
	return applied, changed, errors.Join(errs...)
}

// syncFirewallRules adds the declared rules and deletes the ones LiMDM
// added before that are no longer declared. Rules added by hand or by
// agents before this version are never deleted. Outbound deny is switched
// on after its allow rules and off before they go.
func (a *Agent) syncFirewallRules() error {
	if a.pol.Firewall.Template {
		return errUnrendered
	}
	if a.host.family == "alpine" {
		return a.syncNftables()
	}
	f := a.pol.Firewall
	ufw := a.host.family == "debian"
	switch {
	case ufw && !hasCmd("ufw"), !ufw && !hasCmd("firewall-cmd"):
		return nil // applyFirewall installs the tool first
	}
	deny := egressDeny(f)
	var server []fwRule
	if deny {
		var err error
		if server, err = a.serverEgress(); err != nil {
			return err // nothing changed: never deny outbound without a way back
		}
	}
	want := wantRules(f, !ufw, server)
	applied := slices.Clone(a.state.FirewallRules)
	var errs []error
	changed := false
	if ufw {
		if !deny && a.state.FirewallEgress == "deny" || f.Outbound != nil && f.Outbound.Policy == "allow" && a.state.FirewallEgress != "allow" {
			if _, err := sh("ufw", "default", "allow", "outgoing"); err != nil {
				return err
			}
			a.state.FirewallEgress = "allow"
		}
	} else {
		var err error
		if applied, changed, err = firewalldPrepare(want, applied, deny); err != nil {
			return err
		}
	}
	apply := func(r fwRule, del bool) error {
		if ufw {
			_, err := sh("ufw", ufwArgs(r, del)...)
			return err
		}
		_, err := sh("firewall-cmd", append([]string{"--permanent"}, firewalldArgs(r, del)...)...)
		changed = changed || err == nil
		return err
	}
	// add first: never close a port before its replacement is open
	for _, r := range want {
		if slices.Contains(applied, r) {
			continue
		}
		if err := apply(r, false); err != nil {
			errs = append(errs, err)
		} else {
			applied = append(applied, r)
		}
	}
	for _, r := range slices.Clone(applied) {
		if slices.Contains(want, r) {
			continue
		}
		if err := apply(r, true); err != nil {
			errs = append(errs, err)
			continue
		}
		applied = slices.DeleteFunc(applied, func(e fwRule) bool { return e == r })
		a.event("firewall rule removed: %s", ruleText(r))
	}
	if ufw && deny && a.state.FirewallEgress != "deny" && len(errs) == 0 {
		if _, err := sh("ufw", "default", "deny", "outgoing"); err != nil {
			errs = append(errs, err)
		} else {
			a.state.FirewallEgress = "deny"
		}
	}
	if changed {
		if _, err := sh("firewall-cmd", "--reload"); err != nil {
			errs = append(errs, err)
		}
	}
	a.state.FirewallRules = applied
	return errors.Join(errs...)
}

// ruleText describes a rule for events.
func ruleText(r fwRule) string {
	if r.Out {
		return "outbound " + strings.TrimSpace(firstNonEmpty(r.To, "any")+" "+r.Port)
	}
	s := firstNonEmpty(r.Port, "binding")
	if r.Zone != "" {
		s += " zone " + r.Zone
	}
	if r.Iface != "" {
		s += " on " + r.Iface
	}
	return s + " " + firstNonEmpty(r.From, "from anywhere")
}
