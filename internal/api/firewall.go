package api

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

var (
	zoneRe  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,16}$`)
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
)

// validSource accepts a network in CIDR or a single address (no zone).
func validSource(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil && !strings.Contains(s, "%")
}

// validate checks every rule text. With Template set, a text with template
// actions is only parsed here; the server checks the rendered payload per
// device again (RenderPayload).
func (f Firewall) validate() []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	check := func(s string, ok func(string) bool, format string, a ...any) {
		if f.Template && IsTemplate(s) {
			if _, err := ParseTemplate(s); err != nil {
				bad("template %q: %v", s, err)
			}
			return
		}
		if !ok(s) {
			bad(format, a...)
		}
	}
	port := func(p string) {
		check(p, validPortRule, "invalid firewall rule %q (port 1..65535, ranges low:high)", p)
	}
	for _, a := range f.Allow {
		port(a)
	}
	for _, r := range f.Rules {
		port(r.Port)
		check(r.From, validSource, "firewall rule %s: from must be a network (CIDR) or an address, got %q", r.Port, r.From)
	}
	if len(f.Zones) > 50 {
		bad("at most 50 zones")
	}
	for i, z := range f.Zones {
		if !zoneRe.MatchString(z.Name) || slices.ContainsFunc(f.Zones[:i], func(o FirewallZone) bool { return o.Name == z.Name }) {
			bad("zone %q: lower case name up to 17 characters, each once", z.Name)
		}
		if len(z.Interfaces)+len(z.Sources) == 0 {
			bad("zone %s: needs interfaces or sources", z.Name)
		}
		if len(z.Interfaces)+len(z.Sources)+len(z.Allow) > 200 {
			bad("zone %s: at most 200 entries", z.Name)
		}
		for _, n := range z.Interfaces {
			check(n, ifaceRe.MatchString, "zone %s: invalid interface %q", z.Name, n)
		}
		for _, s := range z.Sources {
			check(s, validSource, "zone %s: source must be a network (CIDR) or an address, got %q", z.Name, s)
		}
		for _, a := range z.Allow {
			port(a)
		}
	}
	if err := validKeep(f.Keep); err != nil {
		errs = append(errs, err)
	}
	if err := validRemove(f.Remove); err != nil {
		errs = append(errs, err)
	}
	if o := f.Outbound; o != nil {
		if o.Policy != "allow" && o.Policy != "deny" {
			bad("outbound policy must be allow or deny")
		}
		if len(o.Allow) > 200 {
			bad("outbound: at most 200 rules")
		}
		for _, e := range o.Allow {
			if e.To == "" && e.Port == "" {
				bad("outbound rule needs a destination, a port or both")
			}
			if e.To != "" {
				check(e.To, validSource, "outbound: destination must be a network (CIDR) or an address, got %q", e.To)
			}
			if e.Port != "" {
				port(e.Port)
			}
		}
	}
	return errs
}

// mergeFirewall combines two firewall payloads: every port, rule and zone
// entry of both; an outbound deny wins over allow.
func mergeFirewall(x, y Firewall) Firewall {
	rules := slices.Clone(x.Rules)
	for _, r := range y.Rules {
		if !slices.Contains(rules, r) {
			rules = append(rules, r)
		}
	}
	zones := slices.Clone(x.Zones)
	for _, z := range y.Zones {
		i := slices.IndexFunc(zones, func(e FirewallZone) bool { return e.Name == z.Name })
		if i < 0 {
			zones = append(zones, z)
			continue
		}
		e := zones[i]
		zones[i] = FirewallZone{Name: z.Name, Interfaces: union(e.Interfaces, z.Interfaces), Sources: union(e.Sources, z.Sources), Allow: union(e.Allow, z.Allow)}
	}
	out := x.Outbound
	if y.Outbound != nil {
		if out == nil {
			out = y.Outbound
		} else {
			o := FirewallOutbound{Policy: out.Policy, Allow: slices.Clone(out.Allow)}
			if y.Outbound.Policy == "deny" {
				o.Policy = "deny"
			}
			for _, e := range y.Outbound.Allow {
				if !slices.Contains(o.Allow, e) {
					o.Allow = append(o.Allow, e)
				}
			}
			out = &o
		}
	}
	return Firewall{Enforce: x.Enforce || y.Enforce, Allow: union(x.Allow, y.Allow), Rules: rules, Zones: zones, Outbound: out, Template: x.Template || y.Template, Keep: union(x.Keep, y.Keep), Remove: union(x.Remove, y.Remove)}
}
