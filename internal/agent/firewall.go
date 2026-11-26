package agent

import (
	"errors"
	"slices"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// ufwArgs are the ufw arguments that add (or, with del, delete) an allow rule.
func ufwArgs(r api.FirewallRule, del bool) []string {
	var args []string
	if del {
		args = []string{"delete"}
	}
	if r.From == "" {
		return append(args, "allow", r.Port)
	}
	port, proto, _ := strings.Cut(r.Port, "/")
	return append(args, "allow", "from", r.From, "to", "any", "port", port, "proto", proto)
}

// firewalldArg is the firewall-cmd option that adds (or removes) a rule:
// a port, or a rich rule for a source network.
func firewalldArg(r api.FirewallRule, del bool) string {
	verb := "--add-"
	if del {
		verb = "--remove-"
	}
	port, proto, _ := strings.Cut(strings.Replace(r.Port, ":", "-", 1), "/")
	if r.From == "" {
		return verb + "port=" + port + "/" + proto
	}
	family := "ipv4"
	if strings.Contains(r.From, ":") {
		family = "ipv6"
	}
	return verb + `rich-rule=rule family="` + family + `" source address="` + r.From + `" port port="` + port + `" protocol="` + proto + `" accept`
}

// syncFirewallRules adds the declared allow rules and deletes the ones LiMDM
// added before that are no longer declared. Rules added by hand or by
// agents before this version are never deleted.
func (a *Agent) syncFirewallRules() error {
	want := a.pol.Firewall.FirewallRules()
	ufw := a.host.family == "debian"
	switch {
	case ufw && !hasCmd("ufw"), !ufw && !hasCmd("firewall-cmd"):
		return nil // applyFirewall installs the tool first
	}
	var errs []error
	applied := slices.Clone(a.state.FirewallRules)
	changed := false
	// add first: never close a port before its replacement is open
	for _, r := range want {
		if slices.Contains(applied, r) {
			continue
		}
		var err error
		if ufw {
			_, err = sh("ufw", ufwArgs(r, false)...)
		} else {
			_, err = sh("firewall-cmd", "--permanent", firewalldArg(r, false))
			changed = changed || err == nil
		}
		if err != nil {
			errs = append(errs, err)
		} else {
			applied = append(applied, r)
		}
	}
	for _, r := range slices.Clone(applied) {
		if slices.Contains(want, r) {
			continue
		}
		var err error
		if ufw {
			_, err = sh("ufw", ufwArgs(r, true)...)
		} else {
			_, err = sh("firewall-cmd", "--permanent", firewalldArg(r, true))
			changed = changed || err == nil
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		applied = slices.DeleteFunc(applied, func(e api.FirewallRule) bool { return e == r })
		a.event("firewall rule removed: %s %s", r.Port, firstNonEmpty(r.From, "from anywhere"))
	}
	if changed {
		if _, err := sh("firewall-cmd", "--reload"); err != nil {
			errs = append(errs, err)
		}
	}
	a.state.FirewallRules = applied
	return errors.Join(errs...)
}
