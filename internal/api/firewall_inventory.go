package api

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// FirewallInventory is the host firewall of a device as the agent read it,
// without changing anything: the backend, the default policies and every
// rule, managed by LiMDM or not.
type FirewallInventory struct {
	Backend     string            `json:"backend"` // ufw | firewalld | nftables | iptables, empty when none was found
	Active      bool              `json:"active"`
	DefaultZone string            `json:"default_zone,omitempty"` // firewalld
	Policy      FirewallPolicies  `json:"policy"`
	Rules       []FirewallInvRule `json:"rules"`
	Truncated   bool              `json:"truncated,omitempty"` // more rules than MaxFirewallRules
	Errors      []string          `json:"errors,omitempty"`    // tools that failed to answer
	// BridgeNets are the subnets of the local container and VM bridges
	// (docker0, br-*, podman*, cni*, virbr*): rules on these addresses
	// (hairpin NAT, masquerade) belong to the container tools.
	BridgeNets []string `json:"bridge_nets,omitempty"`
}

// FirewallPolicies are the default actions per direction (accept, drop,
// reject, deny; empty when unknown).
type FirewallPolicies struct {
	In      string `json:"in"`
	Out     string `json:"out"`
	Forward string `json:"forward"`
}

// FirewallInvRule is one rule of the inventory.
type FirewallInvRule struct {
	// ID names this rule now (Match plus Handle); a removal names it.
	ID string `json:"id"`
	// Match is the stable text of the rule: tool, place and raw text without
	// counters or handles. Exceptions (Firewall.Keep) store it.
	Match     string `json:"match"`
	Source    string `json:"source"` // tool the rule was read with: ufw | firewalld | nftables | iptables | ip6tables
	Origin    string `json:"origin"` // managed | foreign | system
	Table     string `json:"table,omitempty"`
	Chain     string `json:"chain,omitempty"`
	Zone      string `json:"zone,omitempty"`      // firewalld zone or policy
	Direction string `json:"direction,omitempty"` // in | out | forward
	Action    string `json:"action,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Port      string `json:"port,omitempty"`
	Service   string `json:"service,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Iface     string `json:"iface,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Raw       string `json:"raw"`
	Handle    string `json:"handle,omitempty"` // nftables rule handle
	// Risk: removing the rule may cut SSH ("ssh") or the agent's way to the
	// server ("server"); a removal then needs a second confirmation.
	Risk string `json:"risk,omitempty"`
}

// MaxFirewallRules bounds the inventory of one device.
const MaxFirewallRules = 2000

// Origins of inventory rules.
const (
	OriginManaged = "managed"
	OriginForeign = "foreign"
	OriginSystem  = "system"
)

// systemNames are name prefixes of chains, tables, sets, zones and
// interfaces that container, virtualization, VPN and intrusion prevention
// tools own: Docker, Podman (CNI, netavark), libvirt, Kubernetes and its CNI
// plugins, NetBird (table netbird, chains netbird-*, sets nb-*), Tailscale
// (chains ts-*, interface tailscale0), wg-quick (table wg-quick-*), fail2ban
// and CrowdSec. Their rules are shown but never adopted or removed.
var systemNames = []string{"docker", "br-", "veth", "podman", "cni", "netavark", "nv_", "libvirt", "virbr", "kube", "cali", "flannel",
	"cilium", "weave", "f2b-", "fail2ban", "crowdsec", "netbird", "nb-", "tailscale", "ts-", "wg-quick"}

// systemIfaces are interface names of VPN agents: NetBird (wt0), ZeroTier
// (zt plus the network hash).
var systemIfaces = regexp.MustCompile(`^(wt[0-9]+|zt[0-9a-z]{8,})$`)

var nameToken = regexp.MustCompile(`[A-Za-z0-9_.@-]+`)

// SystemRule reports whether a rule belongs to a container,
// virtualization, VPN or intrusion prevention tool. Every name in the rule
// counts, its comment included: a false positive only hides actions.
func SystemRule(r FirewallInvRule) bool {
	text := strings.ToLower(strings.Join([]string{r.Table, r.Chain, r.Zone, r.Iface, r.Action, r.Comment, r.Raw}, " "))
	for _, tok := range nameToken.FindAllString(text, -1) {
		tok = strings.TrimLeft(tok, "@") // nftables sets: @nb-...
		if systemIfaces.MatchString(tok) {
			return true
		}
		for _, p := range systemNames {
			if strings.HasPrefix(tok, p) {
				return true
			}
		}
	}
	return false
}

// LiMDMRule reports whether a rule lives in a table or firewalld zone or
// policy that a LiMDM agent writes: inet limdm (Alpine), inet limdm_fw
// (agents of 0.1), the firewalld policy limdm-egress.
func LiMDMRule(r FirewallInvRule) bool {
	_, table, _ := strings.Cut(r.Table, " ")
	return strings.HasPrefix(table, "limdm") || strings.HasPrefix(r.Zone, "limdm")
}

var addrToken = regexp.MustCompile(`[0-9a-fA-F:.]+(?:/[0-9]{1,3})?`)

// BridgeRule reports whether an address of the rule lies in one of the
// local container bridge subnets.
func BridgeRule(r FirewallInvRule, nets []netip.Prefix) bool {
	if len(nets) == 0 {
		return false
	}
	for _, tok := range addrToken.FindAllString(strings.Join([]string{r.From, r.To, r.Raw}, " "), -1) {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			a, aerr := netip.ParseAddr(tok)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		for _, n := range nets {
			if n.Contains(p.Addr()) && p.Bits() >= n.Bits() {
				return true
			}
		}
	}
	return false
}

// ParseBridgeNets reads BridgeNets, ignoring what is no network and
// anything wider than a /8 (IPv4) or /16 (IPv6): a bridge never spans that.
func ParseBridgeNets(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4() && p.Bits() < 8 || !p.Addr().Is4() && p.Bits() < 16 {
			continue
		}
		out = append(out, p.Masked())
		if len(out) == 64 {
			break
		}
	}
	return out
}

// counterRe matches the counters of nftables and iptables rule texts.
var counterRe = regexp.MustCompile(`counter packets \d+ bytes \d+|\[\d+:\d+\]`)

// Finish sets Match, ID and the origin of r: managed for LiMDM's own
// tables, system for container, VPN and protection tools (names, or an
// address in one of the bridge subnets), else managed when the reader
// recognized a declared rule, else foreign.
func (r *FirewallInvRule) Finish(bridges ...netip.Prefix) {
	place := strings.TrimSpace(strings.Join([]string{r.Table, r.Chain, r.Zone}, " "))
	raw := strings.Join(strings.Fields(counterRe.ReplaceAllString(r.Raw, "counter")), " ")
	r.Match = r.Source + " " + place + ": " + raw
	sum := sha256.Sum256([]byte(r.Match + "\x00" + r.Handle))
	r.ID = hex.EncodeToString(sum[:8])
	switch {
	case LiMDMRule(*r):
		r.Origin = OriginManaged
	case SystemRule(*r) || BridgeRule(*r, bridges):
		r.Origin = OriginSystem
	case r.Origin != OriginManaged:
		r.Origin = OriginForeign
	}
}

// accepts: the rule lets traffic through.
func (r FirewallInvRule) accepts() bool {
	a := strings.ToLower(r.Action)
	return a == "accept" || a == "allow" || a == "limit"
}

// portCovers reports whether a port text ("22", "22/tcp", "1000:2000",
// "1000-2000", "22,80") contains port p; an empty text is any port.
func portCovers(text string, p int) bool {
	text, _, _ = strings.Cut(text, "/")
	if text == "" {
		return true
	}
	for _, part := range strings.Split(text, ",") {
		lo, hi, isRange := strings.Cut(strings.Replace(strings.TrimSpace(part), "-", ":", 1), ":")
		l, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		h := l
		if isRange {
			if h, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if p >= l && p <= h {
			return true
		}
	}
	return false
}

// RuleRisk is the risk of removing r: "ssh" for an inbound rule letting SSH
// through, "server" for an outbound rule letting the agent reach serverPort,
// each only where the default policy of that direction does not accept.
func RuleRisk(r FirewallInvRule, pol FirewallPolicies, serverPort int) string {
	if !r.accepts() || r.Iface == "lo" {
		return ""
	}
	open := func(p string) bool { p = strings.ToLower(p); return p == "accept" || p == "allow" }
	switch r.Direction {
	case "in":
		if !open(pol.In) && (r.Service == "ssh" || r.Service == "" && portCovers(r.Port, 22)) {
			return "ssh"
		}
	case "out":
		if !open(pol.Out) && r.Service == "" && portCovers(r.Port, serverPort) {
			return "server"
		}
	}
	return ""
}

// FirewallRemoveRule is the payload of firewall_remove_rule: one foreign
// rule the agent deletes after reading the firewall again.
type FirewallRemoveRule struct {
	ID          string `json:"id"`
	Raw         string `json:"raw"`                    // must still be the rule's text
	ConfirmRisk bool   `json:"confirm_risk,omitempty"` // the admin confirmed a rule with a risk twice
}

var ruleIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Validate checks the payload shape.
func (p FirewallRemoveRule) Validate() error {
	if !ruleIDRe.MatchString(p.ID) || p.Raw == "" || len(p.Raw) > 4000 || strings.ContainsAny(p.Raw, "\x00\n\r") {
		return errors.New("firewall rule: id and raw text of a rule from the inventory")
	}
	return nil
}

// RemovableRule checks that r may be removed by a firewall_remove_rule
// with confirmRisk.
func RemovableRule(r FirewallInvRule, confirmRisk bool) error {
	switch {
	case r.Origin == OriginSystem || SystemRule(r):
		return errors.New("rule of a container, virtualization or intrusion prevention tool: never removed")
	case r.Origin == OriginManaged:
		return errors.New("rule managed by LiMDM: change the firewall declaration instead")
	case r.Origin != OriginForeign:
		return errors.New("rule of unknown origin")
	case r.Risk != "" && !confirmRisk:
		return fmt.Errorf("removing this rule may cut the device off (%s): confirm the risk", r.Risk)
	}
	return nil
}

// FindRule returns the rule with the given ID.
func (inv FirewallInventory) FindRule(id string) (FirewallInvRule, bool) {
	i := slices.IndexFunc(inv.Rules, func(r FirewallInvRule) bool { return r.ID == id })
	if i < 0 {
		return FirewallInvRule{}, false
	}
	return inv.Rules[i], true
}

// serviceports are the firewalld services an adopted rule can name by port.
var servicePorts = map[string][]string{"ssh": {"22/tcp"}, "http": {"80/tcp"}, "https": {"443/tcp"}, "dhcpv6-client": {"546/udp"},
	"mdns": {"5353/udp"}, "cockpit": {"9090/tcp"}, "dns": {"53/tcp", "53/udp"}, "ntp": {"123/udp"}}

// rulePorts are the ports of r in the declaration format ("22/tcp").
func rulePorts(r FirewallInvRule) ([]string, error) {
	if r.Service != "" {
		if p, ok := servicePorts[r.Service]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("service %s has no known port: add its ports by hand", r.Service)
	}
	port, proto, _ := strings.Cut(r.Port, "/")
	proto = strings.ToLower(cmp.Or(proto, r.Proto))
	if port == "" || (proto != "tcp" && proto != "udp") {
		return nil, errors.New("only rules with a TCP or UDP port can be adopted")
	}
	var out []string
	for _, p := range strings.Split(port, ",") {
		p = strings.Replace(strings.TrimSpace(p), "-", ":", 1) + "/" + proto
		if !validPortRule(p) {
			return nil, fmt.Errorf("port %q cannot be declared", p)
		}
		out = append(out, p)
	}
	return out, nil
}

var zoneNameClean = regexp.MustCompile(`[^a-z0-9_-]`)

// AdoptFragment translates a foreign allow rule into the declaration
// format: ports of the default zone, rules by source, zones for
// interfaces and other firewalld zones, outbound allow rules.
func AdoptFragment(r FirewallInvRule, inv FirewallInventory) (Firewall, error) {
	var f Firewall
	if err := RemovableRule(r, true); err != nil {
		return f, err
	}
	if !r.accepts() {
		return f, errors.New("only rules that allow traffic can be adopted; the declaration has no deny rules")
	}
	ports, err := rulePorts(r)
	if err != nil {
		return f, err
	}
	switch r.Direction {
	case "out":
		if r.To != "" && !validSource(r.To) {
			return f, fmt.Errorf("destination %q cannot be declared", r.To)
		}
		f.Outbound = &FirewallOutbound{Policy: "allow"}
		for _, p := range ports {
			f.Outbound.Allow = append(f.Outbound.Allow, FirewallEgress{To: r.To, Port: p})
		}
		return f, nil
	case "in":
	default:
		return f, errors.New("only inbound and outbound rules can be adopted")
	}
	if r.From != "" && !validSource(r.From) {
		return f, fmt.Errorf("source %q cannot be declared", r.From)
	}
	switch {
	case r.Source == "firewalld" && r.Zone != "" && r.Zone != inv.DefaultZone:
		z := FirewallZone{Name: r.Zone, Allow: ports}
		for _, b := range inv.Rules {
			if b.Source == "firewalld" && b.Zone == r.Zone && b.Action == "bind" {
				if b.Iface != "" {
					z.Interfaces = append(z.Interfaces, b.Iface)
				} else if b.From != "" {
					z.Sources = append(z.Sources, b.From)
				}
			}
		}
		if r.From != "" {
			z.Sources = union(z.Sources, []string{r.From})
		}
		if len(z.Interfaces)+len(z.Sources) == 0 || !zoneRe.MatchString(z.Name) {
			return f, fmt.Errorf("zone %s has no interfaces or sources to declare", r.Zone)
		}
		f.Zones = []FirewallZone{z}
	case r.Iface != "":
		if r.From != "" {
			return f, errors.New("rules with an interface and a source: declare them as a zone by hand")
		}
		name := zoneNameClean.ReplaceAllString(strings.ToLower(r.Iface), "")
		z := FirewallZone{Name: "if-" + name[:min(len(name), 14)], Interfaces: []string{r.Iface}, Allow: ports}
		if !ifaceRe.MatchString(r.Iface) || !zoneRe.MatchString(z.Name) {
			return f, fmt.Errorf("interface %q cannot be declared", r.Iface)
		}
		f.Zones = []FirewallZone{z}
	case r.From != "":
		for _, p := range ports {
			f.Rules = append(f.Rules, FirewallRule{Port: p, From: r.From})
		}
	default:
		f.Allow = ports
	}
	return f, nil
}

// AdoptInto adds rule r to the firewall declaration item. Outbound rules
// need an outbound policy in the item already: adopting one must never
// change the device's outbound default.
func AdoptInto(item Firewall, r FirewallInvRule, inv FirewallInventory) (Firewall, error) {
	frag, err := AdoptFragment(r, inv)
	if err != nil {
		return item, err
	}
	if frag.Outbound != nil {
		if item.Outbound == nil {
			return item, errors.New("outbound rule: set an outbound policy in this item first")
		}
		frag.Outbound.Policy = item.Outbound.Policy
	}
	out := mergeFirewall(item, frag)
	out.Enforce, out.Template, out.Keep, out.Remove = item.Enforce, item.Template, item.Keep, item.Remove
	return out, nil
}

// KeepInto adds rule r to the exceptions of the item: it stays on the device
// and is listed as accepted.
func KeepInto(item Firewall, r FirewallInvRule) (Firewall, error) {
	if err := RemovableRule(r, true); err != nil {
		return item, err
	}
	if len(item.Keep) >= maxKeep {
		return item, fmt.Errorf("at most %d exceptions per item", maxKeep)
	}
	item.Keep = union(item.Keep, []string{r.Match})
	item.Remove = slices.DeleteFunc(slices.Clone(item.Remove), func(m string) bool { return m == r.Match })
	return item, nil
}

// RemoveInto lists rule r in the item's remove list: every agent that gets
// the item deletes the rule whenever it finds it. A rule that may cut SSH
// or the server needs confirmRisk, as for the immediate removal.
func RemoveInto(item Firewall, r FirewallInvRule, confirmRisk bool) (Firewall, error) {
	if err := RemovableRule(r, confirmRisk); err != nil {
		return item, err
	}
	if err := RemoveEntryError(r.Match); err != nil {
		return item, err
	}
	if len(item.Remove) >= maxKeep {
		return item, fmt.Errorf("at most %d rules to remove per item", maxKeep)
	}
	item.Remove = union(item.Remove, []string{r.Match})
	item.Keep = slices.DeleteFunc(slices.Clone(item.Keep), func(m string) bool { return m == r.Match })
	return item, nil
}

// RemoveEntryError refuses a remove entry that names a rule of LiMDM or of
// a container, VPN or protection tool, judged from the entry's text alone
// (the agent checks the live rule again, bridge addresses included).
func RemoveEntryError(m string) error {
	src, rest, _ := strings.Cut(m, " ")
	place, raw, _ := strings.Cut(rest, ": ")
	for _, tok := range strings.Fields(place) {
		if strings.HasPrefix(tok, "limdm") {
			return fmt.Errorf("rule of LiMDM itself, never removed: %q", m)
		}
	}
	if SystemRule(FirewallInvRule{Source: src, Chain: place, Raw: raw}) {
		return fmt.Errorf("rule of a container, virtualization, VPN or intrusion prevention tool, never removed: %q", m)
	}
	return nil
}

// validRemove checks the remove entries of a firewall declaration.
func validRemove(list []string) error {
	if err := validKeep(list); err != nil {
		return errors.New(strings.Replace(err.Error(), "exception", "rule to remove", 1))
	}
	for _, m := range list {
		if err := RemoveEntryError(m); err != nil {
			return err
		}
	}
	return nil
}

const maxKeep = 500

// validKeep checks the exception entries of a firewall declaration.
func validKeep(keep []string) error {
	if len(keep) > maxKeep {
		return fmt.Errorf("at most %d exceptions", maxKeep)
	}
	for _, k := range keep {
		if strings.TrimSpace(k) == "" || len(k) > 1100 || strings.ContainsAny(k, "\x00\n\r") {
			return fmt.Errorf("invalid exception %q: one line up to 1100 characters", k)
		}
	}
	return nil
}
