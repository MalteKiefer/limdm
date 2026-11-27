package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// The firewall inventory: what the host firewall holds, read only, so the
// console can adopt, accept or discard rules LiMDM did not add. Reading
// never changes anything; firewall_remove_rule deletes one foreign rule.

// cmdOut runs a read only tool and returns its standard output, bounded in
// time and size.
func cmdOut(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.WaitDelay = 2 * time.Second
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, lastLines(errb.String(), 2))
	}
	if out.Len() > 16<<20 {
		return "", fmt.Errorf("%s: output too large", name)
	}
	return out.String(), nil
}

// splitArgs splits a rule text into words like a shell: single and double
// quotes group, backslash escapes inside double quotes.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	in, quote, esc := false, rune(0), false
	for _, c := range s {
		switch {
		case esc:
			cur.WriteRune(c)
			esc = false
		case quote == '"' && c == '\\':
			esc = true
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(c)
		case c == '"' || c == '\'':
			quote, in = c, true
		case c == ' ' || c == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

// policyWord normalizes a default action.
func policyWord(s string) string {
	switch s = strings.ToLower(strings.Trim(s, "%")); s {
	case "default", "reject", "%%reject%%":
		return "reject"
	case "deny", "drop", "accept", "allow":
		return s
	}
	return s
}

// ---- ufw ----

// parseUFWStatus reads `ufw status verbose`.
func parseUFWStatus(out string) (bool, api.FirewallPolicies) {
	var pol api.FirewallPolicies
	active := false
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "Status: active" {
			active = true
		}
		if rest, ok := strings.CutPrefix(l, "Default:"); ok {
			for _, part := range strings.Split(rest, ",") {
				f := strings.Fields(part) // "deny (incoming)"
				if len(f) != 2 {
					continue
				}
				switch strings.Trim(f[1], "()") {
				case "incoming":
					pol.In = policyWord(f[0])
				case "outgoing":
					pol.Out = policyWord(f[0])
				case "routed":
					pol.Forward = policyWord(f[0])
				}
			}
		}
	}
	return active, pol
}

// ufwWords are the words of a ufw rule without the leading "ufw" and the
// comment, as `ufw delete` and ufwArgs use them.
func ufwWords(raw string) []string {
	w := splitArgs(raw)
	if len(w) > 0 && w[0] == "ufw" {
		w = w[1:]
	}
	var out []string
	for i := 0; i < len(w); i++ {
		if w[i] == "comment" {
			i++
			continue
		}
		out = append(out, w[i])
	}
	return out
}

// parseUFWAdded reads `ufw show added`: one "ufw ..." line per rule added
// with the ufw command.
func parseUFWAdded(out string, managed map[string]bool) []api.FirewallInvRule {
	var rules []api.FirewallInvRule
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "ufw ") {
			continue
		}
		r := api.FirewallInvRule{Source: "ufw", Raw: l, Direction: "in"}
		w := splitArgs(l)[1:]
		for i := 0; i < len(w); i++ {
			next := func() string {
				if i+1 < len(w) {
					i++
					return w[i]
				}
				return ""
			}
			switch v := w[i]; {
			case v == "route":
				r.Direction = "forward"
			case v == "allow" || v == "deny" || v == "reject" || v == "limit":
				r.Action = v
			case v == "in" || v == "out":
				if r.Direction != "forward" {
					r.Direction = v
				}
			case v == "on":
				r.Iface = cmpOr(r.Iface, next())
			case v == "from":
				r.From = anyEmpty(next())
			case v == "to":
				r.To = anyEmpty(next())
			case v == "port":
				r.Port = next()
			case v == "proto":
				r.Proto = next()
			case v == "comment":
				r.Comment = next()
			case v == "app":
				r.Service = next()
			case v == "log" || v == "log-all":
			case strings.ContainsAny(v[:1], "0123456789"):
				r.Port, r.Proto, _ = strings.Cut(v, "/")
			default:
				r.Service = v // application profile, for example OpenSSH
			}
		}
		if managed[strings.Join(ufwWords(l), " ")] {
			r.Origin = api.OriginManaged
		}
		rules = append(rules, r)
	}
	return rules
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func anyEmpty(s string) string {
	if s == "any" {
		return ""
	}
	return s
}

// ---- firewalld ----

// parseFirewalld reads `firewall-cmd --permanent --list-all-zones` and
// `--list-all-policies`. Every entry becomes a rule whose raw text is the
// firewall-cmd option that adds it, so a removal is that option with
// --remove-.
func parseFirewalld(zones, policies, defZone string, managed map[string]bool) ([]api.FirewallInvRule, api.FirewallPolicies) {
	var rules []api.FirewallInvRule
	pol := api.FirewallPolicies{Out: "accept"}
	parse := func(out, kind string) {
		name, dir := "", "in"
		block := map[string]string{}
		flush := func() {
			if name == "" {
				return
			}
			if kind == "zone" && name == defZone {
				pol.In = policyWord(block["target"])
			}
			if kind == "policy" && strings.Contains(block["ingress-zones"], "HOST") && strings.Contains(block["egress-zones"], "ANY") && block["target"] != "CONTINUE" {
				pol.Out = policyWord(block["target"])
			}
		}
		for _, line := range strings.Split(out, "\n") {
			t := strings.TrimSpace(line)
			switch {
			case t == "":
				continue
			case !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t"):
				flush()
				name, dir, block = strings.Fields(t)[0], "in", map[string]string{}
				continue
			}
			raw := func(opt string) string { return "--" + kind + "=" + name + " --add-" + opt }
			mk := func(r api.FirewallInvRule, opt string) {
				r.Source, r.Zone, r.Raw = "firewalld", name, raw(opt)
				if r.Direction == "" {
					r.Direction = dir
				}
				if managed[r.Raw] {
					r.Origin = api.OriginManaged
				}
				rules = append(rules, r)
			}
			if strings.HasPrefix(t, "rule ") {
				r := parseRichRule(t)
				mk(r, "rich-rule="+t)
				continue
			}
			key, val, ok := strings.Cut(t, ":")
			if !ok {
				continue
			}
			val = strings.TrimSpace(val)
			block[key] = val
			if key == "ingress-zones" && kind == "policy" {
				dir = "forward"
				if strings.Contains(val, "HOST") {
					dir = "out"
				}
			}
			for _, v := range strings.Fields(val) {
				switch key {
				case "interfaces":
					mk(api.FirewallInvRule{Action: "bind", Iface: v}, "interface="+v)
				case "sources":
					mk(api.FirewallInvRule{Action: "bind", From: v}, "source="+v)
				case "services":
					mk(api.FirewallInvRule{Action: "accept", Service: v}, "service="+v)
				case "ports", "source-ports":
					p, proto, _ := strings.Cut(v, "/")
					r := api.FirewallInvRule{Action: "accept", Port: p, Proto: proto}
					if key == "source-ports" {
						r.Port = ""
					}
					mk(r, strings.TrimSuffix(key, "s")+"="+v)
				case "protocols":
					mk(api.FirewallInvRule{Action: "accept", Proto: v}, "protocol="+v)
				case "forward-ports":
					mk(api.FirewallInvRule{Action: "forward-port", Direction: "forward"}, "forward-port="+v)
				case "icmp-blocks":
					mk(api.FirewallInvRule{Action: "icmp-block", Proto: "icmp"}, "icmp-block="+v)
				}
			}
			if key == "masquerade" && val == "yes" {
				mk(api.FirewallInvRule{Action: "masquerade", Direction: "forward"}, "masquerade")
			}
		}
		flush()
	}
	parse(zones, "zone")
	parse(policies, "policy")
	return rules, pol
}

// parseRichRule reads the fields of a firewalld rich rule.
func parseRichRule(rule string) api.FirewallInvRule {
	var r api.FirewallInvRule
	ctx, not := "", false
	for _, w := range splitArgs(rule) {
		k, v, kv := strings.Cut(w, "=")
		switch {
		case w == "NOT":
			not = true
		case !kv && (w == "accept" || w == "reject" || w == "drop" || w == "mark"):
			if ctx != "limit" {
				r.Action = w
			}
		case !kv:
			ctx = w
		case k == "address" || k == "ipset":
			if not {
				v = "!" + v
			}
			if ctx == "destination" {
				r.To = v
			} else {
				r.From = v
			}
			not = false
		case k == "port" && ctx == "port":
			r.Port = v
		case k == "protocol" && ctx == "port", k == "value" && ctx == "protocol":
			r.Proto = v
		case k == "name" && ctx == "service":
			r.Service = v
		}
	}
	return r
}

// firewalldManaged are the raw texts (parseFirewalld) of the rules LiMDM
// applied.
func firewalldManaged(applied []fwRule, defZone string) map[string]bool {
	m := map[string]bool{}
	for _, r := range applied {
		args := firewalldArgs(r, false)
		if !strings.HasPrefix(args[0], "--zone=") && !strings.HasPrefix(args[0], "--policy=") {
			args = append([]string{"--zone=" + defZone}, args...)
		}
		m[strings.Replace(strings.Join(args, " "), "--change-interface=", "--add-interface=", 1)] = true
	}
	return m
}

func ufwManaged(applied []fwRule) map[string]bool {
	m := map[string]bool{}
	for _, r := range applied {
		m[strings.Join(ufwArgs(r, false), " ")] = true
	}
	return m
}

// ---- nftables ----

type nftObj = map[string]json.RawMessage

// nftValue renders the right side of an nftables JSON match.
func nftValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	var o struct {
		Set    []json.RawMessage `json:"set"`
		Range  []json.RawMessage `json:"range"`
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return ""
	}
	switch {
	case o.Prefix != nil:
		return o.Prefix.Addr + "/" + strconv.Itoa(o.Prefix.Len)
	case len(o.Range) == 2:
		return nftValue(o.Range[0]) + "-" + nftValue(o.Range[1])
	case o.Set != nil:
		var parts []string
		for _, e := range o.Set {
			parts = append(parts, nftValue(e))
		}
		return strings.Join(parts, ",")
	}
	return ""
}

var nftHandleRe = regexp.MustCompile(`\s+# handle (\d+)$`)

// nftTexts maps "family table chain handle" to the rule text of
// `nft -a list ruleset`.
func nftTexts(text string) map[string]string {
	out := map[string]string{}
	table, chain := "", ""
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		f := strings.Fields(t)
		switch {
		case len(f) >= 3 && f[0] == "table":
			table, chain = f[1]+" "+f[2], ""
		case len(f) >= 2 && f[0] == "chain":
			chain = f[1]
		case t == "}":
			chain = ""
		case chain != "" && !strings.HasSuffix(t, "{"):
			if m := nftHandleRe.FindStringSubmatchIndex(t); m != nil {
				out[table+" "+chain+" "+t[m[2]:m[3]]] = t[:m[0]]
			}
		}
	}
	return out
}

// parseNft reads `nft -j list ruleset` with the texts of `nft -a list
// ruleset`. Rules of the table inet limdm (Alpine) are LiMDM's.
func parseNft(js, text string) ([]api.FirewallInvRule, api.FirewallPolicies, error) {
	var doc struct {
		Nftables []nftObj `json:"nftables"`
	}
	var pol api.FirewallPolicies
	if err := json.Unmarshal([]byte(js), &doc); err != nil {
		return nil, pol, fmt.Errorf("nft json: %w", err)
	}
	texts := nftTexts(text)
	type chainInfo struct{ Hook, Type, Policy string }
	chains := map[string]chainInfo{}
	var rules []api.FirewallInvRule
	seen := map[string]bool{}
	for _, o := range doc.Nftables {
		if raw, ok := o["chain"]; ok {
			var c struct {
				Family, Table, Name, Type, Hook, Policy string
			}
			if json.Unmarshal(raw, &c) == nil {
				chains[c.Family+" "+c.Table+" "+c.Name] = chainInfo{c.Hook, c.Type, c.Policy}
				dir := map[string]string{"input": "in", "output": "out", "forward": "forward"}[c.Hook]
				if c.Type == "filter" && dir != "" && c.Policy != "" {
					p := map[string]*string{"in": &pol.In, "out": &pol.Out, "forward": &pol.Forward}[dir]
					if *p == "" || c.Policy == "drop" {
						*p = c.Policy
					}
					seen[dir] = true
				}
			}
			continue
		}
		raw, ok := o["rule"]
		if !ok {
			continue
		}
		var x struct {
			Family, Table, Chain, Comment string
			Handle                        int
			Expr                          []nftObj
		}
		if json.Unmarshal(raw, &x) != nil {
			continue
		}
		r := api.FirewallInvRule{Source: "nftables", Table: x.Family + " " + x.Table, Chain: x.Chain, Comment: x.Comment, Handle: strconv.Itoa(x.Handle)}
		r.Direction = map[string]string{"input": "in", "output": "out", "forward": "forward"}[chains[x.Family+" "+x.Table+" "+x.Chain].Hook]
		var words []string
		for _, e := range x.Expr {
			for k, v := range e {
				switch k {
				case "match":
					var m struct {
						Op    string          `json:"op"`
						Left  nftObj          `json:"left"`
						Right json.RawMessage `json:"right"`
					}
					if json.Unmarshal(v, &m) != nil {
						continue
					}
					val := nftValue(m.Right)
					if m.Op == "!=" {
						val = "!" + val
					}
					var p struct{ Protocol, Field, Key string }
					if pl, ok := m.Left["payload"]; ok {
						_ = json.Unmarshal(pl, &p)
					} else if mt, ok := m.Left["meta"]; ok {
						_ = json.Unmarshal(mt, &p)
					}
					switch {
					case p.Field == "dport":
						r.Proto, r.Port = p.Protocol, val
					case p.Field == "saddr":
						r.From = val
					case p.Field == "daddr":
						r.To = val
					case p.Key == "iifname" || p.Key == "iif" || (p.Key == "oifname" || p.Key == "oif") && r.Iface == "":
						r.Iface = val
					case p.Key == "l4proto" && r.Proto == "":
						r.Proto = val
					}
				case "jump", "goto":
					var tg struct{ Target string }
					_ = json.Unmarshal(v, &tg)
					r.Action = k + " " + tg.Target
				case "accept", "drop", "reject", "return", "masquerade", "snat", "dnat", "redirect", "queue":
					r.Action = k
				}
				words = append(words, k)
			}
		}
		r.Raw = texts[r.Table+" "+r.Chain+" "+r.Handle]
		if r.Raw == "" {
			r.Raw = strings.Join(words, " ") // the text listing failed: the expression names
		}
		rules = append(rules, r) // LiMDM's own tables: api.LiMDMRule in Finish
	}
	for _, d := range []struct {
		dir string
		p   *string
	}{{"in", &pol.In}, {"out", &pol.Out}, {"forward", &pol.Forward}} {
		if !seen[d.dir] {
			*d.p = "accept" // no base chain: the kernel accepts
		}
	}
	return rules, pol, nil
}

// ---- iptables ----

// parseIptablesSave reads iptables-save (or ip6tables-save, source names
// the tool).
func parseIptablesSave(out, source string) ([]api.FirewallInvRule, api.FirewallPolicies) {
	var rules []api.FirewallInvRule
	pol := api.FirewallPolicies{In: "accept", Out: "accept", Forward: "accept"}
	table := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "*"):
			table = l[1:]
		case strings.HasPrefix(l, ":") && table == "filter":
			f := strings.Fields(l[1:])
			if len(f) >= 2 {
				switch f[0] {
				case "INPUT":
					pol.In = policyWord(f[1])
				case "OUTPUT":
					pol.Out = policyWord(f[1])
				case "FORWARD":
					pol.Forward = policyWord(f[1])
				}
			}
		case strings.HasPrefix(l, "-A "):
			w := splitArgs(l)
			r := api.FirewallInvRule{Source: source, Table: table, Chain: w[1], Raw: l}
			r.Direction = map[string]string{"INPUT": "in", "OUTPUT": "out", "FORWARD": "forward"}[r.Chain]
			not := ""
			for i := 2; i < len(w); i++ {
				next := func() string {
					if i+1 < len(w) {
						i++
						v := not + w[i]
						not = ""
						return v
					}
					return ""
				}
				switch w[i] {
				case "!":
					not = "!"
				case "-p", "--protocol":
					r.Proto = next()
				case "--dport", "--dports", "--destination-port":
					r.Port = next()
				case "-s", "--source":
					r.From = next()
				case "-d", "--destination":
					r.To = next()
				case "-i", "--in-interface":
					r.Iface = next()
				case "-o", "--out-interface":
					if v := next(); r.Iface == "" {
						r.Iface = v
					}
				case "--comment":
					r.Comment = next()
				case "-j", "--jump", "-g", "--goto":
					t := next()
					switch lt := strings.ToLower(t); lt {
					case "accept", "drop", "reject", "return", "masquerade", "snat", "dnat", "log":
						r.Action = lt
					default:
						r.Action = "jump " + t
					}
				}
			}
			rules = append(rules, r)
		}
	}
	return rules, pol
}

// ---- collection ----

// serverPort is the TCP port the agent reaches the server on.
func (a *Agent) serverPort() int {
	u, err := url.Parse(a.cfg.Server)
	if err != nil {
		return 443
	}
	if p, err := strconv.Atoi(u.Port()); err == nil {
		return p
	}
	if u.Scheme == "http" {
		return 80
	}
	return 443
}

// extraRules are the nftables (or, without nftables rules, iptables) rules
// beside ufw or firewalld; skip drops the backend's own.
func extraRules(inv *api.FirewallInventory, skip func(api.FirewallInvRule) bool) []api.FirewallInvRule {
	var all []api.FirewallInvRule
	if hasCmd("nft") {
		js, err := cmdOut("nft", "-j", "list", "ruleset")
		if err == nil {
			text, _ := cmdOut("nft", "-a", "list", "ruleset")
			all, _, err = parseNft(js, text)
		}
		if err != nil {
			inv.Errors = append(inv.Errors, err.Error())
		}
	}
	if len(all) == 0 {
		all = iptablesRules(inv)
	}
	var out []api.FirewallInvRule
	for _, r := range all {
		if !skip(r) {
			out = append(out, r)
		}
	}
	return out
}

// iptablesRules reads iptables-save and ip6tables-save.
func iptablesRules(inv *api.FirewallInventory) []api.FirewallInvRule {
	var all []api.FirewallInvRule
	for _, tool := range []string{"iptables", "ip6tables"} {
		if !hasCmd(tool + "-save") {
			continue
		}
		out, err := cmdOut(tool + "-save")
		if err != nil {
			inv.Errors = append(inv.Errors, err.Error())
			continue
		}
		rules, pol := parseIptablesSave(out, tool)
		if tool == "iptables" && inv.Backend == "iptables" {
			inv.Policy = pol
		}
		all = append(all, rules...)
	}
	return all
}

// collectFirewall reads the host firewall: the first backend found of a
// running firewalld, an active ufw, nftables and iptables, and beside ufw
// and firewalld the other tables (Docker, libvirt, fail2ban ...).
func (a *Agent) collectFirewall() api.FirewallInventory {
	inv := api.FirewallInventory{}
	var rules []api.FirewallInvRule
	fail := func(err error) { inv.Errors = append(inv.Errors, err.Error()) }
	state, _ := cmdOut("firewall-cmd", "--state")
	ufwStatus := ""
	if hasCmd("ufw") {
		ufwStatus, _ = cmdOut("ufw", "status", "verbose")
	}
	ufwActive, ufwPol := parseUFWStatus(ufwStatus)
	switch {
	case strings.TrimSpace(state) == "running":
		inv.Backend, inv.Active = "firewalld", true
		def, err := cmdOut("firewall-cmd", "--get-default-zone")
		if err != nil {
			fail(err)
		}
		inv.DefaultZone = strings.TrimSpace(def)
		zones, err := cmdOut("firewall-cmd", "--permanent", "--list-all-zones")
		if err != nil {
			fail(err)
		}
		policies, _ := cmdOut("firewall-cmd", "--permanent", "--list-all-policies") // firewalld 0.9 and newer
		rules, inv.Policy = parseFirewalld(zones, policies, inv.DefaultZone, firewalldManaged(a.state.FirewallRules, inv.DefaultZone))
		rules = append(rules, extraRules(&inv, func(r api.FirewallInvRule) bool { return strings.HasSuffix(r.Table, " firewalld") })...)
	case ufwActive:
		inv.Backend, inv.Active, inv.Policy = "ufw", true, ufwPol
		added, err := cmdOut("ufw", "show", "added")
		if err != nil {
			fail(err)
		}
		rules = parseUFWAdded(added, ufwManaged(a.state.FirewallRules))
		rules = append(rules, extraRules(&inv, func(r api.FirewallInvRule) bool {
			return strings.HasPrefix(r.Chain, "ufw") || strings.Contains(r.Action, " ufw")
		})...)
	case hasCmd("nft"):
		inv.Backend = "nftables"
		js, err := cmdOut("nft", "-j", "list", "ruleset")
		if err == nil {
			text, _ := cmdOut("nft", "-a", "list", "ruleset")
			rules, inv.Policy, err = parseNft(js, text)
		}
		if err != nil {
			fail(err)
		}
		inv.Active = len(rules) > 0
		if len(rules) == 0 && hasCmd("iptables-save") { // legacy iptables beside an empty nftables
			inv.Backend = "iptables"
			rules = iptablesRules(&inv)
			inv.Active = len(rules) > 0 || inv.Policy.In != "accept"
		}
	case hasCmd("iptables-save"):
		inv.Backend = "iptables"
		rules = iptablesRules(&inv)
		inv.Active = len(rules) > 0 || inv.Policy.In != "accept"
	}
	if len(rules) > api.MaxFirewallRules {
		rules, inv.Truncated = rules[:api.MaxFirewallRules], true
	}
	port := a.serverPort()
	inv.BridgeNets = bridgeNets()
	bridges := api.ParseBridgeNets(inv.BridgeNets)
	for i := range rules {
		r := &rules[i]
		r.Raw = truncateText(r.Raw, 900)
		r.Comment = truncateText(r.Comment, 200)
		r.Finish(bridges...)
		r.Risk = api.RuleRisk(*r, inv.Policy, port)
	}
	inv.Rules = rules
	if inv.Rules == nil {
		inv.Rules = []api.FirewallInvRule{}
	}
	return inv
}

// bridgeIface matches the local bridges of container and VM tools.
var bridgeIface = regexp.MustCompile(`^(docker[0-9]+|br-[0-9a-f]+|podman[0-9]+|cni[0-9-]*|virbr[0-9]+)$`)

// bridgeNets are the subnets of the local container and VM bridges, read
// from the kernel's interface list (no command runs).
func bridgeNets() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, i := range ifs {
		if !bridgeIface.MatchString(i.Name) {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.IsPrivate() {
				p, err := netip.ParsePrefix(n.String())
				if err == nil {
					out = append(out, p.Masked().String())
				}
			}
		}
	}
	return out
}

// firewallHash is the change marker of an inventory.
func firewallHash(inv api.FirewallInventory) string {
	b, _ := json.Marshal(inv)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// removeArgs is the command that deletes rule r.
func removeArgs(r api.FirewallInvRule) (string, []string, error) {
	switch r.Source {
	case "ufw":
		return "ufw", append([]string{"--force", "delete"}, ufwWords(r.Raw)...), nil
	case "firewalld":
		place, opt, ok := strings.Cut(r.Raw, " ")
		if !ok || !strings.HasPrefix(place, "--zone=") && !strings.HasPrefix(place, "--policy=") || !strings.HasPrefix(opt, "--add-") {
			return "", nil, errors.New("not a firewalld rule text")
		}
		return "firewall-cmd", []string{"--permanent", place, "--remove-" + strings.TrimPrefix(opt, "--add-")}, nil
	case "nftables":
		fam, table, ok := strings.Cut(r.Table, " ")
		if _, err := strconv.Atoi(r.Handle); !ok || err != nil || r.Chain == "" {
			return "", nil, errors.New("nftables rule without table, chain or handle")
		}
		return "nft", []string{"delete", "rule", fam, table, r.Chain, "handle", r.Handle}, nil
	case "iptables", "ip6tables":
		w := splitArgs(r.Raw)
		if len(w) < 2 || w[0] != "-A" || r.Table == "" {
			return "", nil, errors.New("not an iptables rule text")
		}
		w[0] = "-D"
		return r.Source, append([]string{"-t", r.Table}, w...), nil
	}
	return "", nil, fmt.Errorf("unknown rule source %q", r.Source)
}

// firewallRemoveRule deletes one foreign rule (command firewall_remove_rule).
// It reads the firewall again and refuses a rule that changed since the
// inventory, a rule of LiMDM, of a container or virtualization tool, and a
// rule that may cut SSH or the server unless the risk was confirmed.
func (a *Agent) firewallRemoveRule(payload string) (string, error) {
	var p api.FirewallRemoveRule
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		return "", err
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	r, ok := a.collectFirewall().FindRule(p.ID)
	if !ok || r.Raw != p.Raw {
		return "", errors.New("the rule changed or is gone since the inventory; nothing removed")
	}
	if err := api.RemovableRule(r, p.ConfirmRisk); err != nil {
		return "", err
	}
	name, args, err := removeArgs(r)
	if err != nil {
		return "", err
	}
	out, err := sh(name, args...)
	if err == nil && r.Source == "firewalld" {
		_, err = sh("firewall-cmd", "--reload")
	}
	a.sentFwHash = "" // report the new state at the next check in
	if err != nil {
		return out, err
	}
	a.event("firewall rule removed by command: %s", r.Raw)
	return "removed: " + r.Raw, nil
}
