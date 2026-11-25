package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

// Library items are reusable configuration building blocks. A blueprint is an
// assignment map: a tree of "assign" nodes (library items) and "if" nodes with
// rules on device facts. A blueprint may inherit from a parent; the parent's
// map is evaluated first. The server resolves the map per device and merges the
// selected items into one declaration per type, so the agent protocol stays the
// same.

type LibraryItem struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Description string          `json:"description,omitempty"`
	Payload     json.RawMessage `json:"payload"`
}

// Validate checks the payload with the same strict rules the agent applies.
func (li LibraryItem) Validate() error {
	if strings.TrimSpace(li.Name) == "" || len(li.Name) > 100 {
		return errors.New("name must be 1..100 characters")
	}
	return Declaration{Identifier: "item", Type: li.Type, Payload: li.Payload}.apply(&Policy{})
}

type Node struct {
	Kind     string   `json:"kind"`               // assign | if
	Items    []int64  `json:"items,omitempty"`    // assign: library item IDs
	Branches []Branch `json:"branches,omitempty"` // if: first matching branch wins
	Else     []Node   `json:"else,omitempty"`     // if: when no branch matches
}

type Branch struct {
	Match string `json:"match"` // all | any
	Rules []Rule `json:"rules"`
	Nodes []Node `json:"nodes"`
}

type Rule struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// Facts are the device attributes rules can test.
type Facts struct {
	OSID, OSVersion, Arch, Desktop, Vendor, Model, Hostname, Department string
	Tags, Groups                                                        []string
}

// RuleFields lists the fields and the operators that make sense for them.
var RuleFields = map[string][]string{
	"os.id":      {"eq", "ne"},
	"os.version": {"eq", "ne", "gte", "lte"},
	"arch":       {"eq", "ne"},
	"desktop":    {"present", "absent", "contains"},
	"vendor":     {"eq", "contains"},
	"model":      {"eq", "contains"},
	"hostname":   {"eq", "glob"},
	"tag":        {"has", "not_has"},
	"group":      {"member", "not_member"},
	"department": {"eq", "ne"},
}

func (r Rule) valid() error {
	ops, ok := RuleFields[r.Field]
	if !ok {
		return fmt.Errorf("unknown rule field %q", r.Field)
	}
	if !slices.Contains(ops, r.Op) {
		return fmt.Errorf("operator %q not allowed for %s", r.Op, r.Field)
	}
	if r.Op == "glob" {
		if _, err := path.Match(r.Value, ""); err != nil {
			return fmt.Errorf("invalid glob %q", r.Value)
		}
	}
	if len(r.Value) > 200 {
		return errors.New("rule value too long")
	}
	return nil
}

// Matches evaluates one rule. Text comparisons ignore case.
func (r Rule) Matches(f Facts) bool {
	v := strings.ToLower(strings.TrimSpace(r.Value))
	text := func(s string) bool {
		s = strings.ToLower(s)
		switch r.Op {
		case "eq":
			return s == v
		case "ne":
			return s != v
		case "contains":
			return v != "" && strings.Contains(s, v)
		case "present":
			return s != ""
		case "absent":
			return s == ""
		case "glob":
			ok, _ := path.Match(v, s)
			return ok
		}
		return false
	}
	switch r.Field {
	case "os.id":
		return text(f.OSID)
	case "os.version":
		switch r.Op {
		case "gte":
			return f.OSVersion != "" && CompareVersions(f.OSVersion, r.Value) >= 0
		case "lte":
			return f.OSVersion != "" && CompareVersions(f.OSVersion, r.Value) <= 0
		case "eq":
			return f.OSVersion != "" && CompareVersions(f.OSVersion, r.Value) == 0
		case "ne":
			return CompareVersions(f.OSVersion, r.Value) != 0
		}
	case "arch":
		return text(f.Arch)
	case "desktop":
		return text(f.Desktop)
	case "vendor":
		return text(f.Vendor)
	case "model":
		return text(f.Model)
	case "hostname":
		return text(f.Hostname)
	case "department":
		return text(f.Department)
	case "tag":
		has := slices.ContainsFunc(f.Tags, func(t string) bool { return strings.EqualFold(t, v) })
		return has == (r.Op == "has")
	case "group":
		in := slices.ContainsFunc(f.Groups, func(g string) bool { return strings.EqualFold(g, v) })
		return in == (r.Op == "member")
	}
	return false
}

func (b Branch) matches(f Facts) bool {
	if len(b.Rules) == 0 {
		return true
	}
	any := b.Match == "any"
	for _, r := range b.Rules {
		if r.Matches(f) == any {
			return any
		}
	}
	return !any
}

const maxTreeDepth = 12

// ValidateTree checks structure, rules and that every item exists.
func ValidateTree(nodes []Node, itemExists func(int64) bool) error {
	return validateNodes(nodes, itemExists, 0)
}

func validateNodes(nodes []Node, exists func(int64) bool, depth int) error {
	if depth > maxTreeDepth {
		return errors.New("blueprint nested too deeply")
	}
	for _, n := range nodes {
		switch n.Kind {
		case "assign":
			if len(n.Branches) > 0 || len(n.Else) > 0 {
				return errors.New("assign node cannot have branches")
			}
			for _, id := range n.Items {
				if !exists(id) {
					return fmt.Errorf("library item %d does not exist", id)
				}
			}
		case "if":
			if len(n.Branches) == 0 || len(n.Items) > 0 {
				return errors.New("if node needs at least one branch and no items")
			}
			for _, b := range n.Branches {
				if b.Match != "all" && b.Match != "any" {
					return errors.New(`branch match must be "all" or "any"`)
				}
				for _, r := range b.Rules {
					if err := r.valid(); err != nil {
						return err
					}
				}
				if err := validateNodes(b.Nodes, exists, depth+1); err != nil {
					return err
				}
			}
			if err := validateNodes(n.Else, exists, depth+1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown node kind %q", n.Kind)
		}
	}
	return nil
}

// Resolve walks the maps (root ancestor first) and returns the selected item
// IDs in evaluation order, without duplicates (the later occurrence counts).
func Resolve(maps [][]Node, f Facts) []int64 {
	var ids []int64
	var walk func([]Node)
	walk = func(nodes []Node) {
		for _, n := range nodes {
			if n.Kind == "assign" {
				ids = append(ids, n.Items...)
				continue
			}
			matched := false
			for _, b := range n.Branches {
				if b.matches(f) {
					walk(b.Nodes)
					matched = true
					break
				}
			}
			if !matched {
				walk(n.Else)
			}
		}
	}
	for _, m := range maps {
		walk(m)
	}
	// keep the last occurrence so inherited items can be re-ordered by children
	seen := map[int64]bool{}
	var out []int64
	for i := len(ids) - 1; i >= 0; i-- {
		if !seen[ids[i]] {
			seen[ids[i]] = true
			out = append(out, ids[i])
		}
	}
	slices.Reverse(out)
	return out
}

// listTypes merge their payloads; every other type is single valued and the
// item evaluated last wins.
var listTypes = map[string]bool{TypePackages: true, TypeServices: true, TypeFiles: true, TypeFirewall: true, TypeOSVersion: true}

// Merge turns resolved library items into one declaration per type.
func Merge(items []LibraryItem) ([]Declaration, error) {
	byType := map[string]json.RawMessage{}
	var order []string
	for _, it := range items {
		prev, ok := byType[it.Type]
		if !ok {
			order = append(order, it.Type)
			byType[it.Type] = it.Payload
			continue
		}
		if !listTypes[it.Type] {
			byType[it.Type] = it.Payload
			continue
		}
		merged, err := mergePayload(it.Type, prev, it.Payload)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", it.Name, err)
		}
		byType[it.Type] = merged
	}
	out := make([]Declaration, 0, len(order))
	for _, t := range order {
		d := Declaration{Identifier: strings.TrimPrefix(t, "com.limdm."), Type: t, Payload: byType[t]}
		d.ServerToken = d.Token()
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Declaration) int { return strings.Compare(a.Type, b.Type) })
	return out, nil
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func without(a, drop []string) []string {
	return slices.DeleteFunc(slices.Clone(a), func(s string) bool { return slices.Contains(drop, s) })
}

func mergePayload(typ string, a, b json.RawMessage) (json.RawMessage, error) {
	var out any
	switch typ {
	case TypePackages:
		var x, y Packages
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, err
		}
		rm := union(x.Remove, y.Remove)
		out = Packages{Install: without(union(x.Install, y.Install), rm), Remove: rm}
	case TypeServices:
		var x, y Services
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, err
		}
		dis := union(x.Disable, y.Disable)
		out = Services{Enable: without(union(x.Enable, y.Enable), dis), Disable: dis}
	case TypeFiles:
		var x, y filesPayload
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, err
		}
		files := slices.Clone(x.Files)
		for _, f := range y.Files {
			if i := slices.IndexFunc(files, func(e File) bool { return e.Path == f.Path }); i >= 0 {
				files[i] = f
			} else {
				files = append(files, f)
			}
		}
		out = filesPayload{Files: files}
	case TypeFirewall:
		var x, y Firewall
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, err
		}
		out = Firewall{Enforce: x.Enforce || y.Enforce, Allow: union(x.Allow, y.Allow)}
	case TypeOSVersion:
		var x, y osPayload
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, err
		}
		m := map[string]string{}
		for k, v := range x.Min {
			m[k] = v
		}
		for k, v := range y.Min {
			m[k] = v
		}
		out = osPayload{Min: m}
	default:
		if merged, ok, err := mergeExtra(typ, a, b); ok {
			return merged, err
		}
		return b, nil
	}
	return json.Marshal(out)
}

// DefaultLibrary is the CIS Level 1 baseline every new installation starts with.
func DefaultLibrary() []LibraryItem {
	li := func(name, typ, payload string) LibraryItem {
		return LibraryItem{Name: name, Type: typ, Payload: json.RawMessage(payload)}
	}
	return []LibraryItem{
		li("Agent check in every 5 minutes", TypeAgent, `{"checkin_seconds":300}`),
		li("CIS Level 1 baseline", TypeCompliance, `{"level":1,"remediate":true,"exclude":[]}`),
		li("Security updates at night", TypeUpdates, `{"mode":"security","window":"02:00-05:00","reboot":false}`),
		li("Host firewall, SSH allowed", TypeFirewall, `{"enforce":true,"allow":["22/tcp"]}`),
		li("Supported OS versions", TypeOSVersion, `{"min":{"ubuntu":"22.04","debian":"12","fedora":"41"}}`),
		li("Screen lock after 5 minutes", TypeScreenLock, `{"idle_seconds":300}`),
		li("Privacy: no network or session data", TypePrivacy, `{"network_info":false,"logged_in_users":false}`),
	}
}
