package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"text/template/parse"
)

// TemplateVars are the device values a file or firewall template can use.
// The server fills them per device; nothing else is reachable from a
// template (no files, no commands, no environment).
type TemplateVars struct {
	Hostname    string            `json:"hostname"`
	ID          string            `json:"id"`
	Tags        []string          `json:"tags"`
	Tenant      string            `json:"tenant"`
	PrimaryUser string            `json:"primary_user"` // mail address, empty without one
	Attributes  map[string]string `json:"attributes"`   // custom device attributes
	Serial      string            `json:"serial"`       // DMI system serial the device reported, empty for a placeholder
	MAC         string            `json:"mac"`          // MAC address of the primary interface
	Vendor      string            `json:"vendor"`
	Model       string            `json:"model"`
}

// MaxTemplateOutput bounds the text one template renders.
const MaxTemplateOutput = 1 << 20

var errNoFunc = errors.New("not available in templates")

// templateFuncs is the whole FuncMap: a few string helpers. printf and call
// are replaced, since printf with a huge width allocates without bound and
// call runs function values.
var templateFuncs = template.FuncMap{
	"lower":   strings.ToLower,
	"upper":   strings.ToUpper,
	"trim":    strings.TrimSpace,
	"replace": func(s, old, new string) string { return strings.ReplaceAll(s, old, new) },
	"join":    func(v []string, sep string) string { return strings.Join(v, sep) },
	"hasTag":  func(v []string, tag string) bool { return slices.Contains(v, tag) },
	"default": func(def, v string) string { return cmpOr(v, def) },
	"printf":  func(...any) (string, error) { return "", errNoFunc },
	"call":    func(...any) (string, error) { return "", errNoFunc },
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// IsTemplate reports whether s contains template actions.
func IsTemplate(s string) bool { return strings.Contains(s, "{{") }

// ParseTemplate parses s with the restricted rules: no define, block or
// template calls (they allow recursion) and range only over a field of the
// data (.Tags, .Attributes), never over a number.
func ParseTemplate(s string) (*template.Template, error) {
	t, err := template.New("t").Funcs(templateFuncs).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, err
	}
	if len(t.Templates()) > 1 {
		return nil, errors.New("define and block are not allowed")
	}
	if t.Tree != nil {
		if err := checkNode(t.Root); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func checkNode(n parse.Node) error {
	switch n := n.(type) {
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, c := range n.Nodes {
			if err := checkNode(c); err != nil {
				return err
			}
		}
	case *parse.TemplateNode:
		return errors.New("template calls are not allowed")
	case *parse.RangeNode:
		cmds := n.Pipe.Cmds
		if len(n.Pipe.Decl) > 2 || len(cmds) != 1 || len(cmds[0].Args) != 1 {
			return errors.New("range only over .Tags or .Attributes")
		}
		if _, ok := cmds[0].Args[0].(*parse.FieldNode); !ok {
			return errors.New("range only over .Tags or .Attributes")
		}
		return errors.Join(checkNode(n.List), checkNode(n.ElseList))
	case *parse.IfNode:
		return errors.Join(checkNode(n.List), checkNode(n.ElseList))
	case *parse.WithNode:
		return errors.Join(checkNode(n.List), checkNode(n.ElseList))
	}
	return nil
}

type limitWriter struct {
	b bytes.Buffer
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.b.Len()+len(p) > MaxTemplateOutput {
		return 0, fmt.Errorf("output larger than %d bytes", MaxTemplateOutput)
	}
	return w.b.Write(p)
}

// RenderTemplate renders s for one device. A missing attribute is an
// error; use index and default for optional ones:
// {{default "none" (index .Attributes "site")}}.
func RenderTemplate(s string, v TemplateVars) (string, error) {
	t, err := ParseTemplate(s)
	if err != nil {
		return "", err
	}
	if v.Attributes == nil {
		v.Attributes = map[string]string{}
	}
	var w limitWriter
	if err := t.Execute(&w, v); err != nil {
		return "", err
	}
	return w.b.String(), nil
}

// AttributeNameRe is the syntax of a custom device attribute name, usable
// as {{.Attributes.name}}.
var AttributeNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// ValidateAttributes checks custom device attributes: at most 50, names
// as AttributeNameRe, values up to 1024 bytes.
func ValidateAttributes(m map[string]string) error {
	if len(m) > 50 {
		return errors.New("at most 50 attributes")
	}
	for k, v := range m {
		if !AttributeNameRe.MatchString(k) {
			return fmt.Errorf("invalid attribute name %q (letters, digits and _, starting with a letter)", k)
		}
		if len(v) > 1024 {
			return fmt.Errorf("attribute %s: value longer than 1024 bytes", k)
		}
	}
	return nil
}

// RenderPayload renders the templates of a files, firewall or hostname
// payload for one device; other types and payloads without template come back as they
// are. Files render one by one: a file that fails keeps template set (the
// agent then leaves it alone) and its error is returned with the rest.
// A firewall payload renders as a whole and must be valid afterwards;
// otherwise it comes back unchanged and the agent leaves the firewall as
// it is.
func RenderPayload(typ string, payload json.RawMessage, v TemplateVars) (json.RawMessage, error) {
	switch typ {
	case TypeFiles:
		var p filesPayload
		if json.Unmarshal(payload, &p) != nil || !slices.ContainsFunc(p.Files, func(f File) bool { return f.Template }) {
			return payload, nil
		}
		var errs []error
		for i, f := range p.Files {
			if !f.Template {
				continue
			}
			out, err := RenderTemplate(f.Content, v)
			if err != nil {
				errs = append(errs, fmt.Errorf("file %s: %w", f.Path, err))
				continue
			}
			p.Files[i].Content, p.Files[i].Template = out, false
		}
		b, err := json.Marshal(p)
		if err != nil {
			return payload, err
		}
		return b, errors.Join(errs...)
	case TypeFirewall:
		var f Firewall
		if json.Unmarshal(payload, &f) != nil || !f.Template {
			return payload, nil
		}
		var errs []error
		r := func(s *string) {
			if out, err := RenderTemplate(*s, v); err != nil {
				errs = append(errs, err)
			} else {
				*s = strings.TrimSpace(out)
			}
		}
		f.Walk(r)
		f.Template = false
		if err := errors.Join(errs...); err != nil {
			return payload, fmt.Errorf("firewall: %w", err)
		}
		b, err := json.Marshal(f)
		if err != nil {
			return payload, err
		}
		d := Declaration{Identifier: "firewall", Type: TypeFirewall, Payload: b}
		if err := d.apply(&Policy{}); err != nil {
			return payload, fmt.Errorf("firewall after rendering: %w", err)
		}
		return b, nil
	case TypeHostname:
		return renderHostname(payload, v) // hostname.go
	}
	return payload, nil
}
