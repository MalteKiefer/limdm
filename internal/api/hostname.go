package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// TypeHostname sets the host name of a device from a source: its reverse
// DNS name, its DNS name, the DMI serial number, a device template or a
// fixed name. Only the host name changes; the device identity (device ID,
// client certificate, network certificate names) never depends on it.
const TypeHostname = "com.limdm.hostname"

// HostnameSources are the values of Hostname.Source.
var HostnameSources = []string{"rdns", "dns", "serial", "template", "fixed"}

// Hostname is the payload of com.limdm.hostname.
type Hostname struct {
	Source string `json:"source"`         // rdns | dns | serial | template | fixed
	Name   string `json:"name,omitempty"` // source fixed: short name or FQDN
	// Template is rendered by the server per device (TemplateVars plus
	// Serial, MAC, Vendor, Model) before the agent gets it. Used with source
	// template and as the fallback of the other sources.
	Template  string `json:"template,omitempty"`
	Domain    string `json:"domain,omitempty"`     // FQDN = short name + domain; empty keeps the domain the source gives
	Lowercase *bool  `json:"lowercase,omitempty"`  // default true
	MaxLength int    `json:"max_length,omitempty"` // of the short name, 1..63, default 63
	Fallback  string `json:"fallback,omitempty"`   // keep (default) | template
	Hosts     bool   `json:"hosts,omitempty"`      // manage the 127.0.1.1 line of /etc/hosts
	Mailname  bool   `json:"mailname,omitempty"`   // write /etc/mailname where it or an MTA exists
	Pretty    string `json:"pretty,omitempty"`     // pretty host name (hostnamectl --pretty)
}

// HostnameInfo is what the agent reports about its host name: the facts
// the sources use and the result of the declaration. Address, PTR and FQDN
// are only collected with privacy.network_info or while the declaration
// is assigned.
type HostnameInfo struct {
	Address   string     `json:"address,omitempty"`    // primary address: the source of the default route
	MAC       string     `json:"mac,omitempty"`        // hardware address of that interface
	PTR       string     `json:"ptr,omitempty"`        // forward confirmed reverse DNS name of Address
	FQDN      string     `json:"fqdn,omitempty"`       // DNS name of the host (source dns)
	Target    string     `json:"target,omitempty"`     // FQDN (or short name) the declaration computed
	Source    string     `json:"source,omitempty"`     // source that gave it, "template (fallback)" for the fallback
	Result    string     `json:"result,omitempty"`     // unchanged | changed | waiting | failed
	Detail    string     `json:"detail,omitempty"`     // why waiting or failed
	Previous  string     `json:"previous,omitempty"`   // host name before the last change
	ChangedAt *time.Time `json:"changed_at,omitempty"` // time of the last change
	Warning   string     `json:"warning,omitempty"`    // MTA host name differs
}

// HostnameFacts are the device values the sources read.
type HostnameFacts struct {
	PTR    string // forward confirmed PTR name, empty without one
	FQDN   string // DNS name of the host, empty without one
	Serial string // DMI system serial
}

func init() {
	Types[TypeHostname] = `{"source": "template", "template": "pc-{{lower .Serial}}", "domain": "corp.example", "lowercase": true, "max_length": 63, "fallback": "keep", "hosts": true, "mailname": true}`
	payloadShapes[TypeHostname] = Hostname{}
}

// PlaceholderDMI reports whether a firmware value is a vendor placeholder
// ("To be filled by O.E.M.", "Default string", "0" ...) or empty.
func PlaceholderDMI(v string) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(v), ". ")) {
	case "", "to be filled by o.e.m", "to be filled by oem", "default string", "system serial number", "system product name",
		"system manufacturer", "system version", "not specified", "not applicable", "none", "n/a", "na", "oem", "o.e.m",
		"0", "00000000", "0123456789", "123456789", "chassis serial number", "invalid", "unknown", "xxxxxxxxxxxx":
		return true
	}
	return false
}

// SanitizeLabel turns s into one RFC 1123 label: letters and digits stay
// (lower case with lower), every run of other characters becomes one -,
// no - at either end, at most max (1..63) characters.
func SanitizeLabel(s string, lower bool, max int) string {
	if max <= 0 || max > 63 {
		max = 63
	}
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
			if lower {
				r += 'a' - 'A'
			}
		default:
			dash = b.Len() > 0
			continue
		}
		if dash {
			b.WriteByte('-')
			dash = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > max {
		out = strings.TrimRight(out[:max], "-")
	}
	return out
}

// validDomain checks a DNS domain: labels of letters, digits and -, not
// starting or ending with -, each up to 63 characters, 253 in all.
func validDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || SanitizeLabel(l, false, 63) != l {
			return false
		}
	}
	return true
}

func (h Hostname) lower() bool { return h.Lowercase == nil || *h.Lowercase }

func (h Hostname) validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if !slices.Contains(HostnameSources, h.Source) {
		bad("source must be one of %s", strings.Join(HostnameSources, ", "))
	}
	switch h.Fallback {
	case "", "keep", "template":
	default:
		bad("fallback must be keep or template")
	}
	if h.Source == "fixed" && !validDomain(h.Name) {
		bad("name: a host name or FQDN of letters, digits, - and dots is required with source fixed")
	} else if h.Source != "fixed" && h.Name != "" {
		bad("name is only used with source fixed")
	}
	if (h.Source == "template" || h.Fallback == "template") && strings.TrimSpace(h.Template) == "" {
		bad("template is required with source template or fallback template")
	}
	if len(h.Template) > 1024 || !noControl(h.Template, 1024) || strings.ContainsAny(h.Template, "\n") {
		bad("template: one line up to 1024 characters")
	} else if h.Template != "" {
		if _, err := ParseTemplate(h.Template); err != nil {
			bad("template: %v", err)
		}
	}
	if h.Domain != "" && !validDomain(h.Domain) {
		bad("domain: a DNS domain such as corp.example")
	}
	if h.MaxLength < 0 || h.MaxLength > 63 {
		bad("max_length must be 1..63 (0 for 63)")
	}
	if !noControl(h.Pretty, 64) || strings.ContainsAny(h.Pretty, "\n\t\"'\\`$") {
		bad("pretty: one line up to 64 characters, no quotes, backslash or $")
	}
	return errors.Join(errs...)
}

// applyHostname decodes and validates the hostname type.
func (d Declaration) applyHostname(p *Policy) (bool, error) {
	if d.Type != TypeHostname {
		return d.applyLogging(p) // logging.go
	}
	var v Hostname
	if err := strict(d.Payload, &v); err != nil {
		return true, err
	}
	p.Extra.Hostname = &v
	return true, v.validate()
}

// from reads the raw name of one source.
func (h Hostname) from(source string, f HostnameFacts) (string, error) {
	switch source {
	case "rdns":
		if f.PTR == "" {
			return "", errors.New("rdns: no forward confirmed PTR record for the primary address")
		}
		return f.PTR, nil
	case "dns":
		if f.FQDN == "" {
			return "", errors.New("dns: no DNS name with the primary address in the search domains")
		}
		return f.FQDN, nil
	case "serial":
		if PlaceholderDMI(f.Serial) {
			return "", errors.New("serial: no usable DMI serial number")
		}
		return f.Serial, nil
	case "template":
		if IsTemplate(h.Template) {
			return "", errors.New("template: not rendered for this device")
		}
		if strings.TrimSpace(h.Template) == "" {
			return "", errors.New("template: empty")
		}
		return h.Template, nil
	case "fixed":
		return h.Name, nil
	}
	return "", fmt.Errorf("unknown source %q", source)
}

// Resolve computes the host name for the device: the short name, the FQDN
// (the short name when there is no domain) and the source used. It never
// returns an invalid name: a source without a usable value falls back to
// the template with fallback template, else it is an error and the device
// keeps its name.
func (h Hostname) Resolve(f HostnameFacts) (short, fqdn, used string, err error) {
	used = h.Source
	raw, err := h.from(h.Source, f)
	if err != nil && h.Fallback == "template" && h.Source != "template" {
		var ferr error
		if raw, ferr = h.from("template", f); ferr == nil {
			used, err = "template (fallback)", nil
		} else {
			err = errors.Join(err, ferr)
		}
	}
	if err != nil {
		return "", "", used, err
	}
	first, rest, _ := strings.Cut(strings.TrimSuffix(strings.TrimSpace(raw), "."), ".")
	if used == "serial" {
		first, rest = strings.TrimSpace(raw), "" // a serial number is one label, dots included
	}
	short = SanitizeLabel(first, h.lower(), h.MaxLength)
	switch {
	case short == "":
		return "", "", used, fmt.Errorf("%s: %q gives no valid host name", used, raw)
	case strings.Trim(short, "0123456789") == "":
		return "", "", used, fmt.Errorf("%s: %q gives a host name of digits only", used, short)
	case strings.EqualFold(short, "localhost"):
		return "", "", used, fmt.Errorf("%s: localhost is not a host name for a device", used)
	}
	dom := h.Domain
	if dom == "" {
		dom = rest
	}
	if h.lower() {
		dom = strings.ToLower(dom)
	}
	if dom != "" && !validDomain(dom) {
		return "", "", used, fmt.Errorf("%s: invalid domain %q", used, dom)
	}
	fqdn = short
	if dom != "" {
		fqdn += "." + dom
	}
	if len(fqdn) > 253 {
		return "", "", used, fmt.Errorf("%s: FQDN longer than 253 characters", used)
	}
	return short, fqdn, used, nil
}

// renderHostname renders the template of a hostname payload for one device.
// A template that uses .Serial or .MAC while the device has not reported
// that value fails, so no device gets a name like "pc-".
func renderHostname(payload json.RawMessage, v TemplateVars) (json.RawMessage, error) {
	var h Hostname
	if json.Unmarshal(payload, &h) != nil || !IsTemplate(h.Template) {
		return payload, nil
	}
	if strings.Contains(h.Template, ".Serial") && PlaceholderDMI(v.Serial) {
		return payload, errors.New("hostname: the device reported no serial number")
	}
	if strings.Contains(h.Template, ".MAC") && v.MAC == "" {
		return payload, errors.New("hostname: the device reported no primary MAC address")
	}
	out, err := RenderTemplate(h.Template, v)
	if err != nil {
		return payload, fmt.Errorf("hostname: %w", err)
	}
	if out = strings.TrimSpace(out); out == "" || len(out) > 253 || IsTemplate(out) || !noControl(out, 253) || strings.Contains(out, "\n") {
		return payload, errors.New("hostname: the template renders no usable name")
	}
	h.Template = out
	b, err := json.Marshal(h)
	if err != nil {
		return payload, err
	}
	return b, nil
}
