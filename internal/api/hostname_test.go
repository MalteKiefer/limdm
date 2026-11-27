package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeLabel(t *testing.T) {
	for in, want := range map[string]string{
		"PC_017 Büro":                  "pc-017-b-ro",
		"--abc--":                      "abc",
		"a..b":                         "a-b",
		"ÄÖÜ":                          "",
		strings.Repeat("x", 70) + "y":  strings.Repeat("x", 63),
		strings.Repeat("a", 62) + "-b": strings.Repeat("a", 62),
	} {
		if got := SanitizeLabel(in, true, 0); got != want {
			t.Errorf("SanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SanitizeLabel("Web01", false, 4); got != "Web0" {
		t.Errorf("no lower, max 4: %q", got)
	}
}

func TestPlaceholderDMI(t *testing.T) {
	for _, s := range []string{"", " ", "To be filled by O.E.M.", "Default string", "0", "System Serial Number", "N/A"} {
		if !PlaceholderDMI(s) {
			t.Errorf("%q is a placeholder", s)
		}
	}
	if PlaceholderDMI("PF2ABCDE") {
		t.Error("real serial taken as placeholder")
	}
}

func TestHostnameResolve(t *testing.T) {
	f := HostnameFacts{PTR: "WS17.Corp.Example", FQDN: "ws17.lan.example", Serial: "PF2-AB.CD"}
	for _, c := range []struct {
		h                 Hostname
		short, fqdn, used string
		err               string
	}{
		{h: Hostname{Source: "rdns"}, short: "ws17", fqdn: "ws17.corp.example", used: "rdns"},
		{h: Hostname{Source: "rdns", Domain: "other.example"}, short: "ws17", fqdn: "ws17.other.example", used: "rdns"},
		{h: Hostname{Source: "dns"}, short: "ws17", fqdn: "ws17.lan.example", used: "dns"},
		{h: Hostname{Source: "serial"}, short: "pf2-ab-cd", fqdn: "pf2-ab-cd", used: "serial"},
		{h: Hostname{Source: "fixed", Name: "kiosk1.shop.example"}, short: "kiosk1", fqdn: "kiosk1.shop.example", used: "fixed"},
		{h: Hostname{Source: "template", Template: "pc-PF2"}, short: "pc-pf2", fqdn: "pc-pf2", used: "template"},
		{h: Hostname{Source: "template", Template: "pc-{{.Serial}}"}, err: "not rendered"},
		{h: Hostname{Source: "fixed", Name: "12345"}, err: "digits only"},
		{h: Hostname{Source: "fixed", Name: "localhost"}, err: "localhost"},
	} {
		short, fqdn, used, err := c.h.Resolve(f)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%+v: err %v, want %q", c.h, err, c.err)
			}
			continue
		}
		if err != nil || short != c.short || fqdn != c.fqdn || used != c.used {
			t.Errorf("%+v: %q %q %q %v", c.h, short, fqdn, used, err)
		}
	}
	// a junk serial or a missing PTR falls back to the template, or fails with keep
	junk := HostnameFacts{Serial: "To be filled by O.E.M."}
	if _, _, _, err := (Hostname{Source: "serial"}).Resolve(junk); err == nil {
		t.Error("junk serial must fail")
	}
	short, _, used, err := Hostname{Source: "rdns", Fallback: "template", Template: "pc-x1"}.Resolve(junk)
	if err != nil || short != "pc-x1" || used != "template (fallback)" {
		t.Errorf("fallback: %q %q %v", short, used, err)
	}
	if _, _, _, err := (Hostname{Source: "rdns", Fallback: "keep"}).Resolve(junk); err == nil {
		t.Error("rdns without PTR and fallback keep must fail")
	}
}

func TestHostnameValidate(t *testing.T) {
	for _, p := range []string{
		`{"source": "nope"}`,
		`{"source": "fixed"}`,
		`{"source": "fixed", "name": "-bad"}`,
		`{"source": "template"}`,
		`{"source": "rdns", "fallback": "template"}`,
		`{"source": "rdns", "domain": "bad_domain"}`,
		`{"source": "rdns", "max_length": 64}`,
		`{"source": "rdns", "pretty": "a\"b"}`,
		`{"source": "template", "template": "{{define \"x\"}}{{end}}"}`,
	} {
		if err := (LibraryItem{Name: "h", Type: TypeHostname, Payload: json.RawMessage(p)}).Validate(); err == nil {
			t.Errorf("%s must be refused", p)
		}
	}
	if err := (LibraryItem{Name: "h", Type: TypeHostname, Payload: json.RawMessage(Types[TypeHostname])}).Validate(); err != nil {
		t.Errorf("example: %v", err)
	}
}

func TestRenderHostname(t *testing.T) {
	p := json.RawMessage(`{"source": "template", "template": "pc-{{lower .Serial}}-{{index .Attributes \"site\"}}"}`)
	out, err := RenderPayload(TypeHostname, p, TemplateVars{Serial: "AB12", Attributes: map[string]string{"site": "ber"}})
	if err != nil || !strings.Contains(string(out), `"template":"pc-ab12-ber"`) {
		t.Fatalf("%s %v", out, err)
	}
	if out, err := RenderPayload(TypeHostname, p, TemplateVars{Serial: "Default string"}); err == nil || string(out) != string(p) {
		t.Errorf("placeholder serial must fail and keep the payload: %s %v", out, err)
	}
}
