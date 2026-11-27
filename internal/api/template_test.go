package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderTemplate(t *testing.T) {
	v := TemplateVars{Hostname: "pc-1", ID: "d1", Tags: []string{"office", "dev"}, Tenant: "acme", PrimaryUser: "a@b.c", Attributes: map[string]string{"site": "ber"}}
	out, err := RenderTemplate(`{{upper .Hostname}} {{.Attributes.site}} {{join .Tags ","}} {{if hasTag .Tags "dev"}}dev{{end}} {{default "x" (index .Attributes "room")}}{{range .Tags}};{{.}}{{end}}`, v)
	if err != nil || out != "PC-1 ber office,dev dev x;office;dev" {
		t.Fatalf("%q %v", out, err)
	}
	for _, bad := range []string{
		`{{.Attributes.missing}}`,               // missing attribute
		`{{printf "%999999999d" 1}}`,            // unbounded allocation
		`{{define "x"}}{{template "x"}}{{end}}`, // recursion
		`{{template "t"}}`,                      // recursion into itself
		`{{range 1000000000}}{{end}}`,           // long loop
		`{{$n := 9}}{{range $n}}{{end}}`,        // same through a variable
		`{{.Env}}`,                              // nothing else is reachable
		`{{call .Hostname}}`,
	} {
		if _, err := RenderTemplate(bad, v); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := RenderTemplate(`{{range .Tags}}`+strings.Repeat("x", 600<<10)+`{{end}}`, v); err == nil {
		t.Error("output limit")
	}
}

func TestRenderPayload(t *testing.T) {
	v := TemplateVars{Hostname: "pc-1", Attributes: map[string]string{"net": "10.1.0.0/16"}}
	files := json.RawMessage(`{"files":[{"path":"/etc/a","content":"host {{.Hostname}}","mode":"0644","template":true},{"path":"/etc/b","content":"{{.Attributes.nope}}","mode":"0644","template":true},{"path":"/etc/c","content":"{{raw}}","mode":"0644"}]}`)
	out, err := RenderPayload(TypeFiles, files, v)
	var p filesPayload
	if err == nil || json.Unmarshal(out, &p) != nil || p.Files[0].Content != "host pc-1" || p.Files[0].Template || !p.Files[1].Template || p.Files[2].Content != "{{raw}}" {
		t.Fatalf("%s %v", out, err)
	}
	fw := json.RawMessage(`{"enforce":true,"allow":["22/tcp"],"rules":[{"port":"5432/tcp","from":"{{.Attributes.net}}"}],"template":true}`)
	if err := (LibraryItem{Name: "x", Type: TypeFirewall, Payload: fw}).Validate(); err != nil {
		t.Fatal(err)
	}
	out, err = RenderPayload(TypeFirewall, fw, v)
	if err != nil || !strings.Contains(string(out), `"from":"10.1.0.0/16"`) || strings.Contains(string(out), "template") {
		t.Fatalf("%s %v", out, err)
	}
	v.Attributes["net"] = "not a net"
	if out, err = RenderPayload(TypeFirewall, fw, v); err == nil || string(out) != string(fw) {
		t.Fatalf("invalid result delivered: %s", out)
	}
	if err := ValidateAttributes(map[string]string{"1x": "y"}); err == nil {
		t.Fatal("bad attribute name accepted")
	}
}

func TestScriptSchedule(t *testing.T) {
	item := func(s string) LibraryItem {
		return LibraryItem{Name: "x", Type: TypeScripts, Payload: json.RawMessage(`{"scripts":[{"name":"s","body":"true",` + s + `}]}`)}
	}
	if err := item(`"schedule":{"times":["02:00","14:30"],"days":["mon"],"jitter_minutes":30},"run_on_change":true`).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`"interval_hours":24,"schedule":{"times":["02:00"]}`, `"schedule":{"times":[]}`, `"schedule":{"times":["2:00"]}`,
		`"schedule":{"times":["02:00","02:00"]}`, `"schedule":{"times":["02:00"],"jitter_minutes":121}`, `"schedule":{"times":["02:00"],"days":["monday"]}`} {
		if item(bad).Validate() == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestFirewallZonesOutbound(t *testing.T) {
	ok := `{"enforce":true,"allow":[],"zones":[{"name":"internal","interfaces":["wg0"],"sources":["10.0.0.0/8"],"allow":["22/tcp"]}],"outbound":{"policy":"deny","allow":[{"to":"192.0.2.0/24","port":"443/tcp"},{"port":"123/udp"}]}}`
	if err := (LibraryItem{Name: "x", Type: TypeFirewall, Payload: json.RawMessage(ok)}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"enforce":true,"allow":[],"zones":[{"name":"Internal!","interfaces":["wg0"]}]}`,
		`{"enforce":true,"allow":[],"zones":[{"name":"internal","allow":["22/tcp"]}]}`,
		`{"enforce":true,"allow":[],"zones":[{"name":"internal","interfaces":["wg0; rm"]}]}`,
		`{"enforce":true,"allow":[],"outbound":{"policy":"drop"}}`,
		`{"enforce":true,"allow":[],"outbound":{"policy":"deny","allow":[{}]}}`,
		`{"enforce":true,"allow":["{{.Hostname}}"]}`, // template text without template
	} {
		if (LibraryItem{Name: "x", Type: TypeFirewall, Payload: json.RawMessage(bad)}).Validate() == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	m, err := Merge([]LibraryItem{
		{Name: "a", Type: TypeFirewall, Payload: json.RawMessage(`{"enforce":true,"allow":[],"zones":[{"name":"internal","interfaces":["wg0"]}],"outbound":{"policy":"allow","allow":[{"port":"53/udp"}]}}`)},
		{Name: "b", Type: TypeFirewall, Payload: json.RawMessage(`{"enforce":false,"allow":[],"zones":[{"name":"internal","sources":["10.0.0.0/8"]}],"outbound":{"policy":"deny"}}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var f Firewall
	if err := json.Unmarshal(m[0].Payload, &f); err != nil || len(f.Zones) != 1 || len(f.Zones[0].Sources) != 1 || len(f.Zones[0].Interfaces) != 1 || f.Outbound.Policy != "deny" || len(f.Outbound.Allow) != 1 {
		t.Fatalf("%s %v", m[0].Payload, err)
	}
}
