package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkValidate(t *testing.T) {
	if err := (LibraryItem{Name: "x", Type: TypeNetwork, Payload: json.RawMessage(Types[TypeNetwork])}).Validate(); err != nil {
		t.Fatalf("example rejected: %v", err)
	}
	const key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	eap := `"eap":{"method":"peap","identity":"alice","password":"pw","ca_cert":"corp-root","server_domain":"radius.example.com"}`
	good := []string{
		`{"name":"w","type":"wifi","ssid":"Corp","hidden":true,"security":"wpa2-personal","psk":"` + strings.Repeat("a", 64) + `"}`,
		`{"name":"w","type":"wifi","ssid":"Corp","security":"wpa3-enterprise",` + eap + `}`,
		`{"name":"lan","type":"ethernet","security":"802.1x","eap":{"method":"ttls","identity":"a","phase2":"pap","ca_cert":"c","server_domain":"r.example"}}`,
		`{"name":"lan","type":"ethernet","security":"802.1x","eap":{"method":"tls","ca_cert":"c","server_domain":"r.example"}}`,
		`{"name":"v","type":"wireguard","wireguard":{"addresses":["10.0.0.2/32","fd00::2/128"],"peers":[{"public_key":"` + key + `","preshared_key":"` + key + `","endpoint":"[2001:db8::1]:51820","allowed_ips":["0.0.0.0/0"]}]}}`,
		`{"name":"o","type":"openvpn","openvpn":{"content":"client\r\nremote vpn.example.com 1194\r\n"}}`,
	}
	for _, g := range good {
		if err := (LibraryItem{Name: "x", Type: TypeNetwork, Payload: json.RawMessage(`{"profiles":[` + g + `]}`)}).Validate(); err != nil {
			t.Errorf("rejected %s: %v", g, err)
		}
	}
	bad := map[string]string{
		"long ssid":         `{"name":"w","type":"wifi","ssid":"` + strings.Repeat("s", 33) + `","security":"wpa2-personal","psk":"12345678"}`,
		"ssid newline":      `{"name":"w","type":"wifi","ssid":"a\nb","security":"wpa2-personal","psk":"12345678"}`,
		"short psk":         `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-personal","psk":"1234567"}`,
		"hex psk for sae":   `{"name":"w","type":"wifi","ssid":"a","security":"wpa3-personal","psk":"` + strings.Repeat("a", 64) + `"}`,
		"masked psk":        `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-personal","psk":"` + SecretMask + `"}`,
		"open wifi":         `{"name":"w","type":"wifi","ssid":"a"}`,
		"no ca":             `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-enterprise","eap":{"method":"tls","server_domain":"r.example"}}`,
		"no domain":         `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-enterprise","eap":{"method":"tls","ca_cert":"c"}}`,
		"tls with password": `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-enterprise","eap":{"method":"tls","password":"x","ca_cert":"c","server_domain":"r.example"}}`,
		"peap pap":          `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-enterprise","eap":{"method":"peap","identity":"a","phase2":"pap","ca_cert":"c","server_domain":"r.example"}}`,
		"identity newline":  `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-enterprise","eap":{"method":"peap","identity":"a\nb","ca_cert":"c","server_domain":"r.example"}}`,
		"plain ethernet":    `{"name":"lan","type":"ethernet"}`,
		"bad cidr":          `{"name":"v","type":"wireguard","wireguard":{"addresses":["10.0.0.300/32"],"peers":[{"public_key":"` + key + `","allowed_ips":["0.0.0.0/0"]}]}}`,
		"bad key":           `{"name":"v","type":"wireguard","wireguard":{"addresses":["10.0.0.2/32"],"peers":[{"public_key":"abc","allowed_ips":["0.0.0.0/0"]}]}}`,
		"bad endpoint":      `{"name":"v","type":"wireguard","wireguard":{"addresses":["10.0.0.2/32"],"peers":[{"public_key":"` + key + `","endpoint":"vpn;rm","allowed_ips":["0.0.0.0/0"]}]}}`,
		"long interface":    `{"name":"very-long-name","type":"wireguard","wireguard":{"addresses":["10.0.0.2/32"],"peers":[{"public_key":"` + key + `","allowed_ips":["0.0.0.0/0"]}]}}`,
		"ovpn script":       `{"name":"o","type":"openvpn","openvpn":{"content":"client\nscript-security 2\nup /tmp/x\n"}}`,
		"ovpn autoconnect":  `{"name":"o","type":"openvpn","auto_connect":true,"openvpn":{"content":"client\n"}}`,
		"bad name":          `{"name":"../x","type":"wifi","ssid":"a","security":"wpa2-personal","psk":"12345678"}`,
		"unknown field":     `{"name":"w","type":"wifi","ssid":"a","security":"wpa2-personal","psk":"12345678","x":1}`,
	}
	for what, b := range bad {
		if (LibraryItem{Name: "x", Type: TypeNetwork, Payload: json.RawMessage(`{"profiles":[` + b + `]}`)}).Validate() == nil {
			t.Errorf("%s accepted", what)
		}
	}
	dup := `{"profiles":[{"name":"o","type":"openvpn","openvpn":{"content":"client"}},{"name":"o","type":"openvpn","openvpn":{"content":"client"}}]}`
	if (LibraryItem{Name: "x", Type: TypeNetwork, Payload: json.RawMessage(dup)}).Validate() == nil {
		t.Error("duplicate profile names accepted")
	}
}

func TestNetworkSecretsMaskRestoreMerge(t *testing.T) {
	stored := json.RawMessage(`{"profiles":[{"name":"w","type":"wifi","ssid":"a","security":"wpa2-personal","psk":"secret123"},` +
		`{"name":"o","type":"openvpn","openvpn":{"content":"client\n<key>\nPRIVATE\n</key>"}}]}`)
	m := MaskNetworkSecrets(stored)
	if strings.Contains(string(m), "secret123") || strings.Contains(string(m), "PRIVATE") || !strings.Contains(string(m), SecretMask) {
		t.Fatalf("not masked: %s", m)
	}
	restored, err := RestoreNetworkSecrets(m, stored)
	if err != nil || !strings.Contains(string(restored), "secret123") || !strings.Contains(string(restored), "PRIVATE") {
		t.Fatalf("not restored: %s %v", restored, err)
	}
	// a new profile with the mask has no stored secret: validation refuses it
	renamed, _ := RestoreNetworkSecrets(json.RawMessage(strings.Replace(string(m), `"name":"w"`, `"name":"x"`, 1)), stored)
	if (LibraryItem{Name: "x", Type: TypeNetwork, Payload: renamed}).Validate() == nil {
		t.Error("mask saved as secret")
	}
	merged, err := Merge([]LibraryItem{{Name: "a", Type: TypeNetwork, Payload: stored},
		{Name: "b", Type: TypeNetwork, Payload: json.RawMessage(`{"profiles":[{"name":"w","type":"wifi","ssid":"b","security":"wpa2-personal","psk":"other1234"}]}`)}})
	if err != nil {
		t.Fatal(err)
	}
	p, st := Compose(merged)
	if !st[0].Valid || len(p.Extra.Network) != 2 || p.Extra.Network[0].SSID != "b" {
		t.Fatalf("merge: %+v %+v", p.Extra.Network, st)
	}
}
