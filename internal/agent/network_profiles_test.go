package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestRenderKeyfile(t *testing.T) {
	no := false
	psk := renderKeyfile(api.NetworkProfile{Name: "guest", Type: "wifi", SSID: "Ab", Hidden: true, Security: "wpa3-personal",
		PSK: ` p\ss;word`, AutoConnect: &no}, nmEnv{})
	for _, want := range []string{"type=wifi\n", "autoconnect=false\n", "ssid=65;98;\n", "hidden=true\n", "key-mgmt=sae\n", "pmf=3\n",
		`psk=\sp\\ss;word` + "\n", "uuid=" + nmUUID("guest") + "\n", "[ipv4]\nmethod=auto\n"} {
		if !strings.Contains(psk, want) {
			t.Errorf("wifi keyfile lacks %q:\n%s", want, psk)
		}
	}
	tlsFile := renderKeyfile(api.NetworkProfile{Name: "lan", Type: "ethernet", Security: "802.1x",
		EAP: &api.EAP{Method: "tls", CACert: "corp", ServerDomain: "radius.example.com"}},
		nmEnv{CAPath: "/ca/limdm-corp.crt", CertFile: "/n/device.crt", KeyFile: "/n/device.key", Identity: "dev1"})
	for _, want := range []string{"[ethernet]\n", "eap=tls;\n", "identity=dev1\n", "ca-cert=/ca/limdm-corp.crt\n",
		"domain-suffix-match=radius.example.com\n", "client-cert=/n/device.crt\n", "private-key=/n/device.key\n", "autoconnect=true\n"} {
		if !strings.Contains(tlsFile, want) {
			t.Errorf("802.1x keyfile lacks %q:\n%s", want, tlsFile)
		}
	}
	peap := renderKeyfile(api.NetworkProfile{Name: "w", Type: "wifi", SSID: "C", Security: "wpa2-enterprise",
		EAP: &api.EAP{Method: "peap", Identity: "alice", CACert: "c", ServerDomain: "r"}}, nmEnv{CAPath: "/c"})
	if !strings.Contains(peap, "phase2-auth=mschapv2\n") || !strings.Contains(peap, "password-flags=2\n") || strings.Contains(peap, "password=") {
		t.Errorf("peap without password must ask the user:\n%s", peap)
	}
	const pub = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	wg := renderKeyfile(api.NetworkProfile{Name: "vpn", Type: "wireguard", WireGuard: &api.WireGuard{Addresses: []string{"10.8.0.2/32"},
		DNS: []string{"10.8.0.1"}, Peers: []api.WireGuardPeer{{PublicKey: pub, Endpoint: "vpn.example.com:51820", AllowedIPs: []string{"10.0.0.0/8", "fd00::/8"}, PersistentKeepalive: 25}}}},
		nmEnv{WGKey: "PRIV"})
	for _, want := range []string{"interface-name=wg-vpn\n", "private-key=PRIV\n", "[wireguard-peer." + pub + "]\n", "endpoint=vpn.example.com:51820\n",
		"allowed-ips=10.0.0.0/8;fd00::/8;\n", "persistent-keepalive=25\n", "[ipv4]\nmethod=manual\ndns=10.8.0.1;\naddress1=10.8.0.2/32\n", "[ipv6]\nmethod=disabled\n"} {
		if !strings.Contains(wg, want) {
			t.Errorf("wireguard keyfile lacks %q:\n%s", want, wg)
		}
	}
}

// The desktop app and limdm profiles show declarations through maskSecrets.
func TestNetworkSecretsMaskedForUsers(t *testing.T) {
	raw := `{"profiles":[{"name":"w","type":"wifi","ssid":"a","security":"wpa2-personal","psk":"topsecret"},` +
		`{"name":"e","type":"wifi","ssid":"b","security":"wpa2-enterprise","eap":{"method":"peap","identity":"u","password":"topsecret","ca_cert":"c","server_domain":"r"}},` +
		`{"name":"v","type":"wireguard","wireguard":{"addresses":["10.0.0.2/32"],"peers":[{"public_key":"k","preshared_key":"topsecret","allowed_ips":["0.0.0.0/0"]}]}},` +
		`{"name":"o","type":"openvpn","openvpn":{"content":"topsecret"}}]}`
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(maskSecrets(v))
	if strings.Contains(string(b), "topsecret") {
		t.Fatalf("secret shown: %s", b)
	}
}
