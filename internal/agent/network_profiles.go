package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Network profiles become NetworkManager keyfiles named limdm-<name>.nmconnection
// (0600, root). Files with that prefix that are no longer declared are
// removed. WireGuard private keys and the EAP-TLS device key are generated
// here and never leave the device.

const (
	nmDir       = "/etc/NetworkManager/system-connections"
	netDir      = stateDir + "/network"
	netKeyFile  = netDir + "/device.key" // EAP-TLS key, PKCS#8
	netCertFile = netDir + "/device.crt" // issued by the server's network CA
)

func (a *Agent) applyNetwork(profiles []api.NetworkProfile) error {
	if len(profiles) == 0 && !exists(nmDir) {
		return nil // nothing declared and no NetworkManager to clean up
	}
	if len(profiles) > 0 && !hasCmd("nmcli") {
		return errors.New("NetworkManager (nmcli) is not installed")
	}
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		return err
	}
	caDir, caExt, _ := a.host.caAnchors()
	cas := map[string]bool{}
	for _, c := range a.pol.Extra.Certificates {
		cas[c.Name] = true
	}
	identity := ""
	if c := netCert(); c != nil && time.Now().Before(c.NotAfter) {
		identity = c.Subject.CommonName
	}
	desired, wgKeys := map[string]string{}, map[string]string{}
	var keep []string // profiles that cannot be written now keep their last file
	var vpns []api.NetworkProfile
	var errs []error
	for _, p := range profiles {
		file := "limdm-" + p.Name + ".nmconnection"
		env := nmEnv{CertFile: netCertFile, KeyFile: netKeyFile, Identity: identity}
		var err error
		switch {
		case p.Type == "openvpn":
			vpns = append(vpns, p)
			keep = append(keep, file)
			continue
		case p.EAP != nil && !cas[p.EAP.CACert]:
			err = fmt.Errorf("CA certificate %q is not part of a CA certificates item", p.EAP.CACert)
		case p.EAP != nil && p.EAP.Method == "tls" && identity == "":
			err = errors.New("the device certificate for EAP-TLS is not issued yet")
		case p.Type == "wireguard":
			if env.WGKey, err = wgPrivateKey(p.Name); err == nil {
				wgKeys["wg-"+p.Name+".key"] = env.WGKey + "\n"
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			keep = append(keep, file)
			continue
		}
		if p.EAP != nil {
			env.CAPath = filepath.Join(caDir, "limdm-"+p.EAP.CACert+caExt)
		}
		desired[file] = renderKeyfile(p, env)
	}
	changed, err := syncManagedMode(nmDir, "limdm-", ".nmconnection", 0o600, desired, keep...)
	errs = append(errs, err)
	_, err = syncManagedMode(netDir, "wg-", ".key", 0o600, wgKeys)
	errs = append(errs, err)
	if changed {
		if _, err := run(30*time.Second, "nmcli", "connection", "reload"); err != nil {
			errs = append(errs, fmt.Errorf("nmcli connection reload: %w", err))
		} else {
			a.event("network profiles updated (%d managed)", len(desired))
		}
	}
	errs = append(errs, a.applyOpenVPN(vpns))
	return errors.Join(errs...)
}

// openvpnPlugin reports whether the NetworkManager OpenVPN plugin is installed.
func openvpnPlugin() bool {
	for _, d := range []string{"/usr/lib/NetworkManager/VPN", "/usr/lib64/NetworkManager/VPN", "/etc/NetworkManager/VPN"} {
		if exists(d + "/nm-openvpn-service.name") {
			return true
		}
	}
	return false
}

// applyOpenVPN imports .ovpn files with nmcli. The file is kept (0600) in the
// agent's state directory; a changed file or a missing connection imports it
// again. The connection id is limdm-<name>.
func (a *Agent) applyOpenVPN(vpns []api.NetworkProfile) error {
	desired := map[string]string{}
	for _, p := range vpns {
		desired["limdm-"+p.Name+".ovpn"] = strings.ReplaceAll(p.OpenVPN.Content, "\r", "")
	}
	var errs []error
	if len(vpns) > 0 && !openvpnPlugin() {
		errs = append(errs, errors.New("the NetworkManager OpenVPN plugin is not installed (network-manager-openvpn or NetworkManager-openvpn)"))
		vpns = nil
	}
	for _, p := range vpns {
		id := "limdm-" + p.Name
		side, kf := filepath.Join(netDir, id+".ovpn"), filepath.Join(nmDir, id+".nmconnection")
		changed, err := writeIfChanged(side, desired[id+".ovpn"], 0o600)
		if err != nil || (!changed && exists(kf)) {
			errs = append(errs, err)
			continue
		}
		if err := os.Remove(kf); err == nil {
			_, _ = run(30*time.Second, "nmcli", "connection", "reload")
		}
		if out, err := run(time.Minute, "nmcli", "connection", "import", "type", "openvpn", "file", side); err != nil {
			errs = append(errs, fmt.Errorf("%s: import: %w: %s", p.Name, err, strings.TrimSpace(out)))
			continue
		}
		if !exists(kf) {
			errs = append(errs, fmt.Errorf("%s: the imported connection is not stored as %s (NetworkManager 1.20 or newer is required)", p.Name, kf))
			continue
		}
		_, _ = run(30*time.Second, "nmcli", "connection", "modify", id, "connection.autoconnect", "no")
		a.event("imported OpenVPN profile %s", p.Name)
	}
	_, err := syncManagedMode(netDir, "limdm-", ".ovpn", 0o600, desired)
	return errors.Join(append(errs, err)...)
}

// nmEnv holds what a keyfile references on this device.
type nmEnv struct {
	CAPath, CertFile, KeyFile string
	Identity                  string // EAP-TLS default identity: the device certificate's CN
	WGKey                     string // base64 WireGuard private key
}

// nmUUID is a stable UUID per profile name, so a rewritten keyfile stays the
// same connection for NetworkManager.
func nmUUID(name string) string {
	h := sha256.Sum256([]byte("limdm-network:" + name))
	h[6] = h[6]&0x0f | 0x50
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// kfString escapes a GKeyFile string value. Validation already rejects
// control characters.
func kfString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	if strings.HasPrefix(s, " ") {
		s = `\s` + s[1:]
	}
	return s
}

func kfList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, ";") + ";"
}

// renderKeyfile writes one profile in NetworkManager's keyfile format.
// Empty values are left out.
func renderKeyfile(p api.NetworkProfile, env nmEnv) string {
	var b strings.Builder
	section := func(name string, kv ...string) {
		fmt.Fprintf(&b, "[%s]\n", name)
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] != "" {
				fmt.Fprintf(&b, "%s=%s\n", kv[i], kv[i+1])
			}
		}
		b.WriteString("\n")
	}
	on := func(v bool) string {
		if v {
			return "true"
		}
		return ""
	}
	itoa := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	b.WriteString("# Managed by LiMDM (com.limdm.network). Local changes are overwritten.\n")
	conn := []string{"id", p.Name, "uuid", nmUUID(p.Name), "type", p.Type, "autoconnect", strconv.FormatBool(p.Auto())}
	if p.Type == "wireguard" {
		conn = append(conn, "interface-name", p.WireGuard.IfName(p.Name))
	}
	section("connection", conn...)
	switch p.Type {
	case "wifi":
		ssid := make([]string, 0, len(p.SSID))
		for _, c := range []byte(p.SSID) { // a byte list is never mistaken for anything else
			ssid = append(ssid, strconv.Itoa(int(c)))
		}
		section("wifi", "mode", "infrastructure", "ssid", kfList(ssid), "hidden", on(p.Hidden))
		switch p.Security {
		case "wpa2-personal":
			section("wifi-security", "key-mgmt", "wpa-psk", "psk", kfString(p.PSK))
		case "wpa3-personal":
			section("wifi-security", "key-mgmt", "sae", "psk", kfString(p.PSK), "pmf", "3")
		case "wpa2-enterprise":
			section("wifi-security", "key-mgmt", "wpa-eap")
		case "wpa3-enterprise":
			section("wifi-security", "key-mgmt", "wpa-eap", "pmf", "3")
		}
	case "ethernet":
		section("ethernet")
	case "wireguard":
		w := p.WireGuard
		section("wireguard", "private-key", env.WGKey, "mtu", itoa(w.MTU))
		for _, pr := range w.Peers {
			section("wireguard-peer."+pr.PublicKey, "endpoint", pr.Endpoint, "preshared-key", pr.PresharedKey,
				"allowed-ips", kfList(pr.AllowedIPs), "persistent-keepalive", itoa(pr.PersistentKeepalive))
		}
		var v4, v6, dns4, dns6 []string
		for _, a := range w.Addresses {
			if netip.MustParsePrefix(a).Addr().Is4() { // validated
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		for _, d := range w.DNS {
			if strings.Contains(d, ":") {
				dns6 = append(dns6, d)
			} else {
				dns4 = append(dns4, d)
			}
		}
		for _, fam := range []struct {
			name      string
			addr, dns []string
		}{{"ipv4", v4, dns4}, {"ipv6", v6, dns6}} {
			kv := []string{"method", "disabled"}
			if len(fam.addr) > 0 {
				kv = []string{"method", "manual", "dns", kfList(fam.dns)}
				for i, a := range fam.addr {
					kv = append(kv, "address"+strconv.Itoa(i+1), a)
				}
			}
			section(fam.name, kv...)
		}
		return b.String()
	}
	if e := p.EAP; e != nil {
		kv := []string{"eap", e.Method + ";", "ca-cert", env.CAPath, "domain-suffix-match", e.ServerDomain}
		if e.Method == "tls" {
			id := e.Identity
			if id == "" {
				id = env.Identity
			}
			kv = append(kv, "identity", kfString(id), "client-cert", env.CertFile, "private-key", env.KeyFile, "private-key-password-flags", "4")
		} else {
			phase2 := e.Phase2
			if phase2 == "" {
				phase2 = "mschapv2"
			}
			kv = append(kv, "identity", kfString(e.Identity), "anonymous-identity", kfString(e.AnonymousIdentity), "phase2-auth", phase2)
			if e.Password != "" {
				kv = append(kv, "password", kfString(e.Password))
			} else {
				kv = append(kv, "password-flags", "2") // the user's secret agent asks
			}
		}
		section("802-1x", kv...)
	}
	section("ipv4", "method", "auto")
	section("ipv6", "method", "auto", "addr-gen-mode", "stable-privacy")
	return b.String()
}

// wgPrivateKey returns the profile's WireGuard key, generating it on first use.
func wgPrivateKey(profile string) (string, error) {
	path := filepath.Join(netDir, "wg-"+profile+".key")
	if k := readTrim(path); k != "" {
		if raw, err := base64.StdEncoding.DecodeString(k); err == nil && len(raw) == 32 {
			return k, nil
		}
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	k := base64.StdEncoding.EncodeToString(key.Bytes())
	if _, err := writeIfChanged(path, k+"\n", 0o600); err != nil {
		return "", err
	}
	return k, nil
}

// wireguardKeys reports the public keys of the managed WireGuard profiles,
// so the console can show what to enter on the VPN server.
func wireguardKeys(profiles []api.NetworkProfile) []api.WireGuardKey {
	var out []api.WireGuardKey
	for _, p := range profiles {
		if p.Type != "wireguard" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(readTrim(filepath.Join(netDir, "wg-"+p.Name+".key")))
		if err != nil {
			continue
		}
		if k, err := ecdh.X25519().NewPrivateKey(raw); err == nil {
			out = append(out, api.WireGuardKey{Profile: p.Name, Interface: p.WireGuard.IfName(p.Name),
				PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())})
		}
	}
	return out
}

// netCert is the current EAP-TLS device certificate, nil without one.
func netCert() *x509.Certificate {
	c, err := tls.LoadX509KeyPair(netCertFile, netKeyFile)
	if err != nil {
		return nil
	}
	return c.Leaf
}

// ensureNetworkCert requests the EAP-TLS device certificate when a profile
// needs one and renews it 30 days before it expires. The key is generated
// here, only the CSR goes to the server (over mTLS).
func (a *Agent) ensureNetworkCert(ctx context.Context) {
	if !api.NeedsDeviceCert(a.pol.Extra.Network) {
		return
	}
	if c := netCert(); c != nil && time.Until(c.NotAfter) > renewBefore {
		return
	}
	keyPEM, csr, err := newCSR()
	if err != nil {
		a.log.Error("network certificate", "err", err)
		return
	}
	var resp api.EnrollResponse
	if err := a.post(ctx, "/api/v1/network-cert", api.RenewRequest{CSR: csr}, &resp); err != nil {
		a.event("network certificate request failed: %v", err)
		return
	}
	blk, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	c, err := tls.X509KeyPair([]byte(resp.Cert), []byte(pkcs8))
	if err != nil {
		a.event("network certificate unusable: %v", err)
		return
	}
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		a.event("storing network certificate failed: %v", err)
		return
	}
	if _, err := writeIfChanged(netKeyFile, pkcs8, 0o600); err != nil {
		a.event("storing network certificate failed: %v", err)
		return
	}
	if _, err := writeIfChanged(netCertFile, resp.Cert, 0o644); err != nil {
		a.event("storing network certificate failed: %v", err)
		return
	}
	a.event("network certificate issued, valid until %s", c.Leaf.NotAfter.Format(time.DateOnly))
}
