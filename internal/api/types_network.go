package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Network profiles: WLAN, wired 802.1X and VPN connections the agent writes
// as NetworkManager keyfiles. Secrets (pre shared keys, EAP passwords,
// WireGuard preshared keys, OpenVPN configurations) travel only inside the
// signed declaration over mTLS and are masked wherever a person sees them.

const TypeNetwork = "com.limdm.network"

type NetworkProfile struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"`                   // wifi | ethernet | wireguard | openvpn
	AutoConnect *bool      `json:"auto_connect,omitempty"` // default true, not for openvpn
	SSID        string     `json:"ssid,omitempty"`
	Hidden      bool       `json:"hidden,omitempty"`
	Security    string     `json:"security,omitempty"` // wifi: wpa2-personal | wpa3-personal | wpa2-enterprise | wpa3-enterprise; ethernet: 802.1x
	PSK         string     `json:"psk,omitempty"`
	EAP         *EAP       `json:"eap,omitempty"`
	WireGuard   *WireGuard `json:"wireguard,omitempty"`
	OpenVPN     *OpenVPN   `json:"openvpn,omitempty"`
}

// EAP configures 802.1X. The server certificate is checked against a CA
// certificate of the certificates declaration (ca_cert is its name) and
// against server_domain.
type EAP struct {
	Method            string `json:"method"`                       // tls | peap | ttls
	Identity          string `json:"identity,omitempty"`           // tls: default the device certificate's common name
	AnonymousIdentity string `json:"anonymous_identity,omitempty"` // outer identity for peap and ttls
	Password          string `json:"password,omitempty"`           // peap and ttls; empty asks the user
	Phase2            string `json:"phase2,omitempty"`             // peap: mschapv2; ttls: mschapv2 (default) or pap
	CACert            string `json:"ca_cert"`
	ServerDomain      string `json:"server_domain"`
}

// WireGuard: the private key is generated on the device and never leaves
// it; its public key is reported in the inventory.
type WireGuard struct {
	Interface string          `json:"interface,omitempty"` // default wg- plus the profile name
	Addresses []string        `json:"addresses"`           // CIDR
	DNS       []string        `json:"dns,omitempty"`
	MTU       int             `json:"mtu,omitempty"`
	Peers     []WireGuardPeer `json:"peers"`
}

type WireGuardPeer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"` // host:port
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// OpenVPN is imported with the NetworkManager OpenVPN plugin.
type OpenVPN struct {
	Content string `json:"content"` // .ovpn file, inline certificates and keys allowed
}

// WireGuardKey is the public key of a device generated WireGuard key.
type WireGuardKey struct {
	Profile   string `json:"profile"`
	Interface string `json:"interface"`
	PublicKey string `json:"public_key"`
}

// Auto reports whether NetworkManager connects on its own.
func (p NetworkProfile) Auto() bool { return p.AutoConnect == nil || *p.AutoConnect }

// IfName is the WireGuard interface name.
func (w WireGuard) IfName(profile string) string {
	if w.Interface != "" {
		return w.Interface
	}
	return "wg-" + profile
}

// NeedsDeviceCert reports whether a profile authenticates with the device
// certificate LiMDM issues (EAP-TLS).
func NeedsDeviceCert(profiles []NetworkProfile) bool {
	return slices.ContainsFunc(profiles, func(p NetworkProfile) bool { return p.EAP != nil && p.EAP.Method == "tls" })
}

// SecretMask stands for a stored secret in the console. Saving it back keeps
// the stored value.
const SecretMask = "••••••" //nolint:gosec // a placeholder, not a credential

var (
	ifNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	ovpnDenyRe = regexp.MustCompile(`(?im)^[ \t]*-{0,2}(up|down|route-up|route-pre-down|ipchange|client-connect|client-disconnect|learn-address|auth-user-pass-verify|tls-verify|script-security|plugin|iproute|tls-export-cert)([ \t]|$)`)
)

func init() {
	Types[TypeNetwork] = `{"profiles": [{"name": "office", "type": "wifi", "ssid": "Corp", "security": "wpa2-enterprise", "eap": {"method": "tls", "ca_cert": "corp-root", "server_domain": "radius.example.com"}}, {"name": "guest", "type": "wifi", "ssid": "Corp Guest", "security": "wpa3-personal", "psk": "change me please", "auto_connect": false}, {"name": "vpn", "type": "wireguard", "wireguard": {"addresses": ["10.8.0.2/32"], "dns": ["10.8.0.1"], "peers": [{"public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", "endpoint": "vpn.example.com:51820", "allowed_ips": ["10.0.0.0/8"], "persistent_keepalive": 25}]}}]}`
	listTypes[TypeNetwork] = true
}

// plain: printable text without control characters, trimmed, not the mask.
func plain(s string, max int) bool {
	return s != "" && noControl(s, max) && !strings.ContainsAny(s, "\n\t") && strings.TrimSpace(s) == s && s != SecretMask
}

func wgKeyOK(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func prefixesOK(list []string) bool {
	for _, c := range list {
		if _, err := netip.ParsePrefix(c); err != nil {
			return false
		}
	}
	return len(list) > 0
}

// Validate checks one profile. Values end up in keyfiles, so everything is
// allowlisted.
func (p NetworkProfile) Validate() error {
	var errs []error
	bad := func(f string, a ...any) {
		errs = append(errs, fmt.Errorf("network profile %q: "+f, append([]any{p.Name}, a...)...))
	}
	if !nameRe.MatchString(p.Name) {
		bad("name must be lower case letters, digits, dot, dash or underscore")
	}
	wifiOnly := p.SSID != "" || p.Hidden || p.PSK != ""
	switch p.Type {
	case "wifi":
		if len(p.SSID) > 32 || !plain(p.SSID, 32) {
			bad("ssid must be 1 to 32 bytes of printable text")
		}
		switch p.Security {
		case "wpa2-personal", "wpa3-personal":
			psk := p.PSK
			hex64 := len(psk) == 64 && strings.Trim(strings.ToLower(psk), "0123456789abcdef") == ""
			printable := len(psk) >= 8 && len(psk) <= 63 && strings.IndexFunc(psk, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
			if psk == SecretMask {
				bad("the masked pre shared key has no stored value, enter it again")
			} else if !printable && (!hex64 || p.Security != "wpa2-personal") {
				bad("psk must be 8 to 63 printable ASCII characters (wpa2-personal also takes 64 hex digits)")
			}
			if p.EAP != nil {
				bad("eap is only for enterprise security")
			}
		case "wpa2-enterprise", "wpa3-enterprise":
			if p.PSK != "" {
				bad("psk is only for personal security")
			}
			errs = append(errs, p.EAP.validate(p.Name))
		default:
			bad("security must be wpa2-personal, wpa3-personal, wpa2-enterprise or wpa3-enterprise")
		}
	case "ethernet":
		if p.Security != "802.1x" {
			bad("ethernet profiles need security 802.1x")
		}
		if wifiOnly {
			bad("ssid, hidden and psk are only for wifi")
		}
		errs = append(errs, p.EAP.validate(p.Name))
	case "wireguard", "openvpn":
		if wifiOnly || p.Security != "" || p.EAP != nil {
			bad("ssid, hidden, security, psk and eap are only for wifi and ethernet")
		}
		if p.Type == "wireguard" {
			errs = append(errs, p.WireGuard.validate(p.Name))
		} else {
			errs = append(errs, p.OpenVPN.validate(p.Name))
			if p.AutoConnect != nil && *p.AutoConnect {
				bad("openvpn connections are started by the user, auto_connect is not supported")
			}
		}
	default:
		bad("type must be wifi, ethernet, wireguard or openvpn")
	}
	if p.Type != "wireguard" && p.WireGuard != nil || p.Type != "openvpn" && p.OpenVPN != nil {
		bad("wireguard and openvpn settings only belong to profiles of that type")
	}
	return errors.Join(errs...)
}

func (e *EAP) validate(profile string) error {
	if e == nil {
		return fmt.Errorf("network profile %q: eap settings are required", profile)
	}
	var errs []error
	bad := func(f string, a ...any) {
		errs = append(errs, fmt.Errorf("network profile %q: eap: "+f, append([]any{profile}, a...)...))
	}
	if !nameRe.MatchString(e.CACert) {
		bad("ca_cert must name a certificate of a CA certificates item; without it any server could pose as the network")
	}
	if !hostRe.MatchString(e.ServerDomain) {
		bad("server_domain (the RADIUS server certificate's domain) is required")
	}
	for _, id := range []string{e.Identity, e.AnonymousIdentity} {
		if id != "" && !plain(id, 253) {
			bad("identities must be printable text up to 253 characters")
		}
	}
	switch e.Method {
	case "tls":
		if e.Password != "" || e.Phase2 != "" || e.AnonymousIdentity != "" {
			bad("tls uses the device certificate: no password, phase2 or anonymous_identity")
		}
	case "peap", "ttls":
		if e.Identity == "" {
			bad("%s needs an identity", e.Method)
		}
		if e.Password == SecretMask {
			bad("the masked password has no stored value, enter it again")
		} else if e.Password != "" && !plain(e.Password, 256) {
			bad("password must be printable text up to 256 characters")
		}
		if ok := e.Phase2 == "" || e.Phase2 == "mschapv2" || (e.Method == "ttls" && e.Phase2 == "pap"); !ok {
			bad("phase2 is mschapv2 (peap, ttls) or pap (ttls)")
		}
	default:
		bad("method must be tls, peap or ttls")
	}
	return errors.Join(errs...)
}

func (w *WireGuard) validate(profile string) error {
	if w == nil {
		return fmt.Errorf("network profile %q: wireguard settings are required", profile)
	}
	var errs []error
	bad := func(f string, a ...any) {
		errs = append(errs, fmt.Errorf("network profile %q: wireguard: "+f, append([]any{profile}, a...)...))
	}
	if !ifNameRe.MatchString(w.IfName(profile)) {
		bad("interface %q must be up to 15 letters, digits, dot, dash or underscore (set interface for long profile names)", w.IfName(profile))
	}
	if !prefixesOK(w.Addresses) {
		bad("addresses must be one or more CIDR prefixes like 10.8.0.2/32")
	}
	for _, d := range w.DNS {
		if net.ParseIP(d) == nil {
			bad("DNS server %q must be an IP address", d)
		}
	}
	if w.MTU != 0 && (w.MTU < 1280 || w.MTU > 9000) {
		bad("mtu must be 1280..9000")
	}
	if len(w.Peers) == 0 {
		bad("at least one peer is required")
	}
	seen := map[string]bool{}
	for _, pr := range w.Peers {
		if !wgKeyOK(pr.PublicKey) || seen[pr.PublicKey] {
			bad("peer public_key must be a unique base64 encoded 32 byte key")
		}
		seen[pr.PublicKey] = true
		if pr.PresharedKey == SecretMask {
			bad("the masked preshared key has no stored value, enter it again")
		} else if pr.PresharedKey != "" && !wgKeyOK(pr.PresharedKey) {
			bad("peer preshared_key must be a base64 encoded 32 byte key")
		}
		if pr.Endpoint != "" {
			h, port, err := net.SplitHostPort(pr.Endpoint)
			n, perr := strconv.Atoi(port)
			if err != nil || perr != nil || n < 1 || n > 65535 || !hostOrIP(h) {
				bad("peer endpoint %q must be host:port", pr.Endpoint)
			}
		}
		if !prefixesOK(pr.AllowedIPs) {
			bad("peer allowed_ips must be one or more CIDR prefixes")
		}
		if pr.PersistentKeepalive < 0 || pr.PersistentKeepalive > 65535 {
			bad("peer persistent_keepalive must be 0..65535 seconds")
		}
	}
	return errors.Join(errs...)
}

func (o *OpenVPN) validate(profile string) error {
	switch {
	case o == nil || o.Content == "":
		return fmt.Errorf("network profile %q: openvpn content (the .ovpn file) is required", profile)
	case o.Content == SecretMask:
		return fmt.Errorf("network profile %q: the masked openvpn configuration has no stored value, paste it again", profile)
	case !noControl(strings.ReplaceAll(o.Content, "\r", ""), 64<<10):
		return fmt.Errorf("network profile %q: openvpn content must be a text file up to 64 KiB", profile)
	case ovpnDenyRe.MatchString(o.Content):
		return fmt.Errorf("network profile %q: openvpn content must not run scripts or plugins (up, down, script-security, plugin and similar)", profile)
	}
	return nil
}

type networkPayload struct {
	Profiles []NetworkProfile `json:"profiles"`
}

func (d Declaration) applyNetwork(p *Policy) (bool, error) {
	if d.Type != TypeNetwork {
		return false, nil
	}
	var v networkPayload
	if err := strict(d.Payload, &v); err != nil {
		return true, err
	}
	var errs []error
	if len(v.Profiles) > 100 {
		errs = append(errs, errors.New("at most 100 network profiles"))
	}
	names := map[string]bool{}
	for _, pr := range v.Profiles {
		if names[pr.Name] {
			errs = append(errs, fmt.Errorf("network profile %q is listed twice", pr.Name))
		}
		names[pr.Name] = true
		errs = append(errs, pr.Validate())
	}
	p.Extra.Network = v.Profiles
	return true, errors.Join(errs...)
}

// mergeNetwork merges profiles by name; a later item wins.
func mergeNetwork(typ string, a, b json.RawMessage) (json.RawMessage, bool, error) {
	if typ != TypeNetwork {
		return nil, false, nil
	}
	var x, y networkPayload
	if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
		return nil, true, err
	}
	out := x.Profiles
	for _, pr := range y.Profiles {
		if i := slices.IndexFunc(out, func(e NetworkProfile) bool { return e.Name == pr.Name }); i >= 0 {
			out[i] = pr
		} else {
			out = append(out, pr)
		}
	}
	m, err := json.Marshal(networkPayload{Profiles: out})
	return m, true, err
}

// secrets lists pointers to every secret of a profile.
func (p *NetworkProfile) secrets() []*string {
	s := []*string{&p.PSK}
	if p.EAP != nil {
		s = append(s, &p.EAP.Password)
	}
	if p.WireGuard != nil {
		for i := range p.WireGuard.Peers {
			s = append(s, &p.WireGuard.Peers[i].PresharedKey)
		}
	}
	if p.OpenVPN != nil {
		s = append(s, &p.OpenVPN.Content)
	}
	return s
}

// MaskNetworkSecrets replaces the secrets of a network payload with
// SecretMask, for the console editor and the audit log. A payload that does
// not decode is hidden completely.
func MaskNetworkSecrets(raw json.RawMessage) json.RawMessage {
	var v networkPayload
	if json.Unmarshal(raw, &v) != nil {
		return json.RawMessage(`{}`)
	}
	for i := range v.Profiles {
		for _, s := range v.Profiles[i].secrets() {
			if *s != "" {
				*s = SecretMask
			}
		}
	}
	out, _ := json.Marshal(v)
	return out
}

// RestoreNetworkSecrets puts the stored secrets back where the edited
// payload still holds SecretMask, matched by profile name and slot. The
// payload must decode strictly, as validation does afterwards.
func RestoreNetworkSecrets(edited, stored json.RawMessage) (json.RawMessage, error) {
	var e, s networkPayload
	if err := strict(edited, &e); err != nil {
		return nil, err
	}
	if len(stored) > 0 {
		_ = json.Unmarshal(stored, &s) // nothing stored: masks stay and validation names them
	}
	for i := range e.Profiles {
		j := slices.IndexFunc(s.Profiles, func(o NetworkProfile) bool { return o.Name == e.Profiles[i].Name })
		if j < 0 {
			continue
		}
		dst, src := e.Profiles[i].secrets(), s.Profiles[j].secrets()
		// slots line up only for the same shape (same peers in the same order)
		if len(dst) != len(src) {
			continue
		}
		for k := range dst {
			if *dst[k] == SecretMask {
				*dst[k] = *src[k]
			}
		}
	}
	return json.Marshal(e)
}
