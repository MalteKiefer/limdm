package agent

import (
	"encoding/json"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Network inventory. Interfaces, their kind and VPN clients are hardware and
// software inventory and always collected. Addresses, DNS servers and routes
// reveal network locations and need privacy.network_info.

// vpnClients maps systemd units and interface name patterns to a provider.
var vpnClients = []struct {
	Name  string
	Units []string
	Iface *regexp.Regexp
}{
	{"Tailscale", []string{"tailscaled.service"}, regexp.MustCompile(`^tailscale\d*$`)},
	{"NetBird", []string{"netbird.service"}, regexp.MustCompile(`^wt\d+$`)},
	{"Mullvad", []string{"mullvad-daemon.service"}, regexp.MustCompile(`^wg\d*-mullvad$`)},
	{"NordVPN", []string{"nordvpnd.service"}, regexp.MustCompile(`^nordlynx$|^nordtun$`)},
	{"ProtonVPN", nil, regexp.MustCompile(`^proton\d*$|^pvpn`)},
	{"ZeroTier", []string{"zerotier-one.service"}, regexp.MustCompile(`^zt[a-z0-9]+$`)},
	{"Nebula", []string{"nebula.service"}, regexp.MustCompile(`^nebula\d*$`)},
	{"OpenVPN", []string{"openvpn.service"}, nil},
	{"strongSwan (IPsec)", []string{"strongswan.service", "strongswan-starter.service", "ipsec.service"}, nil},
	{"WireGuard", nil, nil}, // wg-quick units and plain wireguard interfaces, see below
}

func ifaceKind(name string) string {
	base := "/sys/class/net/" + name
	uevent := readFile(base + "/uevent")
	switch {
	case strings.Contains(uevent, "DEVTYPE=wireguard"):
		return "wireguard"
	case exists(base + "/tun_flags"):
		return "tun"
	case exists(base + "/wireless"), exists(base + "/phy80211"):
		return "wifi"
	case exists(base + "/bridge"):
		return "bridge"
	case strings.Contains(uevent, "DEVTYPE=vlan"):
		return "vlan"
	case strings.Contains(uevent, "DEVTYPE=bond"), exists(base + "/bonding"):
		return "bond"
	case !exists(base + "/device"):
		return "virtual" // veth, dummy, docker bridges without a backing device
	}
	return "ethernet"
}

func network(priv api.Privacy) (nics []api.NIC, dns []api.DNSConfig, routes []api.Route, vpns []api.VPN) {
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := api.NIC{Name: ifc.Name, MAC: ifc.HardwareAddr.String(), Kind: ifaceKind(ifc.Name), MTU: ifc.MTU,
			State: strings.TrimSpace(readFile("/sys/class/net/" + ifc.Name + "/operstate"))}
		if n.State == "unknown" || n.State == "" { // tunnels report "unknown"
			n.State = "down"
			if ifc.Flags&net.FlagUp != 0 {
				n.State = "up"
			}
		}
		if n.Kind == "tun" || n.Kind == "wireguard" {
			n.MAC = "" // no hardware address
		}
		for _, v := range vpnClients {
			if v.Iface != nil && v.Iface.MatchString(ifc.Name) {
				n.VPN = v.Name
			}
		}
		if n.VPN == "" && n.Kind == "wireguard" {
			n.VPN = "WireGuard"
		}
		if priv.NetworkInfo {
			if as, err := ifc.Addrs(); err == nil {
				for _, a := range as {
					if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
						n.IPs = append(n.IPs, ipn.String())
					}
				}
			}
		}
		nics = append(nics, n)
	}
	vpns = vpnInventory(nics)
	if priv.NetworkInfo {
		dns, routes = dnsConfig(), routeTable()
	}
	return nics, dns, routes, vpns
}

func vpnInventory(nics []api.NIC) []api.VPN {
	var out []api.VPN
	ifaceFor := func(name string) string {
		for _, n := range nics {
			if n.VPN == name {
				return n.Name
			}
		}
		return ""
	}
	for _, v := range vpnClients {
		for _, u := range v.Units {
			if !unitExists(u) {
				continue
			}
			out = append(out, api.VPN{Name: v.Name, Service: u, Active: unitActive(u), Interface: ifaceFor(v.Name)})
		}
	}
	// instances: openvpn@x, openvpn-client@x, wg-quick@x
	if units, err := run(15*time.Second, "systemctl", "list-units", "--all", "--plain", "--no-legend", "openvpn*@*.service", "wg-quick@*.service"); err == nil {
		for _, l := range strings.Split(units, "\n") {
			f := strings.Fields(l)
			if len(f) < 4 {
				continue
			}
			name := "OpenVPN"
			if strings.HasPrefix(f[0], "wg-quick@") {
				name = "WireGuard"
			}
			iface := ""
			if i := strings.Index(f[0], "@"); i > 0 {
				iface = strings.TrimSuffix(f[0][i+1:], ".service")
			}
			out = append(out, api.VPN{Name: name, Service: f[0], Active: f[2] == "active", Interface: iface})
		}
	}
	// running interfaces of known kinds without a unit (manual wg-quick up, NetworkManager)
	for _, n := range nics {
		if n.VPN == "" || slices.ContainsFunc(out, func(v api.VPN) bool { return v.Interface == n.Name }) {
			continue
		}
		out = append(out, api.VPN{Name: n.VPN, Active: n.State != "down", Interface: n.Name})
	}
	return out
}

func unitExists(u string) bool {
	for _, d := range []string{"/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/"} {
		if exists(d + u) {
			return true
		}
	}
	return false
}

var resolvectlLine = regexp.MustCompile(`^(Global|Link \d+ \(([^)]+)\)):\s*(.*)$`)

// dnsConfig prefers systemd-resolved's per link view, else resolv.conf.
func dnsConfig() []api.DNSConfig {
	conf := readFile("/etc/resolv.conf")
	if strings.Contains(conf, "127.0.0.53") {
		servers, _ := run(15*time.Second, "resolvectl", "dns")
		domains, _ := run(15*time.Second, "resolvectl", "domain")
		byScope := map[string]*api.DNSConfig{}
		var order []string
		add := func(out string, set func(*api.DNSConfig, []string)) {
			for _, l := range strings.Split(out, "\n") {
				m := resolvectlLine.FindStringSubmatch(strings.TrimSpace(l))
				if m == nil {
					continue
				}
				scope := "global"
				if m[2] != "" {
					scope = m[2]
				}
				c := byScope[scope]
				if c == nil {
					c = &api.DNSConfig{Scope: scope}
					byScope[scope] = c
					order = append(order, scope)
				}
				set(c, strings.Fields(m[3]))
			}
		}
		add(servers, func(c *api.DNSConfig, v []string) { c.Servers = v })
		add(domains, func(c *api.DNSConfig, v []string) { c.Domains = v })
		var out []api.DNSConfig
		for _, s := range order {
			if c := byScope[s]; len(c.Servers)+len(c.Domains) > 0 {
				out = append(out, *c)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	c := api.DNSConfig{Scope: "resolv.conf"}
	for _, l := range strings.Split(conf, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			c.Servers = append(c.Servers, f[1])
		case "search", "domain":
			c.Domains = append(c.Domains, f[1:]...)
		}
	}
	if len(c.Servers)+len(c.Domains) == 0 {
		return nil
	}
	return []api.DNSConfig{c}
}

// routeTable reads the main IPv4 and IPv6 routing tables via iproute2's JSON output.
func routeTable() []api.Route {
	var out []api.Route
	for _, fam := range []string{"-4", "-6"} {
		raw, err := run(15*time.Second, "ip", "-j", fam, "route", "show")
		if err != nil {
			continue
		}
		var rs []struct {
			Dst      string `json:"dst"`
			Gateway  string `json:"gateway"`
			Dev      string `json:"dev"`
			Protocol string `json:"protocol"`
			Metric   int    `json:"metric"`
		}
		if json.Unmarshal([]byte(raw), &rs) != nil {
			continue
		}
		family := "inet"
		if fam == "-6" {
			family = "inet6"
		}
		for _, r := range rs {
			if family == "inet6" && strings.HasPrefix(r.Dst, "fe80:") {
				continue
			}
			out = append(out, api.Route{Dst: r.Dst, Gateway: r.Gateway, Dev: r.Dev, Proto: r.Protocol, Metric: r.Metric, Family: family})
			if len(out) >= 300 {
				return out
			}
		}
	}
	return out
}

// nssAccounts lists users and groups as NSS resolves them (getent), so accounts
// from sssd, LDAP, winbind, systemd-homed or DynamicUser appear next to the
// local files. Services that disable enumeration only show known entries.
func nssAccounts() ([]api.Account, []api.Group) {
	accountDB, err := run(30*time.Second, "getent", "passwd")
	if err != nil || accountDB == "" {
		accountDB = readFile("/etc/passwd")
	}
	group, err := run(30*time.Second, "getent", "group")
	if err != nil || group == "" {
		group = readFile("/etc/group")
	}
	return parseAccounts(accountDB, group, readFile("/etc/passwd"), readFile("/etc/group"))
}

// parseAccounts merges NSS output with the local files to mark the source.
func parseAccounts(accountDB, group, localAccounts, localGroup string) ([]api.Account, []api.Group) {
	localUsers, localGroups := names(localAccounts), names(localGroup)
	admins := map[string]bool{}
	var groups []api.Group
	seen := map[string]bool{}
	for _, line := range strings.Split(group, "\n") {
		f := strings.Split(line, ":")
		if len(f) != 4 || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		gid, _ := strconv.Atoi(f[2])
		var members []string
		if f[3] != "" {
			members = strings.Split(f[3], ",")
		}
		if slices.Contains(adminGroups, f[0]) {
			for _, m := range members {
				admins[m] = true
			}
		}
		src := "nss"
		if localGroups[f[0]] {
			src = "local"
		}
		groups = append(groups, api.Group{Name: f[0], GID: gid, Members: members, Source: src, System: systemID(gid)})
	}
	var users []api.Account
	seen = map[string]bool{}
	for _, line := range strings.Split(accountDB, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(f[3])
		shell := f[6]
		human := !systemID(uid) && !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "false")
		src := "nss"
		if localUsers[f[0]] {
			src = "local"
		}
		users = append(users, api.Account{Name: f[0], UID: uid, GID: gid, Gecos: strings.Split(f[4], ",")[0], Home: f[5], Shell: shell,
			Source: src, System: uid != 0 && !human, Admin: uid == 0 || admins[f[0]]})
	}
	return users, groups
}

func names(content string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(content, "\n") {
		if n, _, ok := strings.Cut(l, ":"); ok && n != "" && !strings.HasPrefix(n, "#") {
			m[n] = true
		}
	}
	return m
}

// systemID: below 1000, nobody, or the systemd DynamicUser range. Directory
// services (sssd, LDAP, winbind) often use high IDs; those count as people.
func systemID(id int) bool {
	return id < 1000 || id == 65534 || (id >= 61184 && id <= 65519)
}
