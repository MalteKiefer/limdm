package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// com.limdm.hostname: the agent computes the host name from the declared
// source (api.Hostname.Resolve) and sets it only when it differs. The
// device identity (device ID, certificates) does not depend on it.

// Paths and commands, replaced in tests.
var (
	hostsFile             = "/etc/hosts"
	mailnameFile          = "/etc/mailname"
	hostnameFile          = "/etc/hostname"
	machineInfo           = "/etc/machine-info"
	resolvConf            = "/etc/resolv.conf"
	hostCmd               = run
	mtaProbe              = mtaHostname
	dnsResolver  lookuper = net.DefaultResolver
)

// lookuper is the part of net.Resolver the sources use.
type lookuper interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// hostState is what the declaration keeps between cycles.
type hostState struct {
	Candidate string           `json:"candidate,omitempty"` // name computed in the last cycle
	Applied   time.Time        `json:"applied,omitzero"`    // last change made
	Info      api.HostnameInfo `json:"info"`                // last result, reported in the inventory
}

// Markers of the /etc/hosts block when there is no 127.0.1.1 line to reuse.
const (
	hostsBegin = "# BEGIN LiMDM hostname"
	hostsEnd   = "# END LiMDM hostname"
)

// gate decides whether a change may happen now. Names that come from DNS
// (rdns, dns) can change with DHCP: they must come out the same in two
// cycles in a row, and such a change happens at most once an hour, so a
// flapping record never makes the device rename itself in a loop.
func (st *hostState) gate(network, change bool, target string, now time.Time) (bool, string) {
	seen := st.Candidate
	st.Candidate = target
	switch {
	case !change || !network:
		return true, ""
	case seen != target:
		return false, "waiting for the same result in the next check in"
	case now.Sub(st.Applied) < time.Hour:
		return false, "the host name changed less than an hour ago"
	}
	return true, ""
}

func (a *Agent) applyHostname(h *api.Hostname) error {
	if h == nil {
		a.state.Hostname = nil // removing the item leaves the name as it is
		return nil
	}
	st := a.state.Hostname
	if st == nil {
		st = &hostState{}
		a.state.Hostname = st
	}
	cur, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info := hostFacts(ctx, dnsResolver, cur)
	info.Previous, info.ChangedAt = st.Info.Previous, st.Info.ChangedAt
	defer func() { st.Info = info }()
	short, fqdn, used, err := h.Resolve(api.HostnameFacts{PTR: info.PTR, FQDN: info.FQDN, Serial: dmiSerial()})
	info.Source = used
	if err != nil {
		info.Result, info.Detail = "failed", err.Error()
		return err
	}
	info.Target = fqdn
	now := time.Now()
	change := cur != short || exists(hostnameFile) && readTrim(hostnameFile) != short
	ok, why := st.gate(used == "rdns" || used == "dns", change, fqdn, now)
	switch {
	case !ok:
		info.Result, info.Detail = "waiting", why
		return nil
	case change:
		if err := setHostname(short); err != nil {
			info.Result, info.Detail = "failed", err.Error()
			return err
		}
		st.Applied = now
		info.Result, info.Previous, info.ChangedAt = "changed", cur, &now
		a.event("hostname changed from %s to %s (source %s)", cur, short, used)
	default:
		info.Result = "unchanged"
	}
	var errs []error
	if h.Pretty != "" {
		errs = append(errs, setPretty(h.Pretty))
	}
	if h.Hosts {
		errs = append(errs, writeEtc(hostsFile, editHosts(readFile(hostsFile), short, fqdn)))
	}
	mta, mtaName := mtaProbe()
	if h.Mailname && (mta != "" || exists(mailnameFile)) {
		errs = append(errs, writeEtc(mailnameFile, fqdn+"\n"))
	}
	info.Warning = mtaWarning(mta, mtaName, short, fqdn)
	if err := errors.Join(errs...); err != nil {
		info.Result, info.Detail = "failed", err.Error()
		return err
	}
	return nil
}

// hostnameNotes are the declaration status lines of the last result.
func (a *Agent) hostnameNotes() []string {
	st := a.state.Hostname
	if st == nil || st.Info.Result == "" || st.Info.Result == "failed" { // failures are reasons already
		return nil
	}
	i := st.Info
	n := []string{"target " + i.Target + " (source " + i.Source + "): " + i.Result}
	if i.Detail != "" {
		n[0] += ", " + i.Detail
	}
	if i.Result == "changed" {
		n = append(n, "changed from "+i.Previous)
	}
	if i.Warning != "" {
		n = append(n, "warning: "+i.Warning)
	}
	return n
}

// hostnameInfo is the inventory part: the result of the declaration, or
// only the facts without it. Addresses and DNS names need
// privacy.network_info.
func (a *Agent) hostnameInfo(priv api.Privacy) *api.HostnameInfo {
	var info api.HostnameInfo
	if st := a.state.Hostname; st != nil {
		info = st.Info
	} else if priv.NetworkInfo {
		cur, _ := os.Hostname()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		info = hostFacts(ctx, dnsResolver, cur)
	} else if ip := primaryAddr(); ip != nil {
		info.MAC = macOf(ip) // hardware inventory, collected anyway
	}
	if !priv.NetworkInfo {
		info.Address, info.PTR, info.FQDN = "", "", ""
	}
	if info == (api.HostnameInfo{}) {
		return nil
	}
	return &info
}

// hostFacts collects the primary address, its interface's MAC, the
// forward confirmed PTR name and the DNS name of the host.
func hostFacts(ctx context.Context, r lookuper, cur string) api.HostnameInfo {
	var info api.HostnameInfo
	ip := primaryAddr()
	if ip == nil {
		return info
	}
	info.Address, info.MAC = ip.String(), macOf(ip)
	info.PTR = reverseName(ctx, r, ip, cur)
	info.FQDN = dnsName(ctx, r, ip, cur, searchDomains(readFile(resolvConf)))
	return info
}

// reverseName is the first PTR name of ip when it resolves back to ip.
func reverseName(ctx context.Context, r lookuper, ip net.IP, cur string) string {
	names, err := r.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	if name := strings.TrimSuffix(names[0], "."); confirmed(ctx, r, name, ip, cur) {
		return name
	}
	return ""
}

// primaryAddr is the source address of the default route, IPv4 first. A
// UDP connect only selects the route; nothing is sent.
func primaryAddr() net.IP {
	for _, dst := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		c, err := (&net.Dialer{}).DialContext(context.Background(), "udp", dst)
		if err != nil {
			continue
		}
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip
		}
	}
	return nil
}

func macOf(ip net.IP) string {
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		as, _ := ifc.Addrs()
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return ifc.HardwareAddr.String()
			}
		}
	}
	return ""
}

// confirmed reports whether name resolves to ip. The resolver reads
// /etc/hosts before DNS, and the line this declaration writes maps the
// current name to 127.0.1.1: a name that resolves only to loopback counts
// as confirmed when its first label is the current host name, otherwise
// the next cycle would no longer confirm the name it just set.
func confirmed(ctx context.Context, r lookuper, name string, ip net.IP, cur string) bool {
	addrs, err := r.LookupIPAddr(ctx, name)
	if err != nil || len(addrs) == 0 {
		return false
	}
	loop := true
	for _, a := range addrs {
		if a.IP.Equal(ip) {
			return true
		}
		loop = loop && a.IP.IsLoopback()
	}
	first, _, _ := strings.Cut(name, ".")
	short, _, _ := strings.Cut(cur, ".")
	return loop && strings.EqualFold(first, short)
}

// dnsName is the DNS name of the host: the current name if it is an FQDN,
// then the short name in each search domain, in order; the canonical name
// (CNAME target) of the first candidate that resolves to the primary
// address wins.
func dnsName(ctx context.Context, r lookuper, ip net.IP, cur string, domains []string) string {
	short, _, _ := strings.Cut(cur, ".")
	var cands []string
	if strings.Contains(cur, ".") {
		cands = append(cands, cur)
	}
	for _, d := range domains {
		cands = append(cands, short+"."+d)
	}
	for _, c := range cands {
		canon, err := r.LookupCNAME(ctx, c)
		if err != nil {
			continue
		}
		if canon = strings.TrimSuffix(canon, "."); confirmed(ctx, r, canon, ip, cur) {
			return canon
		}
	}
	return ""
}

// searchDomains reads the search list of resolv.conf: the last search or
// domain line wins, as in the resolver, at most six domains.
func searchDomains(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "search" && f[0] != "domain" {
			continue
		}
		out = out[:0]
		for _, d := range f[1:] {
			if d = strings.Trim(d, "."); d != "" && len(out) < 6 {
				out = append(out, d)
			}
		}
	}
	return out
}

func dmiSerial() string {
	if s := cleanDMI(readTrim("/sys/class/dmi/id/product_serial")); s != "" {
		return s
	}
	return strings.TrimRight(readTrim("/proc/device-tree/serial-number"), "\x00")
}

// editHosts sets the host's own line in /etc/hosts: inside the LiMDM block
// when there is one, else the first 127.0.1.1 line (Debian style), else it
// appends the block (RHEL, SUSE, Arch and Alpine have no such line). Every
// other line stays as it is.
func editHosts(content, short, fqdn string) string {
	entry := "127.0.1.1\t" + fqdn
	if fqdn != short {
		entry += "\t" + short
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	for b, l := range lines {
		if strings.TrimSpace(l) != hostsBegin {
			continue
		}
		for e := b + 1; e < len(lines); e++ {
			if strings.TrimSpace(lines[e]) == hostsEnd {
				return join(append(append(lines[:b+1:b+1], entry), lines[e:]...))
			}
		}
	}
	for i, l := range lines {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "127.0.1.1" {
			lines[i] = entry
			return join(lines)
		}
	}
	return join(append(lines, hostsBegin, entry, hostsEnd))
}

// writeEtc writes a world readable file in /etc and restores its SELinux
// label (an atomic rename leaves the label of the directory).
func writeEtc(path, content string) error {
	changed, err := writeIfChanged(path, content, 0o644)
	if changed && err == nil && hasCmd("restorecon") {
		_, _ = hostCmd(30*time.Second, "restorecon", path)
	}
	return err
}

func setHostname(short string) error {
	if systemd() && hasCmd("hostnamectl") {
		_, err := hostCmd(30*time.Second, "hostnamectl", "set-hostname", "--static", "--transient", short)
		return err
	}
	// no systemd (Alpine with OpenRC): the boot scripts read /etc/hostname
	if err := writeEtc(hostnameFile, short+"\n"); err != nil {
		return err
	}
	_, err := hostCmd(30*time.Second, "hostname", "-F", hostnameFile)
	return err
}

// setPretty sets the pretty host name where systemd keeps one.
func setPretty(p string) error {
	if !systemd() || !hasCmd("hostnamectl") {
		return nil
	}
	for _, line := range strings.Split(readFile(machineInfo), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_HOSTNAME="); ok && strings.Trim(v, `"'`) == p {
			return nil
		}
	}
	_, err := hostCmd(30*time.Second, "hostnamectl", "set-hostname", "--pretty", p)
	return err
}

// mtaHostname finds an installed MTA and the host name it is configured
// with: Postfix only when myhostname is set explicitly, Exim its
// primary_hostname. LiMDM never edits MTA configuration.
func mtaHostname() (mta, name string) {
	if hasCmd("postconf") {
		out, err := hostCmd(10*time.Second, "postconf", "-nh", "myhostname")
		if err != nil {
			out = ""
		}
		return "postfix", strings.TrimSpace(out)
	}
	for _, x := range []string{"exim4", "exim"} {
		if hasCmd(x) {
			out, err := hostCmd(10*time.Second, x, "-bP", "primary_hostname")
			first, _, _ := strings.Cut(out, "\n")
			_, v, _ := strings.Cut(first, "=")
			if err != nil {
				v = ""
			}
			return "exim", strings.TrimSpace(v)
		}
	}
	return "", ""
}

func mtaWarning(mta, name, short, fqdn string) string {
	if mta == "" || name == "" || strings.EqualFold(name, fqdn) || strings.EqualFold(name, short) {
		return ""
	}
	return mta + " uses the host name " + name + ", not " + fqdn + "; LiMDM does not change MTA configuration"
}
