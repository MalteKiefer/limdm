package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// stubResolver answers from maps; everything else is "not found".
type stubResolver struct {
	ptr   map[string][]string
	ips   map[string][]string
	cname map[string]string
}

var errNX = errors.New("no such host")

func (s stubResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if v, ok := s.ptr[addr]; ok {
		return v, nil
	}
	return nil, errNX
}

func (s stubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, ip := range s.ips[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
	}
	if out == nil {
		return nil, errNX
	}
	return out, nil
}

func (s stubResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := s.cname[host]; ok {
		return c, nil
	}
	if _, ok := s.ips[host]; ok {
		return host + ".", nil
	}
	return "", errNX
}

func TestHostnameReverseConfirm(t *testing.T) {
	ctx, ip := context.Background(), net.ParseIP("10.0.0.5")
	r := stubResolver{
		ptr: map[string][]string{"10.0.0.5": {"ws17.corp.example."}, "10.0.0.6": {"spoof.corp.example."}},
		ips: map[string][]string{"ws17.corp.example": {"10.0.0.5"}, "spoof.corp.example": {"10.9.9.9"}, "pc1.lan.example": {"127.0.1.1"}},
	}
	if got := reverseName(ctx, r, ip, "debian"); got != "ws17.corp.example" {
		t.Errorf("confirmed PTR: %q", got)
	}
	if got := reverseName(ctx, r, net.ParseIP("10.0.0.6"), "debian"); got != "" {
		t.Errorf("PTR that does not resolve back must be ignored: %q", got)
	}
	if got := reverseName(ctx, r, net.ParseIP("10.0.0.7"), "debian"); got != "" {
		t.Errorf("no PTR: %q", got)
	}
	// the 127.0.1.1 line this declaration wrote confirms the current name only
	if !confirmed(ctx, r, "pc1.lan.example", ip, "pc1") || confirmed(ctx, r, "pc1.lan.example", ip, "other") {
		t.Error("loopback answer: confirmed only for the current name")
	}
}

func TestHostnameDNSName(t *testing.T) {
	ctx, ip := context.Background(), net.ParseIP("10.0.0.5")
	r := stubResolver{
		ips:   map[string][]string{"pc17.b.example": {"10.0.0.5"}, "ws.a.example": {"10.1.1.1"}},
		cname: map[string]string{"ws.b.example": "pc17.b.example."},
	}
	doms := searchDomains("nameserver 10.0.0.53\nsearch old.example\nsearch a.example b.example .\n")
	if strings.Join(doms, ",") != "a.example,b.example" {
		t.Fatalf("search domains: %v", doms)
	}
	if got := dnsName(ctx, r, ip, "ws", doms); got != "pc17.b.example" {
		t.Errorf("dns name: %q", got)
	}
	if got := dnsName(ctx, r, ip, "nothere", doms); got != "" {
		t.Errorf("unknown name: %q", got)
	}
}

func TestEditHosts(t *testing.T) {
	debian := "127.0.0.1\tlocalhost\n127.0.1.1\tdebian\n\n# IPv6\n::1     localhost ip6-localhost ip6-loopback\n"
	rhel := "127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4\n::1         localhost localhost.localdomain localhost6 localhost6.localdomain6\n"
	custom := "127.0.0.1 localhost\n10.0.0.9 nas.lan nas\n#127.0.1.1 commented\n"
	for name, c := range map[string]struct{ in, want string }{
		"debian": {debian, "127.0.0.1\tlocalhost\n127.0.1.1\tpc1.corp.example\tpc1\n\n# IPv6\n::1     localhost ip6-localhost ip6-loopback\n"},
		"rhel":   {rhel, rhel + hostsBegin + "\n127.0.1.1\tpc1.corp.example\tpc1\n" + hostsEnd + "\n"},
		"custom": {custom, custom + hostsBegin + "\n127.0.1.1\tpc1.corp.example\tpc1\n" + hostsEnd + "\n"},
		"empty":  {"", hostsBegin + "\n127.0.1.1\tpc1.corp.example\tpc1\n" + hostsEnd + "\n"},
		"block":  {"10.0.0.9 nas\n" + hostsBegin + "\n127.0.1.1\told\n" + hostsEnd + "\n127.0.1.1 keep\n", "10.0.0.9 nas\n" + hostsBegin + "\n127.0.1.1\tpc1.corp.example\tpc1\n" + hostsEnd + "\n127.0.1.1 keep\n"},
	} {
		got := editHosts(c.in, "pc1", "pc1.corp.example")
		if got != c.want {
			t.Errorf("%s:\n%q\nwant\n%q", name, got, c.want)
		}
		if again := editHosts(got, "pc1", "pc1.corp.example"); again != got {
			t.Errorf("%s: not idempotent", name)
		}
	}
	if got := editHosts(debian, "pc1", "pc1"); !strings.Contains(got, "127.0.1.1\tpc1\n") {
		t.Errorf("without domain: %q", got)
	}
}

func TestHostnameGate(t *testing.T) {
	st, now := &hostState{}, time.Now()
	if ok, _ := st.gate(true, true, "a.example", now); ok {
		t.Fatal("rdns: the first result must wait")
	}
	if ok, _ := st.gate(true, true, "b.example", now); ok {
		t.Fatal("rdns: a different result must wait again")
	}
	if ok, _ := st.gate(true, true, "b.example", now); !ok {
		t.Fatal("rdns: the same result twice applies")
	}
	st.Applied = now
	st.gate(true, true, "c.example", now.Add(10*time.Minute))
	if ok, why := st.gate(true, true, "c.example", now.Add(20*time.Minute)); ok || !strings.Contains(why, "hour") {
		t.Fatalf("at most one change an hour: %v %q", ok, why)
	}
	if ok, _ := st.gate(true, true, "c.example", now.Add(61*time.Minute)); !ok {
		t.Fatal("after an hour it applies")
	}
	if ok, _ := (&hostState{}).gate(false, true, "fixed", now); !ok {
		t.Fatal("fixed sources apply at once")
	}
}

func TestMTAWarning(t *testing.T) {
	if w := mtaWarning("postfix", "mail.old.example", "pc1", "pc1.corp.example"); !strings.Contains(w, "mail.old.example") {
		t.Errorf("warning expected: %q", w)
	}
	for _, name := range []string{"", "pc1", "PC1.corp.example"} {
		if w := mtaWarning("postfix", name, "pc1", "pc1.corp.example"); w != "" {
			t.Errorf("%q: no warning expected, got %q", name, w)
		}
	}
}

// TestApplyHostname runs the declaration against files in a temporary
// directory with the commands stubbed.
func TestApplyHostname(t *testing.T) {
	dir := t.TempDir()
	hostsFile, mailnameFile, hostnameFile = filepath.Join(dir, "hosts"), filepath.Join(dir, "mailname"), filepath.Join(dir, "hostname")
	var cmds []string
	hostCmd = func(_ time.Duration, name string, args ...string) (string, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return "", nil
	}
	mta := ""
	mtaProbe = func() (string, string) { return mta, "mail.old.example" }
	dnsResolver = stubResolver{}
	t.Cleanup(func() {
		hostsFile, mailnameFile, hostnameFile = "/etc/hosts", "/etc/mailname", "/etc/hostname"
		hostCmd, mtaProbe, dnsResolver = run, mtaHostname, net.DefaultResolver
	})
	if err := os.WriteFile(hostsFile, []byte("127.0.0.1 localhost\n127.0.1.1 old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h := &api.Hostname{Source: "fixed", Name: "kiosk1", Domain: "shop.example", Hosts: true, Mailname: true}

	// no MTA and no /etc/mailname: mailname is left alone
	if err := a.applyHostname(h); err != nil {
		t.Fatal(err)
	}
	info := a.state.Hostname.Info
	if info.Result != "changed" || info.Target != "kiosk1.shop.example" || info.Source != "fixed" {
		t.Fatalf("info: %+v", info)
	}
	if readTrim(hostnameFile) != "kiosk1" && !strings.Contains(strings.Join(cmds, ";"), "hostnamectl set-hostname --static --transient kiosk1") {
		t.Errorf("host name not set: %v", cmds)
	}
	if got := readFile(hostsFile); got != "127.0.0.1 localhost\n127.0.1.1\tkiosk1.shop.example\tkiosk1\n" {
		t.Errorf("hosts: %q", got)
	}
	if exists(mailnameFile) {
		t.Error("mailname written without MTA or file")
	}

	// with an MTA: mailname is the FQDN and the differing myhostname is a warning
	mta = "postfix"
	if err := a.applyHostname(h); err != nil {
		t.Fatal(err)
	}
	if readFile(mailnameFile) != "kiosk1.shop.example\n" {
		t.Errorf("mailname: %q", readFile(mailnameFile))
	}
	if w := a.state.Hostname.Info.Warning; !strings.Contains(w, "postfix") {
		t.Errorf("MTA warning missing: %q", w)
	}
	if n := a.hostnameNotes(); len(n) == 0 || !strings.Contains(strings.Join(n, "|"), "warning: postfix") {
		t.Errorf("notes: %v", n)
	}

	// an unusable source keeps the name and fails
	if err := a.applyHostname(&api.Hostname{Source: "serial", Fallback: "keep"}); err == nil && !api.PlaceholderDMI(dmiSerial()) {
		t.Skip("this machine has a DMI serial")
	} else if err == nil || a.state.Hostname.Info.Result != "failed" {
		t.Errorf("junk serial: %v %+v", err, a.state.Hostname.Info)
	}
}
