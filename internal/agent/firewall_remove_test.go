package agent

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// stubTools puts recording stand ins for tools on PATH; nft answers the
// two list commands from the production host fixtures.
func stubTools(t *testing.T, names ...string) (string, func() []string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	js, txt := filepath.Join(dir, "rules.json"), filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(js, []byte(prodNftJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(txt, []byte(prodNftText), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"${0##*/} $1 $2\" in\n" +
		"\"nft -j list\") /bin/cat " + js + "; exit 0;;\n" +
		"\"nft -a list\") /bin/cat " + txt + "; exit 0;;\nesac\n" +
		"echo \"${0##*/} $*\" >> " + log + "\nexit 0\n"
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir, func() []string {
		b, _ := os.ReadFile(log)
		_ = os.Remove(log)
		if s := strings.TrimSpace(string(b)); s != "" {
			return strings.Split(s, "\n")
		}
		return nil
	}
}

// The remove list deletes a foreign rule in every cycle (it came back after
// a reboot: the stub still lists it) and never a rule of LiMDM's legacy
// table or of NetBird, even when listed; a listed exception stays too.
func TestFirewallRemoveList(t *testing.T) {
	_, calls := stubTools(t, "nft")
	rules, _, err := parseNft(prodNftJSON, prodNftText)
	if err != nil {
		t.Fatal(err)
	}
	match := map[string]string{}
	for i := range rules {
		rules[i].Finish()
		match[rules[i].Raw] = rules[i].Match
	}
	foreign := match["tcp dport 8443 accept"]
	f := api.Firewall{Remove: []string{foreign, match[`iif "lo" accept`], match[`iifname "wt0" oifname "wt0" drop`]}}
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), host: &host{family: "debian"}}
	for cycle := 0; cycle < 2; cycle++ {
		a.fwNotes = nil
		a.enforceFirewallRemove(f)
		got := calls()
		if len(got) != 1 || got[0] != "nft delete rule inet filter input handle 6" {
			t.Fatalf("cycle %d: %q notes %q", cycle, got, a.fwNotes)
		}
		if strings.Join(a.fwNotes, "\n") == "" || !strings.Contains(strings.Join(a.fwNotes, "\n"), "left in place") {
			t.Fatalf("notes %q", a.fwNotes)
		}
	}
	f.Keep = []string{foreign}
	a.enforceFirewallRemove(f)
	if got := calls(); len(got) != 0 {
		t.Fatalf("kept rule removed: %q", got)
	}
	// the server refuses such entries before they are saved
	for _, m := range f.Remove[1:] {
		if api.RemoveEntryError(m) == nil {
			t.Errorf("entry accepted: %s", m)
		}
	}
	if api.RemoveEntryError(foreign) != nil {
		t.Error("foreign entry refused")
	}
}

// LiMDM's nftables table loads at boot without touching the nftables
// service or the main configuration (both flush every other table), and
// the generated file deletes and recreates only LiMDM's own table.
func TestNftBootAndOwnTableOnly(t *testing.T) {
	dir, calls := stubTools(t, "nft", "systemctl", "rc-update", "rc-service")
	etc := t.TempDir()
	main := filepath.Join(etc, "nftables.conf")
	mainText := "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n}\n"
	if err := os.WriteFile(main, []byte(mainText), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := []any{nftFile, nftMainConfs, nftEnabled, nftUnitDir, nftInitDir, nftUnitEnabled}
	t.Cleanup(func() {
		nftFile, nftMainConfs, nftEnabled = saved[0].(string), saved[1].([]string), saved[2].([]string)
		nftUnitDir, nftInitDir, nftUnitEnabled = saved[3].(string), saved[4].(string), saved[5].([]string)
	})
	nftFile = filepath.Join(etc, "limdm.nft")
	nftMainConfs, nftEnabled = []string{main}, []string{filepath.Join(etc, "nftables-enabled")}
	nftUnitDir, nftInitDir = etc, etc
	nftUnitEnabled = []string{filepath.Join(etc, "unit-enabled"), filepath.Join(etc, "openrc-enabled")}

	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), host: &host{family: "alpine"},
		pol: api.Policy{Firewall: api.Firewall{Enforce: true, Allow: []string{"22/tcp"}}}}
	if err := a.syncNftables(); err != nil {
		t.Fatal(err)
	}
	first := calls()
	file, _ := os.ReadFile(nftFile)
	if strings.Contains(string(file), "flush ruleset") || !strings.Contains(string(file), "delete table inet limdm\n") || strings.Count(string(file), "table inet") != 3 {
		t.Fatalf("file must only replace inet limdm:\n%s", file)
	}
	unit := filepath.Join(etc, "limdm-firewall.service")
	if !systemd() {
		unit = filepath.Join(etc, "limdm-firewall")
	}
	if b, err := os.ReadFile(unit); err != nil || !strings.Contains(string(b), dir+"/nft -f "+nftFile) {
		t.Fatalf("boot unit %s: %v", b, err)
	}
	// once set up, only the cheap check runs; enabled state comes from the file
	_ = os.WriteFile(nftUnitEnabled[0], nil, 0o644)
	_ = os.WriteFile(nftUnitEnabled[1], nil, 0o644)
	if err := a.syncNftables(); err != nil {
		t.Fatal(err)
	}
	second := calls()
	if len(second) != 1 || second[0] != "nft list table inet limdm" {
		t.Fatalf("second run: %q", second)
	}
	// where nftables.conf includes nftables.d and the service starts at boot, no own unit
	_ = os.Remove(unit)
	_ = os.WriteFile(main, []byte(mainText+"include \"/etc/nftables.d/*.nft\"\n"), 0o644)
	_ = os.WriteFile(nftEnabled[0], nil, 0o644)
	if err := ensureNftBoot(); err != nil {
		t.Fatal(err)
	}
	if exists(unit) || len(calls()) != 0 {
		t.Fatal("own boot unit beside an including nftables.conf")
	}
	if b, _ := os.ReadFile(main); !strings.HasPrefix(string(b), mainText) {
		t.Fatal("main configuration changed")
	}
	for _, c := range append(first, second...) {
		if strings.Contains(c, "nftables") || strings.Contains(c, "flush") {
			t.Errorf("command touches nftables service or configuration: %q", c)
		}
	}
	if len(first) == 0 || !strings.HasPrefix(first[len(first)-1], "systemctl enable limdm-firewall") && !strings.HasPrefix(first[len(first)-1], "rc-update add limdm-firewall") {
		t.Errorf("first run: %q", first)
	}
}
