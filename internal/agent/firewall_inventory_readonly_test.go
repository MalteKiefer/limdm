package agent

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The firewall inventory runs on every check in, also on hosts with their
// own container rules: it may only call read commands. Stub tools record
// every call for a firewalld and a ufw host; each must be on the list.
func TestFirewallInventoryReadOnly(t *testing.T) {
	readOnly := []string{
		"firewall-cmd --state", "firewall-cmd --get-default-zone", "firewall-cmd --permanent --list-all-zones",
		"firewall-cmd --permanent --list-all-policies", "ufw status verbose", "ufw show added",
		"nft -j list ruleset", "nft -a list ruleset", "iptables-save", "ip6tables-save",
	}
	for _, firewalld := range []bool{true, false} {
		dir := t.TempDir()
		log := filepath.Join(dir, "calls")
		state := "echo 'not running'; exit 252"
		if firewalld {
			state = "echo running"
		}
		script := "#!/bin/sh\necho \"${0##*/} $*\" >> " + log + "\n" +
			"case \"${0##*/} $1\" in\n" +
			"\"firewall-cmd --state\") " + state + ";;\n" +
			"\"ufw status\") echo 'Status: active'; echo 'Default: deny (incoming), allow (outgoing), disabled (routed)';;\n" +
			"esac\nexit 0\n"
		for _, name := range []string{"ufw", "firewall-cmd", "nft", "iptables-save", "ip6tables-save"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", dir)
		a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), host: &host{family: "debian"}}
		a.collectFirewall()
		got, _ := os.ReadFile(log)
		calls := strings.Split(strings.TrimSpace(string(got)), "\n")
		if len(calls) < 2 {
			t.Fatalf("firewalld=%v: too few calls %q", firewalld, calls)
		}
		for _, c := range calls {
			if !slices.Contains(readOnly, strings.TrimSpace(c)) {
				t.Errorf("firewalld=%v: not a read command: %q", firewalld, c)
			}
		}
	}
}
