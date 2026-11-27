package agent

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// A firewall declaration without zones, outbound filtering or templates
// must run exactly the commands it ran before those existed (0.18.1): hosts
// with their own container rules (Docker) depend on it. The expected
// command lists were recorded with this harness against the 0.18.1 agent.
func TestFirewallLegacyDeclarationUnchanged(t *testing.T) {
	var f api.Firewall
	if err := json.Unmarshal([]byte(`{"enforce":true,"allow":["22/tcp"],"rules":[{"port":"5432/tcp","from":"10.0.0.0/8"}]}`), &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		family string
		want   []string
	}{
		{"debian", []string{
			"systemctl is-active --quiet nftables",
			"ufw allow 22/tcp",
			"ufw allow from 10.0.0.0/8 to any port 5432 proto tcp",
			"ufw delete allow 8080/tcp",
			"ufw default deny incoming",
			"ufw --force enable",
		}},
		{"rhel", []string{
			"systemctl enable --now firewalld",
			"firewall-cmd --permanent --add-port=22/tcp",
			`firewall-cmd --permanent --add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept`,
			"firewall-cmd --permanent --remove-port=8080/tcp",
			"firewall-cmd --reload",
		}},
	} {
		dir := t.TempDir()
		log := filepath.Join(dir, "calls")
		script := "#!/bin/sh\necho \"${0##*/} $*\" >> " + log + "\n[ \"$1\" = is-active ] && exit 1\nexit 0\n"
		for _, name := range []string{"ufw", "firewall-cmd", "systemctl"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil { //nolint:gosec // test stub must be executable
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", dir)
		a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil)), host: &host{family: c.family}, pol: api.Policy{Firewall: f}}
		if err := json.Unmarshal([]byte(`{"firewall_rules":[{"port":"8080/tcp","from":""}]}`), &a.state); err != nil {
			t.Fatal(err)
		}
		if err := a.applyFirewall(); err != nil {
			t.Fatalf("%s: %v", c.family, err)
		}
		got, _ := os.ReadFile(log)
		calls := strings.Split(strings.TrimSpace(string(got)), "\n")
		// systemd hosts enable through systemctl; the stub has no systemd dir
		// on every test machine, so the enable call shape is not compared
		calls = normalizeEnable(calls)
		if strings.Join(calls, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s calls:\n%s\nwant:\n%s", c.family, strings.Join(calls, "\n"), strings.Join(c.want, "\n"))
		}
		if a.state.FirewallEgress != "" {
			t.Errorf("%s: outbound default touched: %q", c.family, a.state.FirewallEgress)
		}
	}
	// Alpine had no firewall support before; its nftables table for a plain
	// declaration filters inbound only and leaves outbound open.
	nft := nftRuleset(wantRules(f, false, nil), egressDeny(f))
	if !strings.Contains(nft, "hook output priority 0; policy accept;") || strings.Contains(nft, "daddr") {
		t.Errorf("nftables output chain filters without outbound deny:\n%s", nft)
	}
}

func normalizeEnable(calls []string) []string {
	out := calls[:0]
	for _, c := range calls {
		if strings.HasPrefix(c, "systemctl enable") {
			c = "systemctl enable --now firewalld"
		}
		out = append(out, c)
	}
	return out
}
