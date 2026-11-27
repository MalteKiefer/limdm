package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLoggingValidate(t *testing.T) {
	ok := Declaration{Identifier: "logs", Type: TypeLogging, Payload: json.RawMessage(Types[TypeLogging])}
	var p Policy
	if err := ok.apply(&p); err != nil || p.Extra.Logging == nil || !p.Extra.Logging.Journald {
		t.Fatalf("example: %v", err)
	}
	for _, bad := range []string{
		`{"enabled": true}`, // no source
		`{"journald": true, "min_priority": "loud"}`,
		`{"files": ["var/log/x"]}`,
		`{"files": ["/var/log/../etc/shadow"]}`,
		`{"files": ["/proc/kmsg"]}`,
		`{"files": ["/var/log/*.log"]}`,
		`{"include": ["("]}`,
		`{"units": ["a b"]}`,
		`{"container_labels": ["novalue"]}`,
		`{"lines_per_second": 5000}`,
		`{"unknown": 1}`,
	} {
		d := Declaration{Identifier: "logs", Type: TypeLogging, Payload: json.RawMessage(bad)}
		if err := d.apply(&p); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	r, mb, buf, prio := (Logging{MinPriority: "err"}).Limits()
	if r != 20 || mb != 100 || buf != 32 || prio != 3 {
		t.Errorf("limits %d %d %d %d", r, mb, buf, prio)
	}
}

func TestLogGlob(t *testing.T) {
	for _, c := range []struct {
		p, n string
		ok   bool
	}{{"postfix*", "postfix@-.service", true}, {"*.service", "ssh.service", true}, {"ssh", "sshd", false}, {"a[", "a[", true}} {
		if LogGlob(c.p, c.n) != c.ok {
			t.Errorf("%s %s", c.p, c.n)
		}
	}
	if !strings.Contains(strings.Join(LogPriorities, ","), "warning") || LogPriority("WARNING") != 4 {
		t.Error("priorities")
	}
}
