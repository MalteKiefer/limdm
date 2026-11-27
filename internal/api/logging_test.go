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
		`{"files": ["/etc/shadow"]}`,
		`{"files": ["/home/a/app.log"]}`,
		`{"files": ["/srv/log/x"]}`,
		`{"files": ["/opt/app/logs/a.log"]}`, // outside every root
		`{"roots": ["/etc"], "files": ["/etc/app.log"]}`,
		`{"roots": ["/"]}`,
		`{"roots": ["/opt"]}`,
		`{"roots": ["/etc/ssh/keys"]}`,
		`{"roots": ["/home/u/.ssh"]}`,
		`{"roots": ["/opt/app/../../etc"]}`,
		`{"roots": ["/boot/grub"]}`,
		`{"files": ["/var/log/[ab].log"]}`,
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

func TestLogRoots(t *testing.T) {
	ok := Declaration{Identifier: "logs", Type: TypeLogging, Payload: json.RawMessage(`{"enabled": true, "roots": ["/opt/app/logs"], "files": ["/opt/app/logs/app.log"]}`)}
	var p Policy
	if err := ok.apply(&p); err != nil {
		t.Fatal(err)
	}
	roots := []string{"/opt/app/logs", "/etc"}
	if !LogFileAllowed("/opt/app/logs/x/y.log", roots) || LogFileAllowed("/opt/app/logsx/y.log", roots) || LogFileAllowed("/etc/app.log", roots) || LogFileAllowed("/etc/shadow", []string{"/etc/x"}) {
		t.Error("roots")
	}
}

func TestLogRootSecrets(t *testing.T) {
	for _, r := range []string{"/etc/letsencrypt/live", "/etc/pki/tls", "/var/lib/docker/containers", "/var/lib/postgresql/17",
		"/etc/NetworkManager/system-connections", "/home/u/.config/app", "/home/u/.aws", "/etc/wireguard/x"} {
		if LogRootValid(r) {
			t.Errorf("%s accepted as a log root", r)
		}
	}
	for _, r := range []string{"/var/lib", "/var/backups/log", "/opt/app", "/srv/data", "/etc/app/catalog"} {
		if LogRootValid(r) {
			t.Errorf("%s accepted as a log root", r)
		}
	}
	for _, r := range []string{"/opt/app/logs", "/home/u/app/logs", "/var/lib/app/log", "/opt/gitlab/app_logs", "/data/nginx-log"} {
		if !LogRootValid(r) {
			t.Errorf("%s refused as a log root", r)
		}
	}
}

func TestLogFileAllowed(t *testing.T) {
	for p, ok := range map[string]bool{
		"/var/log/syslog": true, "/var/log/nginx/error.log": true, "/srv/paperless/log/app.log": true,
		"/var/log": false, "/var/log/": false, "/var/logs/x": false, "/srv/app/data/x.log": false, "/srv/log/x": false,
		"/etc/shadow": false, "/root/x.log": false, "/home/u/.ssh/id_ed25519": false, "/var/log/../../etc/shadow": false, "var/log/x": false,
	} {
		if LogFileAllowed(p, nil) != ok {
			t.Errorf("%s: want %v", p, ok)
		}
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

func TestLogFilePattern(t *testing.T) {
	for p, ok := range map[string]bool{
		"/var/log/*.log": true, "/var/log/nginx/": true, "/var/log/app?.log": true, "/srv/*/logs/": true, "/srv/*/log/*.log": true,
		"/var/*/x.log": false, "/*/log/x": false, "/etc/*": false, "/srv/*/data/": false, "/var/log/[ab].log": false,
		"/var/log/../shadow": false, "/var/log/*/../../etc/x": false, "var/log/*": false,
	} {
		if _, got := LogFilePattern(p, nil); got != ok {
			t.Errorf("%s: want %v", p, ok)
		}
	}
	if _, ok := LogFilePattern("/opt/app/logs/*.log", []string{"/opt/app/logs"}); !ok {
		t.Error("pattern below a custom root")
	}
}
