package agent

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	in := strings.Join([]string{
		`config reload password=hunter2 user=anna`,
		`client_secret: "s3cr3t value" ok`,
		`Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc`,
		`proxy http://bob:pa55@proxy:3128 used`,
		`recovery 123456-234567-345678-456789-567890-678901-789012-890123`,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
		`apt: 3 packages upgraded`,
	}, "\n")
	out := redact(in)
	for _, leak := range []string{"hunter2", "s3cr3t", "eyJhbGci", "pa55", "345678-456789", "AAAA"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q not redacted:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "user=anna") || !strings.Contains(out, "apt: 3 packages upgraded") {
		t.Fatalf("too much redacted:\n%s", out)
	}
	if got := tail("one\ntwo\nthree\n", 8); got != "[earlier lines cut]\nthree\n" {
		t.Fatalf("tail %q", got)
	}
}

// TestRedactJournal uses journal lines as they appear on Debian, Fedora and
// Arch: passwords typed into the user field of failed logins, tokens in
// URLs and headers (F12).
func TestRedactJournal(t *testing.T) {
	in := strings.Join([]string{
		`2026-11-20T08:01:02+0100 host sshd[811]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=Winter2026!x`,
		`2026-11-20T08:01:04+0100 host sshd[811]: Failed password for invalid user Sommer2026?y from 203.0.113.7 port 52144 ssh2`,
		`2026-11-20T08:01:05+0100 host sshd[811]: Invalid user Herbst2026#z from 203.0.113.7 port 52144`,
		`2026-11-20T08:01:06+0100 host sshd[811]: Connection closed by invalid user Fruehling1 203.0.113.7 port 52144 [preauth]`,
		`2026-11-20T08:02:00+0100 host sudo[912]: pam_unix(sudo:auth): authentication failure; logname=anna uid=1000 euid=0 tty=/dev/pts/0 ruser=anna rhost=  user=anna`,
		`2026-11-20T08:02:01+0100 host sudo[912]: pam_unix(sudo:auth): auth could not identify password for [Geheim42]`,
		`2026-11-20T08:03:00+0100 host login[700]: FAILED LOGIN (1) on '/dev/tty1' FOR 'Passwort123', Authentication failure`,
		`2026-11-20T08:03:30+0100 host gdm-password][1201]: pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=Kennwort9`,
		`2026-11-20T08:04:00+0100 host curl[1300]: GET https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/acme/repo.git`,
		`2026-11-20T08:04:01+0100 host app[1301]: fetching https://storage.example.com/o?X-Amz-Signature=deadbeefcafe&key=AIzaSyA1&x=1`,
		`2026-11-20T08:04:02+0100 host app[1302]: request header Authorization: Token 9f86d081884c7d659a2feaa0c55ad015`,
		`2026-11-20T08:04:03+0100 host app[1303]: token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbm5hIn0.c2lnbmF0dXJl expired`,
		`2026-11-20T08:04:04+0100 host app[1304]: using key AKIAIOSFODNN7EXAMPLE for upload`,
		`2026-11-20T08:04:05+0100 host NetworkManager[600]: wireguard PresharedKey=YmFzZTY0c2VjcmV0 applied`,
		`2026-11-20T08:05:00+0100 host systemd[1]: Started session-3.scope - Session 3 of User anna.`,
	}, "\n")
	out := redact(in)
	for _, leak := range []string{"Winter2026", "Sommer2026", "Herbst2026", "Fruehling1", "Geheim42", "Passwort123", "Kennwort9",
		"ghp_abc", "deadbeefcafe", "AIzaSyA1", "9f86d081", "eyJzdWIi", "AKIAIOSFODNN7", "YmFzZTY0"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q not redacted:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"rhost=203.0.113.7", "github.com/acme/repo.git", "x=1", "Session 3 of User anna", "for upload"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q redacted:\n%s", keep, out)
		}
	}
}
