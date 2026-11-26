package agent

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	in := strings.Join([]string{
		`login failed password=hunter2 user=anna`,
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
