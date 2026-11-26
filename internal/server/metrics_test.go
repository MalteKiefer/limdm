package server

import "testing"

func TestPromLabelEscaping(t *testing.T) {
	var p promWriter
	p.sample("m", 2, "version", "1\"\n\\x")
	if got := p.String(); got != "m{version=\"1\\\"\\n\\\\x\"} 2\n" {
		t.Fatalf("%q", got)
	}
}
