package api

import (
	"slices"
	"testing"
)

func TestParseEvent(t *testing.T) {
	cases := []struct {
		text, key string
		params    []string
	}{
		{"declarations updated (token 42)", "declarations_updated_token", []string{"42"}},
		{"refused new device CAs from the server: none of them is trusted now", "refused_new_device_cas_none_trusted", nil},
		{"tamper: config changed", "tamper", []string{"config changed"}},
		{"agent updated from 1.0 to 1.1", "agent_updated_from_to", []string{"1.0", "1.1"}},
		{"something an older agent wrote", "", nil},
	}
	for _, c := range cases {
		k, p := ParseEvent(c.text)
		if k != c.key || len(p) != len(c.params) || len(p) > 0 && !slices.Equal(p, c.params) {
			t.Errorf("%q: %q %q, want %q %q", c.text, k, p, c.key, c.params)
		}
	}
	for k, f := range EventFormats {
		if _, ok := EventFormats[k]; !ok || f == "" {
			t.Fatalf("empty format %q", k)
		}
	}
}

func TestFormatEvent(t *testing.T) {
	if got := FormatEvent("Agent von %s auf %s aktualisiert", []string{"1.0", "1.1"}); got != "Agent von 1.0 auf 1.1 aktualisiert" {
		t.Fatal(got)
	}
	if got := FormatEvent("%[2]s: %[1]s", []string{"a", "b"}); got != "b: a" {
		t.Fatal(got)
	}
	if got := FormatEvent("x %s %s", []string{"a"}); got != "x a " {
		t.Fatal(got)
	}
}
