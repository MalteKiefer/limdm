package server

import (
	"strings"
	"testing"
)

func TestFriendlyError(t *testing.T) {
	for _, c := range []struct{ lang, in, text, detail string }{
		{"de", "login failed", "Anmeldung fehlgeschlagen", ""},
		{"de", `json: unknown field "idel_seconds"`, "Unbekanntes Feld idel_seconds: Schreibweise mit der Feldreferenz vergleichen.", `json: unknown field "idel_seconds"`},
		{"de", "idle_seconds must be 30..3600", "idle_seconds muss zwischen 30 und 3600 liegen.", "idle_seconds must be 30..3600"},
		{"en", "offline_lock_hours must be 0 (off) up to 8760", "offline_lock_hours must be between 0 and 8760.", "offline_lock_hours must be 0 (off) up to 8760"},
		{"de", "json: cannot unmarshal string into Go struct field screenLockPayload.idle_seconds of type int", "Das Feld idle_seconds hat den falschen Typ: erwartet eine Zahl.", "json: cannot unmarshal string into Go struct field screenLockPayload.idle_seconds of type int"},
		{"en", "invalid character '}' looking for beginning of object key string", "The settings are not valid JSON. Use Format to find the spot.", "invalid character '}' looking for beginning of object key string"},
		{"en", "something new", "something new", ""},
	} {
		got := friendlyError(c.lang, c.in)
		if got.Text != c.text || got.Detail != c.detail {
			t.Errorf("%s %q: got %+v", c.lang, c.in, got)
		}
	}
	// joined errors: each line on its own, the original as detail
	got := friendlyError("en", "idle_seconds must be 30..3600\nlevel must be 1 or 2")
	if !strings.Contains(got.Text, "between 30 and 3600") || !strings.Contains(got.Text, "level must be 1 or 2") || got.Detail == "" {
		t.Errorf("joined: %+v", got)
	}
}
