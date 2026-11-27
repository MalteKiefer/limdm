package server

import (
	"os"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// TestCommandLabels fails when a command type has no German and English
// label in the console, which would show the raw key in the activity.
func TestCommandLabels(t *testing.T) {
	b, err := os.ReadFile("../../web/src/areas/devices/messages.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range append(api.CommandTypes, "shell") {
		if n := strings.Count(string(b), "'devices.type."+typ+"':"); n != 2 {
			t.Errorf("command type %s: %d labels in devices/messages.ts, want German and English", typ, n)
		}
	}
}
