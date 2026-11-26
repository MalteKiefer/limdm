package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestUpdateRefusedWithoutReleaseKey(t *testing.T) {
	old := UpdatePubKey
	t.Cleanup(func() { UpdatePubKey = old })
	UpdatePubKey = ""
	a := &Agent{host: &host{family: "debian"}}
	err := a.installUpdate(context.Background(), api.AgentUpdate{Version: "999.0.0", Sums: "x  limdm-agent_999.0.0_amd64.deb\n"})
	if err == nil || !strings.Contains(err.Error(), "release signing key") {
		t.Fatalf("an agent without UpdatePubKey must refuse self updates, got %v", err)
	}
}
