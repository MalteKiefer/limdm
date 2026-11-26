package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestStartShellRefusals(t *testing.T) {
	now := time.Now()
	good := `{"session":"` + strings.Repeat("a", 43) + `","by":"admin@example.com","max_minutes":60,"idle_minutes":15}`
	ok := func() *Agent { return &Agent{cfg: Config{AllowRemoteShell: true}, state: State{CommandKey: "k"}} }
	for name, c := range map[string]struct {
		a   *Agent
		cmd api.Command
	}{
		"not allowed": {&Agent{state: State{CommandKey: "k"}}, api.Command{Payload: good, CreatedAt: now}},
		"no key":      {&Agent{cfg: Config{AllowRemoteShell: true}}, api.Command{Payload: good, CreatedAt: now}},
		"too old":     {ok(), api.Command{Payload: good, CreatedAt: now.Add(-time.Hour)}},
		"bad payload": {ok(), api.Command{Payload: `{"session":"x"}`, CreatedAt: now}},
		"unknown key": {ok(), api.Command{Payload: strings.TrimSuffix(good, "}") + `,"cmd":"id"}`, CreatedAt: now}},
		"root":        {ok(), api.Command{Payload: strings.Replace(good, `"by"`, `"user":"root","by"`, 1), CreatedAt: now}},
	} {
		if out, err := c.a.startShell(c.cmd); err == nil {
			t.Errorf("%s: started (%s)", name, out)
		}
	}
}
