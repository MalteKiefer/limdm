package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestPrivilegedAccounts(t *testing.T) {
	sudoers := "# alice ALL=(ALL) ALL\nDefaults:carol !requiretty\nUser_Alias OPS = bob,dave\n%devops ALL=(ALL) NOPASSWD: ALL\n"
	for _, c := range []struct {
		name   string
		groups []string
		want   bool
	}{
		{"alice", nil, false}, // commented out
		{"bob", nil, true}, {"dave", nil, true}, {"carol", nil, true},
		{"erin", []string{"devops"}, true}, {"erin", []string{"dev"}, false}, {"ops", nil, false},
	} {
		if got := sudoersNames(sudoers, c.name, c.groups...); got != c.want {
			t.Errorf("sudoersNames(%s, %v) = %v", c.name, c.groups, got)
		}
	}
	if why := privileged("root"); !strings.Contains(why, "uid 0") {
		t.Errorf("root: %q", why)
	}
	if _, err := shellAccount("root", false); err == nil {
		t.Error("root shell without AllowRoot accepted")
	}
}

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
