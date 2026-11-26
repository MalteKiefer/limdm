package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/maltekiefer/limdm/internal/agent"
	"github.com/maltekiefer/limdm/internal/api"
)

// fakeAgent answers the socket protocol with canned responses and records
// the requests.
func fakeAgent(t *testing.T, answer func(agent.DesktopRequest) agent.DesktopResponse) *[]agent.DesktopRequest {
	t.Helper()
	socket = filepath.Join(t.TempDir(), "agent.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var got []agent.DesktopRequest
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			var req agent.DesktopRequest
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			_ = json.Unmarshal(line, &req)
			got = append(got, req)
			_ = json.NewEncoder(c).Encode(answer(req))
			c.Close()
		}
	}()
	return &got
}

func TestSoftwareInstallByName(t *testing.T) {
	reqs := fakeAgent(t, func(r agent.DesktopRequest) agent.DesktopResponse {
		if r.Op == "catalog" {
			return agent.DesktopResponse{OK: true, Apps: []agent.DesktopApp{{CatalogApp: api.CatalogApp{ID: "vlc", Name: "VLC media player", Mode: "available"}}}}
		}
		return agent.DesktopResponse{OK: true}
	})
	if err := run("software", []string{"install", "vlc media player"}); err != nil {
		t.Fatal(err)
	}
	last := (*reqs)[len(*reqs)-1]
	if last.Op != "app-install" || last.App != "vlc" {
		t.Fatalf("sent %+v", last)
	}
	if err := run("software", []string{"install", "gimp"}); err == nil {
		t.Fatal("an app outside the catalog must be refused")
	}
	if err := run("software", []string{"request", "vlc", "--note", "for a course"}); err != nil {
		t.Fatal(err)
	}
	if last := (*reqs)[len(*reqs)-1]; last.Op != "app-request" || last.Note != "for a course" {
		t.Fatalf("note lost: %+v", last)
	}
}

func TestChecksSortedAndStrict(t *testing.T) {
	list := []agent.DesktopCheck{
		{ID: "b", Level: 1, Status: "pass"},
		{ID: "z", Level: 2, Status: "fail"},
		{ID: "c", Level: 1, Status: "na"},
		{ID: "y", Level: 1, Status: "fail"},
		{ID: "a", Level: 1, Status: "fail"},
	}
	sortChecks(list)
	var got string
	for _, c := range list {
		got += c.ID
	}
	if got != "ayzcb" {
		t.Fatalf("order %s", got)
	}
	fakeAgent(t, func(agent.DesktopRequest) agent.DesktopResponse {
		return agent.DesktopResponse{Status: &agent.DesktopStatus{CheckList: list}}
	})
	if err := run("checks", nil); err != nil {
		t.Fatalf("without --strict: %v", err)
	}
	if err := run("checks", []string{"--strict"}); !errors.Is(err, errChecksFailing) {
		t.Fatalf("--strict: %v", err)
	}
}

func TestAgentErrorsAreErrors(t *testing.T) {
	fakeAgent(t, func(agent.DesktopRequest) agent.DesktopResponse { return agent.DesktopResponse{Error: "not allowed"} })
	if err := run("info", nil); err == nil {
		t.Fatal("refusal of the agent not reported")
	}
}
