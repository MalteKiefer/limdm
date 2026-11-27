package server

import (
	"context"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestAppWorkloads(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	const id = "3f4e5d6c7b8a99887766554433221100ffeeddccbbaa00998877665544332211"
	inv := &api.Workloads{Tools: []api.WorkloadTool{{Kind: "docker", Version: "27.3.1"}, {Kind: "qm", Version: "8.2.4"}},
		Items: []api.Workload{{Kind: "docker", ID: id, Name: "paperless", Image: "ghcr.io/paperless-ngx/paperless-ngx:2.13", State: "running"},
			{Kind: "qm", ID: "200", Name: "win11", State: "stopped", Type: "vm"}}}
	tx, _ := db.Begin(ctx)
	if err := storeWorkloads(ctx, tx, "d1", inv); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	code, body := call(dashAuditor, "GET", "/api/v1/devices/d1/workloads", ``)
	if code != 200 || !strings.Contains(body, `"name":"paperless"`) || !strings.Contains(body, `"policy":false`) || !strings.Contains(body, `"allowed":false`) {
		t.Fatalf("device workloads: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/workloads?kind=qm&state=stopped", ``); code != 200 || !strings.Contains(body, `"hostname":"alpha"`) || strings.Contains(body, "paperless") {
		t.Fatalf("fleet: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/workloads?image=PAPERLESS", ``); code != 200 || !strings.Contains(body, "paperless") || strings.Contains(body, "win11") {
		t.Fatalf("fleet image: %d %s", code, body)
	}
	if code, _ := call(dashAuditor, "GET", "/api/v1/workloads?kind=bogus", ``); code != 422 {
		t.Fatalf("bad kind: %d", code)
	}
	send := func(who session, params string) (int, string) {
		return call(who, "POST", "/api/v1/devices/d1/commands", `{"type":"workload_action","params":`+params+`}`)
	}
	start := `{"kind":"qm","id":"200","action":"start"}`
	// the policy must allow it: a clear 409
	if code, body := send(dashAdmin, start); code != 409 || !strings.Contains(body, "Workload control") {
		t.Fatalf("policy off: %d %s", code, body)
	}
	setAgentPolicy(t, db, "workload_control")
	// exact match against the last inventory, strict ids
	for _, bad := range []string{`{"kind":"qm","id":"201","action":"start"}`, `{"kind":"qm","id":"200;reboot","action":"start"}`,
		`{"kind":"docker","id":"` + id[:12] + `","action":"start"}`, `{"kind":"qm","id":"200","action":"kill"}`, `{"kind":"sh","id":"200","action":"start"}`} {
		if code, body := send(dashAdmin, bad); code != 422 {
			t.Fatalf("%s: %d %s", bad, code, body)
		}
	}
	// admins only, helpdesk when the setting allows it
	if code, _ := send(dashHelpdesk, start); code != 403 {
		t.Fatalf("helpdesk: %d", code)
	}
	set := s.settings()
	set.WorkloadsHelpdesk = true
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	if code, body := send(dashHelpdesk, start); code != 202 || !strings.Contains(body, `"type":"workload_action"`) {
		t.Fatalf("helpdesk with the setting: %d %s", code, body)
	}
	// four eyes: stop and restart wait for a second admin, start does not
	set.FourEyesWorkloads = true
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	if code, body := send(dashAdmin, `{"kind":"docker","id":"`+id+`","action":"stop"}`); code != 202 || !strings.Contains(body, "approval_id") {
		t.Fatalf("stop with four eyes: %d %s", code, body)
	}
	if code, body := send(dashAdmin, start); code != 202 || strings.Contains(body, "approval_id") {
		t.Fatalf("start with four eyes: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/devices/bulk", `{"ids":["d1"],"action":"command","params":{"type":"workload_action","kind":"qm","id":"200","action":"start"}}`); code < 400 {
		t.Fatalf("bulk: %d %s", code, body)
	}
	// nil removes the inventory
	tx, _ = db.Begin(ctx)
	if err := storeWorkloads(ctx, tx, "d1", nil); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if code, body := call(dashAuditor, "GET", "/api/v1/devices/d1/workloads", ``); code != 200 || !strings.Contains(body, `"reports":false`) || !strings.Contains(body, `"policy":true`) {
		t.Fatalf("after removal: %d %s", code, body)
	}
}
