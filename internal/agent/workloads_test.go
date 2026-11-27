package agent

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	dockerID1 = "3f4e5d6c7b8a99887766554433221100ffeeddccbbaa00998877665544332211"
	dockerID2 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
)

var workloadFixtures = map[string]string{
	"docker version --format {{.Server.Version}}": "27.3.1\n",
	"docker ps --all --quiet --no-trunc":          dockerID1 + "\n" + dockerID2 + "\n",
	"docker container inspect " + dockerID1 + " " + dockerID2: `[{"Id":"` + dockerID1 + `","Name":"/paperless-webserver-1","Created":"2026-10-01T08:00:00.123Z",
		"Image":"sha256:1111","Config":{"Image":"ghcr.io/paperless-ngx/paperless-ngx:2.13","Labels":{"com.docker.compose.project":"paperless","com.docker.compose.service":"webserver"}},
		"State":{"Status":"running","StartedAt":"2026-11-20T10:00:00Z"},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}},
		"NetworkSettings":{"Ports":{"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"8000"}],"9000/tcp":null}}},
		{"Id":"` + dockerID2 + `","Name":"/redis","Created":"2026-10-01T08:00:00Z","Image":"sha256:2222","Config":{"Image":"redis:7"},
		"State":{"Status":"exited","StartedAt":"0001-01-01T00:00:00Z"},"HostConfig":{"RestartPolicy":{"Name":"no"}},"NetworkSettings":{"Ports":{}}}]`,
	"podman version --format {{.Client.Version}}": "5.2.2\n",
	"podman ps --all --quiet --no-trunc":          dockerID2 + "\n",
	"podman container inspect " + dockerID2: `[{"Id":"` + dockerID2 + `","Name":"web","Created":"2026-10-01T08:00:00Z","ImageName":"docker.io/library/nginx:1.27",
		"Image":"abcd","Config":{"Labels":{"io.podman.compose.project":"site"}},"State":{"Status":"running","StartedAt":"2026-11-01T00:00:00Z"},
		"HostConfig":{"RestartPolicy":{"Name":"always"}},"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"","HostPort":"8080"}]}}}]`,
	"pveversion":               "pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.8-2-pve)\n",
	"pct list":                 "VMID       Status     Lock         Name\n101        running                 dns\n102        stopped    backup       mail\n",
	"pct config 101":           "arch: amd64\ncores: 2\nhostname: dns\nmemory: 512\nostype: debian\nonboot: 1\n",
	"pct config 102":           "cores: 1\nmemory: 1024\nostype: alpine\n",
	"qm list":                  "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n       200 win11                running    8192              64.00 1234\n       201 test                 stopped    2048              32.00 0\n",
	"qm config 200":            "cores: 4\nsockets: 2\nmemory: 8192\nname: win11\nostype: win11\n",
	"qm config 201":            "cores: 2\nmemory: 2048\n",
	"incus version":            "Client version: 6.0.1\nServer version: 6.0.2\n",
	"incus list --format json": `[{"name":"c1","status":"Running","type":"container","created_at":"2026-09-01T00:00:00Z","config":{"image.os":"Debian","image.release":"bookworm","boot.autostart":"true"}},{"name":"vm1","status":"Stopped","type":"virtual-machine","config":{}},{"name":"-bad","status":"Running","type":"container"}]`,
	"lxc version":              "Client version: 5.21.2 LTS\nServer version: 5.21.2 LTS\n",
	"lxc list --format json":   `[]`,
	"lxc-ls --version":         "5.0.3\n",
	"lxc-ls --fancy --fancy-format NAME,STATE,AUTOSTART": "NAME   STATE   AUTOSTART\nweb    RUNNING 1\nold    STOPPED 0\n",
	"virsh --version":  "9.0.0\n",
	"virsh list --all": " Id   Name    State\n------------------------\n 1    vm-a    running\n -    vm-b    shut off\n\n",
}

// workloadReadOnly are the only commands the inventory may run: every one
// lists, inspects or prints a version or configuration.
var workloadReadOnly = map[string][]string{
	"docker": {"version", "ps", "container inspect"}, "podman": {"version", "ps", "container inspect"},
	"pveversion": {""}, "pct": {"list", "config"}, "qm": {"list", "config"},
	"incus": {"version", "list"}, "lxc": {"version", "list"}, "lxc-ls": {"--version", "--fancy"}, "virsh": {"--version", "list"},
}

func fakeWorkloads(t *testing.T, present func(string) bool) *[]string {
	t.Helper()
	var calls []string
	run, has := workloadRun, workloadPresent
	t.Cleanup(func() { workloadRun, workloadPresent = run, has })
	workloadRun = func(name string, args ...string) (string, error) {
		line := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, line)
		if out, ok := workloadFixtures[line]; ok {
			return out, nil
		}
		return "", errors.New("unexpected command " + line)
	}
	workloadPresent = present
	proxmoxConfigs.m = map[string]cachedConfig{}
	return &calls
}

func TestCollectWorkloads(t *testing.T) {
	calls := fakeWorkloads(t, func(string) bool { return true })
	w := collectWorkloads()
	if w == nil || len(w.Errors) != 0 {
		t.Fatalf("inventory: %+v", w)
	}
	tools := map[string]string{}
	for _, tl := range w.Tools {
		tools[tl.Kind] = tl.Version
	}
	want := map[string]string{"docker": "27.3.1", "podman": "5.2.2", "pct": "8.2.4", "qm": "8.2.4", "incus": "6.0.2", "lxd": "5.21.2 LTS", "libvirt": "9.0.0"}
	for k, v := range want {
		if tools[k] != v {
			t.Errorf("tool %s: %q, want %q", k, tools[k], v)
		}
	}
	if _, ok := tools["lxc"]; ok {
		t.Error("plain LXC must be skipped on Proxmox")
	}
	byID := map[string]api.Workload{}
	for _, it := range w.Items {
		byID[it.Kind+"/"+it.ID] = it
	}
	pl := byID["docker/"+dockerID1]
	if pl.Name != "paperless-webserver-1" || pl.Image != "ghcr.io/paperless-ngx/paperless-ngx:2.13" || pl.State != "running" || pl.Restart != "unless-stopped" ||
		pl.Project != "paperless" || pl.Service != "webserver" || !slices.Equal(pl.Ports, []string{"127.0.0.1:8000->8000/tcp", "9000/tcp"}) || pl.Started.IsZero() {
		t.Errorf("docker: %+v", pl)
	}
	if r := byID["docker/"+dockerID2]; r.State != "exited" || !r.Started.IsZero() || r.Restart != "" {
		t.Errorf("redis: %+v", r)
	}
	if p := byID["podman/"+dockerID2]; p.Image != "docker.io/library/nginx:1.27" || p.Project != "site" || !slices.Equal(p.Ports, []string{"8080->80/tcp"}) {
		t.Errorf("podman: %+v", p)
	}
	if c := byID["pct/101"]; c.Name != "dns" || c.State != "running" || c.Image != "debian" || c.CPUs != 2 || c.MemoryMB != 512 || c.Restart != "onboot" {
		t.Errorf("pct 101: %+v", c)
	}
	if c := byID["pct/102"]; c.Name != "mail" || c.State != "stopped" || c.Image != "alpine" {
		t.Errorf("pct 102 (locked): %+v", c)
	}
	if v := byID["qm/200"]; v.Name != "win11" || v.State != "running" || v.CPUs != 8 || v.MemoryMB != 8192 {
		t.Errorf("qm 200: %+v", v)
	}
	if c := byID["incus/c1"]; c.Image != "Debian bookworm" || c.State != "running" || c.Type != "container" || c.Restart != "autostart" {
		t.Errorf("incus c1: %+v", c)
	}
	if v := byID["incus/vm1"]; v.Type != "vm" || v.State != "stopped" {
		t.Errorf("incus vm1: %+v", v)
	}
	if _, ok := byID["incus/-bad"]; ok {
		t.Error("an id starting with a dash must be dropped")
	}
	if v := byID["libvirt/vm-b"]; v.State != "shut off" {
		t.Errorf("virsh: %+v", v)
	}
	// every command of the inventory only reads
	for _, c := range *calls {
		f := strings.Fields(c)
		sub := strings.Join(f[1:min(len(f), 3)], " ")
		ok := slices.ContainsFunc(workloadReadOnly[f[0]], func(p string) bool { return strings.HasPrefix(sub, p) })
		if !ok {
			t.Errorf("inventory ran %q, which is not a read command", c)
		}
	}
}

func TestCollectLXCAndNone(t *testing.T) {
	fakeWorkloads(t, func(k string) bool { return k == "lxc" })
	w := collectWorkloads()
	if w == nil || len(w.Items) != 2 || w.Items[1].Name != "web" || w.Items[1].State != "running" || w.Items[1].Restart != "autostart" || w.Tools[0].Version != "5.0.3" {
		t.Fatalf("lxc: %+v", w)
	}
	fakeWorkloads(t, func(string) bool { return false })
	if w := collectWorkloads(); w != nil {
		t.Fatalf("no tools: %+v", w)
	}
}

func TestWorkloadArgv(t *testing.T) {
	for in, want := range map[api.WorkloadAction]string{
		{Kind: "docker", ID: dockerID1, Action: "stop"}:  "docker stop --time 60 " + dockerID1,
		{Kind: "podman", ID: dockerID1, Action: "start"}: "podman start " + dockerID1,
		{Kind: "qm", ID: "200", Action: "stop"}:          "qm shutdown 200 --timeout 180",
		{Kind: "pct", ID: "101", Action: "restart"}:      "pct reboot 101 --timeout 180",
		{Kind: "lxd", ID: "c1", Action: "restart"}:       "lxc restart c1 --timeout 120",
		{Kind: "lxc", ID: "web", Action: "stop"}:         "lxc-stop --name web --nokill --timeout 120",
		{Kind: "libvirt", ID: "vm-a", Action: "stop"}:    "virsh shutdown vm-a",
	} {
		if err := in.Validate(); err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		if got := strings.Join(workloadArgv(in), " "); got != want {
			t.Errorf("%+v: %q, want %q", in, got, want)
		}
		if slices.Contains(workloadArgv(in), "kill") || slices.Contains(workloadArgv(in), "--force") {
			t.Errorf("%+v kills", in)
		}
	}
}

func TestWorkloadActionGate(t *testing.T) {
	fakeWorkloads(t, func(k string) bool { return k == "qm" })
	cmd := api.Command{ID: 1, Type: "workload_action", Payload: `{"kind":"qm","id":"999","action":"stop"}`}
	a := &Agent{state: State{CommandKey: "k"}}
	if _, err := a.workloadAction(cmd); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("policy off: %v", err)
	}
	a.pol.WorkloadControl = true
	if _, err := a.workloadAction(cmd); err == nil || !strings.Contains(err.Error(), "no qm workload 999") {
		t.Fatalf("unknown vm: %v", err)
	}
	cmd.Payload = `{"kind":"qm","id":"200;reboot","action":"stop"}`
	if _, err := a.workloadAction(cmd); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("bad id: %v", err)
	}
	cmd.Payload = `{"kind":"qm","id":"200","action":"stop","x":1}`
	if _, err := a.workloadAction(cmd); err == nil {
		t.Fatal("unknown field accepted")
	}
	a.state.CommandKey = ""
	cmd.Payload = `{"kind":"qm","id":"200","action":"stop"}`
	if _, err := a.workloadAction(cmd); err == nil || !strings.Contains(err.Error(), "command signing key") {
		t.Fatalf("no key: %v", err)
	}
}

func TestSettleWorkload(t *testing.T) {
	fakeWorkloads(t, func(k string) bool { return k == "docker" })
	step, limit := workloadSettleStep, workloadSettle
	t.Cleanup(func() { workloadSettleStep, workloadSettle = step, limit })
	workloadSettleStep, workloadSettle = time.Millisecond, 20*time.Millisecond
	// the fixture has paperless running and redis exited
	if got := settleWorkload(api.WorkloadAction{Kind: "docker", ID: dockerID1, Action: "restart"}); got != "state: running" {
		t.Fatalf("restart: %q", got)
	}
	if got := settleWorkload(api.WorkloadAction{Kind: "docker", ID: dockerID2, Action: "stop"}); got != "state: exited" {
		t.Fatalf("stop: %q", got)
	}
	if got := settleWorkload(api.WorkloadAction{Kind: "docker", ID: dockerID2, Action: "start"}); !strings.HasPrefix(got, "state: exited (not yet running") {
		t.Fatalf("start not settled: %q", got)
	}
	// still shutting down on the first two looks, stopped on the third
	looks := 0
	workloadRun = func(name string, args ...string) (string, error) {
		if name == "virsh" && args[0] == "list" {
			looks++
			state := "in shutdown"
			if looks >= 3 {
				state = "shut off"
			}
			return " Id   Name    State\n 1    vm-a    " + state + "\n", nil
		}
		return "", nil
	}
	if got := settleWorkload(api.WorkloadAction{Kind: "libvirt", ID: "vm-a", Action: "stop"}); got != "state: shut off" || looks != 3 {
		t.Fatalf("stop after polling: %q (%d looks)", got, looks)
	}
	if got := settleWorkload(api.WorkloadAction{Kind: "libvirt", ID: "vm-b", Action: "stop"}); got != "state: gone" {
		t.Fatalf("gone: %q", got)
	}
}
