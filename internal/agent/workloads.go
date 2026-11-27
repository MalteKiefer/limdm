package agent

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Containers and virtual machines (workloads). The inventory runs only read
// commands (list, inspect, config, version; see workloadReadOnly in the
// test) with a timeout each and a bound on the number of workloads. The
// workload_action command starts, stops or restarts one workload when the
// device's policy allows it; stop and restart shut down gracefully.

// workloadRun runs a read command and returns its standard output; a
// variable, so tests feed fixtures and record every command.
var workloadRun = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.WaitDelay = 5 * time.Second
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, lastLines(errb.String(), 3))
	}
	if out.Len() > 16<<20 {
		return "", fmt.Errorf("%s %s: output too large", name, args[0])
	}
	return out.String(), nil
}

// workloadPresent reports whether a tool is installed and, where probing
// the command alone could change the system, its daemon socket exists:
// Ubuntu's lxd-installer turns a first "lxc" call into a snap install.
var workloadPresent = func(kind string) bool {
	sockets := map[string][]string{
		"docker":  {"/var/run/docker.sock", "/run/docker.sock"},
		"lxd":     {"/var/snap/lxd/common/lxd/unix.socket", "/var/lib/lxd/unix.socket"},
		"incus":   {"/var/lib/incus/unix.socket"},
		"libvirt": {"/run/libvirt/libvirt-sock", "/run/libvirt/virtqemud-sock"},
	}
	if !hasCmd(workloadCmd(kind)) {
		return false
	}
	s, ok := sockets[kind]
	return !ok || slices.ContainsFunc(s, exists)
}

// workloadCmd is the command of a kind.
func workloadCmd(kind string) string {
	switch kind {
	case "lxc":
		return "lxc-ls"
	case "lxd":
		return "lxc"
	case "libvirt":
		return "virsh"
	}
	return kind
}

// workloadsEvery coalesces inventories: check ins in quick succession (sync
// now clicked again and again) read the tools at most once in this time.
const workloadsEvery = 15 * time.Second

// workloads is the inventory for a check in, read again only after
// workloadsEvery or a workload action.
func (a *Agent) workloads() *api.Workloads {
	if a.wlAt.IsZero() || time.Since(a.wlAt) >= workloadsEvery {
		a.wl, a.wlAt = collectWorkloads(), time.Now()
	}
	return a.wl
}

// collectWorkloads reads every installed tool; nil when there is none.
func collectWorkloads() *api.Workloads {
	w := &api.Workloads{Tools: []api.WorkloadTool{}, Items: []api.Workload{}}
	for _, k := range api.WorkloadKinds {
		if k == "lxc" && workloadPresent("pct") {
			continue // lxc-ls on Proxmox lists the pct containers again
		}
		if workloadPresent(k) {
			collectKind(w, k)
		}
	}
	if len(w.Tools) == 0 && len(w.Errors) == 0 {
		return nil
	}
	slices.SortFunc(w.Items, func(a, b api.Workload) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return w
}

// collectKind adds the tool version and workloads of one kind to w.
func collectKind(w *api.Workloads, kind string) {
	var items []api.Workload
	var version string
	var err error
	switch kind {
	case "docker", "podman":
		version, items, err = collectOCI(kind)
	case "pct", "qm":
		version, items, err = collectProxmox(kind)
	case "lxd", "incus":
		version, items, err = collectIncus(kind)
	case "lxc":
		version, items, err = collectLXC()
	case "libvirt":
		version, items, err = collectLibvirt()
	}
	w.Tools = append(w.Tools, api.WorkloadTool{Kind: kind, Version: truncate(version, 64)})
	if err != nil {
		w.Errors = append(w.Errors, truncate(kind+": "+err.Error(), 300))
	}
	if len(items) > api.MaxWorkloads {
		items, w.Truncated = items[:api.MaxWorkloads], true
	}
	w.Items = append(w.Items, items...)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}

// ---- Docker and Podman ----

type ociInspect struct {
	ID        string `json:"Id"`
	Name      string `json:"Name"`
	Created   string `json:"Created"`
	Image     string `json:"Image"`
	ImageName string `json:"ImageName"` // Podman
	Config    struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func collectOCI(kind string) (string, []api.Workload, error) {
	vf := "{{.Server.Version}}"
	if kind == "podman" {
		vf = "{{.Client.Version}}"
	}
	v, err := workloadRun(kind, "version", "--format", vf)
	if err != nil {
		return "", nil, err
	}
	ids, err := workloadRun(kind, "ps", "--all", "--quiet", "--no-trunc")
	if err != nil {
		return firstLine(v), nil, err
	}
	list := strings.Fields(ids)
	list = slices.DeleteFunc(list, func(id string) bool { return !api.ValidWorkloadID(kind, id) })
	if len(list) > api.MaxWorkloads+1 {
		list = list[:api.MaxWorkloads+1] // one more marks the inventory as truncated
	}
	if len(list) == 0 {
		return firstLine(v), nil, nil
	}
	out, err := workloadRun(kind, append([]string{"container", "inspect"}, list...)...)
	if err != nil {
		return firstLine(v), nil, err
	}
	items, err := parseOCIInspect(kind, out)
	return firstLine(v), items, err
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 1971 {
		return time.Time{}
	}
	return t.UTC()
}

// parseOCIInspect reads the JSON of docker or podman container inspect.
func parseOCIInspect(kind, out string) ([]api.Workload, error) {
	var list []ociInspect
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("container inspect: %w", err)
	}
	items := []api.Workload{}
	for _, c := range list {
		if !api.ValidWorkloadID(kind, c.ID) {
			continue
		}
		it := api.Workload{Kind: kind, ID: c.ID, Name: strings.TrimPrefix(c.Name, "/"), Image: cmp.Or(c.Config.Image, c.ImageName),
			ImageID: c.Image, State: strings.ToLower(c.State.Status), Created: parseTime(c.Created), Started: parseTime(c.State.StartedAt),
			Restart: c.HostConfig.RestartPolicy.Name}
		if it.Restart == "no" {
			it.Restart = ""
		}
		l := c.Config.Labels
		it.Project = cmp.Or(l["com.docker.compose.project"], l["io.podman.compose.project"])
		it.Service = cmp.Or(l["com.docker.compose.service"], l["io.podman.compose.service"])
		for port, binds := range c.NetworkSettings.Ports {
			for _, b := range binds {
				it.Ports = append(it.Ports, strings.TrimPrefix(b.HostIP+":", ":")+b.HostPort+"->"+port)
			}
			if len(binds) == 0 {
				it.Ports = append(it.Ports, port)
			}
		}
		slices.Sort(it.Ports)
		it.Ports = slices.Compact(it.Ports)
		items = append(items, it)
	}
	return items, nil
}

// ---- Proxmox VE ----

func collectProxmox(kind string) (string, []api.Workload, error) {
	v, err := workloadRun("pveversion")
	version := ""
	if err == nil {
		version = parsePVEVersion(v)
	}
	out, err := workloadRun(kind, "list")
	if err != nil {
		return version, nil, err
	}
	items := parseProxmoxList(kind, out)
	for i := range items {
		if i >= api.MaxWorkloads {
			break
		}
		if cfg, ok := proxmoxConfig(kind, items[i].ID); ok {
			applyProxmoxConfig(&items[i], cfg)
		}
	}
	return version, items, nil
}

// proxmoxConfigs caches "pct config" and "qm config" for an hour: each call
// takes a noticeable fraction of a second on a host with many guests.
var proxmoxConfigs = struct {
	sync.Mutex
	m map[string]cachedConfig
}{m: map[string]cachedConfig{}}

type cachedConfig struct {
	at  time.Time
	cfg string
}

func proxmoxConfig(kind, id string) (string, bool) {
	proxmoxConfigs.Lock()
	defer proxmoxConfigs.Unlock()
	key := kind + "/" + id
	if c, ok := proxmoxConfigs.m[key]; ok && time.Since(c.at) < time.Hour {
		return c.cfg, true
	}
	cfg, err := workloadRun(kind, "config", id)
	if err != nil {
		return "", false
	}
	proxmoxConfigs.m[key] = cachedConfig{time.Now(), cfg}
	return cfg, true
}

// parsePVEVersion reads "pve-manager/8.1.4/ec5affc9 (running kernel: ...)".
func parsePVEVersion(s string) string {
	f := strings.Split(firstLine(s), "/")
	if len(f) < 2 {
		return firstLine(s)
	}
	return f[1]
}

// parseProxmoxList reads the tables of "pct list" (VMID Status [Lock] Name)
// and "qm list" (VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID).
func parseProxmoxList(kind, out string) []api.Workload {
	items := []api.Workload{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !api.ValidWorkloadID(kind, f[0]) {
			continue // header, empty line
		}
		it := api.Workload{Kind: kind, ID: f[0]}
		if kind == "pct" {
			it.State, it.Name, it.Type = strings.ToLower(f[1]), f[len(f)-1], "container"
		} else {
			it.Name, it.State, it.Type = f[1], strings.ToLower(f[2]), "vm"
			if len(f) > 3 {
				it.MemoryMB, _ = strconv.Atoi(f[3])
			}
		}
		items = append(items, it)
	}
	return items
}

// applyProxmoxConfig reads "key: value" lines of pct config or qm config.
func applyProxmoxConfig(it *api.Workload, cfg string) {
	sockets := 1
	for _, line := range strings.Split(cfg, "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "ostype":
			it.Image = v
		case "cores":
			it.CPUs, _ = strconv.Atoi(v)
		case "sockets":
			sockets, _ = strconv.Atoi(v)
		case "memory":
			it.MemoryMB, _ = strconv.Atoi(v)
		case "onboot":
			if v == "1" {
				it.Restart = "onboot"
			}
		}
	}
	if sockets > 1 {
		it.CPUs *= sockets
	}
}

// ---- LXD and Incus ----

type incusInstance struct {
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	Type      string            `json:"type"`
	CreatedAt string            `json:"created_at"`
	Config    map[string]string `json:"config"`
}

func collectIncus(kind string) (string, []api.Workload, error) {
	cmd := workloadCmd(kind)
	v, _ := workloadRun(cmd, "version")
	out, err := workloadRun(cmd, "list", "--format", "json")
	if err != nil {
		return parseIncusVersion(v), nil, err
	}
	items, err := parseIncusList(kind, out)
	return parseIncusVersion(v), items, err
}

// parseIncusVersion reads "Client version: 6.0\nServer version: 6.0".
func parseIncusVersion(s string) string {
	client := ""
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(line, ":")
		switch strings.TrimSpace(k) {
		case "Server version":
			return strings.TrimSpace(v)
		case "Client version":
			client = strings.TrimSpace(v)
		}
	}
	return client
}

func parseIncusList(kind, out string) ([]api.Workload, error) {
	var list []incusInstance
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	items := []api.Workload{}
	for _, c := range list {
		if !api.ValidWorkloadID(kind, c.Name) {
			continue
		}
		typ := "container"
		if c.Type == "virtual-machine" {
			typ = "vm"
		}
		img := strings.TrimSpace(c.Config["image.os"] + " " + c.Config["image.release"])
		it := api.Workload{Kind: kind, ID: c.Name, Name: c.Name, Type: typ, Image: img, State: strings.ToLower(c.Status), Created: parseTime(c.CreatedAt)}
		if c.Config["boot.autostart"] == "true" {
			it.Restart = "autostart"
		}
		items = append(items, it)
	}
	return items, nil
}

// ---- plain LXC ----

func collectLXC() (string, []api.Workload, error) {
	v, _ := workloadRun("lxc-ls", "--version")
	out, err := workloadRun("lxc-ls", "--fancy", "--fancy-format", "NAME,STATE,AUTOSTART")
	if err != nil {
		return firstLine(v), nil, err
	}
	return firstLine(v), parseLXCLs(out), nil
}

// parseLXCLs reads "lxc-ls -f -F NAME,STATE,AUTOSTART".
func parseLXCLs(out string) []api.Workload {
	items := []api.Workload{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] == "NAME" || !api.ValidWorkloadID("lxc", f[0]) {
			continue
		}
		it := api.Workload{Kind: "lxc", ID: f[0], Name: f[0], Type: "container", State: strings.ToLower(f[1])}
		if len(f) > 2 && f[2] == "1" {
			it.Restart = "autostart"
		}
		items = append(items, it)
	}
	return items
}

// ---- libvirt ----

func collectLibvirt() (string, []api.Workload, error) {
	v, _ := workloadRun("virsh", "--version")
	out, err := workloadRun("virsh", "list", "--all")
	if err != nil {
		return firstLine(v), nil, err
	}
	return firstLine(v), parseVirshList(out), nil
}

// parseVirshList reads the table of "virsh list --all" (Id Name State);
// the state may have two words ("shut off").
func parseVirshList(out string) []api.Workload {
	items := []api.Workload{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "Id" || strings.HasPrefix(f[0], "--") || !api.ValidWorkloadID("libvirt", f[1]) {
			continue
		}
		items = append(items, api.Workload{Kind: "libvirt", ID: f[1], Name: f[1], Type: "vm", State: strings.Join(f[2:], " ")})
	}
	return items
}

// ---- actions ----

// workloadArgv is the command line of an action, built from validated
// values only and run without a shell. Stop and restart shut down
// gracefully with a timeout and never kill a VM.
func workloadArgv(w api.WorkloadAction) []string {
	switch w.Kind {
	case "docker", "podman":
		if w.Action == "start" {
			return []string{w.Kind, "start", w.ID}
		}
		return []string{w.Kind, w.Action, "--time", "60", w.ID}
	case "pct", "qm":
		switch w.Action {
		case "start":
			return []string{w.Kind, "start", w.ID}
		case "stop":
			return []string{w.Kind, "shutdown", w.ID, "--timeout", "180"}
		}
		return []string{w.Kind, "reboot", w.ID, "--timeout", "180"}
	case "lxd", "incus":
		if w.Action == "start" {
			return []string{workloadCmd(w.Kind), "start", w.ID}
		}
		return []string{workloadCmd(w.Kind), w.Action, w.ID, "--timeout", "120"}
	case "lxc":
		switch w.Action {
		case "start":
			return []string{"lxc-start", "--name", w.ID}
		case "stop":
			return []string{"lxc-stop", "--name", w.ID, "--nokill", "--timeout", "120"}
		}
		return []string{"lxc-stop", "--name", w.ID, "--reboot"}
	case "libvirt":
		verb := map[string]string{"start": "start", "stop": "shutdown", "restart": "reboot"}[w.Action]
		return []string{"virsh", verb, w.ID}
	}
	return nil
}

// workloadAction runs a workload_action command: only when the policy
// allows it, with a pinned command key, and only for a workload the device
// has right now (checked against a fresh inventory of that kind).
func (a *Agent) workloadAction(c api.Command) (string, error) {
	if !a.pol.WorkloadControl {
		return "", errors.New("workload control is not allowed by the device's policy (Agent: workload control)")
	}
	if a.state.CommandKey == "" {
		return "", errors.New("workload actions need a pinned command signing key")
	}
	var w api.WorkloadAction
	dec := json.NewDecoder(strings.NewReader(c.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return "", fmt.Errorf("workload action: %w", err)
	}
	if err := w.Validate(); err != nil {
		return "", err
	}
	if !workloadPresent(w.Kind) {
		return "", fmt.Errorf("%s is not installed", w.Kind)
	}
	live := &api.Workloads{}
	collectKind(live, w.Kind)
	it, ok := live.Find(w.Kind, w.ID)
	if !ok {
		return "", fmt.Errorf("no %s workload %s on this device", w.Kind, w.ID)
	}
	argv := workloadArgv(w)
	out, err := run(6*time.Minute, argv[0], argv[1:]...)
	a.event("workload %s %s (%s): %s, error=%v", w.Kind, it.Name, w.ID, w.Action, err)
	a.wlAt = time.Time{} // the next check in reports the new state
	res := strings.TrimSpace(fmt.Sprintf("%s %s %s\n%s", w.Action, w.Kind, it.Name, out))
	if err == nil {
		res += "\n" + settleWorkload(w)
	}
	return res, err
}

// workloadSettle bounds the wait for a workload to reach the state of its
// action, polled every workloadSettleStep; variables for tests.
var workloadSettle, workloadSettleStep = 30 * time.Second, 2 * time.Second

// settleWorkload waits until the workload is in the state its action
// leads to (running after start and restart, stopped after stop) and
// returns the state line of the command result. The next check in, which
// follows at once, then reports the inventory with that state.
func settleWorkload(w api.WorkloadAction) string {
	end := time.Now().Add(workloadSettle)
	for {
		live := &api.Workloads{}
		collectKind(live, w.Kind)
		it, ok := live.Find(w.Kind, w.ID)
		if !ok {
			return "state: gone"
		}
		state := it.State
		if settled(w.Action, state) {
			return "state: " + state
		}
		if time.Now().Add(workloadSettleStep).After(end) {
			want := "running"
			if w.Action == "stop" {
				want = "stopped"
			}
			return fmt.Sprintf("state: %s (not yet %s after %s)", state, want, workloadSettle)
		}
		time.Sleep(workloadSettleStep)
	}
}

// settled reports whether state is the end state of action: docker and
// podman say exited, Proxmox, LXC and Incus stopped, libvirt shut off.
func settled(action, state string) bool {
	if action == "stop" {
		return slices.Contains([]string{"exited", "stopped", "shut off", "created", "dead"}, state)
	}
	return state == "running"
}
