package api

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Containers and virtual machines on a device (workloads): the agent reports
// them read only with the status, the console starts, stops and restarts
// one with the workload_action command when the device's policy allows it
// (com.limdm.agent workload_control).

// WorkloadKinds are the tools the agent reads: Docker, Podman, plain LXC
// (lxc-ls), LXD, Incus, Proxmox containers (pct) and VMs (qm), and libvirt.
var WorkloadKinds = []string{"docker", "podman", "lxc", "lxd", "incus", "pct", "qm", "libvirt"}

// WorkloadActions are the actions of workload_action. Stop and restart are
// graceful (shutdown with a timeout), never a kill of a VM.
var WorkloadActions = []string{"start", "stop", "restart"}

// MaxWorkloads bounds the workloads reported per kind.
const MaxWorkloads = 200

// Workloads is the workload inventory of a device.
type Workloads struct {
	Tools     []WorkloadTool `json:"tools"`
	Items     []Workload     `json:"items"`
	Errors    []string       `json:"errors,omitempty"`    // a tool that could not be read
	Truncated bool           `json:"truncated,omitempty"` // a kind had more than MaxWorkloads
}

// WorkloadTool is an installed tool and its version.
type WorkloadTool struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// Workload is one container or virtual machine. Only fields that do not
// change by themselves are reported, so the status hash stays stable.
type Workload struct {
	Kind     string    `json:"kind"`
	ID       string    `json:"id"` // container ID, VMID or name: what the tool's commands take
	Name     string    `json:"name"`
	Type     string    `json:"type,omitempty"`     // container or vm where the tool runs both (LXD, Incus)
	Image    string    `json:"image,omitempty"`    // image reference or OS template
	ImageID  string    `json:"image_id,omitempty"` // image digest or ID
	State    string    `json:"state"`              // the tool's state, lower case: running, exited, stopped, paused ...
	Created  time.Time `json:"created,omitzero"`
	Started  time.Time `json:"started,omitzero"`
	Restart  string    `json:"restart,omitempty"` // restart policy or autostart
	Ports    []string  `json:"ports,omitempty"`
	Project  string    `json:"project,omitempty"` // compose project
	Service  string    `json:"service,omitempty"` // compose service
	CPUs     int       `json:"cpus,omitempty"`
	MemoryMB int       `json:"memory_mb,omitempty"`
}

// WorkloadAction is the payload of the workload_action command.
type WorkloadAction struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Action string `json:"action"`
}

var (
	workloadNumID   = regexp.MustCompile(`^[0-9]{1,9}$`)
	workloadHexID   = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	workloadNameID  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	errWorkloadKind = errors.New("unknown workload kind")
)

// ValidWorkloadID reports whether id is a well formed ID of the kind. IDs
// never start with a dash, so they cannot be read as an option.
func ValidWorkloadID(kind, id string) bool {
	switch kind {
	case "pct", "qm":
		return workloadNumID.MatchString(id)
	case "docker", "podman":
		return workloadHexID.MatchString(id)
	}
	return workloadNameID.MatchString(id)
}

// Validate checks the command payload.
func (w WorkloadAction) Validate() error {
	if !slices.Contains(WorkloadKinds, w.Kind) {
		return errWorkloadKind
	}
	if !slices.Contains(WorkloadActions, w.Action) {
		return errors.New("action must be start, stop or restart")
	}
	if !ValidWorkloadID(w.Kind, w.ID) {
		return fmt.Errorf("invalid %s workload id", w.Kind)
	}
	return nil
}

// Find returns the workload of kind and id, matched exactly.
func (w *Workloads) Find(kind, id string) (Workload, bool) {
	if w == nil {
		return Workload{}, false
	}
	for _, it := range w.Items {
		if it.Kind == kind && it.ID == id {
			return it, true
		}
	}
	return Workload{}, false
}
