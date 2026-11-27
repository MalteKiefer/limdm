# Containers and VMs

The device page has a tab **Containers and VMs**. It lists the containers and virtual machines
of a device with the versions of the tools that run them, and lets IT start, shut down and
restart one of them when the device's policy allows it.

## Inventory

With every status report the agent reads the installed tools. The inventory is read only:
every command lists, inspects or prints a version or configuration (a test pins the allowed
commands), each with a timeout of 20 seconds, and at most 200 workloads per kind are reported.
Only fields that do not change by themselves are sent (no uptime texts, no counters), so the
status hash stays stable and an unchanged inventory is not sent again.

| Kind | Tool | Read with | Reported |
|---|---|---|---|
| `docker` | Docker | `docker version`, `docker ps --all --quiet --no-trunc`, `docker container inspect` | engine version, ID, name, image and image ID, state, created and started, restart policy, ports, compose project and service |
| `podman` | Podman | the same commands with `podman` | as Docker (also `io.podman.compose.*` labels) |
| `pct` | Proxmox containers | `pveversion`, `pct list`, `pct config` | Proxmox VE version, VMID, name, status, OS type, cores, memory, start at boot |
| `qm` | Proxmox VMs | `pveversion`, `qm list`, `qm config` | VMID, name, status, CPUs (cores times sockets), memory, start at boot |
| `incus` | Incus | `incus version`, `incus list --format json` | server version, name, container or VM, status, image OS and release, autostart |
| `lxd` | LXD | `lxc version`, `lxc list --format json` | as Incus |
| `lxc` | plain LXC | `lxc-ls --version`, `lxc-ls --fancy` | version, name, state, autostart (skipped on Proxmox, where `pct` lists the same containers) |
| `libvirt` | libvirt | `virsh --version`, `virsh list --all` | version, name, state |

`pct config` and `qm config` are cached for an hour per guest. Docker, LXD, Incus and libvirt are
only read when their socket exists: on Ubuntu a first `lxc` call can install the LXD snap
(`lxd-installer`), which an inventory must never do. A tool that cannot be read shows its error
on the tab; the others are still listed.

The server keeps the latest inventory per device (`device_workloads`, one JSONB row with a
hash). `GET /api/v1/devices/{id}/workloads` serves it with the device page's rules,
`GET /api/v1/workloads` lists the workloads of the fleet in the caller's scope, filtered by
`kind`, `state` and `image` ([admin-api.md](admin-api.md)).

## Start, shut down, restart

Actions are off by default and need all of the following:

1. **Policy:** `"workload_control": true` in `com.limdm.agent` (console: blueprint, **Agent**,
   **Workload control**). Without it the server answers `409` with the reason, the console
   shows the buttons disabled with the same hint, and the agent refuses the command as well.
2. **Role:** admins. The helpdesk role only when **Settings, Approvals, Helpdesk may start,
   shut down and restart containers and VMs** is on.
3. **Four eyes:** with four eyes approval on and **Also for shutting down and restarting
   containers and VMs**, stop and restart wait for a second admin in the inbox. Start never does.

The console sends the signed command `workload_action` with `kind`, `id` and `action`
(`start`, `stop`, `restart`), one device at a time (bulk sends are refused). The server checks
the ID against the kind (Proxmox: a number, Docker and Podman: the full hexadecimal ID, others:
letters, digits, dot, dash and underscore, never starting with a dash) and requires an exact
match in the device's last inventory. The agent checks the policy again, needs a pinned command
key, reads the live inventory of that kind and runs the action only for a workload that exists
right now. Commands run with an argument list, never through a shell:

| Kind | Start | Stop | Restart |
|---|---|---|---|
| Docker, Podman | `docker start ID` | `docker stop --time 60 ID` | `docker restart --time 60 ID` |
| Proxmox | `pct start` / `qm start` | `pct shutdown` / `qm shutdown` with `--timeout 180` | `pct reboot` / `qm reboot` with `--timeout 180` |
| LXD, Incus | `incus start NAME` | `incus stop NAME --timeout 120` | `incus restart NAME --timeout 120` |
| LXC | `lxc-start --name NAME` | `lxc-stop --name NAME --nokill --timeout 120` | `lxc-stop --name NAME --reboot` |
| libvirt | `virsh start NAME` | `virsh shutdown NAME` | `virsh reboot NAME` |

Stop always shuts down gracefully. A VM is never killed; Docker and Podman stop the container
with SIGKILL only after the 60 second grace period, as `docker stop` does. Every command is
audited (`command.workload_action`) and its result appears in the device's activity.

Nothing acts on its own: the agent never starts, stops or restarts a workload without an
explicit command from the console, so a host that runs important containers (for example a
document archive) keeps running exactly as it is while it is inventoried.
