# Proxmox VE

Proxmox VE 8 (Debian 12) and 9 (Debian 13) nodes run the normal Debian agent. Their
`/etc/os-release` says Debian, so the agent recognises a node by `/etc/pve` (the cluster file
system) or the `pveversion` command and then follows the rules below. They keep a node and
its cluster intact; nothing has to be configured for them.

## Inventory

* `os_id` stays `debian` (CVE matching, minimum versions), `os_product` is
  `Proxmox VE 8.4` (from `pveversion`).
* `proxmox` holds the pve-manager version, the node name (`/etc/pve/local`) and the corosync
  cluster name (`cluster_name` in `/etc/pve/corosync.conf`, empty on a standalone node).
* The console shows the product in the device header and node and cluster as a fact.
* Blueprint rules can test the product: field **Product** (`os.product`), for example
  `contains proxmox`.
* VMs (`qm`) and containers (`pct`) appear in the workloads tab ([workloads.md](workloads.md)).

## Updates

* A full upgrade is `apt-get dist-upgrade` on a node, never `apt-get upgrade`, which holds
  back or half installs new Proxmox packages. The pending update list is simulated the same
  way. Packages of the Proxmox repositories count as distribution updates.
* Every apt transaction of the agent (install, remove, upgrade, selected upgrades,
  autoremove) is simulated first (`apt-get -s`) and refused when it would remove
  `proxmox-ve` or `pve-manager`. The update run then fails with that reason and changes
  nothing.
* Security only updates use unattended-upgrades as on Debian; it never installs Proxmox
  packages (they are not in the Debian security archive). The agent runs
  `unattended-upgrade` with the host's own configuration and writes none; the `apt-get -s`
  guard does not cover it. unattended-upgrades itself skips any upgrade that would remove a
  package, and its `Remove-Unused-Dependencies` only removes automatically installed
  packages, never the manually installed `proxmox-ve`. Keep it that way: do not list
  Proxmox repositories in `Unattended-Upgrade::Origins-Pattern`, or add `proxmox-ve` and
  `pve-manager` to `Unattended-Upgrade::Package-Blacklist` if you do.
* Without a subscription the enterprise repository answers `apt update` with HTTP 401. When
  that repository is the only one failing, the other lists stay in use, the pending updates
  are listed and the updates tab shows a warning (`pending_warning`). Disable the
  enterprise repository or switch to the no subscription repository to clear it.

## Protected packages

Software removal from the console refuses `proxmox-ve`, `pve-manager`, `pve-cluster`,
`pve-qemu-kvm`, `lxc-pve`, `zfsutils-linux`, `corosync` and the kernels
(`proxmox-kernel-*`, `pve-kernel-*`; headers stay removable).

## Host name

Renaming a node breaks `/etc/pve/nodes/<name>` and the cluster. `com.limdm.hostname`
refuses a change on a node with a failed result that says why, and never writes
`/etc/hosts` there (pve-cluster resolves the node through its line). Rename a node by hand
as the Proxmox documentation describes.

## Firewall

pve-firewall (iptables) or proxmox-firewall (nftables) owns the host firewall. LiMDM does
not enforce a firewall declaration on a node at all: `applyFirewall` and the rule sync
refuse with a clear message, so ufw or firewalld never starts next to it and nothing can
cut corosync (5405 to 5412/udp), the web interface (8006), the SPICE proxy (3128), SSH or
migrations (60000 to 60050). This is the simpler and safer choice compared with filtering
single declarations. Manage the firewall in the Proxmox web interface (Datacenter, Node and
VM firewall).

* The check `firewall.active` passes when `pve-firewall status` reports `enabled/running`.
* In the firewall inventory the `PVEFW-*` chains, the `proxmox-firewall` tables and the
  guest interfaces (`tap100i0`, `fwbr100i0`, `fwln100i0`, `fwpr100p0`) are system rules:
  shown, never adopted or removed.

## Reboots

A reboot stops every guest that is not migrated first. The agent never reboots a node
after updates, whatever the update declaration says; the check `updates.reboot` reports a
pending reboot as everywhere. The reboot and shutdown dialogs of the console show how many
VMs and containers are running on the node.

## Compliance checks

| Check | On a node |
|---|---|
| `net.forwarding` | not applicable: guests in routed, NAT and SDN networks need IP forwarding; the sysctl drop-in leaves it out |
| `ssh.baseline` | `PermitRootLogin prohibit-password` (or `no`) complies, the fix writes `prohibit-password`: the cluster nodes log in to each other as root with keys |
| `ssh.strict` | `AllowTcpForwarding` is not checked or set: migrations tunnel through SSH |
| `firewall.active` | pve-firewall status (see above); the fix is refused |

No check touches the kernel modules a node needs (kvm, vhost, bridge), the bridge netfilter
settings or rpcbind, so nothing else changes on a node.

## CVE data

Nodes are matched against the Debian Security Tracker of their release like Debian.
Packages named `pve-*` or `proxmox-*`, or built from such a source package, are never
matched: they are not Debian's, and the Proxmox kernel must not pick up the findings of
Debian's `linux` source. Proxmox rebuilds of Debian sources (for example `zfs-linux` or
`corosync` with a `pveN` revision) are compared with Debian's fixed version; a `pveN`
revision sorts above the Debian revision of the same upstream version. A Debian kernel
still installed on a node (`linux-image-*`) is matched, because its files are on disk.
