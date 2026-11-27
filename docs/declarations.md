# Declaration reference

Every library item has one of these types. The console shows the example payload when you
create an item, and the editor lists every field of the type (**Field reference**) with a
live JSON check. Payloads are validated strictly on the server when the item is saved and
again on the agent before it is applied; unknown fields are rejected. An invalid
declaration is skipped on the device and reported with its reason on the device page.

"List" types are merged across the items of a blueprint ([concepts.md](concepts.md#merging)),
all others take the item evaluated last. The list types are packages, services, files,
firewall, osversion, repositories, certificates, sysctl, kernelmodules, ssh, flatpak,
scripts, dconf, localusers, sudo, polkit, network and customchecks. How each one merges is
named in its section.

Each section names the type as the console's type picker shows it ("Console:").

## Agent and compliance

### `com.limdm.agent`

Console: **Agent**.

```json
{"checkin_seconds": 300, "offline_lock_hours": 72}
```

| Field | Type | Rules |
|---|---|---|
| `checkin_seconds` | number | required, 30 to 86400; how often the agent checks in |
| `offline_lock_hours` | number | 0 or absent: off; at most 8760. Locks the device after this many hours without server contact, see [desktop-login.md](desktop-login.md#offline-lock) |
| `remote_shell` | boolean | devices accept remote shell sessions, see [remote-shell.md](remote-shell.md) |
| `workload_control` | boolean | default off; the console may start, shut down and restart containers and VMs, see [workloads.md](workloads.md) |

The default library item "Agent check in every 5 minutes" sets 300 seconds.

### `com.limdm.compliance`

Console: **Compliance**.

```json
{"level": 1, "remediate": true, "exclude": [], "advisory": ["boot.secureboot"],
 "grace_hours": 72, "notify": true, "lock_after_hours": 0, "unlock_when_compliant": true}
```

| Field | Type | Rules |
|---|---|---|
| `level` | number | 1 (CIS Level 1 baseline) or 2 (Level 2, stricter) |
| `remediate` | true or false | the agent fixes failing checks that have an automatic fix |
| `exclude` | list of text | check IDs excluded by policy; active risk exceptions recorded on the server are added |
| `advisory` | list of text | check IDs that are reported but do not count against compliance |
| `grace_hours` | number | 0 to 2160; time to fix before the device counts as non compliant (server side) |
| `notify` | true or false | call the compliance webhook when the grace period ends |
| `lock_after_hours` | number | 0 (never) to 2160; lock the device after this long non compliant; not shorter than `grace_hours` |
| `unlock_when_compliant` | true or false | unlock automatically once the device is compliant again |

Check IDs use letters, digits, `.`, `_` and `-`. Details: [compliance.md](compliance.md#policy-comlimdmcompliance).

### `com.limdm.customchecks` (list)

Console: **Custom compliance checks**.

```json
{"checks": [{"id": "custom.no_telnet", "title": "Telnet client is not installed", "severity": "medium", "level": 1,
  "refs": {"bsi": ["SYS.2.3.A1"]}, "package": {"name": "telnet", "state": "absent"}}]}
```

Compliance checks defined by IT, counted like built in checks. Merged by `id`; at most 200.

| Field | Type | Rules |
|---|---|---|
| `checks[].id` | text | `custom.` followed by lower case letters, digits, `.`, `_`, `-` (up to 56 characters); unique |
| `checks[].title` | text | one line, up to 200 characters |
| `checks[].severity` | text | `low`, `medium`, `high` or `critical` |
| `checks[].level` | number | 1 or 2 |
| `checks[].refs` | object | optional `cis`, `bsi`, `iso` (lists of one line references) and `cis_benchmark` (text) |
| `checks[].query` | object | `sql` (one read only `SELECT` or `WITH` statement, up to 4096 characters, no comments), `expect` (`rows`, `no_rows` or `compare`); `compare` also needs `column`, `op` and `value` |
| `checks[].file` | object | `path` (absolute), `state` (`present` or `absent`); for present files optional `max_mode` (octal), `owner`, `group`, `contains` and `not_contains` (RE2, matched per line) |
| `checks[].sysctl` | object | `key`, `op`, `value` |
| `checks[].package` | object | `name`, `state` (`installed` or `absent`) |
| `checks[].service` | object | `name`, `state` (`active` or `inactive`), optional `enabled` |

Every check has exactly one test. `op` is `eq`, `ne`, `lt`, `le`, `gt`, `ge` (numbers),
`contains` or `matches` (RE2); `value` is up to 1024 characters. Queries run with `osqueryi`
without extensions and may read only an allowlist of local tables; writing statements and
tables that reach the network or carve files are refused. Details: [compliance.md](compliance.md#custom-checks-comlimdmcustomchecks).

### `com.limdm.privacy`

Console: **Privacy**.

```json
{"network_info": false, "logged_in_users": false}
```

| Field | Type | Rules |
|---|---|---|
| `network_info` | true or false | IP addresses, DNS configuration and routes, the public address and its location |
| `logged_in_users` | true or false | user names of active sessions |

Without this declaration everything is collected; assign it to switch items off. Interfaces
and MAC addresses are always collected. Switching `network_info` off also deletes the stored
values on the server. The location of the public address is looked up only when
**Settings**, **Security**, **Privacy**, "Look up the location of device public addresses" is
on (off by default). The default library item "Privacy: no network or session data" switches
both off.

## Software

### `com.limdm.updates`

Console: **Software updates**.

```json
{"mode": "security", "window": "02:00-05:00", "reboot": false}
```

With all patch management fields:

```json
{"mode": "security", "window": "22:00-04:00", "reboot": true, "days": ["sat", "sun"], "hold": ["nginx"],
 "autoremove": true, "snap_refresh": "window",
 "reboot_notice_minutes": 10, "reboot_max_defers": 2, "reboot_defer_minutes": 60}
```

| Field | Type | Rules |
|---|---|---|
| `mode` | text | `off`, `security` or `all` |
| `window` | text | local time `HH:MM-HH:MM`; required unless `mode` is `off` (and then still required with `snap_refresh` `window`) |
| `reboot` | true or false | restart inside the window when an update requires it |
| `days` | list of text | `mon` … `sun`, each once; empty means every day |
| `hold` | list of text | up to 200 package names kept at their installed version |
| `autoremove` | true or false | remove packages nothing needs any more after each update run |
| `snap_refresh` | text | empty (snapd untouched), `hold` or `window` |
| `reboot_notice_minutes` | number | 0 to 120; 0 or absent means 5 |
| `reboot_max_defers` | number | 0 to 5, default 0 |
| `reboot_defer_minutes` | number | 15 to 480; 0 or absent means 60 |
| `rules` | list | rules per source; when present they replace `mode` (which may then be `off` or empty); see below |
| `rules[].source` | text | `os_security`, `os_all`, `third_party` or `flatpak`, each once |
| `rules[].mode` | text | `off`, `notify` (report only) or `install` |
| `rules[].window`, `rules[].days` | text, list | as `window` and `days`; an empty window takes the declaration's window and days |
| `rules[].rings` | true or false | install once per wave of the device's update ring |
| `rules[].repos` | list of text | `third_party` only: up to 50 apt origins, dnf repo IDs or zypper aliases (glob); empty is every third party repository |
| `security_max_days` | number | 0 to 365; the check `updates.security_age` fails after this many days of pending security updates, 14 when 0 |

What runs per distribution family:

| Family | `security` | `all` |
|---|---|---|
| Debian, Ubuntu | `unattended-upgrade` (installed when missing) | `apt-get upgrade --with-new-pkgs`, then Flatpak updates |
| Fedora, RHEL family | `dnf upgrade --refresh --security` | `dnf upgrade --refresh`, then Flatpak updates |
| openSUSE Leap, SLES, SLED | `zypper patch --category security` | `zypper update` |
| openSUSE Tumbleweed | `zypper dup` (no separate security channel) | `zypper dup` |
| Arch | `pacman -Syu` plus Flatpak updates (always everything) | same |
| Alpine | `apk upgrade` plus Flatpak updates (always everything) | same |

* `days`: a window across midnight belongs to the day it starts on. Pending security updates
  count as handled until the next window (up to 8 days with `days`, 48 hours without).
* `hold` also applies when `mode` is `off`. Debian family: `apt-mark hold` (installed
  packages only); Fedora family: `excludepkgs` in a libdnf5 drop in and in `/etc/dnf/dnf.conf`
  (dnf4), so dnf neither upgrades nor installs them; Arch: `IgnorePkg` in `/etc/pacman.conf`.
  Alpine refuses `hold` (pin versions in `/etc/apk/world`); SUSE ignores it. Packages removed
  from the list are released again; values changed by hand in `dnf.conf` or `pacman.conf` are
  left alone.
* `autoremove`: `apt-get autoremove --purge` (old kernels included), `dnf autoremove`, pacman
  orphans (`pacman -Qdtq`). No effect on SUSE and Alpine.
* `snap_refresh` (only where snapd is installed): `hold` stops automatic snap refreshes,
  `window` sets `refresh.timer` to the update window and days. Removing it restores the snapd
  default.
* Restart notice and deferral (with `reboot`): the restart is scheduled with `shutdown -r`
  `reboot_notice_minutes` ahead and announced in every desktop session. With
  `reboot_max_defers` the desktop helper offers to postpone it by `reboot_defer_minutes` that
  many times; it asks again shortly before each new time. After the last deferral the restart
  happens. Every deferral is reported as a device event with the user name.

With rules per source and update rings:

```json
{"window": "02:00-05:00", "reboot": true, "security_max_days": 7, "rules": [
  {"source": "os_security", "mode": "install"},
  {"source": "os_all", "mode": "install", "rings": true},
  {"source": "third_party", "mode": "install", "rings": true, "repos": ["Docker*", "google-chrome"]},
  {"source": "flatpak", "mode": "notify"}]}
```

What the sources cover per distribution, how they run, the update rings and the reported
results are in [Patch management](patching.md). Flatpak is its own source now: `all` without
rules still updates Flatpak, `security` never did.

The default library item "Security updates at night" sets `security`, `02:00-05:00`, no
reboot.

### `com.limdm.packages` (list)

Console: **Packages**.

```json
{"install": ["htop"], "remove": ["telnet"]}
```

| Field | Type | Rules |
|---|---|---|
| `install` | list of text | package names (letters, digits, `+ . _ : -`, up to 128 characters) |
| `remove` | list of text | same |

Merged as a union; a package in any `remove` list is dropped from `install`. The agent
installs what is missing and removes what is present with the native package manager (apt,
dnf, zypper, pacman, apk) every cycle.

### `com.limdm.flatpak` (list)

Console: **Flatpak apps**.

```json
{"remotes": [{"name": "flathub", "url": "https://dl.flathub.org/repo/flathub.flatpakrepo"}],
 "install": ["org.mozilla.firefox"], "remove": []}
```

| Field | Type | Rules |
|---|---|---|
| `remotes[].name` | text | lower case letters, digits, `.`, `_`, `-` |
| `remotes[].url` | text | https: a `.flatpakrepo` file or repository URL |
| `remotes[].scope` | text | `system` (default) or `user` |
| `remotes[].disabled` | true or false | keep the remote but switch it off |
| `install` | list of text | application IDs (at least three dot separated parts) |
| `remove` | list of text | same |

Remotes merge by name and scope (a later item wins), apps as a union; `remove` wins over
`install`. Flatpak is installed when missing. Remotes go to the system installation by
default; `"scope": "user"` adds or changes the remote in the installation of every regular
user (uid 1000 and above with a home). A repository URL that differs from the configured one
is changed with `flatpak remote-modify`. Applications are installed system wide.

The device page lists Flatpak applications and remotes of the system and of every user
(**Software**, **Flatpak**). **Edit**, **Disable** and **Enable** open a prefilled library
item; **Add remote** starts an empty one. Remotes managed under **Software**, **Remotes** are
a separate mechanism ([software.md](software.md#flatpak-remotes)).

### `com.limdm.repositories` (list)

Console: **Package sources**. Package sources managed by LiMDM, and unmanaged sources to
switch off.

```json
{"repositories": [
  {"name": "vendor", "family": "debian", "url": "https://repo.example.com/apt",
   "suites": "stable", "components": "main", "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."},
  {"name": "debian", "family": "debian", "url": "https://deb.debian.org/debian",
   "suites": "trixie trixie-updates", "components": "main",
   "key_file": "/usr/share/keyrings/debian-archive-keyring.gpg"}],
 "disable": ["netbird.list"]}
```

| Field | Type | Rules |
|---|---|---|
| `repositories[].name` | text | lower case letters, digits, `.`, `_`, `-`; `osquery` and names starting with `app-` are reserved |
| `repositories[].family` | text | `debian`, `fedora` or `suse` |
| `repositories[].url` | text | https, without credentials |
| `repositories[].suites` | text | apt suites, required for `debian` |
| `repositories[].components` | text | apt components |
| `repositories[].key` | text | ASCII armored signing key, up to 64 KiB |
| `repositories[].key_file` | text | a keyring already on the device below `/usr/share/keyrings`, `/etc/apt/keyrings`, `/etc/pki/rpm-gpg` or `/usr/lib/rpm/gnupg/keys` |
| `repositories[].signed_metadata` | true or false | rpm only: the repository signs its metadata instead of each package (`repo_gpgcheck=1`, `gpgcheck=0`) |
| `disable` | list of text | file names of unmanaged sources to switch off |

Merged by name; `disable` lists are joined. Every source is signed: exactly one of `key`
and `key_file` is required. Each device only uses entries of its own family; Arch and Alpine
use none.

| Family | Source file | Key |
|---|---|---|
| `debian` | `/etc/apt/sources.list.d/limdm-<name>.sources` (deb822) | `/etc/apt/keyrings/limdm-<name>.asc` |
| `fedora` | `/etc/yum.repos.d/limdm-<name>.repo` | `/etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-<name>` |
| `suse` | `/etc/zypp/repos.d/limdm-<name>.repo` (autorefresh) | as for `fedora`, also imported with `rpm --import` |

Files with the `limdm-` prefix that are no longer declared are removed; the agent's own
osquery source and the catalog apps' sources (`limdm-app-*`) are left alone.

`disable` takes `*.list`, `*.sources`, `*.repo` or `sources.list`, not files starting with
`limdm-`. The agent keeps the original in `/var/lib/limdm/repo-backup`, switches the whole
file off (`Enabled: no`, `enabled=0` or commented lines) and restores it once the name is no
longer listed.

On the device page, **Edit** and **Disable** next to a reported source open a prefilled
item: Edit copies all entries of that file into managed sources (http becomes https, check
the URL) and disables the original. Assign the item to a blueprint to apply it.

### `com.limdm.artifacts` (list)

Console: **Uploaded packages**. Installs packages, scripts and files an admin uploaded under
**Software**, **Packages** ([packages.md](packages.md)). The payload names each upload by its
SHA-256; the library item is signed with the command key, so the hash the agent checks comes
from signed data.

```json
{"artifacts": [
  {"sha256": "3f5a...", "name": "vendor-vpn", "kind": "deb", "size": 1048576},
  {"sha256": "9c1e...", "name": "vendor-vpn", "kind": "rpm", "size": 1101004},
  {"sha256": "aa07...", "name": "license", "kind": "file", "size": 812, "path": "/etc/opt/vendor/license.key", "mode": "0600"}]}
```

| Field | Type | Rules |
|---|---|---|
| `artifacts[].sha256` | text | 64 lower case hex characters of an approved upload of the item's tenant |
| `artifacts[].name` | text | letters, digits, `.`, `_`, `+`, `-` |
| `artifacts[].kind` | text | `deb`, `rpm`, `apk`, `pacman`, `flatpak`, `script` or `file`, as uploaded |
| `artifacts[].size` | number | bytes, as uploaded |
| `artifacts[].path` | text | `file` only: absolute, outside user writable and virtual directories |
| `artifacts[].mode` | text | `file` only: octal, default `0644`, no setuid, setgid or sticky bit |

Merged by hash and path (a later item wins). Each upload installs once per device: packages
with the native package manager (dependencies from the configured sources), only on the
matching family (`deb` on Debian and Ubuntu, `rpm` on Fedora, RHEL and SUSE, `apk` on Alpine,
`pacman` on Arch), so one item can carry the package for every family. Flatpak bundles go to
the system installation, scripts run once with `/bin/sh`, files are written as root. Removing
an upload from the item does not uninstall it.

Every kind acts as root, so devices install uploads only when they were enrolled with
`allow_scripts`; other devices report the item as failed.

## System

### `com.limdm.services` (list)

Console: **Services**.

```json
{"enable": [], "disable": ["cups"]}
```

| Field | Type | Rules |
|---|---|---|
| `enable` | list of text | systemd unit names (letters, digits, `@ . _ : -`) |
| `disable` | list of text | same |

Merged as a union; a unit in any `disable` list is dropped from `enable`. The agent runs
`systemctl enable --now` for listed units that are not active and `systemctl disable --now`
for active units in `disable`. Units are not masked.

### `com.limdm.files` (list)

Console: **Files**.

```json
{"files": [{"path": "/etc/motd", "content": "...", "mode": "0644", "owner": "root", "group": "root"}]}
```

| Field | Type | Rules |
|---|---|---|
| `files[].path` | text | absolute and clean, not `/`, not below `/home`, `/tmp`, `/var/tmp`, `/run/user`, `/dev/shm`, `/var/mail` or `/var/spool` |
| `files[].content` | text | the whole file |
| `files[].mode` | text | octal `0000` to `0777`, default `0644`; no setuid, setgid or sticky bits |
| `files[].owner` | text | user name, default root |
| `files[].group` | text | group name, default root |
| `files[].template` | true or false | render `content` per device (see [Templates](#templates)) |

Merged by path, a later item wins. Owner and group must exist on the device. Files removed
from the declaration are deleted from the device: the agent remembers the paths it wrote
(since 0.16) with the SHA-256 sum of their content and removes the undeclared ones, except
while a files declaration is invalid. It removes a file only when it is still a regular file
reached without symlinks and its content still matches the sum; a file someone changed, a
link, or a file written by an agent before the sums existed is left in place and reported as
kept.

On devices enrolled without `allow_scripts` (the opt in remote scripts need) only plain text
locations are accepted: `/etc/motd`, `/etc/issue`, `/etc/issue.net`, and files below
`/etc/motd.d`, `/srv`, `/etc/opt` and `/var/opt`. Everything else is refused, because almost
every other system path is read as code by something running as root (cron, systemd, sudo,
PAM, shell profiles, the dynamic linker, D-Bus, package manager hooks …). There the agent
also refuses files with an execute bit. With `allow_scripts` any allowed absolute path works.

On every device, with or without `allow_scripts`, a path with a symlink in any component,
the file itself included, is refused, so a local user who owns a parent directory cannot
redirect the write, owner change or removal (declare the real path, for example
`/usr/bin/x` instead of `/bin/x` on merged `/usr` systems). The agent opens each directory
from `/` with `O_NOFOLLOW`, writes a temporary file in the opened directory, sets mode and
owner on the open file and renames it in place, so swapping a directory for a link between
check and write has no effect.

#### Templates

With `template` set, the server renders `content` (files) or every rule text (firewall) for
each device with Go `text/template` before it sends the declaration, so the agent only ever
gets the result and the declarations token changes when a value changes. The values are:

| Value | Content |
|---|---|
| `{{.Hostname}}` | host name the device reported |
| `{{.ID}}` | device ID |
| `{{.Tags}}` | tags (list) |
| `{{.Tenant}}` | tenant name |
| `{{.PrimaryUser}}` | mail address of the primary user, empty without one |
| `{{.Attributes.name}}` | custom device attribute, set in the console under **Edit** on the device page or with `PATCH /api/v1/devices/{id}` (`attributes`) |

Functions: `lower`, `upper`, `trim`, `replace s old new`, `join list sep`,
`hasTag .Tags "x"`, `default "fallback" value`, plus the built in `if`, `with`, `range`,
`eq`, `index`, `len`, `and`, `or`, `not`. A missing attribute is an error; for an optional
one write `{{default "none" (index .Attributes "site")}}`. Nothing outside these values is
reachable: no files, commands or environment. `define`, `block` and `template` are refused
(recursion), `range` only works over `.Tags` or `.Attributes`, `printf` and `call` are not
available, and the output is limited to 1 MiB. The syntax is checked when the item is saved;
the editor shows a preview for one device (`POST /api/v1/config/library/render`).

When a template does not render for a device (a missing attribute, a firewall rule that is
not valid afterwards), that file or the whole firewall declaration goes out still marked as
template and the agent leaves the device as it is and reports the problem. A template file is
never written with its raw template text.

### `com.limdm.certificates` (list)

Console: **CA certificates**.

```json
{"certificates": [{"name": "corp-root", "pem": "-----BEGIN CERTIFICATE-----..."}]}
```

| Field | Type | Rules |
|---|---|---|
| `certificates[].name` | text | lower case letters, digits, `.`, `_`, `-`; referenced by `eap.ca_cert` of network profiles |
| `certificates[].pem` | text | one PEM certificate with the CA flag |

Merged by name. CA certificates only, added to the system trust store as `limdm-<name>` and
removed when no longer declared:

| Family | Directory | Update command |
|---|---|---|
| Debian, Ubuntu, Alpine | `/usr/local/share/ca-certificates` (`.crt`) | `update-ca-certificates` |
| Fedora, RHEL family | `/etc/pki/ca-trust/source/anchors` (`.pem`) | `update-ca-trust` |
| SUSE | `/etc/pki/trust/anchors` (`.pem`) | `update-ca-certificates` |
| Arch | `/etc/ca-certificates/trust-source/anchors` (`.crt`) | `update-ca-trust` |

In the library editor, **Add certificate file** takes a PEM or CRT file (also a bundle) and
appends its certificates to the list. The device page (**Declarations**) and the desktop app
(**Certificates**) show subject, issuer, validity and SHA-256 fingerprint of what is
installed.

### `com.limdm.sysctl` (list), `com.limdm.kernelmodules` (list)

Console: **Kernel parameters** and **Blocked kernel modules**.

```json
{"settings": {"vm.swappiness": "10"}}
{"block": ["firewire_core", "thunderbolt"]}
```

| Field | Type | Rules |
|---|---|---|
| `settings` (sysctl) | object of text | key as `a.b` (at least two parts), value up to 200 characters of letters, digits, space and `. _ : / -` |
| `block` (kernelmodules) | list of text | module names, `a-z 0-9 _ -`, up to 64 characters |

Sysctl settings merge by key (a later item wins), modules as a union. Settings go to
`/etc/sysctl.d/70-limdm-custom.conf` and are loaded with `sysctl -p`. Keys that make the
kernel run a program as root are refused: `kernel.modprobe`, `kernel.core_pattern`,
`kernel.poweroff_cmd`, `kernel.hotplug`, `kernel.usermodehelper.*` and `fs.binfmt_misc.*`.
Blocked modules get `install <module> /bin/false` and `blacklist <module>` in
`/etc/modprobe.d/70-limdm-custom.conf`. Both files are removed when nothing is declared.

### `com.limdm.dns`, `com.limdm.ntp`, `com.limdm.proxy`

Console: **DNS**, **Time servers** and **Proxy**.

```json
{"servers": ["10.0.0.53"], "domains": ["corp.example.com"], "dnssec": true}
{"servers": ["ntp1.example.com", "ntp2.example.com"]}
{"http": "http://proxy.example.com:3128", "https": "http://proxy.example.com:3128", "no_proxy": "localhost,127.0.0.1,.example.com"}
```

| Field | Type | Rules |
|---|---|---|
| `servers` (dns) | list of text | IP addresses |
| `domains` (dns) | list of text | search domains |
| `dnssec` (dns) | true or false | `DNSSEC=yes`; otherwise `allow-downgrade` |
| `servers` (ntp) | list of text | at least one host name or IP address |
| `http`, `https` (proxy) | text | `http://` or `https://` with host and optional port and path; no user or password, because the values land in world readable files |
| `no_proxy` (proxy) | text | comma separated hosts, domains or networks |

DNS uses systemd-resolved (`/etc/systemd/resolved.conf.d/60-limdm.conf`); a device without an
active systemd-resolved reports the declaration as failed. NTP uses systemd-timesyncd
(`/etc/systemd/timesyncd.conf.d/60-limdm.conf`) or chrony
(`/etc/chrony/sources.d/limdm.sources`).

Proxy values are written to `/etc/profile.d`, `/etc/environment.d`, apt
(`/etc/apt/apt.conf.d/60limdm-proxy`), dnf5 (`/etc/dnf/libdnf5.conf.d`), dnf4 (`proxy=` in
`/etc/dnf/dnf.conf`, RHEL 9 family) and, on SUSE, `PROXY_ENABLED`, `HTTP_PROXY`,
`HTTPS_PROXY` and `NO_PROXY` in `/etc/sysconfig/proxy` (read by zypper and YaST; the other
lines of the file stay). They also reach the agent itself: a systemd drop in for
`limdm-agent.service` (followed by `systemctl daemon-reload`) sets them for the next start,
and the running agent applies them at once to its own connections and to every tool it runs
(pacman, apk, flatpak, dnf, apt, zypper). Removing the declaration removes all of this and
puts back the values `/etc/sysconfig/proxy` had before; a `proxy=` in `dnf.conf` or a
sysconfig key that was changed by hand stays.

### `com.limdm.scripts` (list)

Console: **Recurring scripts**.

```json
{"scripts": [{"name": "cleanup", "interval_hours": 24, "body": "#!/bin/sh\njournalctl --vacuum-time=$KEEP",
              "params": {"KEEP": "30d"}, "timeout_minutes": 10},
             {"name": "report", "schedule": {"times": ["02:00"], "days": ["mon", "thu"], "jitter_minutes": 30},
              "run_on_change": true, "body": "#!/bin/sh\n/usr/local/bin/report"}]}
```

| Field | Type | Rules |
|---|---|---|
| `scripts[].name` | text | lower case letters, digits, `.`, `_`, `-` |
| `scripts[].interval_hours` | number | 1 to 720; absent (0) with a schedule |
| `scripts[].schedule.times` | list of text | local `HH:MM` of the device, 1 to 24, each once |
| `scripts[].schedule.days` | list of text | `mon` … `sun`; empty is every day |
| `scripts[].schedule.jitter_minutes` | number | 0 to 120 |
| `scripts[].run_on_change` | true or false | also run once when body, params or timeout change |
| `scripts[].body` | text | up to 64 KiB |
| `scripts[].params` | object of text | environment variables: up to 50, names of letters, digits and `_`, values up to 4096 characters, 32 KiB in total |
| `scripts[].timeout_minutes` | number | 1 to 240; 0 or absent means 30 |

Merged by name. Recurring root scripts run only on devices enrolled with `allow_scripts`;
elsewhere the declaration is reported as failed. Reserved variable names are refused:
`PATH`, `IFS`, `HOME`, `SHELL`, `ENV`, `BASH_ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `CDPATH`,
`GLOBIGNORE`, `TMPDIR`, interpreter paths (`PYTHONPATH`, `PERL5LIB`, `NODE_OPTIONS` and
similar) and everything starting with `LD_`, `LC_` or `DYLD_`. Each run is reported to the
server with exit code, start, end and the last 16 KiB of stdout and stderr, and shown under
**Script results** on the device page. While the device is offline it keeps the last 50
results.

A script runs either every `interval_hours` (the first time right after it is declared) or
on a `schedule`. A scheduled script runs at most once per slot: at the first agent loop after
the slot time plus the jitter. A slot missed while the device was off or asleep runs once at
the next chance; several missed slots collapse into one run. A new schedule waits for its
next slot. The jitter is a fixed delay per device and script (a hash of both), so a fleet
spreads over the jitter window but each device keeps its own time. `run_on_change` runs the
script once more when its body, params or timeout change, the first declaration included.
Agents before 0.19 reject `schedule` and `run_on_change` as unknown keys and report the
declaration as invalid instead of running the script. The item editor shows the last run per
device (`GET /api/v1/config/scripts/results?name=`).

### `com.limdm.network` (list)

Console: **Network profiles**.

```json
{"profiles": [{"name": "office", "type": "wifi", "ssid": "Corp", "security": "wpa2-enterprise", "eap": {"method": "tls", "ca_cert": "corp-root", "server_domain": "radius.example.com"}}]}
```

WLAN (WPA2 and WPA3, personal and enterprise), wired 802.1X (EAP-TLS, PEAP, TTLS), WireGuard
and OpenVPN profiles as NetworkManager keyfiles; merged by profile name, at most 100. Fields
of a profile: `name`, `type`, `auto_connect`, `ssid`, `hidden`, `security`, `psk`, `eap`
(`method`, `identity`, `anonymous_identity`, `password`, `phase2`, `ca_cert`,
`server_domain`), `wireguard` (`interface`, `addresses`, `dns`, `mtu`, `peers` with
`public_key`, `preshared_key`, `endpoint`, `allowed_ips`, `persistent_keepalive`) and
`openvpn` (`content`). EAP pins a CA of a certificates item (`ca_cert`) and the server domain.
EAP-TLS uses a device certificate the server issues from its network CA. Secrets are masked
in the console, the audit log, the version history, the admin API, the desktop app and
`limdm blueprint`. Every field with its limits, the device side and the CRL for the RADIUS
server: [Network profiles](network.md).

### `com.limdm.printers`

Console: **Printers**.

```json
{"printers": [{"name": "office", "uri": "ipps://printer.example.com/ipp/print", "location": "2nd floor",
  "description": "Office printer", "default": true, "duplex": "two-sided-long-edge", "paper_size": "A4"}],
 "install_cups": false}
```

| Field | Type | Rules |
|---|---|---|
| `printers[].name` | text | lower case letters, digits, `.`, `_`, `-`; unique |
| `printers[].uri` | text | `ipp://`, `ipps://`, `socket://` or `lpd://` with a host, up to 512 characters, no credentials, spaces, quotes or control characters |
| `printers[].ppd` | text | a model as `lpinfo -m` lists it; required for `socket://` and `lpd://` |
| `printers[].package` | text | package that provides the PPD, installed first |
| `printers[].location` | text | one line up to 128 characters, no quotes |
| `printers[].description` | text | name print dialogs show, defaults to `name`; one line up to 128 characters |
| `printers[].default` | true or false | system default printer; at most one |
| `printers[].duplex` | text | `one-sided`, `two-sided-long-edge` or `two-sided-short-edge` |
| `printers[].paper_size` | text | media name such as `A4`, `Letter` or `iso_a4_210x297mm` |
| `install_cups` | true or false | install CUPS where it is missing |

Not a list type: the item evaluated last wins. At most 100 printers. CUPS print queues are set
up with `lpadmin` (separate arguments, no shell).

* The queue is named `limdm-<name>`. Queues with the `limdm-` prefix that are no longer
  declared are deleted, every other queue is left alone. Removing the item deletes all
  managed queues.
* `ipp://` or `ipps://` without `ppd` gives a driverless IPP Everywhere queue
  (`lpadmin -m everywhere`).
* `duplex` sets `sides-default`, `paper_size` sets `media-default`.
* Queues are never shared (`printer-is-shared=false`).
* A queue is only set up again when its entry changes: `-m everywhere` asks the printer for
  its capabilities and fails while it is off, then the agent retries on the next cycle.
* Devices without CUPS are skipped, unless `install_cups` is true: then the agent installs
  the `cups` package and starts the service.

## Security

### `com.limdm.firewall` (list)

Console: **Firewall**.

```json
{"enforce": true, "allow": ["22/tcp"], "rules": [{"port": "5432/tcp", "from": "10.0.0.0/8"}],
 "zones": [{"name": "internal", "interfaces": ["wg0"], "sources": ["10.0.0.0/8"], "allow": ["9100/tcp"]}],
 "outbound": {"policy": "deny", "allow": [{"to": "192.0.2.0/24", "port": "443/tcp"}, {"port": "80/tcp"}]}}
```

| Field | Type | Rules |
|---|---|---|
| `enforce` | true or false | switch the firewall on and deny inbound traffic except the allowed ports |
| `allow` | list of text | `port/proto` or `low:high/proto`, ports 1 to 65535, proto `tcp` or `udp` |
| `rules[].port` | text | as in `allow` |
| `rules[].from` | text | source network (CIDR) or address |
| `zones[].name` | text | lower case, up to 17 characters, each once |
| `zones[].interfaces` | list of text | interface names, for example `wg0` |
| `zones[].sources` | list of text | networks (CIDR) or addresses; a zone needs interfaces or sources |
| `zones[].allow` | list of text | ports as in `allow` |
| `outbound.policy` | text | `allow` or `deny`; without `outbound` outgoing traffic is left alone |
| `outbound.allow[].to` | text | destination network (CIDR) or address, empty is any |
| `outbound.allow[].port` | text | as in `allow`, empty is any; `to` or `port` is required |
| `template` | true or false | render every rule text per device (see [Templates](#templates)) |

Merged as a union; `enforce` is on when any item sets it, zones of the same name are
combined, and outbound `deny` wins over `allow`. `allow` opens ports for everybody, `rules`
opens a port only for a source network or address, `zones` open ports only for traffic that
arrives on the listed interfaces or from the listed sources.

Zones per backend:

* firewalld: the zone of that name (created when missing). Interfaces are moved into it with
  `--change-interface`, sources added with `--add-source`, ports with `--zone=… --add-port`.
* ufw and nftables have no zones; the closest equivalent is one rule per port, interface and
  source: `ufw allow in on wg0 from 10.0.0.0/8 to any port 9100 proto tcp`. The zone name
  only groups the rules.

Outbound `deny` allows only the listed destinations plus what the device needs to stay
managed: DNS (53 udp and tcp), DHCP (67/udp, 547/udp), NTP (123/udp) and the LiMDM server, or
the proxy the agent reaches it through, resolved at each run. Established connections and
loopback always pass. The allow rules go in first, the deny policy last, and when outbound
deny is no longer declared the policy is switched back before the rules go. With ufw it is
`ufw default deny outgoing` plus `ufw allow out …`; with firewalld a policy object
`limdm-egress` (ingress zone HOST, egress zone ANY, target REJECT, firewalld 0.9 or newer)
holding the allow rules as rich rules; on Alpine the output chain of the LiMDM table. If the
server address cannot be resolved, nothing is changed.

* Debian family: ufw (installed when missing). Allow rules are added first, then
  `ufw default deny incoming` and `ufw --force enable`, so an active SSH session is never cut.
  A rule with a source becomes `ufw allow from … to any port … proto …`. A device with an
  active nftables service and no ufw is reported instead of being overwritten.
* Other families: firewalld (installed and enabled when missing); ports in the default zone,
  rules with a source as rich rules.
* Alpine: nftables (installed and enabled when missing). The agent writes one table it owns,
  `inet limdm`, to `/etc/nftables.d/limdm.nft` (loaded by the stock nftables service at boot)
  and loads it atomically with `nft -f` whenever it changes or is missing. Input policy drop
  with established traffic, loopback, ICMP and DHCP replies allowed, then the declared rules;
  output policy drop only with outbound deny. nftables was chosen over awall because it is the
  kernel's current firewall, needs no second policy language on top of iptables, and is what
  the `firewall.active` check reads. Other tables still apply: a packet must pass every input
  chain, so a stock `/etc/nftables.nft` with its own drop policy must allow the same ports or
  be reduced to the include.

The agent keeps the rules in line with the declaration also while the firewall is active:
new rules are added first, rules it added earlier and that are no longer declared are
deleted. Rules added by hand or by agents before 0.16 are never deleted. Without a firewall
declaration (or with `enforce` off) the rules are left as they are, so a dropped item cannot
lock out SSH. The default library item "Host firewall, SSH allowed" allows `22/tcp`.

### `com.limdm.ssh` (list), `com.limdm.banner`

Console: **SSH server options** and **Login banner**.

```json
{"options": {"AllowGroups": "ssh-users", "Banner": "/etc/issue.net"}}
{"issue": "Authorized use only.", "motd": "Managed by IT."}
```

| Field | Type | Rules |
|---|---|---|
| `options` (ssh) | object of text | allowed options only, values up to 200 characters of letters, digits, space and `, @ . _ : / * -` |
| `issue` (banner) | text | up to 4096 characters, no control characters except newline and tab |
| `motd` (banner) | text | same |

SSH options merge by key (a later item wins). Only sshd options that cannot weaken the
compliance baseline are accepted: `AllowGroups`, `AllowUsers`, `DenyGroups`, `DenyUsers`,
`Banner`, `MaxSessions`, `MaxStartups`, `LogLevel`, `Port`, `ListenAddress`,
`AuthorizedKeysFile`, `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `Ciphers`, `MACs`,
`KexAlgorithms`, `HostKeyAlgorithms` and `PubkeyAcceptedAlgorithms`. `PermitRootLogin` and
similar are rejected. They go to `/etc/ssh/sshd_config.d/02-limdm-custom.conf`, after the
compliance drop in, so sshd keeps the baseline value where both set one. Changes are tested
with `sshd -t` and rolled back on error; sshd is reloaded afterwards. A device without an SSH
server reports the declaration as failed.

The banner writes `issue` to `/etc/issue` and `/etc/issue.net` and `motd` to `/etc/motd`. An
empty field leaves its file alone.

### `com.limdm.screenlock`

Console: **Screen lock**.

```json
{"idle_seconds": 300}
{"idle_seconds": 300, "hide_users": true, "allow_autologin": false}
```

| Field | Type | Rules |
|---|---|---|
| `idle_seconds` | number | 30 to 3600 |
| `hide_users` | true or false | optional; the login screen asks for the user name instead of listing users |
| `allow_autologin` | true or false | optional; `false` switches automatic and timed login off |

Locks the screen after `idle_seconds` and before suspend, on every desktop, in a way users
cannot change:

| Desktop | How |
|---|---|
| GNOME, Budgie, Cinnamon, MATE | dconf system database with locked keys, `disable-lock-screen` locked to `false` too |
| KDE Plasma | `/etc/xdg/kscreenlockerrc`, immutable through KDE kiosk (`[$i]`) |
| Xfce | xfconf system defaults with locked properties (xfce4-screensaver) |
| sway, Hyprland, river, labwc, niri, Wayfire | `swayidle` with `swaylock`; for sway also `/etc/sway/config.d` |
| i3, bspwm, openbox, awesome, herbstluftwm | `xss-lock` with `i3lock` and the X screensaver timeout |

For compositors and window managers the agent starts its own locker in every session (user
unit `limdm-idle-lock`, or directly where the user's service manager is out of reach) and
starts it again within a minute when it is ended. Only that locker counts, not any process
with a locker's name; on X11 the screensaver timeout is set again every minute, so
`xset s off` does not help. Like every remediation this only happens with `remediate` on and
`desktop.screenlock` not excluded. The check fails for a session without the locker, for
desktops LiMDM cannot enforce (COSMIC, LXQt) and for Xfce without xfce4-screensaver. Missing
tools are installed.

Login screen privacy is optional: without `hide_users` and `allow_autologin` the login
manager is left as it is. With `"allow_autologin": false` automatic and timed login are
switched off in GDM (`AutomaticLoginEnable`, `TimedLoginEnable`), SDDM and LightDM, in their
drop in directories and in the main files (`/etc/sddm.conf`, `/etc/lightdm/lightdm.conf`),
which would otherwise win. `"hide_users": true` hides the user list (GDM
`disable-user-list`, LightDM `greeter-hide-users`, SDDM does not remember the last user).
LightDM guest sessions are off whenever the login screen is managed. Agents before 0.9.2
reject the two keys as unknown, so add them only after the fleet runs 0.9.2.

### `com.limdm.localusers` (list)

Console: **Local accounts**.

```json
{"users": [{"name": "svc-backup", "uid": 1500, "full_name": "Backup", "groups": ["backup"],
            "shell": "/bin/bash", "locked": false, "authorized_keys": ["ssh-ed25519 AAAA... backup@example.com"]}]}
```

| Field | Type | Rules |
|---|---|---|
| `users[].name` | text | lower case user name (`a-z`, digits, `_`, `-`, up to 32 characters), not `root`, unique |
| `users[].uid` | number | 1000 to 60000 or absent; used only when the account is created |
| `users[].full_name` | text | up to 100 characters, no colon or comma |
| `users[].groups` | list of text | up to 32 supplementary groups, must exist, not `root` |
| `users[].shell` | text | absolute path, default `/bin/bash` |
| `users[].locked` | true or false | lock the account and end its sessions |
| `users[].authorized_keys` | list of text | up to 100 SSH public keys as `type base64 [comment]`, no options |

Merged by name. A missing account is created with a home and without a password, so it signs
in with its SSH keys; an existing account is never renumbered. Shell and groups are kept in
line: declared groups are added, groups an earlier version of the declaration added and that
are no longer listed are removed, other memberships stay. Unlocking undoes only a lock the
declaration set. `authorized_keys` are written root owned to
`/etc/ssh/limdm_authorized_keys/<user>`, never into the home, and a drop in
(`/etc/ssh/sshd_config.d/00-limdm-keys.conf`) makes sshd read them besides
`~/.ssh/authorized_keys`. This drop in takes precedence over an `AuthorizedKeysFile` set with
`com.limdm.ssh`. Accepted key types: `ssh-ed25519`, `ssh-rsa`, `ssh-dss`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` and the `sk-` security key variants.

Accounts removed from the declaration are locked, never deleted, and their key file is
removed. The imperative user commands on the device page keep working.

### `com.limdm.dconf` (list)

Console: **GNOME settings (dconf)**.

```json
{"settings": {"/org/gnome/desktop/interface/clock-show-seconds": "true",
              "/org/gnome/desktop/background/picture-uri": "'file:///usr/share/backgrounds/corp.png'"},
 "locks": ["/org/gnome/desktop/background/"]}
```

| Field | Type | Rules |
|---|---|---|
| `settings` | object of text | key: full path `/dir/key`; value: GVariant text on one line, up to 1024 characters (strings in single quotes) |
| `locks` | list of text | keys, or directories ending in `/`, users cannot change |

Defaults for every user of GNOME and other dconf based desktops. Merged by key (a later item
wins), locks are joined. Written to `/etc/dconf/db/local.d/70-limdm-custom` and
`/etc/dconf/db/local.d/locks/70-limdm-custom`, next to the screen lock settings, and compiled
with `dconf update`. Removing the declaration removes both files.

### `com.limdm.sudo` (list)

Console: **sudo rules**.

```json
{"rules": [{"name": "developers", "principals": ["%developers"], "run_as": "",
            "commands": ["/usr/bin/apt-get update", "/usr/bin/systemctl restart nginx"], "nopasswd": false}],
 "timestamp_timeout": 5}
```

| Field | Type | Rules |
|---|---|---|
| `rules[].name` | text | `a-z`, `0-9`, `_`, `-`, up to 40 characters (sudo ignores files with dots) |
| `rules[].principals` | list of text | at least one user or `%group`; `ALL` is not allowed |
| `rules[].run_as` | text | empty (root), a user or `ALL` |
| `rules[].commands` | list of text | at least one absolute path with plain arguments (up to 300 characters), or `ALL` |
| `rules[].nopasswd` | true or false | no password prompt |
| `timestamp_timeout` | number | optional, 0 to 60 minutes; 0 asks every time |

Rules merge by name; the last `timestamp_timeout` set wins.

* One drop in per rule, `/etc/sudoers.d/70-limdm-<name>` (mode 0440).
* Sudoers metacharacters (`,` `:` `=` `\` `!` `*`) are rejected in commands, so one entry is
  exactly one command without wildcards.
* Every file is checked with `visudo -c -f` before it is installed. If the whole
  configuration fails `visudo -c` afterwards, the managed files are removed again.
* The compliance defaults (`use_pty`, `logfile`) live in `/etc/sudoers.d/60-limdm`.

### `com.limdm.polkit` (list)

Console: **polkit rules**.

```json
{"rules": [
  {"name": "network", "actions": ["org.freedesktop.NetworkManager.*"], "groups": ["netdev"],
   "result": "yes", "local_active_only": true},
  {"name": "printers", "actions": ["org.opensuse.cupspkhelper.mechanism.*"], "groups": [],
   "result": "auth_self_keep", "local_active_only": true}]}
```

| Field | Type | Rules |
|---|---|---|
| `rules[].name` | text | lower case letters, digits, `.`, `_`, `-` |
| `rules[].actions` | list of text | at least one action ID, or a namespace with `.*` (at least three segments) |
| `rules[].groups` | list of text | empty means every user |
| `rules[].result` | text | `yes`, `no`, `auth_self`, `auth_self_keep`, `auth_admin`, `auth_admin_keep` |
| `rules[].local_active_only` | true or false | only the user at the device |

Merged by name.

* Written to `/etc/polkit-1/rules.d/60-limdm-<name>.rules`; polkitd reloads by itself.
* `org.freedesktop.policykit.*` (pkexec) cannot be granted.
* `result` `yes` needs `groups` or `local_active_only`, so nobody gets an action without
  authentication from remote.

Typical uses: let users manage networks, printers, time zone or mount disks without admin
rights.

### `com.limdm.softwarestore`

Console: **Software store policy**.

```json
{"restrict_flathub": true, "stores_read_only": true, "only_managed_remotes": true}
```

| Field | Type | Rules |
|---|---|---|
| `restrict_flathub` | true or false | remotes marked "Only catalog apps" offer only runtimes and catalog apps |
| `stores_read_only` | true or false | GNOME Software and KDE Discover cannot install, remove or change repositories |
| `only_managed_remotes` | true or false | every Flatpak remote not allowed under **Software**, **Remotes** is disabled, also in users' installations |

Store policy of the software catalog per blueprint; see [software.md](software.md#store-policy).

### `com.limdm.bootloader`

Console: **Boot loader password**.

```json
{"superuser": "bootadmin", "password": "a new password with 12 or more characters", "unrestricted": true}
```

| Field | Type | Rules |
|---|---|---|
| `superuser` | text | GRUB user name (`a-z`, digits, `_`, `-`) |
| `password` | text | 12 to 128 characters; only in the editor, replaced on save |
| `password_pbkdf2` | text | the stored hash, `grub.pbkdf2.sha512.…` |
| `unrestricted` | true or false | the default boot entries start without password; editing entries and the GRUB console need it |

* When the item is saved, the console replaces `password` with `password_pbkdf2` (PBKDF2
  SHA-512, 100000 iterations, the `grub-mkpasswd-pbkdf2` format). The clear text is never
  stored and never sent to devices. To change it, enter `password` again.
* Debian, Ubuntu, Arch and others: `/etc/grub.d/01_limdm_password`, `--unrestricted` in
  `10_linux`, `grub-mkconfig`, `grub.cfg` set to 0600. SUSE uses `grub2-mkconfig` and
  `/boot/grub2/grub.cfg`. Fedora family: `/boot/grub2/user.cfg` in the format of
  `grub2-setpassword` (superuser `root`, `superuser` is ignored).

### `com.limdm.diskencryption`

Console: **Disk encryption recovery**.

```json
{"escrow": true, "rotate_after_view": true, "require_all": true, "exclude": ["/boot"],
 "tpm2": {"pcrs": [7], "pin": false, "require": true}}
```

| Field | Type | Rules |
|---|---|---|
| `escrow` | true or false | every LUKS volume needs a recovery key stored on the server (check `disk.recovery`) |
| `rotate_after_view` | true or false | replace a key once someone viewed it in the console |
| `require_all` | true or false | every local volume must be on LUKS, not only `/` |
| `exclude` | list of text | absolute mount points other than `/` exempt from `require_all` |
| `tpm2.pcrs` | list of number | PCRs 0 to 23, each once; default 7 |
| `tpm2.pin` | true or false | the TPM also needs a PIN at boot |
| `tpm2.require` | true or false | the check `disk.tpm` fails while a volume is not bound |

LUKS recovery key escrow, rotation, four eyes approval for key views and TPM 2.0 binding:
[disk-encryption.md](disk-encryption.md). The `tpm2` entry binds every LUKS volume to the TPM
with `systemd-cryptenroll` when its recovery key is escrowed; the recovery key stays valid
([disk-encryption.md](disk-encryption.md#tpm-unlock)).

Without `require_all` the check `disk.encryption` only looks at `/`. With it, every local
volume must be on LUKS except the mount points in `exclude`; an entry covers everything below
it (`/boot` also covers `/boot/efi`). The device page marks excluded volumes. The default
library item "Disk encryption on all volumes, /boot excluded" is a ready made start.

### `com.limdm.login`

Console: **Desktop login (OIDC)**.

```json
{"issuer": "https://accounts.google.com", "client_id": "...", "client_secret": "...",
 "allowed_domain": "example.com", "mode": "session", "reverify_hours": 720, "grace_hours": 168}
```

| Field | Type | Rules |
|---|---|---|
| `enabled` | true or false | `false` switches SSO off (for example for servers below a desktop blueprint); the agent removes its PAM hook |
| `issuer` | text | required, https |
| `client_id` | text | required |
| `client_secret` | text | stored sealed on the server, opened only for delivery to devices |
| `allowed_domain` | text | Google `hd` claim, or the email domain |
| `mode` | text | `session` (default) or `login` |
| `local_password` | true or false | login mode: the password typed at an SSO login becomes the local password until `reverify_hours` have passed |
| `reverify_hours` | number | session mode: 1 to 8760, default 720; login mode with `local_password`: 1 to 2160 |
| `grace_hours` | number | session mode: 1 to 2160, default 168 |
| `offline_grace_hours` | number | login mode: 0 to 720, default 72 |

Always name the `mode`. An item without `mode` but with `local_password` (and
`reverify_hours` up to 2160) counts as written before 0.11 and runs in login mode.

Desktop login with SSO. See [desktop-login.md](desktop-login.md).

### `com.limdm.osversion` (list)

Console: **OS versions**.

```json
{"min": {"ubuntu": "24.04", "debian": "12", "fedora": "42"}}
```

| Field | Type | Rules |
|---|---|---|
| `min` | object of text | os-release `ID` to minimum `VERSION_ID` (digits and dots) |

Merged by distribution ID, a later item wins. Minimum versions for the `os.supported` check.
The default library item "Supported OS versions" sets Ubuntu 22.04, Debian 12 and Fedora 41.
