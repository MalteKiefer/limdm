# Agent deployment

`limdm-agent` runs as a root service on every device (systemd, OpenRC on Alpine). Every
release ships the agent package as `.deb`, `.rpm`, Arch package (`.pkg.tar.zst`) and
`.apk` for amd64 and arm64, plus a `tar.gz`. The package contains

* `limdm-agent`, the agent,
* `limdm`, the command line for users ([Command line for users](#command-line-for-users)),
* `limdm-desktop` and `/usr/lib/limdm/limdm-desktop-ui`, the tray and the desktop app
  ([Desktop app and tray](#desktop-app-and-tray)),
* the units `limdm-agent.service`, `limdm-watchdog.service` and `limdm-watchdog.timer`
  (or `/etc/init.d/limdm-agent`), the rollback script `/usr/lib/limdm/limdm-watchdog.sh`,
  the PAM profile for `pam-auth-update`, the XDG autostart entry, the systemd user unit
  `limdm-desktop.service` and the menu entries.

osquery is a hard dependency of the deb and rpm and comes from the official osquery
repository. Arch and Alpine have no osquery package; the agent uses its native inventory
there.

## Supported distributions

| Family | Distributions | Packages | Init | Notes |
|---|---|---|---|---|
| Debian | Debian 12 and later, Ubuntu 22.04 and later, Mint 21 and later, Pop!_OS 22.04 and later | apt, `.deb` | systemd | full feature set |
| Fedora | Fedora, CentOS Stream 9 and later, RHEL, Rocky and Alma 9 and later | dnf, `.rpm` | systemd | full feature set |
| SUSE | openSUSE Leap 16, openSUSE Tumbleweed, SLES and SLED 16 | zypper, `.rpm` | systemd | see [SUSE](#suse) |
| Arch | Arch, Manjaro, EndeavourOS | pacman, `.pkg.tar.zst` | systemd | no osquery (native inventory); pending updates through `pacman-contrib`; updates are always full upgrades |
| Alpine | Alpine 3.17 and later | apk, `.apk` | OpenRC | no osquery; no host firewall management; SSO login needs linux-pam; no systemd watchdog (supervise-daemon restarts the agent) |

The agent needs OpenSSL 3: the installer verifies the Ed25519 signature of the release with
`openssl pkeyutl -rawin`, which OpenSSL 1.1.1 lacks, and the packages depend on
`openssl >= 3`. Systems whose default OpenSSL is 1.1.1 are not supported, with no fallback:
Ubuntu 20.04, Debian 11, RHEL, Rocky and Alma 8, CentOS Stream 8, openSUSE Leap 15 and
SLES 15 (both still ship OpenSSL 1.1.1 as `openssl`), and Alpine 3.16 and older. On them
the installer stops with "this system is not supported by the LiMDM agent (OpenSSL 3
required)".

Arch and Alpine are rolling or have no separate security channel: every pending update
counts for the security update check, and "install all updates" upgrades everything.

### SUSE

The SUSE family uses the same `.rpm` as Fedora. Its hard dependencies are names both
families share; tools named differently on SUSE (`iproute2`, `procps`, `gpg2`) are weak
dependencies, and the agent installs any missing tool itself.

* Packages: `zypper --non-interactive install --no-recommends`. New or changed package
  sources trigger `zypper refresh` before the next install.
* Updates on Leap, SLES and SLED: security only runs `zypper patch --category security`,
  all updates run `zypper update`. Pending updates come from `zypper list-updates` and
  `zypper list-patches --category security`.
* Tumbleweed (and Slowroll) is rolling: every update runs `zypper dup` and every pending
  update counts as a security update, as on Arch.
* Reboot required: `/run/reboot-needed` or `zypper needs-rebooting`.
* Repositories: declare them with `"family": "suse"`; they are written to
  `/etc/zypp/repos.d` with `autorefresh=1`, and the signing key is imported with
  `rpm --import` so zypper does not ask whether to trust it. Catalog apps use the Fedora
  package names and Fedora (rpm-md) repositories. Switching off unmanaged `.repo` files
  works as on Fedora, with the original kept in `/var/lib/limdm/repo-backup`.
* osquery comes from the official rpm repository, as on Fedora.
* Firewall: firewalld. Mandatory access control is checked as it runs: AppArmor or
  SELinux (Leap 16 and Tumbleweed use SELinux).
* PAM: the SSO hook goes into `common-auth` (the `common-auth-pc` file of pam-config);
  if a later `pam-config` run drops it, the agent adds it again. The password quality fix
  installs `pam_pwquality` and runs `pam-config --add --pwquality`.
* CA certificates go to `/etc/pki/trust/anchors`, the boot loader password uses
  `grub2-mkconfig` and `/boot/grub2/grub.cfg`.
* Admins join `wheel`. openSUSE's default sudoers asks for the root password
  (`Defaults targetpw`) and does not grant `wheel`; add a `com.limdm.sudo` rule for
  `%wheel` to make it an admin group.
* The proxy declaration writes the environment files and sets `PROXY_ENABLED`,
  `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in `/etc/sysconfig/proxy`, which zypper and
  YaST read. Only these keys are changed, and only while they still hold the value LiMDM
  wrote.
* Agent self updates install the package with `zypper install --allow-unsigned-rpm`; its
  SHA-256 was checked against the signed release checksums before.
* Transactional systems (openSUSE MicroOS, SL Micro) are not supported: their read only
  root needs `transactional-update`.

## Enrollment tokens

**Enrollment** in the console creates tokens with a note, an optional blueprint, a number of
uses (1 to 10000) and a validity (1 to 90 days). The token is shown once. The page shows the
commands below with the token filled in. **Revoke** ends a token at once (audit
`token.revoke`); devices already enrolled with it are not affected. With multi tenancy a
token enrolls into the tenant it was created in, and tokens of a disabled tenant stop
working ([tenants.md](tenants.md)).

## One device: install script

```sh
curl -fsSL https://mdm.example.com/install.sh | sudo LIMDM_TOKEN=lmt_... sh
```

`/install.sh` is generated by your server and contains its agent URL and device CA
fingerprint, no secret. It

1. detects the architecture (amd64, arm64) and the package manager (apt, dnf, zypper,
   pacman or apk); other systems use the tar.gz release by hand,
2. writes `/etc/limdm/enroll.conf` (0600) from `LIMDM_TOKEN`; without `LIMDM_TOKEN` it uses
   an existing `/etc/limdm/enroll.conf`,
3. finds the newest release of `LIMDM_RELEASE_REPO` through the GitHub API, downloads
   `limdm-agent_<version>_linux_<arch>.<deb|rpm|pkg.tar.zst|apk>`,
   `limdm_<version>_SHA256SUMS` and its signature `limdm_<version>_SHA256SUMS.sig`, checks
   the Ed25519 signature with the release public key embedded in the script (the key the
   server has, `LIMDM_RELEASE_PUBLIC_KEY`; OpenSSL 3 does the check) and then the package
   against the signed sums; anything that does not verify stops the installation, so a
   tampered GitHub release cannot install anything,
4. on apt, dnf and zypper systems adds the osquery repository, trusting only the embedded
   signing key `1484 120A C4E9 F8A1 A577 AEEE 97A8 0C63 C9D8 B80B`,
5. installs osquery and the agent; the package enrolls the device from `enroll.conf` in its
   post install step, and the script enables and starts the service.

| Variable | |
|---|---|
| `LIMDM_TOKEN` | enrollment token |
| `LIMDM_ALLOW_SCRIPTS=true` | allow remote scripts on this device |
| `LIMDM_ALLOW_REMOTE_SHELL=true` | allow remote support shells ([remote-shell.md](remote-shell.md)) |

Running the script again on an enrolled device upgrades the agent.

## Mass deployment: enroll.conf

Distribute `/etc/limdm/enroll.conf` (mode 0600) with Ansible, Puppet, Salt or a golden image:

```toml
server = "https://mdm.example.com:8444"
fingerprint = "<device CA SHA-256 from the Enrollment page>"
token = "lmt_..."
allow_scripts = false
allow_remote_shell = false
```

| Key | Required | |
|---|---|---|
| `server` | yes | agent API URL (the agent listener, port 8444 by default) |
| `fingerprint` | yes | SHA-256 of the device CA, shown on **Enrollment** |
| `token` | yes | enrollment token |
| `allow_scripts` | no | `true` allows remote scripts and `com.limdm.files` targets outside the plain text allowlist; default `false` |
| `allow_remote_shell` | no | older local opt in for remote support shells; the policy (**Agent**, **Remote shell**) decides now ([remote-shell.md](remote-shell.md)) |

Lines starting with `#` are comments. Both `allow_*` values are stored in
`/etc/limdm/agent.json` and cannot be switched on from the server later; enroll again to
change them.

Then install the package by any means (your own apt or dnf mirror, the release files, or the
install script without `LIMDM_TOKEN`). The agent enrolls

* in the package's post install step, when the file exists, and
* at every service start while the device is not enrolled,

and deletes the file afterwards, because the token must not stay on disk. Use one token with
enough uses per rollout wave.

Example with Ansible:

```yaml
- name: LiMDM enrollment
  ansible.builtin.copy:
    dest: /etc/limdm/enroll.conf
    mode: "0600"
    content: |
      server = "https://mdm.example.com:8444"
      fingerprint = "{{ limdm_fingerprint }}"
      token = "{{ limdm_token }}"
- name: LiMDM agent
  ansible.builtin.shell: curl -fsSL https://mdm.example.com/install.sh | sh
  args:
    creates: /etc/limdm/device.pem
```

## Manual installation and other systems

```sh
# SHA256SUMS and SHA256SUMS.sig of the release next to the package; the key is the
# RELEASE_KEY line of https://mdm.example.com/install.sh
sudo LIMDM_RELEASE_PUBLIC_KEY=<hex> sh install-agent.sh ./limdm-agent_0.16.0_linux_amd64.deb   # adds osquery, installs both
sudo limdm-agent enroll --config /etc/limdm/enroll.conf
sudo systemctl enable --now limdm-agent
```

or with flags: `limdm-agent enroll --server URL --fingerprint FP --token TOKEN [--allow-scripts] [--allow-remote-shell]`.
`install-agent.sh` verifies the signature of `limdm_<version>_SHA256SUMS` and the package
checksum before it installs anything; there is no way to skip it. Packages you build yourself
are signed with your own release key (`limdm-server keygen`, see [operations.md](operations.md#release-key)).
Both installers stop at once on a system without OpenSSL 3.
Distributions without apt, dnf, zypper, pacman or apk use the tar.gz release; the agent
falls back to native inventory when osquery is missing.

## What enrollment does

The agent fetches the device CA over TLS, accepts it only when its SHA-256 matches the
fingerprint, creates a P-256 key locally and sends only a certificate signing request with
the token. The key never leaves the device (`/etc/limdm/device.pem`, 0600). From then on
every connection is mTLS with TLS 1.3, pinned to that CA. Certificates last 90 days and
rotate automatically 30 days before they expire, or earlier when the server asks (device CA
rotation, [keys.md](keys.md)).

## Agent command line

All subcommands except `version` and `pam-auth` need root.

| Command | |
|---|---|
| `limdm-agent run` | the service; enrolls from `/etc/limdm/enroll.conf` first when the device is not enrolled |
| `limdm-agent enroll --config FILE` | enroll with an enroll.conf file |
| `limdm-agent enroll --server URL --fingerprint FP --token TOKEN [--allow-scripts] [--allow-remote-shell]` | enroll with flags; the three values are required |
| `limdm-agent check [--level 1\|2]` | local compliance report, changes nothing; `--level` overrides the declared level |
| `limdm-agent recovery-key [--all]` | create and escrow LUKS recovery keys; asks for each disk passphrase; `--all` also replaces keys already escrowed |
| `limdm-agent watchdog` | run by `limdm-watchdog.timer`: unmasks, enables and starts the agent when needed |
| `limdm-agent tamper-report MSG` | queue a tamper event (used by the package scripts) |
| `limdm-agent pam-auth` | PAM helper for the desktop login, called by `pam_exec` ([desktop-login.md](desktop-login.md)) |
| `limdm-agent version` | installed version |

Other useful commands:

| Command | |
|---|---|
| `systemctl kill --kill-who=main -s USR1 limdm-agent` | check in now |
| `journalctl -u limdm-agent` | agent log |

## What the agent does

Each cycle (default every 5 minutes) the agent renews certificates when due, applies the
declarations, runs the compliance checks, collects inventory and checks in; the steps are
in [concepts.md](concepts.md#agent-cycle). In addition it

* asks the server every minute whether a command or an agent update waits
  ([Command delivery](#command-delivery)),
* serves the desktop app, the tray and `limdm` on `/run/limdm/agent.sock`,
* installs missing tools it needs once a day ([Dependencies](#dependencies)),
* starts the desktop helper in graphical sessions that did not start it themselves,
* keeps enforcing the stored declarations while the server is unreachable, and locks the
  device after `offline_lock_hours` without contact when that is set.

The agent runs with lower CPU and I/O priority (systemd `Nice=10`, `CPUWeight=20`,
`IOSchedulingClass=best-effort` with priority 7; on OpenRC nice 10 and ionice 2:7), so its
background work yields to users on laptops and to workloads on servers. Package installs it
starts inherit that priority.

### Privacy options

Two features send data to third parties. Both are off by default and switched on in
**Settings**, **Security**, **Privacy**:

* **Look up the location of device public addresses**: the server sends a device's
  public address to `LIMDM_GEOIP_URL` (default ipwho.is) when it changes. The device page
  shows the location. The agent is not involved.
* **Agents may ask public DNS over HTTPS resolvers (Cloudflare, Google) when the system
  resolver fails**: when the system resolver cannot resolve the server name, the agent asks
  `1.1.1.1`, `8.8.8.8`, `1.0.0.1` and `8.8.4.4` over HTTPS. The agent remembers the setting
  for its next start. `"no_fallback_dns": true` in `/etc/limdm/agent.json` keeps the
  fallback off on one device, whatever the server says.

The agent uses the declared proxy (`com.limdm.proxy`) for its own connections.

## Dependencies

The packages depend on the tools the agent calls (osquery, systemd, util-linux, cryptsetup,
iproute, procps, kmod, gnupg; on Arch also shadow and pacman-contrib, on Alpine OpenRC and
the util-linux tools) and recommend the ones compliance remediation uses (firewall, audit,
nftables, unattended upgrades, libpam-pwquality or dnf plugins). The agent does not rely on
them being present: once a day it installs whatever is missing. Desktop tools are only
suggested by the packages, so servers never get GTK: on devices with a desktop the agent
installs zenity (kdialog on KDE Plasma), libnotify, dconf, Python with GTK 4 and
libadwaita for the desktop app and, with a wlroots compositor, swayidle, and retries daily if that fails.

## Desktop app and tray

`limdm-desktop` runs as the user in every graphical session. It shows a tray icon, opens the
desktop app and asks the user for what only the user can provide. It talks only to the
agent socket `/run/limdm/agent.sock`; the agent identifies callers by their peer
credentials and only serves users with an active local session (and root).

### Starting

The helper starts through the systemd user unit `limdm-desktop.service` (enabled for all
users, bound to `graphical-session.target`), through XDG autostart
(`/etc/xdg/autostart`), and where neither applies (sway or Hyprland without systemd
integration, i3) the agent starts it on its next cycle. A lock in `$XDG_RUNTIME_DIR` keeps
one instance per user.

| Option | |
|---|---|
| `limdm-desktop` | tray icon and reminders |
| `--no-tray` | only the reminders, for sessions without a tray host |
| `--now` | ask for a missing recovery key right away (menu entry **Disk recovery key**) |
| `--message TEXT`, `--message-title TITLE` | show a message from IT (started by the agent) |
| `--reboot-at HH:MM`, `--reboot-defers N`, `--reboot-defer-minutes M` | offer to postpone a planned restart (started by the agent) |

### Tray

The tray icon is the LiMDM logo with a status dot: green (compliant), amber (checks
failing), red (no contact to the server or locked). The menu names who manages the device,
shows the state and the last check in, and offers **Open LiMDM…**, **Install Software…**,
**Compliance…**, **Set Up Recovery Key…** and **Confirm Company Account…** when needed,
**Check In Now** (at most every 30 seconds) and **Agent Log…**; the agent version is at the
bottom and in the tooltip. While IT runs a remote shell it shows **IT remote support
session running**. The tray uses StatusNotifierItem: sway with waybar, KDE Plasma, Xfce,
Cinnamon and Ubuntu show it; stock GNOME needs the AppIndicator extension.

### Desktop app

**LiMDM** in the applications menu (or **Open LiMDM…** in the tray) opens a window in the
style of GNOME Settings (GTK 4, libadwaita 1.4) with these pages:

| Page | |
|---|---|
| Overview | state, who manages the device, last check in, **Check In Now**, open tasks such as a missing recovery key |
| Software | the company catalog: install, remove or request apps ([software.md](software.md)) |
| Compliance | every check with its result, grouped by failing, exceptions, not applicable and passed |
| Profiles | every declaration in force with its settings, secrets masked |
| Certificates | CA certificates IT installed, with subject, issuer, validity and fingerprint |
| Disk Encryption | store a recovery key with the disk passphrase |
| Agent Log | journal entries of the agent and its watchdog, optionally only warnings and errors |
| About | versions and server |

It shows the company logo, or the LiMDM logo, and follows the system's light or dark style;
the button next to the logo switches between system, dark and light. Without GTK 4 and
libadwaita 1.4 (Ubuntu 22.04) the tray falls back to simple dialogs.

### Dialogs and notifications

Dialogs are libadwaita message dialogs from the desktop app (`limdm-desktop-ui --dialog`);
without GTK 4 and libadwaita 1.4 the helper uses zenity (kdialog on KDE Plasma). Texts
follow the session language and fall back to the system locale (English and German).
Dialogs follow the GNOME HIG: a short heading, one sentence, buttons named after their
action.

Users see a notification when IT schedules a restart or shutdown (with the time), locks the
device, starts or ends a remote shell, or needs a recovery key. **Send message…** on a
device page shows a notification and a dialog to everyone signed in on the desktop.

### Restart after updates

When `com.limdm.updates` restarts the device after updates (`reboot`), the agent schedules
the restart with `shutdown -r` `reboot_notice_minutes` ahead (default 5) and notifies every
graphical session. With `reboot_max_defers` above 0 the helper asks **Restart scheduled**
with the buttons **Postpone N minutes** and **Restart as planned**. Each postponement moves
the restart by `reboot_defer_minutes` (default 60) and is recorded as a device event; the
dialog comes again shortly before the new time until no postponements are left
([declarations.md](declarations.md#comlimdmupdates)).

## Command line for users

`limdm` does on a terminal what the desktop app does in its window. It runs as the signed
in user, talks only to the agent socket and needs no root; over SSH it is refused unless
the user also has an active local session (root is always allowed).

| Command | |
|---|---|
| `limdm info` (alias `status`) | everything about this device and the agent: manager, system, hardware, server, check in, declarations, updates, locks, compliance, recovery keys, company account, remote support session |
| `limdm checks` | every compliance check with its result |
| `limdm profiles` | declarations in force (secrets masked) |
| `limdm certificates` (alias `certs`) | CA certificates IT installed |
| `limdm log [-n 50]` | latest entries of the agent log |
| `limdm sync` | check in now |
| `limdm software list` (alias `limdm software`, `limdm apps`, `ls`) | catalog apps with mode and state |
| `limdm software install APP`, `limdm software remove APP` | install or remove an app the catalog offers (ID or name) |
| `limdm software request APP [--note TEXT]` | ask IT for a catalog app in request mode |
| `limdm software search QUERY` | search Flathub for apps outside the catalog |
| `limdm software request-new FLATPAK_ID [--remote flathub] [--name NAME] [--note TEXT]` | ask for an app outside the catalog |
| `limdm software requests` | your requests for apps outside the catalog |
| `limdm sso [status]` | company account of your session and when it was last confirmed |
| `limdm sso confirm` | confirm the company account: prints a URL and a code and waits up to ten minutes for the sign in |
| `limdm recovery-key` | create the disk recovery key IT asks for (reads the passphrase from the terminal) |
| `limdm support end` | end the remote support session IT opened ([remote-shell.md](remote-shell.md)) |
| `limdm version` | agent version |

`--json` prints `info`, `checks`, `profiles`, `certificates`, `log` and `software list` as
JSON. The agent decides as for the app: only catalog apps install, and only in the modes the
catalog allows.

## Tamper protection

* `limdm-agent.service` refuses `systemctl stop` (`RefuseManualStop`) and restarts after a
  kill (`Restart=always`).
* `limdm-watchdog.timer` runs `limdm-agent watchdog` every 5 minutes: it unmasks, enables and
  starts the agent when needed. The agent in turn keeps the watchdog timer enabled.
* Removing the package needs a release from the console (**More actions**, **Agent**,
  **Allow uninstall for 1 hour**); otherwise the package manager stops with an error.
  Upgrades are not affected.
* Everything found and fixed, and every removal attempt, is reported as a tamper event: the
  device page shows a notice, the audit log has an `agent.tamper` entry and the
  notification event `device.tamper` goes out.

A root user can still defeat this, for example by deleting the binaries or overriding the
units. The goal is detection and self healing, not an absolute barrier: a device whose agent
was removed stops checking in, turns `stale` and, with `offline_lock_hours`, locks itself.

## Updates

Agents are updated from the console, page **Agents**:

1. The server checks `LIMDM_RELEASE_REPO` on GitHub every six hours (or on **Check for new
   versions**), downloads the agent packages and verifies them against the release's
   `SHA256SUMS` and `SHA256SUMS.sig`.
2. An admin **approves** a version. Nothing is installed before that.
3. Rollout: with **Update agents automatically**, devices tagged with the **Pilot tag** get
   an approved version at their next check in, all others after the delay (default 7
   days) spread over the **Rollout window** (default 24 hours): each device gets the version
   at its own fixed offset within the window (derived from device and version), so a release
   reaches the fleet evenly instead of within one poll minute. 0 hands it to all at once.
   The server serves at most `LIMDM_UPDATE_DOWNLOADS` packages at once per instance
   (default 20); further downloads wait up to 20 seconds, then get 503 with `Retry-After`
   and the agent tries again later without counting a failed update. **Update agent…** on a device page installs the newest approved version, or any
   fetched version that is not blocked and newer than the running one, on that device
   only, regardless of policy and delay. Picking a version counts as its approval for this
   device. Agents never downgrade: an older pick is dropped. **Outdated agents** on the
   Agents page updates single devices to the newest approved version.
4. The agent checks the Ed25519 signature of the checksums against the release key
   compiled into it (an agent built without one refuses every self update and reports
   why), downloads the package for its distribution and architecture over mTLS, verifies
   the checksum, keeps a copy of the running binary in `/var/lib/limdm/rollback` and
   installs the package in a separate transient systemd unit (a detached process on
   OpenRC) with apt, dnf, zypper, pacman or apk.
5. The new agent confirms the update at its first start. If it does not within 15 minutes,
   the watchdog (`/usr/lib/limdm/limdm-watchdog.sh`, plain shell) restores the previous
   binary and restarts the agent, which reports the rollback.

The device page shows the update state (`offered`, `ok`, `failed`, `rolled_back`); every
outcome is in the audit log as `agent.update`. After three failed or rolled back devices a
version is blocked automatically. Admins can block and approve versions at any time; only
newer versions are offered, so blocking stops a rollout but does not downgrade devices.
How releases are signed is in [operations.md](operations.md#releases-and-agent-updates).

Hosting the packages in your own repository and updating with the package manager works as
well.

## Files

| Path | Content |
|---|---|
| `/etc/limdm/agent.json` | server URL, device ID, `allow_scripts`, `allow_remote_shell`, `no_fallback_dns` |
| `/etc/limdm/device.pem` | device key and client certificate in one file (0600) |
| `/etc/limdm/ca.crt` | pinned device CA, the only trust anchor of the agent channel |
| `/etc/limdm/enroll.conf` | enrollment settings, deleted after enrollment |
| `/etc/limdm/users.json`, `/etc/limdm/login.json` | desktop login ([desktop-login.md](desktop-login.md#files-on-the-device)) |
| `/var/lib/limdm/state.json` | stored declarations, pending results and events, pinned command key, last server contact (0600) |
| `/var/lib/limdm/repo-backup/` | originals of package sources switched off |
| `/var/lib/limdm/network/` | EAP-TLS device key and certificate (0600) |
| `/var/lib/limdm/printers.json` | printer queues LiMDM manages |
| `/var/lib/limdm/updates/`, `/var/lib/limdm/rollback/`, `update-pending.json`, `update-result.json` | agent self update and rollback |
| `/var/lib/limdm/tamper.log` | tamper events queued by the package scripts |
| `/var/lib/limdm/uninstall-allowed` | uninstall release from the console, valid for one hour |
| `/var/lib/limdm/sso-verified.json`, `/var/lib/limdm/auth-events.log` | desktop login state |
| `/var/lib/limdm/device-lock-users.json`, `/var/lib/limdm/lock-after-lost` | accounts locked by a device lock or lost mode |
| `/var/lib/limdm-support` | home of the remote shell support account `limdm-support` |
| `/var/cache/limdm/logo.png`, `/var/cache/limdm/catalog/`, `/var/cache/limdm/search/` | company logo and app icons for the desktop helper |
| `/run/limdm/agent.sock` | socket for the desktop helper and `limdm` |

## Lock and unlock

**Lock device** works the same on every desktop:

* `/etc/nologin` refuses new logins (also SSH, except root).
* The local passwords of all people's accounts (UID 1000 and up with a login shell) are
  locked, so neither a login screen nor the screen locker accepts them. The agent remembers
  which accounts it locked; **Unlock device** releases exactly those (SSO rules may keep
  managed users locked).
* Terminal and SSH sessions of people end (they cannot be locked); root's stay. While the
  device is locked, the agent ends such sessions again every minute.
* Graphical sessions are locked, not ended, like on Windows and macOS (unsaved work stays):
  GNOME, KDE Plasma, Xfce, Cinnamon and MATE through logind (Xfce additionally with i3lock),
  compositors and window managers without a logind aware locker (labwc, sway, Hyprland,
  river, niri, Wayfire, i3 and others) get swaylock or i3lock started directly, again every
  minute while the device stays locked.

Whether a session still needs the agent's locker is decided only from what the session's
user cannot fake. The agent skips a session whose logind `Desktop` (set by the display
manager at login) is GNOME, KDE Plasma, Cinnamon or MATE, whose shell locks itself on
logind's request. So that the user cannot make these shells ignore the request with their
own `disable-lock-screen` setting (`org.gnome.desktop.lockdown`, `org.cinnamon.desktop.lockdown`,
`org.mate.lockdown`), the agent sets it to `false` in the dconf system database with a lock
while the device is locked or lost (`/etc/dconf/db/local.d/50-limdm-device-lock`), and removes
it on unlock. KDE Plasma has no such dconf key; its user restriction `action/lock_screen` in
`kdeglobals` is not overridden. Every other graphical session gets swaylock or i3lock started by the
agent, even when a locker seems to run already: logind's `LockedHint` (the session owner
sets it), process names (any program can be called `i3lock`) and a locker's environment
(a real locker can run on another, nested or virtual display) are not trusted. A second
locker on an already locked session fails harmlessly. Xfce sessions therefore may get
i3lock on top of their own locker.

Sessions are found through logind, one by one (also several sessions of one user), and
each gets the display and D-Bus environment of its own processes.

After unlocking, users unlock their screen with their usual password. Lost mode locks the
passwords the same way and ends the sessions. The device page shows the latest lock,
unlock, lost mode, wipe and uninstall release with who sent it and whether the device
carried it out.

## Other commands

* **Install all updates**: apt (waits up to 15 minutes for a dpkg lock held by
  unattended-upgrades or PackageKit), dnf, zypper, pacman or apk, then system wide
  Flatpaks.
* **Run script**: a shebang (`#!/bin/bash`, `#!/usr/bin/env python3`) picks the
  interpreter, otherwise `/bin/sh`; works on hardened systems with a noexec `/var`.
  **Parameters** (`NAME=value` per line) arrive as environment variables; names are
  letters, digits and underscore, and variables that change how code is loaded (`PATH`,
  `LD_*`, `BASH_ENV`, `PYTHONPATH` …) are refused. The timeout is 1 to 240 minutes
  (default 30). The device reports exit code, start and end, and the last 16 KiB of stdout
  and stderr; **Script results** on the **Commands** tab shows the newest 50 (200 are
  kept per device). Recurring scripts (`com.limdm.scripts`) report the same way instead of
  an event. Scripts only run on devices enrolled with `allow_scripts`; with four eyes
  approval on they wait for a second admin.
* **Send message**: a notification and a dialog in every graphical session; the command
  fails when no dialog could be shown.
* **Collect logs** (admins and helpdesk, **Commands** tab, **Diagnostics**): the agent
  sends the last 2000 lines of its own journal (agent and watchdog) and the warnings and
  errors of the current boot (last 1000 lines), at most 512 KiB. Before sending it masks
  private keys, `key=value` pairs with secret names (password, token, secret, api key …),
  authorization headers, credentials in URLs and recovery keys. The server keeps the
  newest 10 bundles per device; admins and the helpdesk download them as text, and every
  download is in the audit log as `device.diagnostics.download`.

The device list, bulk actions and every action of the device page are described in
[console.md](console.md#areas).

## Command delivery

Besides the regular check in, the agent asks the server every minute whether something waits
(`POST /api/v1/poll`, a single boolean) and checks in at once if so: queued commands, and an
agent update that is due (a version picked for the device, an admin request, or an approved
version the rollout policy releases for it). Agent updates can carry security fixes, so they
do not wait for the next regular check in. A version being installed or one that already
failed on the device does not trigger check ins. After failed polls the agent waits longer,
up to 5 minutes plus up to half of that as random delay, and returns to one minute with the
first answer. Failed check ins back off the same way: the interval doubles per failure up to
15 minutes, with up to 50 % random delay, so a fleet does not return in the same seconds
after a server outage. When the server answers 503 or 429 (overloaded, too many parallel
package downloads) the agent honors `Retry-After` (at most 30 minutes, plus jitter) for check
ins, polls and update downloads; a deferred update download is not reported as a failed
update and is offered again later. Restart and shutdown
delays count from when the command was sent in the console; a command that arrives late
still gives users at least one minute of warning.
