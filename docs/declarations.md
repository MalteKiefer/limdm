# Declaration reference

Every library item has one of these types. The console shows the example payload when you
create an item. Payloads are validated strictly on the server and again on the agent;
unknown fields are rejected. "List" types are merged across items of a blueprint, all others
take the item evaluated last ([concepts.md](concepts.md#merging)).

## Agent and compliance

### `com.limdm.agent`

```json
{"checkin_seconds": 300, "offline_lock_hours": 72}
```

* `checkin_seconds`: 30 to 86400.
* `offline_lock_hours`: lock the device after this many hours without server contact, 0 or
  absent disables it, at most 8760. See [desktop-login.md](desktop-login.md#offline-lock).

### `com.limdm.compliance`

```json
{"level": 1, "remediate": true, "exclude": [], "advisory": ["boot.secureboot"],
 "grace_hours": 72, "notify": true, "lock_after_hours": 0, "unlock_when_compliant": true}
```

Level 1 or 2, automatic remediation, documented exceptions, advisory checks, grace period
and actions. Details: [compliance.md](compliance.md).

### `com.limdm.privacy`

```json
{"network_info": false, "logged_in_users": false}
```

Without this declaration everything is collected; assign it to switch items off.
`network_info` covers IP addresses, DNS and routes (interfaces and MAC addresses are always
collected) as well as the public address and its location that the server records;
switching it off also deletes stored values. `logged_in_users` reports active sessions.

## Software

### `com.limdm.updates`

```json
{"mode": "security", "window": "02:00-05:00", "reboot": false}
```

`mode` is `off`, `security` or `all`. Updates run inside the local time window; with
`reboot` the device restarts in the window when the update requires it.

Optional patch management fields:

```json
{"mode": "security", "window": "22:00-04:00", "days": ["sat", "sun"], "hold": ["nginx"],
 "autoremove": true, "snap_refresh": "window"}
```

* `days`: weekdays (`mon` … `sun`) the window applies to; empty means every day. A window
  across midnight belongs to the day it starts on. Pending security updates count as
  handled until the next window (up to 8 days with `days`, 48 hours without).
* `hold`: packages kept at their installed version, also when `mode` is `off`. Debian
  family: `apt-mark hold` (installed packages only); Fedora family: `excludepkgs` in a
  libdnf5 drop in and in `/etc/dnf/dnf.conf` (dnf4), so dnf neither upgrades nor installs
  them; Arch: `IgnorePkg` in `/etc/pacman.conf`. Not supported on Alpine (pin versions in
  `/etc/apk/world`). Packages removed from the list are released again; values changed by
  hand in `dnf.conf` or `pacman.conf` are left alone.
* `autoremove`: after each update run remove packages nothing needs any more, old kernels
  included (`apt-get autoremove --purge`, `dnf autoremove`, pacman orphans).
* `snap_refresh` (only where snapd is installed): `hold` stops automatic snap refreshes,
  `window` sets `refresh.timer` to the update window and days. Removing it restores the
  snapd default.
* Restart notice and deferral (with `reboot`): the restart is scheduled
  `reboot_notice_minutes` ahead (default 5, at most 120) and announced in every desktop
  session. With `reboot_max_defers` (0 to 5, default 0) the desktop helper offers to
  postpone it by `reboot_defer_minutes` (15 to 480, default 60) that many times; it asks
  again shortly before each new time. After the last deferral the restart happens. Every
  deferral is reported as an event with the user name.

### `com.limdm.packages` (list)

```json
{"install": ["htop"], "remove": ["telnet"]}
```

### `com.limdm.flatpak` (list)

```json
{"remotes": [{"name": "flathub", "url": "https://dl.flathub.org/repo/flathub.flatpakrepo"}],
 "install": ["org.mozilla.firefox"], "remove": []}
```

Remotes go to the system installation by default. `"scope": "user"` adds or changes the
remote in the installation of every regular user (uid 1000 and above with a home).
`"disabled": true` keeps a remote but switches it off; a repository URL that differs from the
configured one is changed with `flatpak remote-modify`. Applications are installed system
wide.

The device page lists Flatpak applications and remotes of the system and of every user
(**Software**, **Flatpak**). **Edit**, **Disable** and **Enable** open a prefilled library
item; **Add remote** starts an empty one.

### `com.limdm.repositories` (list)

Package sources managed by LiMDM, and unmanaged sources to switch off.

```json
{"repositories": [
  {"name": "vendor", "family": "debian", "url": "https://repo.example.com/apt",
   "suites": "stable", "components": "main", "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."},
  {"name": "debian", "family": "debian", "url": "https://deb.debian.org/debian",
   "suites": "trixie trixie-updates", "components": "main",
   "key_file": "/usr/share/keyrings/debian-archive-keyring.gpg"}],
 "disable": ["netbird.list"]}
```

* `family`: `debian` (written as deb822 `.sources`), `fedora` (`.repo` in `/etc/yum.repos.d`)
  or `suse` (`.repo` in `/etc/zypp/repos.d`, key imported into rpm); each device only
  uses entries of its family.
* `url` must be https. Every source is signed: either an armored `key` (written to
  `/etc/apt/keyrings` or `/etc/pki/rpm-gpg`) or a `key_file` that already exists on the device
  under `/usr/share/keyrings`, `/etc/apt/keyrings`, `/etc/pki/rpm-gpg` or `/usr/lib/rpm/gnupg/keys`
  (SUSE distribution keys).
* The name `osquery` is reserved for the agent's own source.
* `disable` lists file names of unmanaged sources (`*.list`, `*.sources`, `*.repo`,
  `sources.list`). The agent keeps the original in `/var/lib/limdm/repo-backup`, switches
  the whole file off (`Enabled: no`, `enabled=0` or commented lines) and restores it once
  the name is no longer listed. Files managed by LiMDM cannot be disabled.

On the device page, **Edit** and **Disable** next to a reported source open a prefilled
item: Edit copies all entries of that file into managed sources (http becomes https,
check the URL) and disables the original. Assign the item to a blueprint to apply it.

## System

### `com.limdm.services` (list)

```json
{"enable": [], "disable": ["cups"]}
```

### `com.limdm.files` (list)

```json
{"files": [{"path": "/etc/motd", "content": "...", "mode": "0644", "owner": "root", "group": "root"}]}
```

Absolute, clean paths; merged by path. `owner` and `group` are names (default root).
Files removed from the declaration are deleted from the device: the agent remembers the
paths it wrote (from this version on) and removes the undeclared ones, except while a files
declaration is invalid.

On devices enrolled without `allow_scripts` (the opt in remote scripts need) only plain
text locations are accepted: `/etc/motd`, `/etc/issue`, `/etc/issue.net`, and files below
`/etc/motd.d`, `/srv`, `/etc/opt` and `/var/opt`. Everything else is refused, because
almost every other system path is read as code by something running as root (cron,
systemd, sudo, PAM, shell profiles, the dynamic linker, D-Bus, package manager hooks …).
There the agent also refuses files with an execute bit and paths with a symlink in any
component, the file itself included, so a link cannot redirect the write. With
`allow_scripts` any absolute path outside user writable directories works as before.

### `com.limdm.certificates` (list)

```json
{"certificates": [{"name": "corp-root", "pem": "-----BEGIN CERTIFICATE-----..."}]}
```

CA certificates only, added to the system trust store (`/usr/local/share/ca-certificates` with
`update-ca-certificates`, `/etc/pki/ca-trust/source/anchors` with `update-ca-trust`); removed
when no longer declared. In the library editor, **Add certificate file** takes a PEM or CRT
file (also a bundle) and appends its certificates to the list. The device page
(**Declarations**) and the desktop app (**Certificates**) show subject, issuer, validity and
SHA-256 fingerprint of what is installed.

### `com.limdm.sysctl` (list), `com.limdm.kernelmodules` (list)

```json
{"settings": {"vm.swappiness": "10"}}
{"block": ["firewire_core", "thunderbolt"]}
```

### `com.limdm.dns`, `com.limdm.ntp`, `com.limdm.proxy`

```json
{"servers": ["10.0.0.53"], "domains": ["corp.example.com"], "dnssec": true}
{"servers": ["ntp1.example.com", "ntp2.example.com"]}
{"http": "http://proxy.example.com:3128", "https": "http://proxy.example.com:3128", "no_proxy": "localhost,127.0.0.1,.example.com"}
```

DNS uses systemd-resolved; NTP uses systemd-timesyncd or chrony. Proxy values are written
to `/etc/profile.d`, `/etc/environment.d`, apt (`/etc/apt/apt.conf.d/60limdm-proxy`), dnf5
(`/etc/dnf/libdnf5.conf.d`), dnf4 (`proxy=` in `/etc/dnf/dnf.conf`, RHEL 9 family) and, on
SUSE, `PROXY_ENABLED`, `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in `/etc/sysconfig/proxy`
(read by zypper and YaST; the other lines of the file stay). They
also reach the agent itself: a systemd drop in for `limdm-agent.service` (followed by
`systemctl daemon-reload`) sets them for the next start, and the running agent applies them
at once to its own connections and to every tool it runs (pacman, apk, flatpak, dnf, apt).
Removing the declaration removes all of this and puts back the values `/etc/sysconfig/proxy`
had before; a `proxy=` in `dnf.conf` or a sysconfig key that was changed by hand stays. The values are checked against strict patterns because they end up in shell
files.

### `com.limdm.scripts` (list)

```json
{"scripts": [{"name": "cleanup", "interval_hours": 24, "body": "#!/bin/sh\njournalctl --vacuum-time=$KEEP",
              "params": {"KEEP": "30d"}, "timeout_minutes": 10}]}
```

Recurring root scripts, only on devices enrolled with `allow_scripts`. `params` are passed as
environment variables (names as for the script command, reserved ones such as `PATH` and
`LD_*` are refused), `timeout_minutes` is 1 to 240 (default 30). Each run is reported to the
server with exit code, start, end and truncated output and shown under **Script results**
on the device page.

### `com.limdm.network` (list)

```json
{"profiles": [{"name": "office", "type": "wifi", "ssid": "Corp", "security": "wpa2-enterprise", "eap": {"method": "tls", "ca_cert": "corp-root", "server_domain": "radius.example.com"}}]}
```

WLAN (WPA2/WPA3 personal and enterprise), wired 802.1X (EAP-TLS, PEAP, TTLS), WireGuard and
OpenVPN profiles as NetworkManager keyfiles; merged by profile name. EAP pins a CA of a
certificates item (`ca_cert`) and the server domain. EAP-TLS uses a device certificate the
server issues from its network CA. Secrets are masked in the console, the audit log, the
version history, the admin API, the desktop app and `limdm profiles`. Every field, the device side and the CRL for the RADIUS
server: [Network profiles](network.md).

### `com.limdm.printers`

```json
{"printers": [{"name": "office", "uri": "ipps://printer.example.com/ipp/print", "location": "2nd floor",
  "description": "Office printer", "default": true, "duplex": "two-sided-long-edge", "paper_size": "A4"}],
 "install_cups": false}
```

CUPS print queues, set up with `lpadmin` (separate arguments, no shell).

* The queue is named `limdm-<name>`; `name` uses lower case letters, digits, `.`, `_` and `-`.
  Queues with the `limdm-` prefix that are no longer declared are deleted, every other queue
  is left alone. Removing the item deletes all managed queues.
* `uri`: `ipp://` or `ipps://` gives a driverless IPP Everywhere queue (`lpadmin -m everywhere`).
  `socket://` and `lpd://` need a `ppd`. Credentials in the URI, spaces, quotes and control
  characters are refused.
* `ppd`: a model as `lpinfo -m` lists it (for example `drv:///sample.drv/generic.ppd`);
  `package` names the package that provides it and is installed first.
* `description` is the name print dialogs show (defaults to `name`), `location` is shown
  next to it. Both are one line of up to 128 characters.
* `duplex`: `one-sided`, `two-sided-long-edge` or `two-sided-short-edge` (`sides-default`);
  `paper_size`: a media name such as `A4`, `Letter` or `iso_a4_210x297mm` (`media-default`).
* `default`: the system default printer; at most one.
* Queues are never shared (`printer-is-shared=false`).
* A queue is only set up again when its entry changes: `-m everywhere` asks the printer for
  its capabilities and fails while it is off, then the agent retries on the next cycle.
* Devices without CUPS are skipped, unless `install_cups` is true: then the agent installs
  the `cups` package and starts the service.

## Security

### `com.limdm.firewall` (list)

```json
{"enforce": true, "allow": ["22/tcp"], "rules": [{"port": "5432/tcp", "from": "10.0.0.0/8"}]}
```

`allow` opens ports for everybody, `rules` opens a port only for a source network (CIDR)
or address. ufw (Debian family) gets `ufw allow from … to any port … proto …`, firewalld a
rich rule in the default zone. The agent keeps the rules in line with the declaration also
while the firewall is active: new rules are added first, rules it added earlier and that
are no longer declared are deleted. Rules added by hand or by agents before 0.16 are never
deleted. Without a firewall declaration (or with `enforce` off) the rules are left as they
are, so a dropped item cannot lock out SSH.

### `com.limdm.ssh` (list), `com.limdm.banner`

```json
{"options": {"AllowGroups": "ssh-users", "Banner": "/etc/issue.net"}}
{"issue": "Authorized use only.", "motd": "Managed by IT."}
```

Only sshd options that cannot weaken the compliance baseline are accepted (for example
`AllowGroups`, `Banner`, `Ciphers`, `Port`); `PermitRootLogin` and similar are rejected.
Changes are tested with `sshd -t` and rolled back on error.

### `com.limdm.screenlock`

```json
{"idle_seconds": 300}
{"idle_seconds": 300, "hide_users": true, "allow_autologin": false}
```

Locks the screen after `idle_seconds` (30 to 3600) and before suspend, on every desktop, in a
way users cannot change:

| Desktop | How |
|---|---|
| GNOME, Budgie, Cinnamon, MATE | dconf system database with locked keys |
| KDE Plasma | `/etc/xdg/kscreenlockerrc`, immutable through KDE kiosk (`[$i]`) |
| Xfce | xfconf system defaults with locked properties (xfce4-screensaver) |
| sway, Hyprland, river, labwc, niri, Wayfire | `swayidle` with `swaylock`; for sway also `/etc/sway/config.d` |
| i3, bspwm, openbox, awesome, herbstluftwm | `xss-lock` with `i3lock` and the X screensaver timeout |

For compositors and window managers the agent starts its own locker in every session (user
unit `limdm-idle-lock`, or directly where the user's service manager is out of reach) and
starts it again within a minute when it is ended. Only that locker counts, not any process
with a locker's name; on X11 the screensaver timeout is set again every minute, so
`xset s off` does not help. Like every remediation this only happens with `remediate` on
and `desktop.screenlock` not excluded. The check fails for a session without the locker, for
desktops LiMDM cannot enforce (COSMIC, LXQt) and for Xfce without xfce4-screensaver. Missing
tools are installed.

Login screen privacy is optional: without `hide_users` and `allow_autologin` the login
manager is left as it is. With `"allow_autologin": false` automatic and timed login are
switched off in GDM (`AutomaticLoginEnable`, `TimedLoginEnable`), SDDM and LightDM, in their
drop-in directories and in the main files (`/etc/sddm.conf`, `/etc/lightdm/lightdm.conf`),
which would otherwise win. `"hide_users": true` hides the user list (GDM
`disable-user-list`, LightDM `greeter-hide-users`, SDDM does not remember the last user).
LightDM guest sessions are off whenever the login screen is managed. Agents before 0.9.2
reject the two keys as unknown, so add them only after the fleet runs 0.9.2.

### `com.limdm.localusers` (list)

```json
{"users": [{"name": "svc-backup", "uid": 1500, "full_name": "Backup", "groups": ["backup"],
            "shell": "/bin/bash", "locked": false, "authorized_keys": ["ssh-ed25519 AAAA... backup@example.com"]}]}
```

Local accounts that must exist; items are merged by name. A missing account is created
with a home (`uid` is used only then, 1000 to 60000; an existing account is never
renumbered) and without a password, so it signs in with its SSH keys. Shell and groups are
kept in line: declared groups are added, groups an earlier version of the declaration
added and that are no longer listed are removed, other memberships stay. `locked` locks
the account and ends its sessions; unlocking undoes only a lock the declaration set.
`authorized_keys` are plain public keys (no options); they are written root owned to
`/etc/ssh/limdm_authorized_keys/<user>`, never into the home, and a drop in
(`00-limdm-keys.conf`) makes sshd read them besides `~/.ssh/authorized_keys`. This drop in
takes precedence over an `AuthorizedKeysFile` set with `com.limdm.ssh`.

Accounts removed from the declaration are locked, never deleted, and their key file is
removed. The imperative user commands on the device page keep working.

### `com.limdm.dconf` (list)

```json
{"settings": {"/org/gnome/desktop/interface/clock-show-seconds": "true",
              "/org/gnome/desktop/background/picture-uri": "'file:///usr/share/backgrounds/corp.png'"},
 "locks": ["/org/gnome/desktop/background/"]}
```

Defaults for every user of GNOME and other dconf based desktops. Keys are full paths, values
GVariant text (strings in single quotes) on one line. `locks` lists keys or directories
(ending in `/`) users cannot change. Written to `/etc/dconf/db/local.d/70-limdm-custom`
and its locks file next to the screen lock settings, compiled with `dconf update`; items
are merged by key, locks are joined. Removing the declaration removes both files.

### `com.limdm.sudo` (list)

```json
{"rules": [{"name": "developers", "principals": ["%developers"], "run_as": "",
            "commands": ["/usr/bin/apt-get update", "/usr/bin/systemctl restart nginx"], "nopasswd": false}],
 "timestamp_timeout": 5}
```

* One drop in per rule, `/etc/sudoers.d/70-limdm-<name>` (mode 0440). Names use `a-z`,
  `0-9`, `_` and `-` (sudo ignores files with dots).
* `principals`: users or `%groups`; `ALL` is not allowed. `run_as`: empty (root), a user or `ALL`.
* `commands`: absolute paths with plain arguments, or `ALL`. Sudoers metacharacters
  (`,` `:` `=` `\` `!` `*`) are rejected, so one entry is exactly one command without wildcards.
* Every file is checked with `visudo -c -f` before it is installed. If the whole
  configuration fails `visudo -c` afterwards, the managed files are removed again.
* The compliance defaults (`use_pty`, `logfile`) live in `/etc/sudoers.d/60-limdm`.

### `com.limdm.polkit` (list)

```json
{"rules": [
  {"name": "network", "actions": ["org.freedesktop.NetworkManager.*"], "groups": ["netdev"],
   "result": "yes", "local_active_only": true},
  {"name": "printers", "actions": ["org.opensuse.cupspkhelper.mechanism.*"], "groups": [],
   "result": "auth_self_keep", "local_active_only": true}]}
```

* Written to `/etc/polkit-1/rules.d/60-limdm-<name>.rules`; polkitd reloads by itself.
* `actions`: action IDs, or a namespace with `.*` (at least three segments).
* `groups`: empty means every user. `local_active_only`: only the user at the device.
* `result`: `yes`, `no`, `auth_self`, `auth_self_keep`, `auth_admin`, `auth_admin_keep`.
* `org.freedesktop.policykit.*` (pkexec) cannot be granted.

Typical uses: let users manage networks, printers, time zone or mount disks without admin
rights.

### `com.limdm.softwarestore`

```json
{"restrict_flathub": true, "stores_read_only": true}
```

Store policy of the software catalog per blueprint; see [software.md](software.md#store-policy).

### `com.limdm.bootloader`

```json
{"superuser": "bootadmin", "password": "a new password with 12 or more characters", "unrestricted": true}
```

* When the item is saved, the console replaces `password` with `password_pbkdf2`
  (PBKDF2 SHA-512, 100000 iterations, the `grub-mkpasswd-pbkdf2` format). The clear text is
  never stored and never sent to devices. To change it, enter `password` again.
* `unrestricted`: the default boot entries start without password; editing entries and the
  GRUB console need it.
* Debian and Ubuntu: `/etc/grub.d/01_limdm_password`, `--unrestricted` in `10_linux`,
  `grub-mkconfig`, `grub.cfg` set to 0600. Fedora: `/boot/grub2/user.cfg` in the format of
  `grub2-setpassword` (superuser `root`).

### `com.limdm.diskencryption`

```json
{"escrow": true, "rotate_after_view": true, "require_all": true, "exclude": ["/boot"]}
```

LUKS recovery key escrow. See [disk-encryption.md](disk-encryption.md).

`"tpm2": {"pcrs": [7], "pin": false, "require": true}` also binds every LUKS volume to the
TPM 2.0 with `systemd-cryptenroll` when its recovery key is escrowed; the recovery key stays
valid. `pcrs` are 0..23 (default 7), `pin` asks the user for a PIN at boot, `require` makes
the check `disk.tpm` fail while a volume is not bound. See
[disk-encryption.md](disk-encryption.md#tpm-unlock).

Without `require_all` the check `disk.encryption` only looks at `/`. With it, every local
volume must be on LUKS except the mount points in `exclude`; an entry covers everything below
it (`/boot` also covers `/boot/efi`). The device page marks excluded volumes. The library
item "Disk encryption on all volumes, /boot excluded" is a ready made start.

### `com.limdm.login`

```json
{"issuer": "https://accounts.google.com", "client_id": "...", "client_secret": "...",
 "allowed_domain": "example.com", "mode": "session", "reverify_hours": 720, "grace_hours": 168}
```

Always name the `mode`. An item without `mode` but with `local_password` counts as written
before 0.11 and runs in login mode.

Desktop login with SSO. See [desktop-login.md](desktop-login.md).

### `com.limdm.osversion` (list)

```json
{"min": {"ubuntu": "24.04", "debian": "12", "fedora": "42"}}
```

Minimum versions for the `os.supported` check.
