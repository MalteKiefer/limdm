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
collected), `logged_in_users` reports active sessions. The public address and its location
are recorded by the server and are not affected ([security.md](security.md#privacy)).

## Software

### `com.limdm.updates`

```json
{"mode": "security", "window": "02:00-05:00", "reboot": false}
```

`mode` is `off`, `security` or `all`. Updates run inside the local time window; with
`reboot` the device restarts in the window when the update requires it.

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

* `family`: `debian` (written as deb822 `.sources`) or `fedora` (`.repo`); each device only
  uses entries of its family.
* `url` must be https. Every source is signed: either an armored `key` (written to
  `/etc/apt/keyrings` or `/etc/pki/rpm-gpg`) or a `key_file` that already exists on the device
  under `/usr/share/keyrings`, `/etc/apt/keyrings` or `/etc/pki/rpm-gpg`.
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
{"files": [{"path": "/etc/motd", "content": "...", "mode": "0644"}]}
```

Absolute, clean paths; merged by path.

### `com.limdm.certificates` (list)

```json
{"certificates": [{"name": "corp-root", "pem": "-----BEGIN CERTIFICATE-----..."}]}
```

CA certificates only, added to the system trust store.

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
to `/etc/profile.d`, `/etc/environment.d` and the apt or dnf configuration; they are checked
against strict patterns because they end up in shell files.

### `com.limdm.scripts` (list)

```json
{"scripts": [{"name": "cleanup", "interval_hours": 24, "body": "#!/bin/sh\njournalctl --vacuum-time=30d"}]}
```

Recurring root scripts, only on devices enrolled with `allow_scripts`.

## Security

### `com.limdm.firewall` (list)

```json
{"enforce": true, "allow": ["22/tcp"]}
```

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
```

GNOME idle lock, locked against user changes.

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

Without `require_all` the check `disk.encryption` only looks at `/`. With it, every local
volume must be on LUKS except the mount points in `exclude`; an entry covers everything below
it (`/boot` also covers `/boot/efi`). The device page marks excluded volumes. The library
item "Disk encryption on all volumes, /boot excluded" is a ready made start.

### `com.limdm.login`

```json
{"issuer": "https://accounts.google.com", "client_id": "...", "client_secret": "...",
 "allowed_domain": "example.com", "local_password": true, "reverify_hours": 168}
```

Desktop login with SSO. See [desktop-login.md](desktop-login.md).

### `com.limdm.osversion` (list)

```json
{"min": {"ubuntu": "24.04", "debian": "12", "fedora": "42"}}
```

Minimum versions for the `os.supported` check.
