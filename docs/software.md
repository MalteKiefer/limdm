# Software catalog (self service)

Users install approved software from the **Software** page of the LiMDM desktop app. They
need no admin rights: the desktop app hands the agent the ID of a catalog entry, never a
package name, and the agent installs only what the catalog offers that device.

```
LiMDM desktop app ── socket: install "firefox" ──► limdm-agent (root)
                                                     in this device's catalog?
                                                     Flatpak or package, first source that works
                                                     result to the app, inventory and audit
```

## Catalog

**Software** in the console lists the apps. A new installation starts with 25 well known
apps (Firefox, Thunderbird, Chromium, Google Chrome, LibreOffice, GIMP, Inkscape, VLC, Visual
Studio Code, Slack, Zoom, Spotify, Discord, Signal, Telegram, KeePassXC, Bitwarden, OBS Studio,
Audacity, Blender, Remmina, FileZilla, Nextcloud, Element, Postman). An update adds 53
more: 50 apps from Flathub (browsers like Brave, Vivaldi, Microsoft Edge, Mullvad Browser and
Tor Browser; office and notes like ONLYOFFICE, Obsidian, Joplin, Zotero, Okular; graphics and
video like Krita, darktable, Kdenlive, FreeCAD, KiCad, draw.io; chat like Mattermost,
Rocket.Chat, Zulip, Jitsi Meet; development like IntelliJ IDEA, PyCharm, VSCodium, DBeaver,
Wireshark, Podman Desktop; remote access like AnyDesk and RustDesk; and more), plus the VPN
clients **Mullvad VPN**, **Tailscale** and **NetBird** from their vendors' package
repositories. Apps deleted from the catalog are not added again.

Per app:

| Field | Meaning |
|---|---|
| Mode | **available**: users install and remove it; **on request**: users ask, an admin decides under **Requests** (see [Requests and decisions](#requests-and-decisions)); **required**: installed on every device that gets it |
| Sources | Flatpak ID (from Flathub or another managed remote) and Debian/Ubuntu or Fedora package names; SUSE devices use the Fedora names. **Install from** sets which comes first, the other is the fallback |
| Vendor package repository | for packages the distribution does not ship: repository URL (Debian: suite and components) and the vendor's ASCII armored signing key, for Debian and for Fedora (also used on SUSE) |
| Also installed when | further package names that count as installed (`firefox-esr`, `code`) |
| Blueprints | none: every device; otherwise only devices whose blueprint (or a parent) is listed |
| Icon | Flatpak apps get theirs from Flathub; upload a PNG for others |

## Vendor package repositories

Software that needs a system service (VPN clients, endpoint agents) does not work as a
Flatpak; it comes as a package from the vendor's own repository. An app can carry one
repository per family. The agent adds it right before installing the packages:

| Device | Source file | Key |
|---|---|---|
| Debian, Ubuntu | `/etc/apt/sources.list.d/limdm-app-<name>.sources` | `/etc/apt/keyrings/limdm-app-<name>.asc` |
| Fedora, RHEL family | `/etc/yum.repos.d/limdm-app-<name>.repo` | `/etc/pki/rpm-gpg/RPM-GPG-KEY-limdm-app-<name>` |
| SUSE (the Fedora repository) | `/etc/zypp/repos.d/limdm-app-<name>.repo` | as for Fedora, also imported with `rpm --import` |

The agent keeps the repository for updates while the app is installed and removes it with
the app. Unsigned repositories are refused. For
repositories that sign their metadata instead of each package (NetBird's RPM repository),
tick **the repository signs its metadata**; dnf and zypper then check `repo_gpgcheck`.
Package sources declared with a **Package sources** library item
([declarations.md](declarations.md#comlimdmrepositories-list)) are separate and never touch
these files.

## Installed is installed

An app counts as installed when any of its sources or further names is installed, whatever
way it got there: system Flatpak, a user's own Flatpak installation, or a distribution
package. Firefox installed as `firefox` (rpm) or `firefox-esr` (deb) is shown as installed
and never offered again as Flatpak. The device page (**Software**, **Catalog**) shows each
app's state and how it is installed.

## Taking over installed Flatpaks

Flatpaks that users or IT installed before the catalog can be taken over: **Software**,
**Catalog** lists Flatpaks installed on devices but not in the catalog, with the number of
devices; **Add selected to catalog** creates entries (mode available, icon from Flathub).
On a device page (**Software**, **Flatpak**) each app has **Add to catalog**. Devices that
have such an app count it as installed and managed right away; nothing is installed again.
Take over what you want to keep before switching on the Flathub filter: apps outside the
catalog get no updates once it is on.

## Adding apps from Flathub

**Software**, **Add app** searches Flathub. **Add to catalog** takes over name, summary,
category and icon; the entry opens for editing. The console asks Flathub through the
server, so browsers need no access to Flathub and the strict content security policy stays.

## Requests for apps outside the catalog

In the desktop app, **+** next to the search opens **Request another app**. Users search
Flathub (through the agent and the server; devices never talk to Flathub for this), pick an
app and add a note. The request shows under **Requests** in the console with **not in
catalog**:

* **Approve** creates a catalog entry in mode on request (or reuses the one for this
  Flatpak) and approves the device; **Approve and install** does the same and installs it.
* **Approve for everyone** creates the entry in mode available.
* **Deny** keeps the catalog as it is.

Users see their requests and the decision under **My requests**. Only Flathub and managed
remotes that are allowed can be requested; the agent allows 20 searches a minute and 20
unsent requests.

## Requests and decisions

A request goes to the server at once: the desktop app hands it to the agent, which checks
in right away. An admin decides under **Configuration, Software, Requests** or on the
**Requests** tab of the device:

* **Approve** (Freigeben): the user may install the app from the desktop app, as any
  available app. Nothing is installed without the user.
* **Approve and install** (Freigeben und installieren): the agent installs the app at once
  on the requesting device. The request then shows **installing**, **installed** or
  **install failed** with the error; a failed install is tried again after an hour.
* **Deny**: the user may ask again.

Timing: while a request is open the agent polls the server every 10 seconds instead of every
minute (only while the server answers, and for at most 24 hours per request). The poll
reports a decision made since the last check in, the agent checks in and shows the decision
as a desktop notification in the user's language, so the answer arrives within about 10 to
20 seconds. An install follows right after that check in; the user gets a notification with
the result, and the console shows it after the next check in (a few seconds after the
install ends). No connection stays open.

The API takes the same decision: `POST /api/v1/software/requests/{id}/approve` with the
optional body `{"install": true}`; without a body it approves only. The audit log records
`catalog.request.approve` or `catalog.request.approve+install` (also for `approve-all`).
Agents before 0.25 install every approved request on their own.

To install or remove software on every device of a blueprint without any request, use the
library items `com.limdm.packages` (install and remove lists of distribution packages) and
`com.limdm.flatpak` (Flatpak apps), see [declarations](declarations.md).

## Flatpak remotes

**Software**, **Remotes** lists the remotes IT manages, Flathub from the start:

* **allowed** remotes are added to the system installation of every device and kept enabled;
  **blocked** ones are disabled, in the system and in users' installations.
* **Only catalog apps**: with the store filter on (`restrict_flathub`), the remote gets a
  filter that allows runtimes and the catalog's apps from that remote only.
* **Found on devices, not managed** lists remotes devices have that IT does not manage
  (Fedora Flatpaks, FlatPark, own repositories) with the device count: **Take over** makes
  it a managed, allowed remote; **Block** disables it everywhere.
* **Add remote** takes a `.flatpakrepo` file, a repository or an `oci+https://` URL.

A catalog app installs its Flatpak from the remote chosen in its editor (Flathub by
default); Flatpaks taken over from devices keep the remote they came from. The agent applies
all of this every cycle, so changes users make to remotes do not last.

## Store policy

The store policy is set per blueprint with the library item **Software store policy**
(`com.limdm.softwarestore`):

```json
{"restrict_flathub": true, "stores_read_only": true, "only_managed_remotes": true}
```

`only_managed_remotes` disables every Flatpak remote that is not allowed under **Remotes**,
also in users' installations. Devices without such an item use the default under **Software**, **Settings**. Agents
before 0.10.1 report the item as invalid but keep working; the server applies the policy
either way.

* **Flathub offers only catalog apps.** A Flatpak remote filter (`deny *`, runtimes and the
  catalog's Flatpaks allowed) is set on the system's and every user's `flathub` remote, so
  users cannot install other Flathub apps with `flatpak --user` either.
* **GNOME Software and KDE Discover are read only.** A polkit rule
  (`/etc/polkit-1/rules.d/60-limdm-store-readonly.rules`) refuses installing, removing and
  repository changes through PackageKit and Flatpak for users. The agent runs as root and is
  not affected. The desktop app shows a note that software comes from the catalog.

AppImages are not supported on purpose: no signature checks, no updates, no central removal.

## Audit

Saving and deleting apps, settings and every request decision are in the audit log
(`catalog.*`, an approval with install as `catalog.request.approve+install`); requests also
record the user and their note. Installs and removals on a
device are device events.
