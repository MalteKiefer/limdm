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
Audacity, Blender, Remmina, FileZilla, Nextcloud, Element, Postman). Apps deleted from the
catalog are not added again.

Per app:

| Field | Meaning |
|---|---|
| Mode | **available**: users install and remove it; **on request**: users ask, an admin approves under **Requests**, then the device installs it by itself; **required**: installed on every device that gets it |
| Sources | Flatpak ID from Flathub and Debian/Ubuntu or Fedora package names; **Install from** sets which comes first, the other is the fallback |
| Also installed when | further package names that count as installed (`firefox-esr`, `code`) |
| Blueprints | none: every device; otherwise only devices whose blueprint (or a parent) is listed |
| Icon | Flatpak apps get theirs from Flathub; upload a PNG for others |

## Installed is installed

An app counts as installed when any of its sources or further names is installed, whatever
way it got there: system Flatpak, a user's own Flatpak installation, or a distribution
package. Firefox installed as `firefox` (rpm) or `firefox-esr` (deb) is shown as installed
and never offered again as Flatpak. The device page (**Software**, **Catalog**) shows each
app's state and how it is installed.

## Store policy

**Software**, **Settings**:

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
(`catalog.*`); requests also record the user and their note. Installs and removals on a
device are device events.
