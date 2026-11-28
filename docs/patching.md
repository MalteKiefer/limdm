# Patch management

How LiMDM installs updates: rules per update source, update rings with
waves, what the agent reports, the fleet view of security updates and
CVEs, and rollback. The declaration fields are in
[declarations.md](declarations.md#comlimdmupdates); the console pages are
under **Updates** and on the device page (tab **Updates**).

## Rules per source

`com.limdm.updates` has a simple `mode` (`off`, `security`, `all`) and,
for finer control, `rules`: one rule per source with its own `mode`
(`off`, `notify`, `install`), `window`, `days` and `rings`. When `rules`
are present they replace `mode` (set `mode` to `off` or leave it empty).

| Source | What it is |
|---|---|
| `os_security` | security updates of the distribution |
| `os_all` | every update of the distribution (security included) |
| `third_party` | vendor repositories: apt sources, dnf and zypper repositories that are not the distribution's own; `repos` limits it |
| `flatpak` | system wide Flatpak apps and runtimes of every remote (Flathub and others) |

`notify` installs nothing; the pending updates appear in the console.
`install` runs once a day inside the window, or with `rings` once per
wave (below).

The old `mode` maps to rules, so existing declarations keep their
behaviour: `security` is `os_security` install, `all` is `os_all`,
`third_party` and `flatpak` install (what `all` always did: apt and dnf
upgraded every repository, then Flatpak).

### What counts as third party

* Debian family: the apt origin of the candidate (as `apt-get -s upgrade`
  prints it). `Debian`, `Debian-Security`, `Debian Backports`, `Ubuntu`,
  `UbuntuESM`, `UbuntuESMApps`, `Raspbian`, `Raspberry Pi Foundation`,
  `linuxmint` and origins that start with the os-release ID are the
  distribution; everything else is third party. `repos` matches origins
  (shell glob, for example `Docker*`).
* Fedora and RHEL family: the dnf repo ID. `fedora`, `updates`,
  `updates-testing`, `baseos`, `appstream`, `extras`, `crb`,
  `powertools` and the like, `rhel-*` and Oracle's `ol<N>_*` are the
  distribution; EPEL and vendor repos are third party. `repos` are repo
  IDs (glob).
* openSUSE Leap, SLES, SLED: zypper repo aliases `repo-*`, `openSUSE*`,
  `SLE*`, `SUSE*` and repositories on download.opensuse.org,
  cdn.opensuse.org or updates.suse.com, except OBS project repositories
  (`/repositories/` in the URL). `repos` are aliases.
* Arch, Alpine, openSUSE Tumbleweed: no third party source the agent can
  separate. `os_all` updates everything, `third_party` reports
  `unsupported`.

### How a source is installed

| Source | Debian, Ubuntu | Fedora, RHEL | openSUSE, SLES | Arch, Alpine, Tumbleweed |
|---|---|---|---|---|
| `os_security` | `unattended-upgrade` | `dnf upgrade --security` | `zypper patch --category security` | full upgrade (no security channel) |
| `os_all` | `apt-get upgrade --with-new-pkgs` (`apt-get dist-upgrade` on Proxmox VE, [proxmox.md](proxmox.md)), or `apt-get install --only-upgrade name=version` for the distribution's packages when third party updates are pending | `dnf upgrade`, or `dnf upgrade --repo=<distribution repos>` | `zypper update`, or `zypper update --repo <aliases>` | full upgrade |
| `third_party` | `apt-get install --only-upgrade name=version` of the matching packages | `dnf upgrade --repo=<matching repos>` | `zypper update --repo <matching aliases>` | unsupported |
| `flatpak` | `flatpak update --system` | same | same | same |

### Honest results

The agent compares the installed package versions before and after a
run. A run that changed nothing is reported as `no_updates`, never as
installed. Results per source: `installed` (with the number of changed
packages), `no_updates`, `failed` (with the last output lines) and
`unsupported`. The mail complaints of `unattended-upgrade` ("can not send
mail") are filtered from the output.

## Update rings

Rings stage updates: a pilot ring installs first, the broad fleet later.

* Rings are ordered per tenant (`position`, lowest first). A device
  belongs to the first ring it matches: a device tag, a directory group
  of its primary user, a blueprint (the device's effective blueprint or
  one it inherits from) or `all devices` (every device not in an earlier
  ring). The server works this out at every check in; the ring page
  counts devices by their last check in.
* A **wave** starts in the first ring, by an admin (**Start a new
  wave**) or every `wave_days` days (first ring only). The first ring has
  it at once.
* Ring N gets the newest wave that is at least its `deferral_days` old
  (counted from the start of the wave) and that ring N-1 already has. A
  paused ring N-1 stops the rollout to ring N and every ring after it.
* With `require_approval` the wave stops before the ring until an admin
  approves it; approving lets the wave the ring before has through.
* **Pause** stops installs in a ring at once (the gate the devices get is
  closed) and holds up later rings. **Resume** opens it again.
* The server moves waves along every five minutes and right after a
  change; every step is audited (`update_wave.start`, `update_ring.wave`,
  `update_ring.pause`, `update_ring.resume`, `update_ring.approve`,
  `update_ring.save`, `update_ring.delete`).

A rule with `rings` installs once per wave that reached the device's
ring, in its window; a failed run is retried a day later. A device in no
ring is not gated: it installs in every window as without rings. A rule
without `rings` ignores the rings (for example security updates every
night, everything else per wave).

### Limits

A wave is a point in time, not a frozen set of package versions: a device
installs what its repositories offer when it runs the wave. A broad ring
seven days behind the pilot therefore also gets updates published in
those seven days. Freezing versions needs a repository snapshot (for
example a local mirror per ring, delivered with `com.limdm.repositories`).
Older agents ignore the gate.

## Pending updates and the device view

The agent lists the pending updates its package manager knows, refreshed
at most hourly (the same refresh the check `updates.security` uses, no
extra downloads): package, installed and candidate version, origin
(apt origin, repo ID, Flatpak remote), source, security flag, severity
and CVE IDs where the advisories have them:

* Fedora and RHEL: `dnf updateinfo list --security` (severity) and
  `--with-cve` (CVE IDs).
* openSUSE and SLES: needed security patches from `zypper list-patches
  --category security` with severity and the CVE IDs of their issue
  list (patches appear as entries of their own).
* Debian and Ubuntu: apt knows whether a candidate comes from a security
  archive, not which CVEs it fixes. CVE IDs and severity come from the
  server side import below.
* Arch and Alpine: no security information; every pending update counts
  as a security update for the checks. CVE IDs come from the server side
  import below.

The device tab **Updates** shows the ring, the last run per source, the
pending list and the rollback actions.

## Fleet view and CVEs

**Updates, Security** shows the devices with security updates, the open
CVEs (a CVE counts as open while a pending update fixes it) with their
highest severity and the devices each one affects, and the pending
updates per package. **Package versions** lists the installed versions of
one package across the fleet.

For Fedora, RHEL and SUSE the CVE data is what the devices' package
managers already know. For Debian, Ubuntu, Arch and Alpine it comes from
the import below. CVEs without a fix available are not shown.

## CVE data for Debian, Ubuntu, Arch and Alpine

apt, pacman and apk do not know which CVEs an update fixes. With a feed
switched on under **Settings, CVE data** (each feed is off by default, it
downloads from third parties), the leading server instance imports the
distribution's security data once a day and matches it against the
package versions the devices already report. Nothing is requested on the
devices.

| Distribution | Source (default URL) | What is kept |
|---|---|---|
| Debian 10 to 14 | Debian Security Tracker JSON, `https://security-tracker.debian.org/tracker/data/json` | resolved CVEs per release (codename), source package, fixed version, urgency (`low`, `medium`, `high`); `unimportant` and end of life entries are left out |
| Ubuntu | OSV export by Canonical, `https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip` | `UBUNTU-CVE` records per release (`24.04`, ...), source package, fixed version, Ubuntu priority; Ubuntu Pro releases are left out |
| Arch | Arch Security Tracker, list of AVGs, `https://security.archlinux.org/issues/all.json` | groups with status `Fixed`: every package and CVE of the group, fixed version, severity (`Unknown` is left empty); no release dimension (rolling) |
| Alpine | secdb, `https://secdb.alpinelinux.org` + `/<branch>/main.json` and `/community.json` | `secfixes` per branch: origin package, fixed version, CVE IDs (`0`, never affected, is left out); no severity |

Why these sources:

* Ubuntu: OSV is maintained by Canonical, JSON with one record per CVE,
  plain fixed versions per release and the Ubuntu priority. OVAL is XML
  per release and the USN database has no priorities.
* Arch: the AVG list (`issues/all.json`) holds packages, fixed version,
  severity and CVEs in one record. The ASA advisories do not list the
  fixed version per package.
* Alpine: only the branches the Alpine devices report are downloaded:
  `VERSION_ID` 3.20.3 is `v3.20`, a development snapshot
  (`3.21_alpha…`) is `edge`. With no Alpine device the import records
  that as its error.
* Feed cost: a distribution feed is downloaded only while at least one
  device in service runs that distribution (`os_id`). A switched on feed
  without such a device shows **no devices, skipped** in the feed state
  and costs nothing; the Ubuntu export alone is far beyond 500 MB a day.
* CISA KEV (optional, off by default): the Known Exploited
  Vulnerabilities list,
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
  a small JSON file imported with the same switch, URL, limit and state
  as the distribution feeds. It marks known exploited CVEs on the
  [Vulnerabilities](vulnerabilities.md) page.

Limits and failures:

* The URLs (https only; for Alpine the secdb base address) and the
  download limit per feed (1024 MB when empty, all Alpine files of one
  import together) are settings, so a mirror works. Downloads have a 30
  minute timeout; the Debian and Arch JSON are parsed as streams, the
  Ubuntu zip goes to a temporary file and each record (at most 4 MB) is
  read on its own.
* A failed import (unreachable, too large, no data) keeps the last data
  and records the error; **Updates, Security** shows each feed, whether
  it is on, the age of its data, the last error and **Refresh now**
  (admins of the whole installation, imports the switched on feeds; audited as
  `cve_feeds.refresh`). After a failure the next attempt is six hours
  later. Switching a feed off stops its imports; its last data stays.

Matching:

* A device matches when its installed version is older than the fixed
  version of its release, compared with the package manager's own rules:
  * Debian and Ubuntu: dpkg (epoch, `~` before everything, letters
    before other characters, digit runs as numbers);
  * Arch: pacman's `vercmp` (epoch, pkgver segments split at
    separators, numeric segments newer than alpha ones, a trailing alpha
    segment older than the end, pkgrel only when both versions have one);
  * Alpine: apk (digits, an optional letter, `_alpha`, `_beta`, `_pre`,
    `_rc` before the release, `_cvs`, `_svn`, `_git`, `_hg`, `_p` after
    it, then `-rN`).
* Package names: Debian and Ubuntu track source packages, so the agent
  reports the source package of every Debian package
  (`dpkg-query ${source:Package}` or osquery). Alpine tracks origin
  packages: the agent reads them from `apk list -I` (`apk info -v` as
  fallback, without origin). Arch tracks package names; the agent also
  reports the pkgbase of split packages (`%BASE%` in pacman's local
  database), and both are matched. Older agents send no source package:
  their package name is used, which misses packages such as `libssl3`
  (source `openssl`) or `libcrypto3` (origin `openssl`).
* Versions: the trackers list fixed source versions, and a Debian binary
  package can carry its own version (`postgresql` 17+278+deb13u1 is built
  from `postgresql-common` 278+deb13u1). The agent reports the source
  version when it differs (`dpkg-query ${source:Version}`, or the version
  osquery shows after the source name) and the matching compares it.
  Older agents send none: their binary version stands in, which can show
  a CVE as open that is fixed. Once an upgraded agent reports the source
  version, such a finding is dropped (not counted as remediated). Alpine
  origin and Arch pkgbase versions are the package's own version.
* Matches are refreshed after each import, once at every server start,
  and whenever a device sends a new package list or update status; the
  CVEs of pending dnf and zypper updates are recorded as findings too.
  Each finding keeps its history, see [Vulnerabilities](vulnerabilities.md).
  Open matches show in the fleet CVE view, as **Known
  vulnerabilities** on the device tab, and as CVEs on the pending updates
  of the same package.
* Releases: Debian by `VERSION_ID` (10 buster to 14 forky), Ubuntu by
  `VERSION_ID`, Alpine by branch, Arch without.
* Derivatives are matched against the feed of their base, from `ID_LIKE`
  and the base codename the agent reports (agents before 0.24.0 send
  neither, so their derivatives stay unmatched):
  * `ID_LIKE` names ubuntu (Linux Mint, Pop!_OS, Zorin, elementary OS,
    TUXEDO OS, KDE neon, AnduinOS ...): the Ubuntu feed, release from
    `UBUNTU_CODENAME` (jammy 22.04, noble 24.04, plucky 25.04, questing
    25.10, resolute 26.04). An unknown or missing codename is not matched.
  * `ID_LIKE` names debian but not ubuntu (LMDE): the Debian feed by
    `DEBIAN_CODENAME`, when it is a known release (buster to forky).
  * `ID_LIKE` names arch or manjaro (Manjaro, EndeavourOS, Garuda,
    CachyOS, BigLinux): the Arch feed.
  * Not matched: Kali (rolling on Debian testing), Raspberry Pi OS with
    `ID=raspbian`, postmarketOS and every other derivative.

  A feed downloads when only derivatives of its base are in service. Such
  findings show **via Ubuntu feed** (or Debian, Arch) on the device and in
  the vulnerability's device list. A derivative that rebuilds packages of
  its base with its own versions (Pop!_OS, elementary OS, Manjaro's held
  back or patched packages) can show a CVE as open that its build fixed,
  or miss one in a package the base does not ship; take these findings as
  a pointer, not a verdict.

## Compliance

`updates.security_age` fails when security updates have been pending
longer than `security_max_days` of `com.limdm.updates` (14 days when
unset). The agent remembers since when security updates are pending
without a break. `updates.security` and `updates.auto` stay as before;
`updates.auto` passes when a rule installs OS updates.

## Rollback

Two device commands, admins only:

* `package_hold` keeps a package at its installed version
  (`apt-mark hold`, `dnf versionlock`, `zypper addlock`; dnf4 needs the
  versionlock plugin) or releases it again (`release`). Arch and Alpine
  are not supported. For a hold on many devices use `hold` in
  `com.limdm.updates`.
* `package_downgrade` installs an older version (the given one, or the
  highest available below the installed one) and holds the package
  there, so the next run does not upgrade it again. Debian family
  (`apt-get install --allow-downgrades name=version`) and dnf
  (`dnf downgrade`) only, and only when the older version is still in a
  configured repository. With four eyes approval on it needs a second
  admin, like wipe.
