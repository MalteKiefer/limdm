# Vulnerabilities

The console page **Vulnerabilities** (main navigation, between Compliance
and Configuration; command palette "Open vulnerabilities") shows the known
CVEs of the devices in scope, one row per CVE. The data comes from the
matching described in [Patch management](patching.md#cve-data-for-debian-ubuntu-arch-and-alpine):
the distributions' security data for Debian, Ubuntu, Arch and Alpine (and
their derivatives such as Linux Mint, LMDE or Manjaro, through the feed of
the base), and the advisories of pending dnf and zypper updates on Fedora, RHEL and SUSE.
Without any CVE data switched on, Debian, Ubuntu, Arch and Alpine show
nothing; the page then links to **Settings, CVE data**.

## Findings and status

A finding is one CVE in one package of one device. It keeps:

* `first_seen`: when it first matched (again after a remediation),
* `last_seen`: the last package report or update status that confirmed it,
* `remediated_at`: when a later report no longer matched because the
  package changed or went away.

A finding that stops matching while its package is unchanged was never
real (corrected security data, or the source version of an upgraded
agent) and is dropped instead of remediated, so the remediation numbers
stay honest.

Status of a finding: **Remediated** when `remediated_at` is set,
**Risk accepted** while an active acceptance covers it, else **Active**.
A CVE is active when any of its findings is, else accepted when any is,
else remediated. The list shows active CVEs by default.

## Severity, CVSS and KEV

| Level | Debian urgency | Ubuntu priority | Arch severity | dnf and zypper advisories |
|---|---|---|---|---|
| Critical | | critical | Critical | Critical |
| High | high | high | High | Important |
| Medium | medium | medium | Medium | Moderate |
| Low | low | low, negligible | Low | Low |
| Unknown | not yet assigned | | Unknown | none |

A CVE takes the highest level its findings state. CVSS v3 base scores are
computed from the vectors in the Ubuntu OSV data (no NVD download); where
no source states a level, the score decides (9.0 critical, 7.0 high, 4.0
medium, above 0 low). Without an Ubuntu device (or a derivative matched
against Ubuntu, such as Linux Mint) the Ubuntu feed is skipped and no CVSS
scores exist. **Known exploited** comes from the optional CISA
KEV feed (Settings, CVE data), off by default.

## The page

* Cards: active CVEs by severity (donut with the total), remediation
  status of the findings (donut with the remediated share), the packages
  with the most active CVEs (a click filters the table). Each donut has a
  table view.
* Filters: search by CVE or package, severity, status, device, operating
  system, package, first detected from and to, known exploited only;
  clear. Every filter, the sort, the open CVE and full screen live in the
  URL.
* Table: CVE, vulnerable software (`+N` for more packages), severity as
  four segments plus its name, CVSS, known exploited, first detected,
  devices, status, row menu. Sort by CVE, severity, CVSS, first detected
  or devices; pages of 100 load while scrolling; column chooser; CSV
  export of the filtered list (up to 10000 rows).
* Detail sheet: severity, CVSS and vector, KEV entry (name, dates,
  ransomware use), first detection, sources, packages with installed and
  fixed versions, the devices with their status and dates, risk
  acceptances, links (CVE.org, NVD, the distribution trackers, KEV).

## Risk acceptance

Admins accept the risk of a CVE with a reason and a last valid day (at
most one year): for every device of their tenant (a global admin: every
tenant), or for one device and/or one package. An admin limited to tags
accepts for one device of the scope. While it is valid the covered
findings count as accepted, not active; once it expires or is revoked
(**Reopen**) they are active again without any further step. Accepting
and reopening are audited (`vulnerability.accept`, `vulnerability.reopen`).
Unlike compliance exceptions, acceptances do not go through four eyes
approval.

## API

`GET /api/v1/vulnerabilities`, `GET /api/v1/vulnerabilities/summary`,
`GET /api/v1/vulnerabilities/{cve}`, `POST .../{cve}/accept` and
`POST .../{cve}/reopen`; see [Admin API](admin-api.md). Read routes follow
the role, scope and tenant of the device list.
