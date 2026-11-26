# Console

The web console runs on the console listener (`LIMDM_PUBLIC_URL`). This page goes through
every page of the navigation in its order, names what it shows and which actions it offers,
and ends with what each role may do. Labels are the English labels of the console; switch
the language with **DE** and **EN** at the bottom of the sidebar.

The sidebar groups the pages:

| Group | Pages |
|---|---|
| (top) | Overview, Devices, Compliance |
| Configuration | Library, Directory, Blueprints, Enrollment, Agents, Software |
| Evidence | Audit log, Approvals |
| Administration | Users, Settings, API tokens, Company, Tenants, Network certificates |
| (bottom) | Help, your profile, language, **Sign out**, tenant switcher |

Pages a role cannot use are hidden from its navigation and answer 403 when opened directly
([Roles and permissions](#roles-and-permissions)). Every state change is a POST with a CSRF
token; errors show inside the layout with **Technical detail** and a back link. Page headers
carry a **?** link to the matching documentation.

## Overview

The landing page (`/`).

* **Fleet status**: active devices by state (**Compliant**, **In grace period**,
  **Non-compliant**, **Stale**, **Pending**) with **What the states mean**.
* **Compliance trend**: share of compliant devices, daily, 30 days.
* **Operating systems**: the OS mix of the fleet.
* **Most failing checks**: checks with the most failing devices; each count opens the
  device list filtered to those devices.
* **Recent activity**: the newest audit entries.
* Actions: **Evidence CSV** (compliance export) and **Enroll device** (opens Enrollment).

**First steps** is a checklist for admins. It stays until all five steps are done or
**Hide** is pressed (remembered in this browser for a year):

| Step | Done when | Link |
|---|---|---|
| Company settings | a company name is set | Settings, Branding |
| Sign in method | OIDC issuer and client ID are set | Settings, SSO |
| First enrollment token | a token was created or a device exists | Enrollment |
| First blueprint | a blueprint other than `default` exists | Blueprints |
| First device | a device enrolled | Enrollment |

## Devices

`/devices` lists every device in the scope of the account: host name, status, system,
blueprint, tags, agent version, memory and last seen.

### Filters

All filters combine (AND). Each active filter shows as a chip that removes only itself.

| Filter | Query key | |
|---|---|---|
| **Search** | `q` | text in host name, OS, device ID, blueprint and tags |
| **Status** | `status` | `compliant`, `in grace`, `non-compliant`, `stale`, `pending`, `retired` |
| Tag | `tag` | devices with this tag |
| **Package** | `pkg` | installed package from the inventory, see below |
| Catalog app installed | `app` | set by the counts on the Software page |
| Flatpak installed | `flatpak` | |
| Flatpak remote | `remote` | |
| Blueprint | `blueprint` | set by the counts on the Blueprints page |
| Agent version | `agent` | set by the counts on the Agents page |
| Failing check | `failing` | set by the counts on Overview and Compliance |

The package filter is a name, or a name, an operator and a version: `openssl` matches any
version, `openssl < 3.0.13` compares versions (operators `<`, `<=`, `=`, `!=`, `>=`, `>`).
Versions compare by their runs of digits and the epoch is ignored, so `3.0.2-0ubuntu1.15`
is lower than `3.0.13` and `3.0.13-1~deb12u1` is higher; letters and the Debian `~` ordering
are not evaluated. Every device count elsewhere in the console opens this list with the
matching filter. Search, status counts and paging run in the database; the list shows 200
devices per page (**Previous**, **Next**).

### Exports

**Inventory CSV** (hardware inventory per device) and **Packages CSV** (one row per
installed package and device) cover the devices in the scope. Exports are for admins and
auditors; every export is audited with its SHA-256.

### Bulk actions

Select devices with the checkboxes (or all shown) and pick an action:

* **Run**: **Sync now**, **Install all updates**, **Reboot now**, **Lock device**,
  **Unlock device** (admins and helpdesk), **Update agent to the newest version** (admins).
* **Software**: **Install** or **Remove** a catalog app (admins).
* **Tags**: **Add tag**, **Remove tag** (admins). Tags are blueprint conditions.
* **Script**: **Run script** with **Parameters** and a timeout on every selected device
  that allows scripts (admins). With four eyes approval on, one request per device goes to
  Approvals.

Lost mode and wipe are single device actions.

### Device page

The header shows host name and state. **Sync now** (admins and helpdesk) asks for a check in;
**Edit device details** (admins) sets the **Blueprint**, the **Tags**, the **Primary user**
from the directory and the **Desktop users** (`username email [admin]` per line,
[desktop-login.md](desktop-login.md)). Notices show a tamper report, a compliance lock and
a running grace period.

**More actions** groups the actions by impact; dialogs ask before irreversible or
disruptive steps:

| Group | Actions | Who |
|---|---|---|
| Updates | **Install all updates**, **Send message…** | admin, helpdesk |
| | **Update agent…** (pick an approved or fetched version) | admin |
| Power | **Reboot now**, **Reboot later…**, **Shut down now**, **Shut down later…** | admin, helpdesk |
| Security | **Lock device** (blocks logins until unlocked, data stays), **Unlock device** | admin, helpdesk |
| | **Lost mode…** (lock plus message; only IT can open the disk after power off), **End lost mode** | admin |
| | **Retire device…** (ends management, revokes the certificate, data stays) | admin |
| | **Wipe device…** (erases all data for good) | admin |
| Agent | **Run script…**, **Remote shell…**, **Allow uninstall for 1 hour** | admin |

Lost mode and wipe are confirmed by typing the host name. With four eyes approval on,
lost mode, wipe and scripts go to Approvals first ([security.md](security.md#four-eyes-approval)).

Tabs:

| Tab | Content |
|---|---|
| Overview | state, failing checks, blueprint and its source, primary user, location, disk recovery keys, charts of the last 7 days |
| Hardware | system, system board, processor and memory, disks, volumes, TPM, **Recovery keys** with **Show key** |
| Network | public address, interfaces, VPN, **WireGuard keys**, **Network certificates**, DNS, default gateways, routes |
| Software | **Packages** (search, paging), **Package sources**, **Apps** (Flatpak, Snaps, AppImages, with **Remove**), **Catalog** |
| Accounts | **Users** and **Groups** of the device (**Show system accounts**); **Add local user…**, and per account **Reset password**, **Lock account**, **Unlock account**, **Make administrator**, **Remove admin rights**, **Delete account** |
| Compliance | every check with result, detail and references; **Evidence CSV** |
| Declarations | resolved blueprint chain, the items that apply and the declaration status reported by the agent |
| Commands | **Send command** (also script parameters and timeout), **History**, **Diagnostics** (**Collect logs**, downloads), **Script results**, **Device events**, **Remote shell sessions**, **Retire device**, **Delete device** |

**Show key** opens a disk recovery key after a reason; every view is audited and with the
setting on needs approval first ([disk-encryption.md](disk-encryption.md)). Reset password,
lock and unlock of local accounts are open to the helpdesk; creating, deleting and admin
rights are for admins. **Delete device** is offered for retired devices only and deletes the
device with its events, metrics, commands, recovery keys and app requests (confirmed with
the host name). How the agent carries out each command is in
[agent.md](agent.md#lock-and-unlock).

## Compliance

`/compliance` aggregates the checks of all devices in scope.

* State counts, **History**, **Inventory CSV**, **Audit CSV**, **Evidence CSV**.
* Check list with filters: search, **State** (Failing, Passing), **Level**, **Framework**
  (BSI IT-Grundschutz, CIS Benchmark, ISO/IEC 27001), **Sort** (by ID, most failing).
  Each row shows pass, fail, exception and n/a counts and the failing devices.
* **Coverage by framework**: pass and fail summed over devices per control.
* **Risk exceptions** with **Exceptions CSV** and **Revoke**; **Add risk exception** takes
  the **Check ID**, the mode (`exclude` or `advisory`), an optional **Device tag**, the
  **Reason**, the **Risk owner**, the **Approver** and the expiry
  ([compliance.md](compliance.md#risk-exceptions)).

**History** (`/compliance/history`) shows the state at the end of any date for all devices
or one device, the state per check and the changes up to that date; **Report as CSV**
exports it ([compliance.md](compliance.md#evidence)).

## Library

`/library` lists library items by type with name, description and the blueprints using
them; **New item** and **Item type** start an item, the filter searches name, description and
blueprint. Items with an invalid signature are marked and not delivered. **Deleted** lists
deleted items, which stay restorable from their history.

The item editor shows the type description, **Settings** as JSON with a live check
(**Format** indents it), the **Field reference**, **Documentation**, and for CA
certificates **Add certificate file**. Saving takes two steps: **Review changes** shows the
diff and the affected devices, **Save item** stores it. **Version history** lists the
versions with a diff, **Roll back** and **Restore**. **Delete item** is possible when no
blueprint uses it ([concepts.md](concepts.md#versions-and-preview)).

Network secrets are masked in the editor; with multi tenancy, shared items of the Default
tenant are read only for tenants.

## Directory

`/directory` shows **People** and **Groups** from SCIM 2.0 or Google Workspace.

* People: name, email, department, source and state, with search.
* Groups: members, the **Blueprint** the group assigns and its **Priority** (lowest wins),
  **Save**.
* **Settings**: the SCIM **Base URL** and token (**Create token**, **Rotate token**, shown
  once), Google Workspace (**Admin to impersonate**, **Service account key**,
  **Save and sync**, **Sync Google now**, last sync; syncs hourly).

Details are in [configuration.md](configuration.md#directory). The directory is global:
admins and auditors without a device scope and without a tenant see it.

## Blueprints

`/blueprints` lists blueprints with parent, how they are assigned (set on the device,
directory group with priority, or every device without another assignment for `default`),
device count and update time; **Deleted** lists deleted blueprints. **New blueprint** opens
the editor: name, **Inherits from**, description and the **Assignment map** (visual editor,
with the JSON below). **Review changes** and **Save blueprint** work as for items, as do
**Version history** and **Delete blueprint** (devices assigned to it fall back to
`default`). See [concepts.md](concepts.md#blueprints).

## Enrollment

`/tokens` creates enrollment tokens and shows how to deploy the agent.

* **New token**: **Note**, **Blueprint** (or **Default only**), **Uses** (1 to 10000),
  **Valid for days** (1 to 90), **Create token**. The token is shown once with **Copy**.
* **Deploy the agent**: the install command for a **Single device**, the enroll.conf for
  **Mass deployment**, with the token filled in and copy buttons.
* **Active tokens** with uses left, expiry, creator and **Revoke**.
* **Agent endpoint**: agent URL, transport and the device CA fingerprint.

See [agent.md](agent.md#enrollment-tokens).

## Agents

`/agents` manages agent releases ([agent.md](agent.md#updates)).

* **Versions** fetched from the release repository, with state (available, approved,
  blocked), signature, devices and failures; **Approve**, **Block**,
  **Check for new versions**, **Show older versions**.
* **Rollout**: **Update agents automatically**, **Pilot tag**, **Delay for all other
  devices (days)**.
* **Fleet**: devices per agent version; **Outdated agents** updates single devices to the
  newest approved version (**Update to**).

## Software

`/software` is the company software catalog ([software.md](software.md)).

* Catalog apps with category, mode (off, required, on request, available), sources,
  installed count and scope; **Add app** searches Flathub or takes an app by hand.
* **Installed on devices, not in the catalog**: **Add selected to catalog**.
* **Managed remotes** with **Allow**, **Block**, **Allow all apps**, **Stop managing**;
  remotes **Found on devices, not managed** with **Take over**; **Add remote**.
* Software requests from users: **Approve for this device**, **Approve for everyone**,
  **Deny**.
* **Store policy**: Flathub offers only catalog apps, GNOME Software and KDE Discover read
  only, only managed Flatpak remotes.

## Audit log

`/audit` shows the append only, hash chained audit log, 100 entries per page (**Newest
entries**, **Older entries**).

* Filters: search over all fields, **Actor**, **Action**, **Target**, **From**, **To**,
  **Filter**, **Reset**. Actions are shown readable and translated.
* Exports with the same filters: **CSV** (with `prev`, `hash` and `tenant_id`, for
  `limdm-server audit verify`) and **JSON Lines**. Every export is audited.
* **Verify whole chain** checks every entry from the start and shows **Hash chain verified
  end to end** or the first entry where the chain breaks, plus the time of the last full
  verification.

The chain, its keys and retention are described in [security.md](security.md#audit-log).

## Approvals

`/approvals` lists four eyes requests: command (wipe, lost mode, script), **Role change**,
**Recovery key view** and remote shell, with target, requester, reason, status and expiry.
Another admin **Approve**s or **Reject**s; nobody decides their own request, and requests
expire after 24 hours. Approved commands run at once; an approved recovery key view or
remote shell is usable by the requester for one hour. The helpdesk sees only its own
requests. See [security.md](security.md#four-eyes-approval).

## Users

`/users` lists console accounts: OIDC identities and local accounts (password and TOTP),
with type, role, scope, last sign in, and whether they come from a directory group or are
global.

* Per account: **Role**, **Scope tags**, **Scope groups**, disabled, **Save**;
  **Reset credentials** for local accounts.
* **Add user**: **OIDC (email)** or **Local account** (needs **Allow local accounts** in the
  settings), **Role**. Local accounts get a generated password and TOTP secret, shown once.
* **What the roles may do** explains the roles.

Role changes wait for approval when four eyes approval is on. See
[configuration.md](configuration.md#console-users-and-roles).

## Settings

`/settings` has five tabs. The fields are described in
[configuration.md](configuration.md#console-settings).

| Tab | Cards |
|---|---|
| General | **Access** (local accounts, stale threshold), **Console access by network** (allowed and blocked networks) |
| Security | **Password policy**, **Four eyes approval**, **Audit log retention**, **Privacy** (geolocation, DNS over HTTPS fallback), **Remote shell**, **Keys** (global admins, [keys.md](keys.md)) |
| SSO | **Single sign on (OIDC)**: issuer, client ID and secret, allowed domain, MFA (amr or acr), **Console roles from groups** |
| Notifications | **Notification channels**, **Add channel** (Slack, Discord, email, webhook), the events per channel, **Compliance webhook** ([notifications.md](notifications.md)) |
| Branding | **Company name**, **Logo** |

Tenant accounts see only the Notifications tab, with the channels of their tenant.

## API tokens

`/settings/api` creates tokens for the admin REST API and Prometheus metrics: **Name**,
**Role** (admin, helpdesk, auditor, metrics), **Read only**, **Scope tags** (helpdesk and
auditor), **Valid for days** (1 to 365). The token is shown once; **Revoke** ends it.
**OpenAPI document** links `/api/v1/openapi.json`. See [admin-api.md](admin-api.md).

## Company

Tenant admins only: the branding of their tenant (**Company name**, **Accent color**,
**Logo (PNG)**). Empty fields use the global branding ([tenants.md](tenants.md#branding)).

## Tenants

Global administrators with `LIMDM_MULTI_TENANT=true`: the tenant list with company name,
devices and status, **New tenant**, the tenant page (name, disabled, branding) and
**Shared objects** (library items and blueprints of Default every tenant may use). The
tenant switcher at the bottom of the sidebar narrows every page to one tenant or shows
**All tenants (global)**. See [tenants.md](tenants.md).

## Network certificates

`/network` (admins in the navigation, auditors by URL) shows the EAP-TLS device certificates
for WLAN and wired 802.1X: issued certificates with device, serial, subject alternative
names, expiry and state; the network CA with **Download CA certificate**; the revocation
list with **Download CRL** and the **CRL token** for RADIUS servers (**Create token**,
**Rotate token**, shown once). See [network.md](network.md#device-certificates-for-eap-tls).

## Help

`/help` explains the terms of the console (glossary), the device states, levels L1 and L2,
the roles and the device actions by impact (lock, lost mode, retire, wipe), with links to
this documentation.

## Profile

Your name at the bottom of the sidebar opens `/profile`: language and date format (stored in
the browser) and, for local accounts, **Change password**, a new authenticator app (TOTP) and
recovery codes. Five wrong entries lock a local account for 15 minutes
([configuration.md](configuration.md#profile)).

## Roles and permissions

### Roles

| | admin | helpdesk | auditor |
|---|---|---|---|
| Sees | everything | Overview, Devices, Compliance, Library, Blueprints, Enrollment, Approvals (own requests), Help | everything, including the audit log |
| Changes | everything | the device commands below, nothing else | nothing |
| Exports | yes | no | yes |
| Audit log, **Verify whole chain** | yes | no | yes |
| Disk recovery keys | view (with reason) | view (with reason) | no |
| Remote shell | start, end, transcripts | start only when **The helpdesk role may start sessions** is on; own sessions, no transcripts | transcripts only |
| Decide approvals | yes | no | no |

Device commands of the helpdesk role (`helpdeskCommands` in `internal/server/web.go`, one
list for console, bulk actions and API): `sync`, `update`, `reboot`, `shutdown`, `lock`,
`unlock`, `message`, `user_password`, `user_lock`, `user_unlock` and `diagnostics` (collect
and download logs). Scripts, lost mode, wipe, retire, delete, agent updates, software,
tags, account creation, deletion and admin rights stay with admins. The help page and the
Users page show the same role descriptions.

### Device scopes

Helpdesk and auditor accounts can be limited to devices with given **Scope tags** or whose
primary user is in given **Scope groups** (directory groups). The scope is enforced on the
server for every device list, device page, command, export, recovery key, remote shell,
approval and audit entry: devices outside it answer 404. Scoped accounts cannot open pages
with fleet wide data (Directory, Agents, Software, Network certificates, version history).
Admins are never scoped. Roles and tags can also come from directory groups or the OIDC
groups claim (**Console roles from groups**, `group; role; tag,tag` per line;
[configuration.md](configuration.md#role-groups)). API tokens take scope tags the same way.

### Tenants and global administrators

With multi tenancy, an account bound to a tenant reaches only tenant aware pages: the
Overview, Devices, Compliance, Library, Blueprints, Enrollment, Audit log, Approvals,
Users, Settings (Notifications only), API tokens, Network certificates of its devices,
Company and Help. Everything global answers 403: Directory, Agents, Software, the other
settings tabs and the Keys card, Tenants, the CRL token and **Verify whole chain**.

Global administrators (accounts without a tenant) see all tenants, switch between them
with the tenant switcher and manage tenants. The **Keys** card (rotation of the device CA,
network CA, command key, session key and webhook secret) is for global admins without a
device scope only, also when they switched to a tenant. See
[tenants.md](tenants.md#tenant-accounts).

### Four eyes rules

With **Require a second administrator's approval** on (**Settings**, **Security**), wipe,
lost mode, scripts (also bulk and through the admin API, which answers 202 with an
`approval_id`) and role changes of console users wait for a second admin. Optional:
**Also for recovery key views** and **Also for remote shell sessions**. The requester never
approves their own request, requests expire after 24 hours, and the setting needs at least
two active admins. Details: [security.md](security.md#four-eyes-approval).
