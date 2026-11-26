# Console

The web console runs on the console listener (`LIMDM_PUBLIC_URL`). After sign in the
server opens the console app under `/app/` (`/` leads there). This page names its areas,
the addresses of the former server rendered console and what each role may do.

## Console app

The app has a command palette (Ctrl+K), light and dark design, comfortable and compact
density, German and English, and works down to phone width. It talks only to the admin API
(`/api/v1`) with the session cookie and a CSRF header, so every action has the roles,
scopes, tenant rules, four eyes approval and audit entries of the API
([admin-api.md](admin-api.md#console-app)). The date notation picked in the profile (ISO,
German, British, US) follows the account across devices.

## Areas

| Area | Address | What it holds |
|---|---|---|
| Home | `/app/` | fleet state, what needs attention, first steps |
| Inbox | `/app/inbox` | approvals, warnings, open commands |
| Devices | `/app/devices` | device list with filters, saved views, exports and bulk actions; device page with every command, the remote shell, recovery keys and diagnostics; **Add device** (`/app/devices/enroll`) with the enrollment tokens |
| Compliance | `/app/compliance` | checks, heatmap, history, policies, risk exceptions |
| Configuration | `/app/config` | blueprints, library items, software catalog, uploaded packages, with version history, preview and rollback |
| Updates | `/app/updates` | update rings and waves, open security updates and CVEs, installed package versions; the device page has an **Updates** tab ([Patch management](patching.md)) |
| Activity | `/app/activity` | audit log with filters and chain verification |
| Reports | `/app/reports` | exports and scheduled reports |
| Settings | `/app/settings` | sign in, security, users, tenants, API tokens, notifications, backup, retention, operations, directory, network certificates, agents |
| Profile, Help | `/app/profile`, `/app/help` | password, authenticator app, recovery codes; glossary and roles |

Areas a role cannot use are hidden from its navigation, and the API answers 403
([Roles and permissions](#roles-and-permissions)).

## Former addresses

The server rendered console of earlier versions is gone. Its page addresses redirect to the
matching page of the app, so bookmarks keep working: for example `/devices/{id}` to
`/app/devices/{id}`, `/library/{id}` to `/app/config/library/{id}`, `/settings/api` to
`/app/settings?s=tokens` and `/audit` to `/app/activity`. Addresses without an obvious
match (`/classic`, `/shell/{sid}`) lead to `/app/`. The map is `classicPaths` in
`internal/server/web.go`. Still served by the server outside `/app/`: the sign in page,
`/install.sh`, the branding logo, catalog and Flathub icons, tenant logos, the network CA and
CRL (`/network/ca.pem`, `/network/crl.pem`) and the remote shell WebSocket.

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
tags, account creation, deletion and admin rights stay with admins. The helpdesk cannot
reset, lock or unlock accounts that can reach root (uid 0, member of `sudo`, `wheel` or
`admin`, named in a sudoers rule; the agent also refuses members of `docker`, `lxd`,
`incus-admin`, `libvirt` and `disk`, which reach root without sudo): the server refuses them from the last inventory with a
clear message, and the agent refuses them from its own view, because the server signs a
`no_admin` flag into every user command of the helpdesk. Accounts with uid 0 are refused
for every role. The help page and the
users section of the settings show the same role descriptions.

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
lost mode, scripts, package downgrades (also bulk and through the admin API, which answers 202 with an
`approval_id`) and role changes of console users wait for a second admin. Optional:
**Also for recovery key views** and **Also for remote shell sessions**. The requester never
approves their own request, requests expire after 24 hours, and the setting needs at least
two active admins. Details: [security.md](security.md#four-eyes-approval).
