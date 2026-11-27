# Concepts

LiMDM follows the model of Apple's Declarative Device Management: the server describes the
desired state, the agent makes the device match it on its own, keeps enforcing it while
offline and reports the result. There are no remote procedure calls except a few one off
commands.

## Declarations

A declaration is one piece of desired state: `identifier`, `type` (for example
`com.limdm.firewall`) and a JSON `payload`. Each declaration carries a `server_token` that
changes with its content. The agent stores the declarations it received and only downloads
them again when the combined token changes. Every type and field is described in
[declarations.md](declarations.md).

Payloads are validated strictly twice: by the server when an item is saved and by the agent
before it applies anything (unknown fields, option injection in package and unit names,
path traversal, shell and config metacharacters).

## Library

The **Library** holds reusable items, each one validated payload of one type, for example
"CIS Level 1 baseline", "Proxy Berlin" or "Developers may restart nginx". The item editor
describes every type, shows an example payload and a field reference generated from the
payload types, checks the JSON while you type (**Format** indents it) and links the type's
section in [declarations.md](declarations.md).

The server signs every item when it is saved. An item whose signature does not verify is
marked **Signature invalid** in the library and is not delivered to devices until it is
opened and saved again.

### Shared items of the Default tenant

With [multi tenancy](tenants.md) on, global administrators can mark library items and
blueprints of the tenant **Default** as shared (**Tenants**, **Shared objects**). Every
tenant reads them and uses them in its own blueprints, but cannot change or delete them.
The `default` blueprint is shared. Without multi tenancy everything belongs to Default and
this has no visible effect.

## Blueprints

A blueprint is an **assignment map**: a tree of

* **assign** nodes, which add library items, and
* **if** nodes with one or more branches. Each branch has rules combined with `all` or
  `any`; the first matching branch wins, otherwise the `else` nodes apply. Branches can
  contain further nodes, up to 12 levels deep.

Rules test device facts:

| Field | Operators |
|---|---|
| `os.id` (the `ID` of `/etc/os-release`, for example `debian`, `ubuntu`, `fedora`, `opensuse-leap`, `sles`, `arch`, `alpine`) | `eq`, `ne` |
| `os.version` | `eq`, `ne`, `gte`, `lte` (version aware) |
| `arch` | `eq`, `ne` |
| `desktop` | `present`, `absent`, `contains` |
| `vendor`, `model` | `eq`, `contains` |
| `hostname` | `eq`, `glob` |
| `tag` | `has`, `not_has` (tags are set on the device page) |
| `group` | `member`, `not_member` (directory groups of the primary user) |
| `department` | `eq`, `ne` (from the directory) |

Text comparisons ignore case. The visual editor in the console builds the tree; the JSON
form below it is the same data.

### Inheritance

A blueprint can inherit from a parent. The parent's map is evaluated first, then the
child's. An item selected twice counts at its last position, so a child can override
inherited single value items.

### Versions and preview

Every save of a library item or blueprint is kept as a version: author, time, payload and,
for items, the signature. The **Version history** link in the editor lists the versions
and shows a line diff between any two. **Roll back** saves an older version again as the
newest one; it is validated, signed and audited (`library.rollback`, `blueprint.rollback`)
like any save. A deleted object keeps its last version: the library and blueprint pages
list deleted objects, and **Restore** brings one back under its old ID (blueprints that
inherited from a deleted blueprint and devices assigned to it are not reassigned). The
version tables are append only. Secrets never enter them: login client secrets are stored
sealed, network secrets masked ([Network profiles](network.md#secrets)). Saves through the
admin API create versions like console saves. With multi tenancy, restoring a deleted
object is possible in the global view only.

The editor saves in two steps: **Review changes** shows the diff against the stored
version and the active devices that get the change (devices whose blueprint, or a
blueprint inheriting from it, uses the item), then **Save item** or **Save blueprint**
stores it. **Review again** shows the preview once more after further edits.

The console app (`/app/config`) reviews while you edit: the effect panel shows the devices
that get the change (online and offline), the expected effect on compliance (a changed
level, checks newly excluded or advisory, library items added to or removed from a
blueprint) and the diff. A blueprint change can go to **pilot devices first**: the changed
map is saved as a copy of the blueprint (`<name>.pilot`, same parent) and set on the chosen
devices of the blueprint. **Promote to all** saves the map into the blueprint as a new
version, **Abort** drops it; both put the pilot devices back on what they had set before
and delete the copy (audited as `blueprint.pilot` and `blueprint.pilot_end`).

### Which blueprint a device gets

Every device has exactly one blueprint:

1. the blueprint set explicitly on the device (device page, or the enrollment token's
   blueprint at enrollment), otherwise
2. the blueprint of the primary user's directory group (lowest priority number wins), otherwise
3. `default`.

The device page names the source next to the blueprint, and the blueprint list shows per
blueprint how many devices have it set directly and which groups assign it.

### Merging

The server walks the blueprint chain for the device and merges the selected items into one
declaration per type:

* **List types** are combined:
  * packages and services: union, removal and disabling win over installation and enabling;
  * files: by path, a later item wins;
  * firewall rules: union, `enforce` if any item enforces, zones of the same name combined,
    outbound `deny` wins over `allow`;
  * OS minimum versions;
  * package sources, CA certificates, recurring scripts, local accounts, polkit rules and
    sudo rules: by name, a later item wins; switched off package sources are combined;
  * kernel parameters, SSH options and dconf settings: by key, a later item wins (dconf
    locks are combined);
  * blocked kernel modules: union;
  * Flatpak apps and remotes: a later item wins for the same remote;
  * network profiles: by name; custom compliance checks: by ID.
* **All other types** are single valued: the item evaluated last wins.

Only library items of the device's own tenant and of the Default tenant are loaded. Risk
exceptions ([compliance.md](compliance.md#risk-exceptions)) are applied to the merged
compliance declaration last. The device page shows the resolved chain and which items
apply. Devices pick up changes at their next check in.

## Directory

People and groups come from SCIM 2.0 or Google Workspace ([configuration.md](configuration.md#directory)).

* A device's **primary user** links it to a person; their groups and department become
  rule facts, and group assignments select the blueprint.
* **Desktop users** are listed per device (`username email [admin]`). The agent creates
  these accounts and manages admin group membership ([desktop-login.md](desktop-login.md)).
* A person deactivated in the directory is removed from the account list of every device
  at its next check in; the agent then locks the account (home directory kept). Accounts
  without a directory entry are not affected.
* Directory groups can grant console roles and limit helpdesk and auditor accounts to the
  devices of their members ([console.md](console.md#roles-and-permissions)).

## Agent cycle

Every check in interval (`checkin_seconds` in `com.limdm.agent`, default 300 seconds, plus
up to 10 percent random delay so a fleet does not check in at the same moment) the agent:

1. renews its client certificate when it expires within 30 days or the server asks, and
   requests or renews its EAP-TLS network certificate when a network profile needs one,
2. picks up recovery key requests, confirms or reports an agent update, collects tamper
   reports and keeps the watchdog timer enabled,
3. converges: applies the declarations, runs the compliance checks, remediates where
   allowed,
4. collects inventory and the desktop login results,
5. checks in over mTLS: sends status and package list (each only when it changed),
   command results, script results, events, metrics, app requests and escrowed recovery
   keys; receives declarations (only when the token changed), desktop users, commands,
   branding, the software catalog, a new command key or device CA, renewal requests, an
   agent update and the server's privacy settings.

When something changed (new declarations, new users, a command), the agent runs the next
cycle after 5 to 60 seconds instead of waiting for the interval. Besides the cycle it asks
the server every minute whether a command or an agent update waits
([agent.md](agent.md#command-delivery)).

When the server is unreachable the agent keeps enforcing the stored declarations.
`com.limdm.agent` with `offline_lock_hours` locks the device after a defined time without
server contact ([desktop-login.md](desktop-login.md#offline-lock)).

## Status

Per declaration the agent reports whether it is `valid` (payload accepted) and `active`
(desired state reached), with reasons. A failing compliance check marks the declaration
whose goal it verifies as not active. Compliance results, inventory and declaration status
appear on the device page; the overview and compliance pages aggregate them.

Device states:

| State | Meaning |
|---|---|
| `compliant` | every counted check passes |
| `in grace` | checks fail, the grace period of the compliance item is still running |
| `non-compliant` | at least one check fails and the grace period is over; notification and automatic lock follow if the compliance item sets them |
| `stale` | no check in for longer than **Device counts as stale after (hours)** in **Settings**, **General**; the shown state may be outdated |
| `pending` | enrolled, but no compliance results yet |
| `retired` | no longer managed; the certificate is revoked and the device cannot check in |

The help page of the console and the tooltips of the status labels use the same wording.

## Commands

One off actions from the device page or the device list:

| Command | What it does | Who |
|---|---|---|
| `sync` | check in now | admin, helpdesk |
| `update` | install all updates | admin, helpdesk |
| `reboot`, `shutdown` | now or after a delay of up to 1440 minutes (default 1) | admin, helpdesk |
| `lock`, `unlock` | blocks new logins and locks running sessions, and releases it again | admin, helpdesk |
| `message` | notification and dialog in every graphical session | admin, helpdesk |
| `user_password`, `user_lock`, `user_unlock` | reset the password of, lock or unlock a local account; never an account with uid 0; for the helpdesk never an account with admin rights | admin, helpdesk |
| `diagnostics` | collect redacted agent logs | admin, helpdesk |
| `user_create`, `user_admin`, `user_delete` | create a local account, change its admin right, delete it | admin |
| `app_install`, `app_remove`, `software_remove` | install or remove catalog apps, remove software found on the device | admin |
| `script` | root shell script with parameters and a timeout, only on devices enrolled with `allow_scripts` (no protection against admins, see below) | admin |
| `allow_uninstall` | allow removing the agent package for one hour | admin |
| `lost`, `found` | lost mode and its end ([disk-encryption.md](disk-encryption.md#lost-or-stolen-devices)) | admin |
| `wipe` | erase the device | admin |

`lost` and `wipe` are confirmed by typing the host name and are sent to one device at a
time. With four eyes approval on, `wipe`, `lost` and `script` wait for a second admin
([security.md](security.md#four-eyes-approval)). `allow_scripts` does not keep an
administrator out of a device: other declarations (repositories, packages, sudo, local
users, artifacts) also run code as root. Four eyes approval, signed commands and the audit
log are the controls against a single administrator
([security.md](security.md#known-limitations-of-the-agent)). The interactive support terminal
(`shell`) is started on the device's remote shell page and decided by its own setting
([remote-shell.md](remote-shell.md)); it is no command of the device page or the admin
API.

Commands are signed with the command key and delivered until the device reports a result;
the agent runs each one once. Unanswered commands expire after 7 days, finished ones are
deleted after 180 days. Results show on the device page and in the audit log. Reboot and
shut down now, lock and account lock ask for confirmation first.

## Help in the console

**Help** in the sidebar explains the terms the console uses, the device states, the roles
and the device actions by impact (lock, lost mode, retire, wipe). Page headers link the
matching documentation, status labels explain themselves on hover, and the overview shows
admins a first steps checklist until company settings, sign in, an enrollment token, a
blueprint and a device exist. [console.md](console.md) describes every page.
