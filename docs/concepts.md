# Concepts

LiMDM follows the model of Apple's Declarative Device Management: the server describes the
desired state, the agent makes the device match it on its own, keeps enforcing it while
offline and reports the result. There are no remote procedure calls except a few one off
commands.

## Declarations

A declaration is one piece of desired state: `identifier`, `type` (for example
`com.limdm.firewall`) and a JSON `payload`. Each declaration carries a `server_token` that
changes with its content. The agent stores the declarations it received and only downloads
them again when the combined token changes.

Payloads are validated strictly twice: by the server when an item is saved and by the agent
before it applies anything (unknown fields, option injection in package and unit names,
path traversal, shell and config metacharacters).

## Library

The **Library** holds reusable items, each one validated payload of one type, for example
"CIS Level 1 baseline", "Proxy Berlin" or "Developers may restart nginx". The item editor
describes every type, shows an example payload and a field reference generated from the
payload types, checks the JSON while you type (**Format** indents it) and links the type's
section in [declarations.md](declarations.md).

## Blueprints

A blueprint is an **assignment map**: a tree of

* **assign** nodes, which add library items, and
* **if** nodes with one or more branches. Each branch has rules combined with `all` or
  `any`; the first matching branch wins, otherwise the `else` nodes apply. Branches can
  contain further nodes, up to 12 levels deep.

Rules test device facts:

| Field | Operators |
|---|---|
| `os.id` (`debian`, `ubuntu`, `fedora`) | `eq`, `ne` |
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

* **List types** are combined: packages and services (removal wins over installation),
  files (by path), firewall rules (union, `enforce` if any item enforces), OS minimum
  versions, package sources, certificates, kernel parameters, blocked modules, SSH options,
  Flatpak, scripts, polkit and sudo rules (by name).
* **All other types** are single valued: the item evaluated last wins.

The device page shows the resolved chain and which items apply. Devices pick up changes at
their next check in.

## Directory

People and groups come from SCIM 2.0 or Google Workspace ([configuration.md](configuration.md#directory)).

* A device's **primary user** links it to a person; their groups and department become
  rule facts, and group assignments select the blueprint.
* **Desktop users** are listed per device (`username email [admin]`). The agent creates
  these accounts and manages admin group membership ([desktop-login.md](desktop-login.md)).
* A person deactivated in the directory is removed from the account list of every device
  at its next check in; the agent then locks the account (home directory kept). Accounts
  without a directory entry are not affected.

## Agent cycle

Every check in interval (default 5 minutes, `com.limdm.agent`):

1. renew the client certificate if it expires within 30 days,
2. converge: apply declarations, run compliance checks, remediate where allowed,
3. check in over mTLS: send status (only when it changed), package list (only when it
   changed), command results, events, metrics and escrowed recovery keys; receive
   declarations (only when the token changed), desktop users, commands, branding.

When the server is unreachable the agent keeps enforcing the stored declarations.
`com.limdm.agent` with `offline_lock_hours` locks the device after a defined time without
server contact ([desktop-login.md](desktop-login.md#offline-lock)).

## Status

Per declaration the agent reports whether it is `valid` (payload accepted) and `active`
(desired state reached), with reasons. Compliance results, inventory and declaration status
appear on the device page; the overview and compliance pages aggregate them.

Device states: `compliant`, `in grace` (failing, grace period running), `non-compliant`,
`stale` (no check in for the stale threshold), `pending` (no report yet), `retired`.

## Commands

One off actions from the device page: `sync`, `update` (install all updates), `reboot`
and `shutdown` (in one minute), `lock` and `unlock` (blocks new logins, locks running
sessions), `script` (root shell script, only on devices enrolled with `allow_scripts`, admins
only), and for lost devices `lost`, `found` and `wipe` (admins only, confirmed with the host
name, see [disk-encryption.md](disk-encryption.md#lost-or-stolen-devices)). Commands are
delivered until the device reports a result; the agent runs each one once. Unanswered
commands expire after 7 days. Results show on the device page and in the audit log.
The helpdesk role may send `sync`, `update`, `reboot`, `shutdown`, `lock`, `unlock` and
messages, and reset the password of or lock a local account; everything else is for admins.
Reboot and shut down now, lock and account lock ask for confirmation first.

## Help in the console

**Help** in the sidebar explains the terms the console uses, the device states, the roles
and the device actions by impact (lock, lost mode, retire, wipe). Page headers link the
matching documentation, status labels explain themselves on hover, and the overview shows
admins a first steps checklist until company settings, sign in, an enrollment token, a
blueprint and a device exist.
