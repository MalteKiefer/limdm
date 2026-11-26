# Tenants

One LiMDM server can serve several companies: an MSP with its customers, or a group of
companies. Each company is a **tenant** (Mandant). A tenant's admins, helpdesk and auditors
see only its devices and configuration. The agent is unchanged; a device belongs to the
tenant of the enrollment token it enrolled with.

Multi tenancy is off by default. A single company install sees no change: all data belongs
to the tenant **Default**, and every existing console user is a global administrator.

## Turning it on

Set `LIMDM_MULTI_TENANT=true` in the server environment and restart
([configuration.md](configuration.md#environment-variables)). Global administrators then get
**Tenants** in the navigation and a tenant switcher at the bottom of the side bar. The
variable only shows these pages: the isolation below applies at all times, also when the
variable is switched off again later.

## Model

* **Tenant 1, Default**, owns everything from before tenants existed and the objects global
  administrators create in the global view. It cannot be disabled.
* **Owned by one tenant**: devices, enrollment tokens, library items, blueprints, risk
  exceptions, approvals, network certificates, device events, compliance history and the
  tags on its devices.
* **Tenant or global**: console users (OIDC and local), API tokens and notification
  channels. A NULL tenant means global.
* **Global only**: server settings (listeners, OIDC, password policy, four eyes, retention,
  remote shell, privacy), the CA and signing keys, the directory (SCIM, Google Workspace,
  role mappings), the software catalog and Flatpak remotes, agent releases, the network CA
  and its CRL, and the Prometheus metrics.

## Global administrators (super admins)

A console user without a tenant is global. Accounts from `LIMDM_ADMINS`, `LIMDM_AUDITORS`,
from directory group mappings and from `limdm-server local-admin` are global.

* **Tenants** (`/tenants`): create tenants, open one to rename, disable or brand it, and
  choose the **shared objects** (below).
* **Tenant switcher**: "All tenants (global)" shows every tenant; choosing a tenant narrows
  every page to it. The choice lives in the signed session cookie and is checked on every
  request. Objects created in a tenant belong to it, objects created in the global view
  belong to Default. Users and API tokens created in a tenant belong to it, created in the
  global view they are global.
* **Global audit view**: the audit log in the global view shows every entry.

To set up a customer: create the tenant, switch to it, add its first admin under **Users**,
create an enrollment token under **Enrollment** and roll out the agent with it.

## Tenant accounts

A tenant admin works like an admin of a single company install, limited to the tenant:
devices, commands, remote shell, compliance and its history, risk exceptions, blueprints,
library items, enrollment tokens, users, approvals, audit log and exports, API tokens,
notification channels (the only tab of **Settings** they see), network certificates of
their devices, and **Company** for the branding. Helpdesk and auditor accounts of a tenant
can be limited further with device scopes ([configuration.md](configuration.md#console-users-and-roles)).

Every other page answers 403: Directory, Agents, Software, the other settings tabs
(including the **Keys** card), the network CRL and its token, Tenants, **Verify whole
chain** on the audit log (the chain is global), and pages added later until they are made
tenant aware.
Objects of other tenants answer 404, whether addressed in the console, in an export or in
the admin API.

## Shared library items and blueprints

On **Tenants**, **Shared objects**, global administrators mark library items and blueprints
of the Default tenant as shared. Every tenant can read them and use them in its own
blueprints (a shared blueprint as parent, a shared item in an assignment), but cannot change
or delete them. There is one `default` blueprint for the whole installation: it belongs to
Default, applies to every device of every tenant without another blueprint, and is shared
(the server shares it again at every start, even if it was unchecked).

A blueprint can only reference items and a parent the tenant can see; saving any other
reference is refused. When a device's declarations are resolved, only library items of the
device's tenant and of Default are loaded, so a reference across tenants never delivers
another tenant's item.

## Branding

**Company** (tenant admins) or the tenant's page (global administrators) sets the company
name, the logo (PNG) and an accent color. They are shown in the console of the tenant and
sent to the desktop helper on its devices. Empty fields fall back to the global branding of
**Settings**, **Branding**.

## Disabling a tenant

A disabled tenant's users and API tokens can no longer sign in and its enrollment tokens
stop working. Its devices keep checking in and keep their configuration; enable the tenant
again to manage them. Deleting a tenant is not supported: retire and delete its devices,
then disable it.

## Audit, notifications, approvals

* Audit entries carry the tenant they belong to: the tenant the request acts for, else the
  tenant of the device the entry is about, else none (a global entry). The chain stays one
  global chain; the tenant is hashed as a fifth field when set, so entries from before
  tenants keep their hashes and moving an entry to another tenant breaks verification.
  Tenant admins see their tenant's entries; global entries only global administrators.
* Device events reach the notification channels of the device's tenant and all global
  channels. Events without a device (role changes, approval requests, a broken audit chain)
  reach global channels only.
* Four eyes requests belong to the requester's tenant (for global administrators: the
  tenant of the target device or user). They are decided by an admin of that tenant or a
  global administrator.

## Limits

* Library item and blueprint names are unique across the installation, so a name taken by
  another tenant is refused.
* Version history: restoring a deleted library item or blueprint is available in the global
  view only, and the restored object belongs to Default.
* Directory, SSO and the software catalog are per installation. Directory group role
  mappings create global accounts.
