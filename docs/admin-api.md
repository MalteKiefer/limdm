# Admin API

The console offers a REST API under `<LIMDM_PUBLIC_URL>/api/v1/` for scripts, ticket systems
and other integrations. It runs on the console listener and uses the same functions as the
console: the same role rules, device scopes, tenant limits, four eyes approval, validation
and audit entries. The OpenAPI 3.1 description is served at `/api/v1/openapi.json` (no token
needed) and lives in the repository as
[`internal/server/openapi.json`](../internal/server/openapi.json). `/api/v1/docs` renders it as
a reference page on the console itself (no token, no scripts, no external resources).

## Tokens

Admins create tokens under Administration, **API tokens** (`/settings/api`). Auditors see the
list but cannot create or revoke; the helpdesk role does not see the page.

* **Name**: up to 100 characters, shown in the audit log, for example `ticket system`.
* **Role**: `admin`, `helpdesk`, `auditor` or `metrics`. A token can do what its role can do
  in the console. `auditor` and `metrics` tokens are always read only. `metrics` tokens only
  read [`/metrics`](#metrics); every other path answers `403`.
* **Read only**: an admin or helpdesk token that may only read.
* **Valid for days**: 1 to 365; every token expires.
* **Scope tags**: optional device tags (comma separated) for a `helpdesk` or `auditor`
  token, as for scoped console users ([security.md](security.md)). A scoped token lists,
  reads and commands only devices with one of the tags (other devices answer `404`), sees
  only their audit entries and tags, and gets `403` on `/metrics`. Empty means every device
  (of the token's tenant). Directory group scopes exist for console users only. Admin and
  metrics tokens cannot be scoped. The tags are stored as `scope_tags` with the token.
* **Tenant**: a token created while switched to a tenant (or by a tenant admin) belongs to
  that tenant ([tenants.md](tenants.md)). It lists, reads and changes only that tenant's
  devices, commands, library items, blueprints, tags and audit entries; shared library
  items and blueprints of Default are readable, never writable; objects of other tenants
  answer `404`. Tokens created in the global view are global and see every tenant. Metrics
  tokens are always global (creating one in a tenant view is refused), and tenant tokens get
  `403` on `/metrics`. Tokens of a disabled tenant answer `401` (`tenant disabled`).

The token (`lma_...`) is shown once. The server stores only its SHA-256 hash, the first 12
characters for recognition, the creator, the expiry and the last use (updated at most once a
minute). The list shows each token as active, expired or revoked. **Revoke** ends a token at
once. A token keeps working when the admin who created it leaves; revoke it then.

Send the token as a bearer token. The API sets no cookies and reads none, so there is nothing
for cross site requests to abuse.

```sh
curl -H "Authorization: Bearer $LIMDM_TOKEN" https://mdm.example.com/api/v1/devices?tag=finance
```

### Scopes

A token can further be limited to scopes (console form or `scopes` when created through the
API); without scopes it can do everything its role allows. `read`: the `GET` endpoints of
devices, commands, library items, blueprints and tags; `commands`: send device commands;
`library`: change library items, blueprints and devices; `audit`: the audit log; `admin`:
approvals, exceptions, tokens and tenants. A request outside the scopes answers `403` and is
audited as `api.denied`. A token with scopes creates only tokens limited to some of its own
scopes. Tokens are rotated by creating the successor and deleting the old
one (`POST` and `DELETE /api/v1/tokens`); they are valid for at most 365 days.

### Roles

| Level | Roles | Endpoints |
|---|---|---|
| read | `admin`, `helpdesk`, `auditor` (read only tokens included) | every `GET` except the audit log |
| audit | `admin`, `auditor` | `GET /api/v1/audit` |
| helpdesk | `admin`, `helpdesk`, not read only | `POST /api/v1/devices/{id}/commands`; the command type decides further |
| admin | `admin`, not read only | `PATCH`, `POST`, `PUT`, `DELETE` on devices, library items, blueprints, exceptions, tokens and tenants; deciding approvals |
| metrics | `metrics`, `admin`, `auditor`; global and unscoped only | `GET /metrics` |

## Audit

Entries made through the API name the token as actor: `api:<name>#<id>`. Commands queued
through the API carry the same name as creator. In addition:

| Action | When |
|---|---|
| `api_token.create`, `api_token.revoke` | A token was created (detail: role, read only, days, prefix, scope tags) or revoked in the console |
| `api.auth_failed` | An unknown, expired, revoked or disabled tenant token was sent (detail: reason and client address) |
| `api.denied` | A valid token tried something its role, read only flag or scope does not allow (target: method and path) |
| `api.read` | A read through the API (target: method and path, detail: query). By default only the sensitive reads, `GET /api/v1/audit` and `GET /api/v1/devices/{id}`; `LIMDM_AUDIT_API_READS=all` records every read, `off` none ([configuration.md](configuration.md)) |

Audit entries in `GET /api/v1/audit` carry `tenant_id` when they belong to a tenant; it is
hashed after `detail` as a fifth chain field ([tenants.md](tenants.md#audit-notifications-approvals)).

## Limits

* 600 requests per minute and token; then `429` with `Retry-After: 60`.
* Failed authentications: 20 per client address and token in five minutes, as for SCIM, and
  200 per client address; then `429` with `Retry-After: 300` before the token is even
  checked. A script retrying a wrong token so locks out only that token, not valid tokens
  behind the same NAT. A request without any token counts but is not audited, and at most 30
  failures a minute go to the audit log (the server log gets every one).
* Request bodies up to 1 MiB; a larger body answers `400`.
* The console's network allow and block lists apply.

## Conventions

* JSON (RFC 8259), UTF-8, times RFC 3339. Requests with a body send
  `Content-Type: application/json`; unknown fields are refused, and the body holds exactly
  one JSON value.
* Errors are RFC 9457 problem details (`application/problem+json`) with `status`, `detail`
  and a machine readable `code` (`type` is `urn:limdm:problem:<code>`: `bad_request`,
  `unauthorized`, `forbidden`, `not_found`, `conflict`, `invalid`, `rate_limited`, `busy`, ...),
  also for unknown paths (`404`) and wrong methods (`405` with `Allow`). A `422` names the
  request field in `errors: [{"field": "payload", "message": "..."}]` (`name`, `type`,
  `payload`, `tree`, `parent_id`, `tags`, `blueprint_id`, `params`, or the
  `Idempotency-Key` header; empty when the request as a whole is wrong). A `401` carries
  `WWW-Authenticate: Bearer realm="limdm", error="invalid_token"`.
* Status codes: `200` read or replaced, `201` created (with `Location`), `202` command
  queued or approval requested, `204` deleted, `400` malformed request, `401` token missing
  or invalid, `403` role does not allow it, `404` not found or outside the token's tenant or
  scope, `409` name taken, object still in use or device retired, `415` not JSON, `422`
  rejected by validation, `429` rate limited, `503` server busy (database lock or statement
  timeout; retry after `Retry-After`).
* Every answer carries `X-Request-ID`; a well formed one sent with the request is kept.
  Server log lines of failed requests name it.
* Lists take `limit` (1 to 500, default 100) and return `{"items": [...], "next_cursor": "..."}`.
  Pass `next_cursor` as `cursor` for the next page; it is absent on the last page.
  `GET /api/v1/tags` is not paged.
* Lists of the console app follow more conventions, implemented for devices first:
  `filter` takes the [query language](#query-language), `sort` a field (`-field` for
  descending; the cursor belongs to the sort it came with) and `<list>/facets` counts the
  matching objects per value.

## Endpoints

| Method and path | Level | Request | Answer |
|---|---|---|---|
| `GET /api/v1/devices` | read | [filters](#device-filters), `limit`, `cursor` | `200` page of devices (`id`, `hostname`, `os`, `agent_version`, `blueprint`, `tags`, `status`, `failing`, `checks`, `last_seen`, `retired`) |
| `GET /api/v1/devices/{id}` | read | | `200` device with `blueprint_id`, `enrolled_at` and `inventory` |
| `PATCH /api/v1/devices/{id}` | admin | `{"tags": [...], "blueprint_id": 3, "users": [{"username", "email", "admin"}], "primary_user": "jane@example.com"}`; fields left out stay, `null` assigns default, `""` clears the primary user | `200` device; audited as `device.assign` |
| `GET /api/v1/devices/{id}/commands` | read | `limit`, `cursor` | `200` page of commands, newest first |
| `POST /api/v1/devices/{id}/commands` | helpdesk | `{"type", "params"}`, see [Commands](#commands) | `202` command or `202` approval request |
| `GET /api/v1/commands/{id}` | read | | `200` command: `id`, `device_id`, `type`, `status`, `output`, `created_by`, `created_at`, `updated_at` |
| `GET /api/v1/library-items` | read | `limit`, `cursor` | `200` page of items (`id`, `name`, `type`, `description`, `payload`) |
| `POST /api/v1/library-items` | admin | item without `id` | `201` item; audited as `library.save`; `202` approval request for root effective types while [four eyes approval](security.md#four-eyes-approval) is on |
| `GET /api/v1/library-items/{id}` | read | | `200` item |
| `PUT /api/v1/library-items/{id}` | admin | full item | `200` item; audited as `library.save`; `202` approval request as for `POST` |
| `DELETE /api/v1/library-items/{id}` | admin | | `204`; `409` while a blueprint uses it; audited as `library.delete` |
| `GET /api/v1/blueprints` | read | `limit`, `cursor` | `200` page of blueprints (`id`, `name`, `description`, `parent_id`, `tree`, `updated_at`) |
| `POST /api/v1/blueprints` | admin | `{"name", "description", "parent_id", "tree"}` | `201` blueprint; audited as `blueprint.save` |
| `GET /api/v1/blueprints/{id}` | read | | `200` blueprint |
| `PUT /api/v1/blueprints/{id}` | admin | full blueprint | `200` blueprint; audited as `blueprint.save` |
| `DELETE /api/v1/blueprints/{id}` | admin | | `204`; its devices fall back to default; audited as `blueprint.delete` |
| `GET /api/v1/tags` | read | | `200` `{"items": [{"name", "devices"}]}`, tags of active devices |
| `GET /api/v1/audit` | audit | `q`, `actor`, `action`, `target`, `from`, `to`, `limit`, `cursor` | `200` page of entries (`id`, `at`, `actor`, `action`, `target`, `detail`, `prev`, `hash`, `tenant_id`), newest first |
| `GET /api/v1/approvals` | read | `status`, `limit`, `cursor` | `200` page of approval requests (`id`, `action`, `target`, `payload`, `reason`, `requested_by`, `status`, `decided_by`, `decided_at`, `created_at`, `expires_at`), newest first; helpdesk tokens see their own |
| `GET /api/v1/approvals/{id}` | read | | `200` approval request |
| `POST /api/v1/approvals/{id}/approve`, `.../reject` | admin | optional `{"reason"}` (up to 500 characters; a console session must give one to reject, `422` otherwise) | `200` approval request with `decision_reason` (and `credentials` of an approved local account or token); `409` for an own, decided or expired request; audited as `approval.approve` or `approval.reject` with the reason |
| `GET /api/v1/exceptions` | read | | `200` `{"items": [...]}` risk exceptions with `state` |
| `POST /api/v1/exceptions` | admin | `{"check_id", "mode", "tag", "reason", "owner", "approver", "expires": "YYYY-MM-DD"}` | `201` `{"id"}`; audited as `exception.add`; with four eyes approval on `202` `{"approval_id"}` (the approving admin becomes the approver) |
| `DELETE /api/v1/exceptions/{id}` | admin | | `204`; audited as `exception.revoke` |
| `GET /api/v1/compliance` | read | | `200` device states, every reported check with pass, fail, n/a and exception counts, framework controls; titles in the caller's language |
| `GET /api/v1/compliance/checks/{id}` | read | | `200` one check with the result of each device in scope (failing first, at most 500) |
| `GET /api/v1/compliance/heatmap?group=blueprint\|tenant` | read | | `200` passed and failed results per check area and blueprint or tenant |
| `GET /api/v1/compliance/history?at=YYYY-MM-DD&device=ID` | read | | `200` state at the end of that day, per device or for one device with its changes |
| `GET /api/v1/compliance/policies` | read | | `200` compliance policies and custom checks of the library with the blueprints using them |
| `GET /api/v1/exports/{kind}` | audit | | the console export (`compliance.csv`, `compliance-history.csv`, `exceptions.csv`, `inventory.csv`, `packages.csv`, `audit.csv`, `audit.jsonl`, `evidence.json`, `evidence.pdf` with `days` 1..365, default 90; the audit exports take the filters of `/api/v1/audit`), audited as `export` and `export.done` with the SHA-256; the evidence exports also as `evidence.sign` |
| `POST /api/v1/exception-requests` | helpdesk | `{"check_id", "mode", "tag", "reason", "owner", "expires"}` | `202` `{"approval_id"}`; a four eyes request (`exception.add`) another admin approves |
| `GET /api/v1/tokens` | audit | | `200` `{"items": [...]}` tokens without secrets |
| `POST /api/v1/tokens` | admin | `{"name", "role", "days", "read_only", "scope_tags", "scopes"}` | `201` token with `token` (the secret, shown once); audited as `api_token.create` |
| `DELETE /api/v1/tokens/{id}` | admin | | `204`; audited as `api_token.revoke` |
| `GET /api/v1/tenants` | admin, global token | | `200` `{"items": [...]}` tenants with device counts; `404` without multi tenancy |
| `POST /api/v1/tenants` | admin, global token | `{"name"}` | `201` `{"id"}`; `409` name taken; audited as `tenant.add` |
| `GET /api/v1/devices/{id}/detail` | read | | `200` everything the device page shows: inventory, check results, declaration states, resolved chain, protective actions, recovery key metadata, network certificates, catalog state and app requests, 7 day metrics, and switches for the actions (shell, four eyes) |
| `GET /api/v1/devices/{id}/packages` | read | | `200` `{"items": [{"name", "version", "arch"}]}` |
| `GET /api/v1/devices/{id}/timeline` | read | `kind`, `limit`, `cursor` | `200` page of events, commands, script results, shell sessions (helpdesk: its own) and diagnostics bundles (admin, helpdesk), newest first |
| `GET /api/v1/devices/{id}/diagnostics/{cid}` | helpdesk | | `200` text attachment; audited as `device.diagnostics.download` |
| `POST /api/v1/devices/{id}/retire` | admin | | `200` device; audited as `device.retire` |
| `DELETE /api/v1/devices/{id}` | admin | `confirm` (the host name) | `204`; `409` unless retired; audited as `device.delete` |
| `POST /api/v1/devices/{id}/agent-update` | admin | `{"version"}` (empty: newest approved) | `202`; audited as `agent_update.request` |
| `POST /api/v1/devices/{id}/recovery-keys/{uuid}/view` | helpdesk | `{"reason"}` | `200` `{"key", "rotate", ...}`; with four eyes for recovery keys `state` `reason`, `requested` or `pending` instead of the key; audited as `recovery.view` |
| `POST /api/v1/devices/{id}/shell` | helpdesk, console session | `{"user"}` | `201` `{"id"}`, the terminal connects to `/shell/{id}/ws?csrf=`; `202` waits for approval; audited as `shell.start` |
| `GET /api/v1/devices/{id}/shell-sessions`, `GET /api/v1/shell-sessions/{sid}` | read | | sessions; the transcript for admins and auditors after the end |
| `POST /api/v1/shell-sessions/{sid}/end` | helpdesk | | `204`; the user who started it or an admin |
| `POST /api/v1/devices/bulk` | helpdesk | `{"ids": [...], "action": "command:sync", "params": {...}}`; actions `command:<type>` (not `lost`, `wipe`), `agent-update`, `tag-add`, `tag-remove` (admin) | `202` `{"status": "queued"}` or `{"status": "approval", "approvals": n}` |
| `GET /api/v1/devices/catalog-apps` | read | | `200` enabled catalog apps (`id`, `name`) for bulk install and removal |
| `GET /api/v1/devices/primary-users` | admin | `q` | `200` up to 20 directory email addresses, 120 searches a minute. The directory is installation wide: an account bound to a tenant or a device scope sees, and may set as primary user, only people who already are the primary user of a device in its tenant and scope (the console device page applies the same rule) |
| `GET /api/v1/enrollment-tokens` | read | | `200` active tokens with `agent_url`, `public_url`, `fingerprint`, `release_repo` for the install command and `enroll.conf` |
| `POST /api/v1/enrollment-tokens` | admin | `{"note", "blueprint_id", "uses", "days"}` | `201` `{"id", "token"}` (shown once); audited as `token.create` |
| `DELETE /api/v1/enrollment-tokens/{id}` | admin | | `204`; audited as `token.revoke` |
| `GET /api/v1/devices/facets` | read | [filters](#query-language) | `200` counts per status, OS, agent, blueprint and tag |
| `GET /api/v1/me` | read | | `200` the caller: `login`, `role`, `tenant`, `super`, scope, `scopes`, `permissions` (`read`, `audit`, `commands`, `admin`, `tenants`), `four_eyes`, `locale`, `company_name`, `accent`, and for sessions `csrf_token` |
| `GET /api/v1/events/stream` | read | | server sent events, see [Console app](#console-app) |
| `GET /api/v1/views` | read | `list` | `200` own and shared saved views |
| `POST /api/v1/views` | self | `{"list", "name", "query", "sort", "columns", "shared"}` | `201` view; only admins share; shared views are audited as `view.save` |
| `PUT /api/v1/views/{id}`, `DELETE /api/v1/views/{id}` | self | | `200` view or `204`; own views, admins also delete shared ones (`view.delete`) |
| `GET /api/v1/schemas`, `GET /api/v1/schemas/{type}` | read | `lang` (`de`, `en`) | declaration types with title, description, documentation link and `four_eyes`; JSON Schema (draft 2020-12) of a payload, derived from the Go types, with titles, help texts, sections, choices, widgets and limits per field |
| `GET /api/v1/config/blueprints` | read | | `200` blueprints with `devices`, devices by `status`, `items`, assignment `sources` (devices, directory groups, default), `inherited`, `read_only`, a running `pilot`, plus `deleted` blueprints and the `rule_fields` of conditions |
| `GET /api/v1/config/library` | read | | `200` library items (network secrets masked) with `used_by`, `invalid` signature, `read_only`, plus `deleted` items |
| `POST /api/v1/config/library/preview`, `POST /api/v1/config/blueprints/preview` | admin | item or blueprint as for a save (with `id` for an existing one) | `200` review: line `diff` to the stored version, `devices` (`online`, `offline`, by `status`, `sample`), `needs_approval`, expected `impact` (compliance level, excluded or advisory checks, items added or removed); nothing is saved |
| `GET /api/v1/config/library/template` | admin, no device scope | `type`, or `device` with `file` or `remote` and `inst`, `mode` (`edit`, `disable`, `enable`) | `200` start of a new library item (`type`, `name`, `description`, `payload`): the example payload of the type, or a sources or Flatpak item from what the device (in scope) reported; nothing is saved |
| `GET /api/v1/config/{kind}/{id}/versions` | read, not device scoped | `kind` is `blueprints` or `library` | `200` versions newest first with the text diffs compare, `exists` |
| `POST /api/v1/config/{kind}/{id}/rollback` | admin, not device scoped | `{"version"}` | `200` saved as the newest version or restored; `202` approval request for root effective items; audited as `library.rollback`, `blueprint.rollback` |
| `POST /api/v1/config/blueprints/{id}/pilot` | admin, not device scoped | `{"tree", "devices"}` | `201` pilot: the changed map goes into a copy `<name>.pilot` set on these devices of the blueprint; audited as `blueprint.pilot` |
| `POST /api/v1/config/blueprints/{id}/pilot/{op}` | admin, not device scoped | `op` `promote` or `abort` | `200`; promote saves the pilot map as a new version, both put the devices back and delete the copy; audited as `blueprint.pilot_end` |
| `GET /api/v1/software/catalog`, `.../requests`, `.../remotes`, `.../settings` | audit, global accounts | | `200` catalog apps with installs and Flatpaks to take over; app requests; managed and found remotes; store settings |
| `POST /api/v1/software/apps`, `PUT`/`DELETE /api/v1/software/apps/{id}` | admin, global accounts | catalog app with `sources`, `scope`, `icon` (PNG, base64) | `200`, `204`; `202` approval request for a required app with four eyes; audited as `catalog.save`, `catalog.delete` |
| `POST /api/v1/software/flathub`, `GET /api/v1/software/flathub/search` | admin / audit | `{"id", "mode"}`, `q` | add a Flathub app (`201`, `202`), search Flathub through the server |
| `POST /api/v1/software/import` | admin | `{"flatpaks"}` | `200` Flatpaks of the fleet taken into the catalog |
| `POST /api/v1/software/requests/{id}/{op}` | admin | `op` `approve`, `approve-all`, `deny` | `200`; audited as `catalog.request.<op>` |
| `PUT /api/v1/software/remotes/{name}`, `POST /api/v1/software/remotes/{name}/{op}` | admin | remote; `op` `allow`, `block`, `filter`, `unmanage` | `200`; audited as `catalog.remote` |
| `PUT /api/v1/software/settings` | admin | `{"restrict_flathub", "stores_read_only", "only_managed_remotes"}` | `200`; audited as `catalog.settings` |
| `GET /api/v1/packages` | audit, not device scoped | | `200` uploads of the tenant with `usage` and `snippet`, limits, quota use |
| `POST /api/v1/packages` | admin, not device scoped | multipart: `name`, `version`, `kind`, `reason`, `file` (up to the upload limit) | `201` `uploaded`, or `pending` with four eyes; audited as `artifact.upload` |
| `DELETE /api/v1/packages/{id}` | admin, not device scoped | | `204`; `409` while a library item uses it; audited as `artifact.delete` |
| `PUT /api/v1/packages/settings` | admin, global accounts | `{"max_upload_mb", "quota_mb", "quota_count", "store", "s3"}` | `200`; an empty S3 `secret` keeps the stored one; audited as `artifact.settings` |
| `GET /api/v1/stats/fleet` | read | | `200` devices per status, online, agent versions, OS, one fleet grid cell per device |
| `GET /api/v1/stats/compliance` | read | `days` (1 to 400, default 30) | `200` score, frameworks, most failing checks, daily history (global view only) |
| `GET /api/v1/stats/attention` | read | | `200` pending approvals, failed and sent commands of 24 hours, non compliant and stale devices, exceptions expiring in 7 days, last backup (global view, admin and auditor) |
| `GET /api/v1/stats/tenants` | admin, super admin in the all tenants view | | `200` per tenant: devices, compliant, non compliant, stale, pending, score, pending approvals; `404` without multi tenancy |
| `GET /api/v1/stats/commands` | read | `days` (1 to 90, default 14) | `200` failed and all commands per day, devices in scope |
| `GET /api/v1/onboarding` | read | | `200` first steps of a new installation (admins in the global view until done), else empty |
| `GET /api/v1/commands` | read | `status`, `days` (1 to 90, default 7), `limit`, `cursor` | `200` commands of every device in scope with host name, newest first, never the payload |
| `GET /api/v1/activity` | read | `kind`, `category`, `q`, `actor`, `action`, `target`, `from`, `to`, `limit`, `cursor` | `200` audit log (admins and auditors, audited as a read like `/api/v1/audit`) and device events (device scope) as one stream, newest first |
| `GET /api/v1/activity/histogram` | read | the filters of `/api/v1/activity` | `200` counts per day and category, default the last 30 days, at most 400 |
| `GET /api/v1/audit/status`, `POST /api/v1/audit/verify` | audit | | `200` first broken entry (0 = intact), last full verification, keyed from, known actions; `verify` checks the whole chain now (audited as `audit.verify`) |
| `GET /api/v1/stats/updates` | read | `days` (1 to 400, default 30) | `200` devices with pending security updates (from the detail of the check `updates.security`), their sum, devices failing it for more than 14 days, devices on the newest approved agent release (else the newest reported); daily history in the global view |
| `GET /api/v1/stats/annotations` | audit | `days` | `200` key rotations, approved agent releases, blueprint changes and failed backups per day, for the history charts |
| `GET /api/v1/report-schedules` | audit | | `200` own schedules (admins: all of the tenant view) and the channels a schedule may use |
| `POST /api/v1/report-schedules` | admin or auditor person, not a token | `{"view_id", "cadence", "channels", "emails"}` | `200` schedule of a saved report (list `reports`); audited as `report.schedule`; see [Scheduled reports](#scheduled-reports) |
| `DELETE /api/v1/report-schedules/{id}`, `POST .../{id}/run`, `GET .../{id}/runs` | owner, or admin of the tenant view | | `204`, the new run, or the kept runs; audited as `report.unschedule` and `report.run` |
| `GET /api/v1/report-runs/{id}` | audit | | the file of a run: its owner, or admins and auditors without a device scope in the same or the all tenants view; audited as `report.download` |
| `GET /api/v1/openapi.json` | none | | the OpenAPI document |
| `GET /api/v1/docs` | none | | the reference page |
| `GET /metrics` | metrics | | Prometheus text format, see [Metrics](#metrics) |

### Device filters

`q` (text in host name, OS, id, blueprint, tags), `status` (`compliant`, `in grace`,
`non-compliant`, `stale`, `pending`, `retired`), `tag`, `app`, `flatpak`, `remote`,
`blueprint`, `agent`, `failing` (check id) and `pkg`. All given filters apply together;
a value above 200 characters or an unknown `status` is answered with 400, never with the
unfiltered fleet. `pkg` is a package name with an optional version
comparison:

```sh
curl -G -H "Authorization: Bearer $LIMDM_TOKEN" https://mdm.example.com/api/v1/devices \
  --data-urlencode 'pkg=openssl < 3.0.13' --data-urlencode 'status=compliant'
```

Versions compare by their runs of digits; the epoch is ignored, letters and the Debian `~`
ordering are not evaluated.

### Query language

`filter` holds free words and `key:value` terms (`key:"value with spaces"`); every term
must match. Free words search host name, OS, id, blueprint and tags. Keys of devices:
`status` (`compliant`, `in-grace`, `non-compliant`, `stale`, `pending`, `retired`, and
`locked`: locked by the compliance policy or a lock command), `os` (part of the name),
`kind` (`desktop` or `server`), `tag`, `blueprint`, `agent`, `check` (id of a failing check), `pkg` (as
above, `pkg:openssl<3.0.13`), `app`, `flatpak`, `remote` and `seen` (`>7d` last check in
older than, `<2h` newer than; `m`, `h`, `d`). At most 20 terms of 200 characters; an
unknown key or value is a 400. `sort` takes `hostname`, `os`, `agent`, `failing` or
`last_seen`.

The console speaks German, so the German names of the prototype work as well and mean
the same: keys `zustand` (status), `system` and `betriebssystem` (os), `art` (kind),
`schlagwort` (tag), `pruefung` (check), `paket` (pkg), `quelle` (remote), `zuletzt` and
`gesehen` (seen) and `offline` (`offline:7d` is `seen:>7d`); status values `konform`,
`nicht-konform`, `in-karenz` (or `karenz`), `veraltet` and `offline` (stale),
`ausstehend`, `ausgemustert` and `gesperrt` (locked); kind values `arbeitsplatz`, `laptop`,
`notebook` (desktop) and `server`. Saved views keep the text as typed.

`GET /api/v1/devices/facets` takes the same filters and answers
`{"total", "facets": {"status", "os", "agent", "blueprint", "tag"}, "keys"}` with at most 25
values per facet and the keys with a help text for the query bar.

```sh
curl -G -H "Authorization: Bearer $LIMDM_TOKEN" https://mdm.example.com/api/v1/devices \
  --data-urlencode 'filter=status:non-compliant os:"Ubuntu 24" seen:<1d' --data-urlencode 'sort=-last_seen'
```

### Console app

The console app (`/app/`) uses this API with the console session instead of a token. A
request with the session cookie and without `Authorization` is checked like a console
page: the session must be valid, `Sec-Fetch-Site` (when sent) must be `same-origin`, `Origin`
(when sent) must be `LIMDM_PUBLIC_URL`, and every request other than `GET`, `HEAD` and
`OPTIONS` must carry the session's CSRF token (`csrf_token` of `GET /api/v1/me`) in
`X-CSRF-Token`. The session acts under its login with its role, tenant and device scope,
600 requests a minute; audit entries name the login, not a token.

Access levels beyond a route's own (audit entries in the event stream, sharing a view)
check role and token scopes together, so a token limited to `read` never receives audit
data.

`GET /api/v1/events/stream` sends server sent events, each limited to the caller's tenant
and device scope: `device` (a check in: `id`, `hostname`, `status`, `last_seen`),
`activity` (new audit entries: `id`, `at`, `actor`, `action`, `target`; admin and auditor
with the `audit` scope; opening such a stream is an audited read of the audit log) and
`inbox` (`pending` approvals, when the number changes). A stream ends after four minutes and
the browser reconnects; each caller may hold five streams.

### Settings and administration

The settings area of the console app calls the same functions as the classic pages, so
every guard holds through the API too:

* `GET /api/v1/settings` and `PATCH /api/v1/settings/{section}` (global admins; auditors
  read). A section saves only its own fields; left out fields keep their value. Secrets
  (OIDC client secret, logo bytes) are never returned; `oidc_client_secret` sets one,
  `clear_secret` removes it. The lockout guards of the console apply (own address,
  local login only off with an OIDC admin, four eyes approval needs two admins).
* `/api/v1/users`: add (local accounts answer their credentials once), change role, state
  and scope, reset local credentials. Self demotion is refused, the last admin stays,
  admin changes wait for approval (`202` with the approval) while four eyes approval is on.
* `/api/v1/tenants/{id}` (name, state, branding), `/api/v1/tenants/shared`,
  `POST /api/v1/tenants/switch` (super admin sessions, audited as `tenant.switch`).
* `/api/v1/keys`, `/api/v1/backup` (targets, schedules with a preview, runs, verify),
  `/api/v1/notification-channels`, `/api/v1/directory`, `/api/v1/network`,
  `/api/v1/agents` and the own `/api/v1/profile` (console sessions only).

Global pages (settings, keys, backup, directory, agents) refuse tenant accounts and
accounts with a device scope, as the classic console does.

### Audit filters

`q` searches actor, action, target and detail; `actor` is a part of the actor; `action` a
prefix (`api.` finds every API entry); `target` an exact target; `from` and `to` are dates
(`YYYY-MM-DD`, both inclusive).

### Commands

The body names a console command type and the fields of the console form. Params are
strings, numbers or booleans; `true` is sent as a checked box.

```json
{"type": "reboot", "params": {"minutes": 5}}
{"type": "message", "params": {"title": "Maintenance", "text": "Please save your work."}}
{"type": "wipe", "params": {"confirm": "pc-042", "reason": "stolen, ticket 4711"}}
{"type": "user_create", "params": {"username": "anna", "full_name": "Anna", "password": "...", "admin": false}}
```

| Types | Roles |
|---|---|
| `sync`, `update`, `reboot`, `shutdown`, `lock`, `unlock`, `message`, `user_password`, `user_lock`, `user_unlock`, `diagnostics` | admin, helpdesk |
| `script`, `lost`, `found`, `wipe`, `allow_uninstall`, `app_install`, `app_remove`, `user_create`, `user_admin`, `user_delete`, `software_remove` | admin |

Fields: `minutes` (reboot, shutdown: 0 to 1440, default 1), `confirm` and `message` (lost,
wipe: `confirm` is the host name), `title` and `text` (message), `payload` (script), `app`
(app_install, app_remove), `username`, `full_name`, `password`, `admin`, `keep_home` (user
commands), `kind`, `name`, `installation` (software_remove), `reason` (shown with an
approval request, up to 500 characters). A type the token's role may not send answers `403`
and is audited as `api.denied`; other rule violations answer `422`. A retired device answers
`409`.

The answer is `202` with the command and `Location: /api/v1/commands/{id}`. Send an
`Idempotency-Key` header (up to 255 printable characters) to make a retry after a timeout
safe: within 24 hours the same token and key get the first answer again
(`Idempotent-Replayed: true`) instead of a second command; the key with another request
answers `422`, while the first is still running `409`. Poll
`GET /api/v1/commands/{id}` until `status` is `ok`, `failed` or `expired` (`pending` and
`sent` are still open; commands expire after 7 days). The payload is never returned, since
it can hold a password.

With four eyes approval on (Settings, Security), wipe, lost mode and scripts do not run:
the answer is `202` with `{"approval_id": 12, "status": "pending"}` (`ApprovalPending` in the
OpenAPI document, `Location: /api/v1/approvals/{id}`) instead of a command, and another
admin decides under **Approvals** in the console (`params.reason` is shown there) or through
`POST /api/v1/approvals/{id}/approve`. Neither the requesting token nor the person who created
it can approve; once approved, the command is queued with the token as creator.

### Library items and blueprints

Library items take `name`, `type`, `description` and `payload` like the console editor and
are validated and signed the same way. Every save creates a version like a console save.
Answers mask network secrets; a `PUT` that sends the mask back keeps them. A certificate
item takes its certificates in the payload (the PEM upload is a console feature).
Blueprints take `name`, `description`, `parent_id` and `tree` (the JSON of the blueprint
editor). Deleting a library item a blueprint uses answers `409`. The default blueprint
cannot be renamed (`404`) or deleted (`409`), and never inherits.

`GET` and every save of a single item or blueprint answer with an `ETag`. Send it back as
`If-Match` with a `PUT`: when the object changed since (another automation or the console),
the answer is `412` with the current `ETag` and nothing is saved. The comparison locks the row
in the transaction of the save, so two writers with the same `ETag` cannot both win. A `PUT`
without `If-Match` replaces as before.

## Metrics

`GET /metrics` answers in the Prometheus text format (`text/plain; version=0.0.4`). It
needs a global, unscoped token of the role `metrics`, `admin` or `auditor`; helpdesk,
scoped and tenant tokens get `403` (`api.denied`). Setup and alerts:
[operations.md](operations.md#prometheus-metrics).

| Metric | Type | Labels |
|---|---|---|
| `limdm_devices` | gauge | `status` |
| `limdm_devices_last_checkin` | gauge | `age` (`lt_1h`, `lt_24h`, `lt_7d`, `lt_30d`, `ge_30d`, `never`) |
| `limdm_compliance_failing_devices` | gauge | `check` |
| `limdm_commands_open` | gauge | `status` (`pending`, `sent`) |
| `limdm_agent_versions` | gauge | `version` |
| `limdm_notifications_24h` | gauge | `result` (`ok`, `failed`) |
| `limdm_audit_chain_intact` | gauge | |
| `limdm_audit_verified_timestamp_seconds` | gauge | (only after a first verification) |
| `limdm_http_requests_total` | counter | `listener` (`console`, `agent`), `method`, `code`; per instance |

## Scheduled reports

A saved report preset (a saved view of the list `reports`, query
`kind=<export>&...`, `days=N` for the last N days) can run daily, weekly on
Monday or monthly on the first, at 06:00 server time. The leader instance runs
it as its owner with the role, device scope and tenant the owner has at that
moment, in the tenant view it was scheduled in, through the same export as the
console (audited as `export` and `export.done`). An owner who is disabled or no
longer admin or auditor gets a failed run instead of a file.

The server keeps the last 10 files of a schedule (at most 64 MB each) and sends
the chosen notification channels a link with the row count and the SHA-256,
never the file; e-mail addresses go through the first e-mail channel of the
tenant view. Downloading needs a sign in. Scheduling (`report.schedule`,
`report.unschedule`), every run (`report.run`, with the recipients) and every
download (`report.download`) are audited.

