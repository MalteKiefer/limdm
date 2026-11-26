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
| `PATCH /api/v1/devices/{id}` | admin | `{"tags": [...], "blueprint_id": 3}`; fields left out stay, `null` assigns default | `200` device; audited as `device.assign` |
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
| `POST /api/v1/exceptions` | admin | `{"check_id", "mode", "tag", "reason", "owner", "approver", "expires": "YYYY-MM-DD"}` | `201` `{"id"}`; audited as `exception.add` |
| `DELETE /api/v1/exceptions/{id}` | admin | | `204`; audited as `exception.revoke` |
| `GET /api/v1/tokens` | audit | | `200` `{"items": [...]}` tokens without secrets |
| `POST /api/v1/tokens` | admin | `{"name", "role", "days", "read_only", "scope_tags", "scopes"}` | `201` token with `token` (the secret, shown once); audited as `api_token.create` |
| `DELETE /api/v1/tokens/{id}` | admin | | `204`; audited as `api_token.revoke` |
| `GET /api/v1/tenants` | admin, global token | | `200` `{"items": [...]}` tenants with device counts; `404` without multi tenancy |
| `POST /api/v1/tenants` | admin, global token | `{"name"}` | `201` `{"id"}`; `409` name taken; audited as `tenant.add` |
| `GET /api/v1/devices/facets` | read | [filters](#query-language) | `200` counts per status, OS, agent, blueprint and tag |
| `GET /api/v1/me` | read | | `200` the caller: `login`, `role`, `tenant`, `super`, scope, `scopes`, `permissions` (`read`, `audit`, `commands`, `admin`, `tenants`), `four_eyes`, `locale`, `company_name`, `accent`, and for sessions `csrf_token` |
| `GET /api/v1/events/stream` | read | | server sent events, see [Console app](#console-app) |
| `GET /api/v1/views` | read | `list` | `200` own and shared saved views |
| `POST /api/v1/views` | self | `{"list", "name", "query", "sort", "columns", "shared"}` | `201` view; only admins share; shared views are audited as `view.save` |
| `PUT /api/v1/views/{id}`, `DELETE /api/v1/views/{id}` | self | | `200` view or `204`; own views, admins also delete shared ones (`view.delete`) |
| `GET /api/v1/schemas`, `GET /api/v1/schemas/{type}` | read | | declaration types; JSON Schema (draft 2020-12) of a payload, derived from the Go types |
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
| `GET /api/v1/compliance/history` | read | `at` (date, default today), `device` | `200` state at the end of the day per device, or per check of one device with its changes |
| `GET /api/v1/exports/{kind}` | audit | `compliance.csv`, `compliance-history.csv` (`at`, `device`), `inventory.csv`, `packages.csv`, `exceptions.csv`, `audit.csv` and `audit.jsonl` (the audit filters) | the console's evidence exports, audited as `export` and `export.done` with row count and SHA-256 |
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
`status` (`compliant`, `in-grace`, `non-compliant`, `stale`, `pending`, `retired`), `os`
(part of the name), `tag`, `blueprint`, `agent`, `check` (id of a failing check), `pkg` (as
above, `pkg:openssl<3.0.13`), `app`, `flatpak`, `remote` and `seen` (`>7d` last check in
older than, `<2h` newer than; `m`, `h`, `d`). At most 20 terms of 200 characters; an
unknown key or value is a 400. `sort` takes `hostname`, `os`, `agent`, `failing` or
`last_seen`. `GET /api/v1/devices/facets` takes the same filters and answers
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
