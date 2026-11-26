# Admin API

The console offers a REST API under `<LIMDM_PUBLIC_URL>/api/v1/` for scripts, ticket systems
and other integrations. It runs on the console listener and uses the same functions as the
console: the same role rules, device scopes, tenant limits, four eyes approval, validation
and audit entries. The OpenAPI 3.1 description is served at `/api/v1/openapi.json` (no token
needed) and lives in the repository as
[`internal/server/openapi.json`](../internal/server/openapi.json).

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

### Roles

| Level | Roles | Endpoints |
|---|---|---|
| read | `admin`, `helpdesk`, `auditor` (read only tokens included) | every `GET` except the audit log |
| audit | `admin`, `auditor` | `GET /api/v1/audit` |
| helpdesk | `admin`, `helpdesk`, not read only | `POST /api/v1/devices/{id}/commands`; the command type decides further |
| admin | `admin`, not read only | `PATCH`, `POST`, `PUT`, `DELETE` on devices, library items and blueprints |
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
  also for unknown paths (`404`) and wrong methods (`405` with `Allow`). A `401` carries
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
| `POST /api/v1/library-items` | admin | item without `id` | `201` item; audited as `library.save` |
| `GET /api/v1/library-items/{id}` | read | | `200` item |
| `PUT /api/v1/library-items/{id}` | admin | full item | `200` item; audited as `library.save` |
| `DELETE /api/v1/library-items/{id}` | admin | | `204`; `409` while a blueprint uses it; audited as `library.delete` |
| `GET /api/v1/blueprints` | read | `limit`, `cursor` | `200` page of blueprints (`id`, `name`, `description`, `parent_id`, `tree`, `updated_at`) |
| `POST /api/v1/blueprints` | admin | `{"name", "description", "parent_id", "tree"}` | `201` blueprint; audited as `blueprint.save` |
| `GET /api/v1/blueprints/{id}` | read | | `200` blueprint |
| `PUT /api/v1/blueprints/{id}` | admin | full blueprint | `200` blueprint; audited as `blueprint.save` |
| `DELETE /api/v1/blueprints/{id}` | admin | | `204`; its devices fall back to default; audited as `blueprint.delete` |
| `GET /api/v1/tags` | read | | `200` `{"items": [{"name", "devices"}]}`, tags of active devices |
| `GET /api/v1/audit` | audit | `q`, `actor`, `action`, `target`, `from`, `to`, `limit`, `cursor` | `200` page of entries (`id`, `at`, `actor`, `action`, `target`, `detail`, `prev`, `hash`, `tenant_id`), newest first |
| `GET /api/v1/openapi.json` | none | | the OpenAPI document |
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

The answer is `202` with the command and `Location: /api/v1/commands/{id}`. Poll
`GET /api/v1/commands/{id}` until `status` is `ok`, `failed` or `expired` (`pending` and
`sent` are still open; commands expire after 7 days). The payload is never returned, since
it can hold a password.

With four eyes approval on (Settings, Security), wipe, lost mode and scripts do not run:
the answer is `202` with `{"approval_id": 12, "status": "pending"}` (`ApprovalPending` in the
OpenAPI document, `Location: /approvals`) instead of a command, and another admin decides
under **Approvals** in the console (`params.reason` is shown there). Tokens cannot approve;
once approved, the command is queued with the token as creator.

### Library items and blueprints

Library items take `name`, `type`, `description` and `payload` like the console editor and
are validated and signed the same way. Every save creates a version like a console save.
Answers mask network secrets; a `PUT` that sends the mask back keeps them. A certificate
item takes its certificates in the payload (the PEM upload is a console feature).
Blueprints take `name`, `description`, `parent_id` and `tree` (the JSON of the blueprint
editor). Deleting a library item a blueprint uses answers `409`. The default blueprint
cannot be renamed (`404`) or deleted (`409`), and never inherits.

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
