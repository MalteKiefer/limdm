# Admin API

The console offers a REST API under `<LIMDM_PUBLIC_URL>/api/v1/` for scripts, ticket systems
and other integrations. It runs on the console listener and uses the same functions as the
console: the same role rules, the same validation and the same audit entries. The OpenAPI 3.1
description is served at `/api/v1/openapi.json` (no token needed) and lives in the repository
as [`internal/server/openapi.json`](../internal/server/openapi.json).

## Tokens

Admins create tokens under Administration, **API tokens** (`/settings/api`):

* **Name**: shown in the audit log, for example `ticket system`.
* **Role**: `admin`, `helpdesk`, `auditor` or `metrics`. A token can do what its role can do
  in the console. `auditor` tokens only read. `metrics` tokens only read
  [`/metrics`](operations.md#prometheus-metrics).
* **Read only**: an admin or helpdesk token that may only read.
* **Valid for days**: 1 to 365; every token expires.
* **Scope tags**: optional device tags (comma separated) for a `helpdesk` or `auditor`
  token, as for scoped console users ([security.md](security.md)). A scoped token lists,
  reads and commands only devices with one of the tags (other devices answer `404`), sees
  only their audit entries and tags, and gets no `/metrics`. Directory group scopes exist
  for console users only. Admin and metrics tokens cannot be scoped.

The token (`lma_...`) is shown once. The server stores only its SHA-256 hash, the first
characters for recognition, the creator, the expiry and the last use (updated at most once a
minute). **Revoke** ends a token at once. A token keeps working when the admin who created it
leaves; revoke it then.

Send the token as a bearer token. The API sets no cookies and reads none, so there is nothing
for cross site requests to abuse.

```sh
curl -H "Authorization: Bearer $LIMDM_TOKEN" https://mdm.example.com/api/v1/devices?tag=finance
```

## Audit

Entries made through the API name the token as actor: `api:<name>#<id>`. In addition:

| Action | When |
|---|---|
| `api_token.create`, `api_token.revoke` | A token was created or revoked in the console |
| `api.auth_failed` | An unknown, expired or revoked token was sent (detail: reason and client address) |
| `api.denied` | A valid token tried something its role does not allow |

## Limits

* 600 requests per minute and token; then `429` with `Retry-After`.
* Failed authentications: 20 per client address in five minutes, as for SCIM; then `429`
  before the token is even checked. A request without any token counts but is not audited.
* Request bodies up to 1 MiB.
* The console's network allow and block lists apply.

## Conventions

* JSON (RFC 8259), UTF-8, times RFC 3339. Requests with a body send
  `Content-Type: application/json`; unknown fields are refused.
* Errors are RFC 9457 problem details (`application/problem+json`) with `status` and `detail`,
  also for unknown paths (`404`) and wrong methods (`405` with `Allow`).
* Status codes: `200` read or replaced, `201` created (with `Location`), `202` command
  queued, `204` deleted, `400` malformed request, `401` token missing or invalid, `403` role
  does not allow it, `404` not found, `409` name taken or object still in use, `415` not JSON,
  `422` rejected by validation, `429` rate limited.
* Lists take `limit` (1 to 500, default 100) and return `{"items": [...], "next_cursor": "..."}`.
  Pass `next_cursor` as `cursor` for the next page; it is absent on the last page.

## Endpoints

| Method and path | Role | Purpose |
|---|---|---|
| `GET /api/v1/devices` | any | Devices; filters as in the console, combined |
| `GET /api/v1/devices/{id}` | any | One device with inventory |
| `PATCH /api/v1/devices/{id}` | admin | `{"tags": [...], "blueprint_id": 3}`; `null` assigns default |
| `GET /api/v1/devices/{id}/commands` | any | Commands of a device, newest first |
| `POST /api/v1/devices/{id}/commands` | admin, helpdesk | Queue a command |
| `GET /api/v1/commands/{id}` | any | Status and output of a command |
| `GET`, `POST /api/v1/library-items` | any, admin | List, create |
| `GET`, `PUT`, `DELETE /api/v1/library-items/{id}` | any, admin | Read, replace, delete |
| `GET`, `POST /api/v1/blueprints` | any, admin | List, create |
| `GET`, `PUT`, `DELETE /api/v1/blueprints/{id}` | any, admin | Read, replace, delete |
| `GET /api/v1/tags` | any | Tags of active devices with counts |
| `GET /api/v1/audit` | admin, auditor | Audit log, newest first |

"any" means every role except `metrics`.

### Device filters

`q` (text in host name, OS, id, blueprint, tags), `status` (`compliant`, `in grace`,
`non-compliant`, `stale`, `pending`, `retired`), `tag`, `app`, `flatpak`, `remote`,
`blueprint`, `agent`, `failing` (check id) and `pkg`. All given filters apply together.
`pkg` is a package name with an optional version comparison:

```sh
curl -G -H "Authorization: Bearer $LIMDM_TOKEN" https://mdm.example.com/api/v1/devices \
  --data-urlencode 'pkg=openssl < 3.0.13' --data-urlencode 'status=compliant'
```

Versions compare by their runs of digits; the epoch is ignored, letters and the Debian `~`
ordering are not evaluated.

### Commands

The body names a console command type and the fields of the console form:

```json
{"type": "reboot", "params": {"minutes": 5}}
{"type": "message", "params": {"title": "Maintenance", "text": "Please save your work."}}
{"type": "wipe", "params": {"confirm": "pc-042"}}
{"type": "user_create", "params": {"username": "anna", "full_name": "Anna", "password": "...", "admin": false}}
```

The rules are the console's: scripts, lost mode, wipe, allow uninstall, user, software and
app commands need the admin role; lost mode and wipe need the host name in `confirm`. The
answer is `202` with the command and its `Location`. Poll `GET /api/v1/commands/{id}` until
`status` is `ok`, `failed` or `expired`. The payload is never returned, since it can hold a
password.

With four eyes approval on (Settings, Security), wipe, lost mode and scripts do not run:
the answer is `202` with `{"approval_id": 12, "status": "pending"}` and an admin decides
under **Approvals** in the console (`params.reason` is shown there). The token can never
approve its own request; once approved, the command is queued with the token as creator.
Library item answers mask network secrets; a `PUT` that sends the mask back keeps them, and
every save creates a version like a console save.

### Library items and blueprints

Library items take `name`, `type`, `description` and `payload` like the console editor and
are validated and signed the same way. A certificate item takes its certificates in the
payload (the PEM upload is a console feature). Blueprints take `name`, `description`,
`parent_id` and `tree` (the JSON of the blueprint editor). Deleting a library item a
blueprint uses answers `409`; the default blueprint cannot be renamed or deleted.
