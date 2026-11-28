# Agent API

This page covers the agent API. The REST API for administrators and integrations is in
[admin-api.md](admin-api.md).

The agent talks to the server over its own listener (`LIMDM_AGENT_LISTEN`), TLS 1.3 only. The
server certificate comes from the device CA; the agent pins that CA by its SHA-256
fingerprint at enrollment. Every endpoint except `GET /api/v1/ca` and `POST /api/v1/enroll`
needs the device's client certificate from the device CA, and the server accepts only the
serial currently registered for the device (or its pending successor after a renewal). JSON
bodies are UTF-8 (RFC 8259), times RFC 3339.

## Versioning

All paths carry the version prefix `/api/v1/`. There is no version negotiation: new fields
are added as optional JSON fields (`omitempty`), so an older agent ignores what it does not
know and a newer agent leaves out what an older server does not read. The agent reports
its version as `agent_version` in every check in, and the console shows it per device and on
**Agents**. A change that breaks this would get a new prefix.

## Errors

Errors are RFC 9457 problem details:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json

{"type": "urn:limdm:problem:forbidden", "code": "forbidden", "title": "Forbidden", "status": 403, "detail": "certificate revoked"}
```

| Status | Meaning |
|---|---|
| 400 | malformed JSON, body above the limit of the endpoint, or an invalid certificate signing request |
| 401 | no valid client certificate from the device CA |
| 403 | certificate not the registered one (revoked, replaced, device retired), enrollment token invalid, expired or used up, tenant disabled, or no EAP-TLS network profile for `network-cert` |
| 404 | unknown remote shell session; agent packages, catalog icons and Flathub icons answer a plain `404` without problem details |
| 409 | remote shell session already connected |
| 429 | rate limit (failed enrollments per address, Flathub search and icons, network certificates per device) |
| 500 | internal error; details only in the server log |
| 503 | remote shell relay to another server instance unavailable |

A body above the limit ends the JSON decoding, so it answers `400`, not `413`.

## Endpoints

| Method and path | Auth | Body limit | Purpose |
|---|---|---|---|
| `GET /api/v1/ca` | none | | the device CA certificate (PEM) |
| `POST /api/v1/enroll` | token | 64 KiB | `{"token", "csr", "hostname", "machine_id"}` → `{"device_id", "cert"}`. Only failed attempts count: 20 per 5 minutes and address, so a rollout behind one NAT is not slowed. The device joins the tenant and blueprint of its token. A second enrollment of the same `machine_id` in the same tenant is recorded in the audit log (`device.duplicate`); retiring the older record is left to an admin, because the machine ID proves nothing. |
| `POST /api/v1/renew` | device (expired allowed) | 64 KiB | `{"csr"}` → `{"device_id", "cert"}`. The new certificate becomes active at its first use and revokes the old one then. A certificate that expired less than 180 days ago may still renew. |
| `POST /api/v1/checkin` | device | 16 MiB | status, inventory, packages, command results, events → declarations, users, commands, catalog, branding, update offer, key fields. See [Check in](#check-in). |
| `POST /api/v1/poll` | device | | → `{"pending": true}` when commands, a due agent update or a directory change for a device user wait; the agent then checks in |
| `POST /api/v1/network-cert` | device | 64 KiB | `{"csr"}` → `{"device_id", "cert"}`: EAP-TLS certificate from the network CA, only when an EAP-TLS network profile applies to the device; 5 per 10 minutes and device. See [Network profiles](network.md#device-certificates-for-eap-tls). |
| `GET /api/v1/agent-packages/{version}/{file}` | device | | agent package of an approved, not blocked release, or of the version an admin picked for the device; the file must be listed in the release's `SHA256SUMS` |
| `GET /api/v1/catalog/icons/{id}` | device | | catalog app icon (PNG) |
| `GET /api/v1/catalog/search?q=` | device | | Flathub search through the server; 30 per 10 minutes and device, cached for an hour |
| `GET /api/v1/catalog/flathub-icon?u=` | device | | Flathub icon proxy, only `dl.flathub.org` and PNG; 300 per 10 minutes and device, cached |
| `POST /api/v1/shell/{session}` | device | stream | remote shell relay, only for the device of the session. See [Remote shell relay](#remote-shell-relay). |

A device checks in once per check in interval and polls every minute. The interval comes
from the agent declaration (`checkin_seconds`, 30 to 86400, default 300 in the seeded
library item); without one the agent uses five minutes. Up to 10% jitter spreads the
fleet. After failures the poll doubles its wait up to five minutes, plus up to 10 seconds of
jitter. After a poll answered `pending` the agent polls every 10 seconds for five minutes, and
a check in for queued commands skips converging and the inventory (see
[agent.md](agent.md#command-delivery)). One check in per device runs at a time (row lock).

## Check in

The request carries `agent_version`, `arch`, the hashes of what the agent already has
(`declarations_token`, `status_hash`, `packages_hash`, `branding_hash`, `catalog_hash`,
`ca_hash`), and, when needed, `status`, `packages`, `results` (command results with
`id`, `ok`, `output` and for scripts and diagnostics their structured result), `metrics`,
`recovery_keys` (new LUKS recovery keys to escrow), `update_result`, `events`,
`app_requests` (self service requests), `script_results` (recurring scripts) and
`command_key` (the pinned command key). `status_hash` leaves out small changes (free space
within 5 % of a volume, SSO confirmations on the same day), so the full `status` is sent
only when something relevant changed; the compliance detail of a pending reboot names the
date since when, not a running duration.

The response carries:

| Field | When |
|---|---|
| `declarations_token`, `declarations` | always the token; the declarations only when the token differs |
| `users` | always: the directory users of the device |
| `commands` | pending commands, signed (see [Integrity](#integrity)) |
| `need_status`, `need_packages` | the server asks for the full status or package list because its hash differs |
| `agent_update` | a due agent release: `version`, `sums` (`SHA256SUMS`), `sums_sig` |
| `server_time` | always |
| `recovery_rotate` | escrowed recovery keys that were viewed and must be replaced |
| `branding` | company name and logo of the device's tenant, when `branding_hash` differs ([brand-guidelines.md](brand-guidelines.md#customer-branding)) |
| `catalog` | the self service app catalog, when `catalog_hash` differs; every app and remote carries `signature` (command key over `limdm-catalog-app-v1` or `limdm-catalog-remote-v1` and the signed fields, [security.md](security.md#agent-channel)) |
| `signed_data`, `signed_users` | the server signs catalog entries and the user list; `signed_users` is `{"users", "signature"}`, the list as saved (signature over `limdm-users-v1`, the device ID and the list), of which `users` may be a subset |
| `fallback_dns` | the server setting that allows public DNS over HTTPS when the system resolver fails |
| `command_key` | always: the public command key (hex) |
| `command_key_rollover` | during a command key rotation: `{"key", "signature"}`, the new key signed by the old one |
| `device_cas` | the PEM bundle of the device CAs to trust (both during a CA rotation), when `ca_hash` differs |
| `renew_cert` | the client certificate was issued by a device CA that is being retired: renew now |
| `renew_network_cert` | the same for the EAP-TLS certificate during a network CA rotation |

Agents renew their client certificate and their EAP-TLS certificate 30 days before expiry
(both are valid 90 days), or at once when `renew_cert` or `renew_network_cert` is set.
Rotation steps: [keys.md](keys.md#rotation).

## Remote shell relay

A session starts as a signed `shell` command that carries the session ID, the local user,
the console user and the time limits. The agent then opens `POST /api/v1/shell/{session}`:
the request body streams terminal output, the response streams frames to the agent. A frame
is one type byte (`i` input, `r` resize with columns and rows as two big endian uint16),
a big endian uint16 length and the payload (at most 65535 bytes). Only the device of the
session may connect, and only once (`409` otherwise). With several server instances the
session is relayed to the instance that holds the console side. See
[remote-shell.md](remote-shell.md).

## Related endpoints on the console listener

These are not part of the agent listener but serve devices and network infrastructure:

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /install.sh` | none | installer script for the newest agent release from the release repository (deb or rpm, SHA-256 verified, osquery with pinned key) with the server URL and the device CA fingerprint filled in. Reads `LIMDM_TOKEN`, `LIMDM_ALLOW_SCRIPTS=true` and `LIMDM_ALLOW_REMOTE_SHELL=true`, or an existing `/etc/limdm/enroll.conf`. Contains no secret. `404` when no release repository is configured. |
| `GET /network/crl.pem` | console session or bearer token | CRL of the network CA (valid 7 days) for RADIUS servers. Send the CRL token (`lmc_...`) from **Network certificates** as `Authorization: Bearer`; the server stores only its SHA-256. Failed tokens: 20 per 5 minutes and address, then `429`. |
| `GET /network/ca.pem` | console session | network CA certificate; during a rotation both CAs |

The CRL token is created or replaced under **Network certificates** with **Create token**
or **Rotate token** (audited as `network.crl_token`, announced as a warning notification). See
[network.md](network.md#revocation).

## Integrity

* **Commands** carry an Ed25519 signature over device ID, command ID, type, creation time
  and payload, made with `command.key` when the command is created. The agent pins the public
  key (`command_key` in the check in response) and refuses unsigned or altered commands.
  The recovery keys a lost mode command carries are added at delivery and not signed.
* **Library items** are signed with the same key when saved in the console or through the
  admin API. The server checks the signature before it merges items into a device's
  declarations; an item changed outside the console is not delivered and logged as an error.
* **Agent packages** are verified against the release's `SHA256SUMS`, and the agent accepts
  `SHA256SUMS` only with a valid signature of the release key compiled into it
  ([operations.md](operations.md#release-key)).

`command.key` lives in the CA directory (or the HSM), never in the database. Back it up with
the CA key. During a command key rotation the check in response also carries
`command_key_rollover` and the agent reports its pinned key as `command_key`, so the console
can show how far the rotation has reached the fleet; during a device CA rotation the response
carries `device_cas` and `renew_cert`, during a network CA rotation `renew_network_cert`
([keys.md](keys.md)).
