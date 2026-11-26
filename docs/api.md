# Agent API

This page covers the agent API. The REST API for administrators and integrations is in
[admin-api.md](admin-api.md).

The agent talks to the server over its own listener (`LIMDM_AGENT_LISTEN`), TLS 1.3 only.
Every endpoint except `GET /api/v1/ca` and `POST /api/v1/enroll` needs the device's client
certificate from the device CA; the server accepts only the serial currently registered
for the device (or its pending successor after a renewal). JSON bodies are UTF-8 (RFC 8259),
times RFC 3339.

## Errors

Errors of the agent API are RFC 9457 problem details:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json

{"type": "about:blank", "title": "Forbidden", "status": 403, "detail": "certificate revoked"}
```

| Status | Meaning |
|---|---|
| 400 | malformed JSON or certificate signing request |
| 401 | no valid client certificate |
| 403 | certificate revoked, device retired, or enrollment token invalid or used up |
| 404 | unknown package, icon or release |
| 413 | body above the limit of the endpoint |
| 429 | rate limit (enrollment per address, Flathub search and icons per device) |
| 500 | internal error; details only in the server log |

## Endpoints

| Method and path | Auth | Body limit | Purpose |
|---|---|---|---|
| `GET /api/v1/ca` | none | | the device CA certificate (PEM); enrollment pins it by SHA-256 fingerprint |
| `POST /api/v1/enroll` | token | 64 KiB | `{"token", "csr", "hostname", "machine_id"}` → `{"device_id", "cert"}`; 20 attempts per 5 minutes and address. A second enrollment of the same `machine_id` is recorded in the audit log (`device.duplicate`); retiring the older record is left to an admin, because the machine ID proves nothing. |
| `POST /api/v1/renew` | device (expired allowed) | 64 KiB | new CSR → new certificate, active at its first use |
| `POST /api/v1/checkin` | device | 16 MiB | status, inventory, results, events → declarations, users, commands, catalog, update offer |
| `POST /api/v1/poll` | device | | `{"pending": true}` when commands, a due agent update or a directory change for a device user wait; the agent then checks in |
| `GET /api/v1/agent-packages/{version}/{file}` | device | | agent package of an approved release, or the version picked for the device |
| `GET /api/v1/catalog/icons/{id}` | device | | catalog app icon (PNG) |
| `GET /api/v1/catalog/search?q=` | device | | Flathub search through the server; 30 per 10 minutes and device, cached for an hour |
| `GET /api/v1/catalog/flathub-icon?u=` | device | | Flathub icon proxy, only `dl.flathub.org`; 300 per 10 minutes and device, cached |

A device checks in once per check in interval (agent declaration, default 15 minutes) and
polls every minute with jitter; after failures the poll backs off to five minutes. One
check in per device runs at a time (row lock).

## Integrity

* **Commands** carry an Ed25519 signature over device, ID, type, creation time and payload,
  made with `command.key` when the command is created. The agent pins the public key
  (`command_key` in the check in response) and refuses unsigned or altered commands.
* **Library items** are signed with the same key when saved in the console. The server
  checks the signature before it merges items into a device's declarations; an item changed
  outside the console is not delivered and logged as an error.
* Agent packages are verified against the release's signed `SHA256SUMS`.

`command.key` lives in the CA directory, never in the database. Back it up with the CA key.
