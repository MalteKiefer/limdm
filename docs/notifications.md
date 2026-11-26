# Notifications

**Settings**, **Notifications** has two ways to hear about events:

* **Notification channels** send the events you choose to Slack, Discord, email or a signed
  webhook.
* The **Compliance webhook** posts every device that becomes non-compliant (and every
  tamper report) to one URL. It is described in [compliance.md](compliance.md#webhook).

## Events

Each channel subscribes to event types; none selected means all events. The console shows
the label, webhooks receive the code.

| Code | Label | When | Severity |
|---|---|---|---|
| `device.noncompliant` | Device became non-compliant | a device still fails checks when its grace period ends and the compliance policy has `notify` on | warning |
| `device.tamper` | Tamper attempt on a device | the agent reports a tamper attempt (also in the audit log) | critical |
| `device.enrolled` | Device enrolled | a device joined | info |
| `command.failed` | Lock, wipe, lost mode or script failed | lock, unlock, lost mode, end of lost mode, wipe or a script failed on the device | critical |
| `agent.update_failed` | Agent update failed and rolled back | an agent update failed, with or without rollback | warning |
| `catalog.request` | App requested by a user | a user requested an app | info |
| `directory.user_disabled` | Device user disabled in the directory | a device user was disabled in the directory; the device locks the account | warning |
| `recovery.view` | Recovery key viewed | somebody viewed a disk recovery key (with the reason, if given) | warning |
| `command.wipe_lost` | Wipe or lost mode sent | a wipe or lost mode was queued for a device | critical |
| `command.script` | Script sent to a device | a script was queued for a device (the text is in the audit log) | warning |
| `user.role_change` | Console user role changed | the role of a console user changed (and who approved it) | warning |
| `approval.request` | Four eyes approval requested | a [four eyes approval](security.md#four-eyes-approval) was requested | warning |
| `audit.broken` | Audit log verification failed | the daily verification found the audit hash chain broken | critical |
| `network.crl_token` | Network CRL token rotated | an admin rotated the bearer token for network CRL downloads | warning |
| `keys.rotate` | Key rotation started or finished | a key rotation (device CA, network CA, command key, session key) was started or finished, or the webhook signing secret was rotated ([keys.md](keys.md)) | warning |

**Send test** delivers an event with the code `test`.

## Channels

| Kind (console) | Setup | Message |
|---|---|---|
| Slack | an incoming webhook URL (`https://hooks.slack.com/…`) | title, text and an "Open in LiMDM" link; host and user names are escaped, so they cannot form links or mentions |
| Discord | a channel webhook URL (`https://discord.com/api/webhooks/…`, also `discordapp.com`, `ptb.discord.com`, `canary.discord.com`) | an embed coloured by severity; mentions are switched off |
| Email (SMTP) | SMTP server, port, encryption (`STARTTLS` or `TLS`), optional user and password, sender, 1 to 20 recipients | subject `[LiMDM] <title>`, plain text; plain SMTP is refused, TLS 1.2 at least, header values are encoded and control characters removed |
| Webhook | an https URL | the JSON event, signed |

Every channel has a name (1 to 80 characters, unique). Channels can be tested, switched off
and on, and deleted; adding, switching and deleting are audited
(`notification.channel_add`, `notification.channel_enable`, `notification.channel_disable`,
`notification.channel_delete`). A channel cannot be edited: delete it and add it again.

### Webhook channel payload and signature

```json
{"type": "device.tamper", "title": "Tamper attempt on pc1", "text": "...", "severity": "critical",
 "device_id": "...", "hostname": "pc1", "console_url": "https://mdm.example.com/devices/...",
 "at": "2026-11-26T08:00:00Z"}
```

`device_id` and `hostname` are left out for events without a device. The request carries
`X-LiMDM-Timestamp: <unix seconds>` and `X-LiMDM-Signature: sha256=<hex>`, the
HMAC-SHA256 of `<timestamp>.<raw body>`, exactly like the
[compliance webhook](compliance.md#webhook). The key is the webhook signing secret
([keys.md](keys.md#webhook-signing-secret)), shown to admins as **Signing key** in the
Compliance webhook card. Reject timestamps older than five minutes.

## Delivery

Delivery runs in the background, so the action that caused the event never waits. Each
channel gets three attempts (at once, after 10 seconds, after a minute), each with a 30
second limit. The outcome is shown as the channel's last delivery and kept in
`notification_log` for 30 days; failures are also in the server log. In a cluster the
instance where the event happened delivers it.

Targets are checked after name resolution: loopback, link local (including cloud metadata
at 169.254.169.254), multicast and unspecified addresses are refused; private networks are
allowed (an internal SIEM or mail relay). An outbound proxy from the environment
(`HTTPS_PROXY`) is used, and the target is checked before the request goes to it.
Redirects are not followed.

Webhook URLs (Slack, Discord, webhook) and the SMTP password are credentials. They are
sealed with AES-256-GCM, bound to the channel, and never shown again; the list shows only
the host (email: recipients and SMTP server).

## Tenants

With several [tenants](tenants.md) a channel belongs to the tenant that created it, or is
global when a global administrator created it in the global view.

* A tenant channel receives only the events of its tenant's devices.
* A global channel receives the events of every tenant.
* Events without a device (`user.role_change`, `approval.request`, `audit.broken`,
  `network.crl_token`, `keys.rotate`) reach global channels only.

Tenant accounts see only the **Notifications** tab of the settings, with their own channels;
they cannot see or change the compliance webhook or the signing secret.
