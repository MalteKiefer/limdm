# Notifications

**Settings**, **Integrations** sends events to channels: email, Slack, Discord or a signed
webhook. Each channel subscribes to event types (none selected: all). Delivery runs in the
background with three attempts (at once, after 10 seconds, after a minute); every outcome
is in the channel's last delivery and kept for 30 days. **Send test** checks a channel.

| Event | When |
|---|---|
| `device.noncompliant` | a device fails checks after its grace period |
| `device.tamper` | the agent reports a tamper attempt (also in the audit log) |
| `device.enrolled` | a device joined |
| `command.failed` | lock, unlock, lost mode, end of lost mode, wipe or a script failed on the device |
| `agent.update_failed` | an agent update failed, with or without rollback |
| `catalog.request` | a user requested an app |
| `directory.user_disabled` | a device user was disabled in the directory; the device locks the account |

## Channels

| Kind | Setup | Notes |
|---|---|---|
| Slack | an incoming webhook URL (`https://hooks.slack.com/…`) | host and user names are escaped, they cannot form links or mentions |
| Discord | a channel webhook URL (`https://discord.com/api/webhooks/…`) | an embed coloured by severity; mentions are switched off |
| Email | SMTP server, port, STARTTLS or TLS, user and password, sender, up to 20 recipients | plain SMTP is refused; header values are encoded |
| Webhook | an https URL | the JSON event, signed like the compliance webhook (`X-LiMDM-Timestamp`, `X-LiMDM-Signature: sha256=HMAC(key, timestamp + "." + body)`) |

Webhook URLs and the SMTP password are credentials: they are stored encrypted (AES-GCM,
bound to the channel) and never shown again; the list shows only the host. Redirects are
not followed. The compliance webhook under **Monitoring** keeps working alongside.
