# Data retention

Every data type LiMDM stores about devices and people has a retention period, set under
**Settings, Data retention**. An hourly job on one instance deletes what is older. Set the
periods with your data protection officer and, where shell transcripts or events can be used
to monitor employees, with the works council. The table names the usual purpose and legal
reasoning; it is guidance, not legal advice.

| Data type | Default | Range (days) | Purpose | Legal reasoning |
|---|---|---|---|---|
| Audit log | 1095 (3 years) | 365 to 36500, or 0 (keep) | proof of administrative actions, investigation of incidents | ISO/IEC 27001:2022 A.5.33 and A.8.15 ask for protected logs over an audit period; three years cover a certification cycle (initial audit and two surveillance audits). GDPR Art. 5(1)(e) storage limitation forbids keeping personal data (actors, targets, host names) without an end; 0 keeps everything and needs a documented reason |
| Device events | 365 | 30 to 3650 | troubleshooting, incident review | GDPR Art. 5(1)(e); one year covers seasonal problems and most incident investigations |
| Compliance history | 1095 | 90 to 3650 | evidence of the compliance state over time | ISO/IEC 27001 A.5.36 (compliance with policies) and customer audits usually look back up to three years. The latest change per device and check always stays, so the current state remains explained |
| Finished commands | 180 | 30 to 3650 | who did what on which device | operational need; the latest lock, unlock, lost mode, end of lost mode and wipe stay regardless, the device page shows them. The audit log keeps the actions for its own period |
| Script results | 90 | 7 to 3650 | output of scripts for troubleshooting | output can contain personal data; besides the period at most 200 results per device are kept |
| Diagnostics bundles | 30 | 1 to 365 | support cases | bundles contain logs with user and host names; besides the period at most 10 bundles per device are kept |
| Remote shell transcripts | 90 | 7 to 3650 | evidence of support sessions | screen output can show anything a user had open; subject to co-determination (BetrVG section 87(1) no. 6); keep short and agree the period |
| Device metrics | 30 | 1 to 365 | device charts | performance data, operational need only |
| Notification log | 30 | 7 to 365 | delivery troubleshooting | operational need only |

Not configurable:

| Data | Kept |
|---|---|
| Fleet history (overview chart) | 400 days, aggregate numbers only |
| Approval requests | expire after 24 hours; decided requests stay with the audit log |
| Library item and blueprint versions | forever (append only); they hold configuration, no personal data |
| Retired devices | until deleted on the device page; the deletion removes events, metrics, commands, recovery keys and app requests |
| Backups | per target by the GFS counts under **Settings, Backup** ([backup.md](backup.md#schedule)) |

## Why the audit log is no longer kept forever

Up to 0.16 the audit log was kept forever unless a period was set. It records people (the
acting admin, the affected user, host names), so unlimited storage conflicts with GDPR
Art. 5(1)(e). The default is now three years: enough for ISO 27001 evidence and incident
investigation, with the syslog copy (`LIMDM_SYSLOG`) as the long term archive if your policy
demands one. A period saved before (**Settings, Security**) still applies until the retention
tab is saved; an installation that needs to keep everything sets 0 there, with a documented
reason.

The audit log is cut only behind a fully verified hash chain. The last deleted entry's id and
hash become a checkpoint signed with the audit key, from which verification starts; the
deletion is itself an audit entry ([security.md](security.md#audit-log)). `audit_log` and
`device_events` refuse deletes outside the retention job.

## Retention in backups

Deleting a record does not reach into archives already written. The backup schedule deletes
archives the GFS counts no longer keep (default: 7 daily, 4 weekly, 12 monthly), so personal
data in backups ends at the latest about a year after it was deleted from the database. This
expiry instead of deleting single records inside archives is the common practice for GDPR
Art. 17 in backups; document it in the record of processing activities (Art. 30). Archives
under S3 Object Lock stay until their lock ends.

## Tax and commercial law

LiMDM data are usually not accounting records. HGB section 257 and AO section 147 (6 or 10
years) apply only if your organization uses LiMDM data as such, for example as the basis of
invoices. Do not keep everything "just in case".
