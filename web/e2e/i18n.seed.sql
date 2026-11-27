-- A device with an agent event for the language tests (e2e/i18n.spec.ts); idempotent.
BEGIN;
SET LOCAL limdm.retention = 'on'; -- device_events are append only outside the retention
DELETE FROM devices WHERE id = 'e2e-i18n';
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version, enrolled_at)
VALUES ('e2e-i18n', 'si18n', now() + interval '300 days', 'e2e-i18n', '{"os_name":"Debian 12"}', '{}', now(),
  '[{"id":"updates.security_age","title":"No security update pending longer than allowed","level":1,"status":"pass"}]', 0, '0.21.0', now() - interval '1 day');
INSERT INTO device_events(device_id, at, detail) VALUES ('e2e-i18n', now() - interval '5 minutes', 'declarations updated (token 42)');
INSERT INTO compliance_changes(device_id, at, check_id, status) VALUES ('e2e-i18n', now() - interval '4 minutes', 'updates.security_age', 'pass');
COMMIT;
