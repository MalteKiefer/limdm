-- Log lines for the Logs page tests (e2e/logs.spec.ts); idempotent.
BEGIN;
SET LOCAL limdm.retention = 'on'; -- device_events are append only outside the retention
DO $$
DECLARE d date;
BEGIN
  FOR i IN -1..1 LOOP
    d := (now() AT TIME ZONE 'UTC')::date + i;
    EXECUTE format('CREATE TABLE IF NOT EXISTS device_logs_%s PARTITION OF device_logs FOR VALUES FROM (%L) TO (%L)',
      to_char(d, 'YYYYMMDD'), d::timestamp AT TIME ZONE 'UTC', (d + 1)::timestamp AT TIME ZONE 'UTC');
  END LOOP;
END $$;
DELETE FROM device_logs WHERE device_id LIKE 'e2e-lg%';
DELETE FROM log_alerts WHERE name LIKE 'e2e %';
DELETE FROM devices WHERE id LIKE 'e2e-lg%';
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version, enrolled_at)
VALUES
  ('e2e-lg1', 'l1', now() + interval '300 days', 'e2e-mail', '{"os_id":"debian","os_name":"Debian GNU/Linux 13 (trixie)","os_version":"13"}', '{}', now(), '[]', 0, '0.20.2', now() - interval '40 days'),
  ('e2e-lg2', 'l2', now() + interval '300 days', 'e2e-docs', '{"os_id":"debian","os_name":"Debian GNU/Linux 13 (trixie)","os_version":"13"}', '{}', now(), '[]', 0, '0.20.2', now() - interval '40 days');
INSERT INTO device_logs(at, device_id, tenant_id, source, unit, priority, host, message, fields, dedup) VALUES
  (now() - interval '20 minutes', 'e2e-lg1', 1, 'journald', 'postfix@-.service', 3, 'e2e-mail', 'connect to mx.example.com[192.0.2.1]:25: Connection refused', '{"_PID":"4242","SYSLOG_IDENTIFIER":"postfix/smtp"}', '\x01'),
  (now() - interval '19 minutes', 'e2e-lg1', 1, 'journald', 'postfix@-.service', 6, 'e2e-mail', 'status=deferred (connect to mx.example.com: Connection refused)', '{"_PID":"4242"}', '\x02'),
  (now() - interval '18 minutes', 'e2e-lg1', 1, 'journald', 'sshd.service', 6, 'e2e-mail', 'Accepted publickey for admin from 198.51.100.7 port 51234 ssh2', NULL, '\x03'),
  (now() - interval '10 minutes', 'e2e-lg2', 1, 'container', 'paperless', 6, '', 'GET /api/documents/ 200', '{"container_id":"abcdef123456","compose_project":"paperless"}', '\x04'),
  (now() - interval '5 minutes', 'e2e-lg2', 1, 'container', 'paperless', 4, '', 'WARNING slow consumer queue', '{"container_id":"abcdef123456"}', '\x05');
COMMIT;
