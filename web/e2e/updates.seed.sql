-- Devices for the updates area tests (e2e/updates.spec.ts); idempotent.
BEGIN;
SET LOCAL limdm.retention = 'on'; -- device_events are append only outside the retention
DELETE FROM update_rings WHERE name LIKE 'e2e-%';
DELETE FROM devices WHERE id LIKE 'e2e-up%';
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version, enrolled_at, updates)
VALUES
  ('e2e-up1', 'u1', now() + interval '300 days', 'e2e-up1', '{"os_name":"Fedora 41","os_version":"41"}', '{e2epilot}', now(), '[]', 0, '0.19.0', now() - interval '5 days',
   '{"pending":[{"name":"openssl","current":"1:3.2.2-1.fc41","candidate":"1:3.2.2-9.fc41","origin":"updates","source":"os_all","security":true,"severity":"Important","cves":["CVE-2024-5535"]},
                {"name":"code","current":"1.94","candidate":"1.95","origin":"code","source":"third_party"}],
     "runs":[{"source":"os_security","at":"2026-11-25T02:10:00Z","result":"no_updates","detail":"Nothing to do."}]}');
INSERT INTO device_packages(device_id, name, version, arch) VALUES ('e2e-up1', 'openssl', '1:3.2.2-1.fc41', 'x86_64');
COMMIT;
