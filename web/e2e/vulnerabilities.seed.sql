-- Findings for the vulnerabilities page tests (e2e/vulnerabilities.spec.ts); idempotent.
-- CVE-2099-* IDs keep them apart from the findings other seeds add.
BEGIN;
SET LOCAL limdm.retention = 'on'; -- device_events are append only outside the retention
DELETE FROM cve_acceptances WHERE cve LIKE 'CVE-2099-%';
DELETE FROM devices WHERE id LIKE 'e2e-vu%';
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version, enrolled_at)
VALUES
  ('e2e-vu1', 'v1', now() + interval '300 days', 'e2e-vu1', '{"os_id":"debian","os_name":"Debian GNU/Linux 13 (trixie)","os_version":"13"}', '{}', now(), '[]', 0, '0.19.1', now() - interval '40 days'),
  ('e2e-vu2', 'v2', now() + interval '300 days', 'e2e-vu2', '{"os_id":"fedora","os_name":"Fedora Linux 41","os_version":"41"}', '{}', now(), '[]', 0, '0.19.1', now() - interval '40 days');
INSERT INTO device_cves(device_id, cve, package, installed, fixed, severity, first_seen, last_seen, remediated_at) VALUES
  ('e2e-vu1', 'CVE-2099-0001', 'libssl3', '3.0.11-1', '3.0.14-1', 'high', now() - interval '12 days', now(), NULL),
  ('e2e-vu2', 'CVE-2099-0001', 'openssl', '1:3.2.2-1.fc41', '1:3.2.2-9.fc41', 'Important', now() - interval '9 days', now(), NULL),
  ('e2e-vu1', 'CVE-2099-0002', 'libxml2', '2.9.14+dfsg-1.3', '2.9.14+dfsg-1.3+deb13u1', '', now() - interval '5 days', now(), NULL),
  ('e2e-vu1', 'CVE-2099-0003', 'curl', '8.5.0-1', '8.5.0-2', 'low', now() - interval '3 days', now(), NULL),
  ('e2e-vu1', 'CVE-2099-0004', 'bash', '5.2.15-2', '5.2.15-2+deb13u1', 'medium', now() - interval '30 days', now() - interval '2 days', now() - interval '2 days');
INSERT INTO cve_scores(cve, cvss, vector, source) VALUES ('CVE-2099-0002', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'ubuntu')
  ON CONFLICT (cve) DO UPDATE SET cvss = EXCLUDED.cvss, vector = EXCLUDED.vector;
INSERT INTO cve_kev(cve, name, added, due, ransomware) VALUES ('CVE-2099-0002', 'libxml2 test entry', '2026-01-05', '2026-01-26', true)
  ON CONFLICT (cve) DO UPDATE SET name = EXCLUDED.name;
COMMIT;
