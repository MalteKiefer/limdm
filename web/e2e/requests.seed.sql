-- A pending app request for the "approve and install" test (e2e/config.spec.ts); idempotent.
BEGIN;
DELETE FROM devices WHERE id = 'e2e-req1';
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, last_seen, enrolled_at)
VALUES ('e2e-req1', 'sreq1', now() + interval '300 days', 'e2e-req1', '{"os_name":"Ubuntu 24.04 LTS"}', now(), now() - interval '1 day');
INSERT INTO catalog_apps(slug, name, mode, sources) VALUES ('e2e-notes', 'E2E Notes', 'request', '[{"kind":"flatpak","flatpak":"org.example.E2ENotes"}]')
ON CONFLICT (slug) DO NOTHING;
INSERT INTO catalog_requests(device_id, app, username, note) VALUES ('e2e-req1', 'e2e-notes', 'eve', 'for the e2e test');
COMMIT;
