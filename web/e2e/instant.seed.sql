-- A device for the inbox and confirm label tests (e2e/instant.spec.ts); idempotent
-- (an upsert: device events of earlier runs keep the device from being deleted).
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, last_seen, enrolled_at)
VALUES ('e2e-inst1', 'sinst1', now() + interval '300 days', 'e2e-inst1', '{"os_name":"Fedora Linux 43"}', now(), now() - interval '1 day')
ON CONFLICT (id) DO UPDATE SET last_seen = now();
UPDATE catalog_requests SET status = 'denied', decided_by = 'e2e', decided_at = now() WHERE device_id = 'e2e-inst1' AND status = 'pending';
