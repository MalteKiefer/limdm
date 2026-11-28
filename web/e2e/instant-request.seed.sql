-- A user's software request arriving while the console is open (e2e/instant.spec.ts).
INSERT INTO catalog_requests(device_id, flatpak, remote, app_name, username, note)
VALUES ('e2e-inst1', 'org.example.E2EInstant', 'flathub', 'E2E Instant', 'pia', 'for the bell test');
