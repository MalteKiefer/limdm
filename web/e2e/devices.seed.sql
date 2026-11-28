-- Devices for the devices area tests (e2e/devices.spec.ts); idempotent.
BEGIN;
SET LOCAL limdm.retention = 'on'; -- device_events are append only outside the retention
DELETE FROM devices WHERE id LIKE 'e2e-%';
INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version, enrolled_at)
VALUES
  ('e2e-ws1', 's1', now() + interval '300 days', 'e2e-ws1',
   '{"os_name":"Ubuntu 24.04 LTS","os_version":"24.04","kernel":"6.8.0","arch":"x86_64","desktop":"GNOME","memory_mb":16384,"vendor":"Lenovo","model":"T14","serial":"PF12345",
     "cpu":"Intel Core i7","cpu_cores":8,"cpu_threads":16,"disk_gb":512,
     "volumes":[{"device":"/dev/mapper/root","mount":"/","fs":"ext4","size_gb":500,"free_gb":120,"encrypted":true,"encryption":"LUKS2"}],
     "disks":[{"name":"nvme0n1","model":"Samsung","size_gb":512,"type":"ssd"}],
     "accounts":[{"name":"jdoe","uid":1000,"home":"/home/jdoe","shell":"/bin/bash","source":"local","admin":true}],
     "interfaces":[{"name":"wlp0s20f3","kind":"wifi","state":"up","ips":["192.168.1.20/24"],"mac":"aa:bb:cc:dd:ee:ff","mtu":1500}],
     "flatpaks":[{"id":"org.mozilla.firefox","name":"Firefox","version":"130.0","branch":"stable","origin":"flathub","installation":"system"}]}',
   '{prod,berlin}', now(), '[{"id":"ssh.root","title":"SSH root login disabled","level":1,"status":"pass","refs":{"bsi":["SYS.1.3.A2"]}},{"id":"firewall.active","title":"Host firewall is active","level":1,"status":"pass"}]', 0, '0.17.0', now() - interval '30 days'),
  ('e2e-ws2', 's2', now() + interval '300 days', 'e2e-ws2',
   '{"os_name":"Debian 12","desktop":"KDE","memory_mb":8192,"serial":"PF67890"}',
   '{prod}', now() - interval '2 hours', '[{"id":"disk.encryption","title":"Disk encryption","level":1,"status":"fail","detail":"/ is not encrypted"}]', 1, '0.16.0', now() - interval '10 days'),
  ('e2e-srv1', 's3', now() + interval '300 days', 'e2e-srv1',
   '{"os_name":"Debian GNU/Linux 12 (bookworm)","os_id":"debian","os_version":"12","os_product":"Proxmox VE 8.4","proxmox":{"version":"8.4.1","node":"e2e-srv1","cluster":"lab"},"memory_mb":32768}',
   '{}', now() - interval '9 days', '[]', 0, '0.17.0', now() - interval '60 days');
INSERT INTO device_events(device_id, at, detail) VALUES ('e2e-ws1', now() - interval '5 minutes', 'checked in from the e2e seed');
INSERT INTO compliance_changes(device_id, at, check_id, status) VALUES ('e2e-ws1', now() - interval '4 minutes', 'ssh.root', 'pass');
-- an ended fish session (escape sequences, autosuggestion, missing newline marker)
INSERT INTO shell_sessions(id, device_id, requested_by, local_user, created_at, connected_at, ended_at, end_reason, transcript)
VALUES ('e2e-sh1', 'e2e-ws1', 'local:e2e', 'limdm-support', now() - interval '20 minutes', now() - interval '19 minutes', now() - interval '18 minutes', 'ended in the console', decode('1b5d303b7e071b5b3f32303034681b5b33326d6d616c74651b28421b5b6d407063201b5b33326d7e1b28421b5b6d3e201b5b4b6c1b5b39306d73202d6c611b28421b5b6d1b5b3544731b5b39306d202d6c611b28421b5b6d1b5b34441b5b4b0d0a1b5b3f323030346c1b5b30313b33346d446f63756d656e74731b5b306d2020612e7478742020622e7478740d0a1b5b326de28f8e1b28421b5b6d202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020200d200d1b5b33326d6d616c74651b28421b5b6d407063201b5b33326d7e1b28421b5b6d3e20657869740d0a', 'hex'));
-- firewall inventory (R3-F): a foreign rule, a foreign SSH rule (risk) and a Docker rule (system)
INSERT INTO device_firewall(device_id, inventory, hash) VALUES ('e2e-ws1', '{"backend":"ufw","active":true,"policy":{"in":"deny","out":"allow","forward":"disabled"},"rules":[
  {"id":"00000000000000a1","match":"ufw : ufw allow 8080/tcp","source":"ufw","origin":"foreign","direction":"in","action":"allow","port":"8080","proto":"tcp","raw":"ufw allow 8080/tcp"},
  {"id":"00000000000000a2","match":"ufw : ufw allow 22/tcp","source":"ufw","origin":"foreign","direction":"in","action":"allow","port":"22","proto":"tcp","raw":"ufw allow 22/tcp","risk":"ssh"},
  {"id":"00000000000000a3","match":"iptables filter FORWARD: -A FORWARD -o docker0 -j ACCEPT","source":"iptables","origin":"system","table":"filter","chain":"FORWARD","direction":"forward","action":"accept","iface":"docker0","raw":"-A FORWARD -o docker0 -j ACCEPT"}]}', 'e2e');
INSERT INTO device_packages(device_id, name, version, arch) VALUES ('e2e-ws1', 'openssl', '3.0.2-0ubuntu1', 'amd64'), ('e2e-ws1', 'bash', '5.2.21', 'amd64'), ('e2e-ws2', 'openssl', '3.0.15-1', 'amd64');
-- containers and VMs (workloads tab)
INSERT INTO device_workloads(device_id, inventory, hash) VALUES ('e2e-ws1', '{"tools":[{"kind":"docker","version":"27.3.1"},{"kind":"qm","version":"8.2.4"}],
  "items":[{"kind":"docker","id":"3f4e5d6c7b8a99887766554433221100ffeeddccbbaa00998877665544332211","name":"paperless-webserver-1","image":"ghcr.io/paperless-ngx/paperless-ngx:2.13","state":"running","project":"paperless","service":"webserver","ports":["127.0.0.1:8000->8000/tcp"]},
  {"kind":"qm","id":"200","name":"win11","type":"vm","state":"stopped","cpus":4,"memory_mb":8192}]}', 'e2e'),
  -- a Proxmox VE node: two running guests, one stopped
  ('e2e-srv1', '{"tools":[{"kind":"pct","version":"8.4.1"},{"kind":"qm","version":"8.4.1"}],
  "items":[{"kind":"pct","id":"101","name":"dns","type":"container","state":"running"},{"kind":"qm","id":"100","name":"web","type":"vm","state":"running"},
  {"kind":"qm","id":"102","name":"old","type":"vm","state":"stopped"}]}', 'e2e');
COMMIT;
