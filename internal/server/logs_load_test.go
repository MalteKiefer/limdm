package server

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestLogSearchVolume fills the test database with LIMDM_TEST_LOG_LINES
// log lines (5,000,000 when set to 1) of 2000 devices over seven days and
// prints the time of the console's searches:
//
//	LIMDM_TEST_LOG_LINES=1 go test -run TestLogSearchVolume -v ./internal/server
func TestLogSearchVolume(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("LIMDM_TEST_LOG_LINES"))
	if n == 0 {
		t.Skip("LIMDM_TEST_LOG_LINES not set")
	}
	if n == 1 {
		n = 5000000
	}
	_, db, call := dashServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := ensureLogPartitions(ctx, db, now.AddDate(0, 0, -8), now.AddDate(0, 0, 2)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags, last_seen, checks, failing)
		SELECT 'dev' || g, 's', now(), 'host' || g || '.corp.test', CASE WHEN g % 10 = 0 THEN '{mail}'::text[] ELSE '{}' END, now(), '[]', 0
		FROM generate_series(0, 1999) g`); err != nil {
		t.Fatal(err)
	}
	for done := 0; done < n; done += 1000000 {
		if _, err := db.Exec(ctx, `INSERT INTO device_logs(at, device_id, tenant_id, source, unit, priority, host, message, dedup)
			SELECT now() - random() * interval '7 days', 'dev' || (g % 2000), 1, CASE WHEN g % 5 = 0 THEN 'container' ELSE 'journald' END,
				(ARRAY['postfix@-.service', 'sshd.service', 'cron.service', 'nginx', 'paperless', 'systemd-logind.service'])[1 + g % 6],
				(g % 8)::smallint, 'host' || (g % 2000),
				(ARRAY['connect to mx.example.com[192.0.2.1]:25: Connection refused', 'Accepted publickey for root from 198.51.100.7 port 51234 ssh2',
					'pam_unix(cron:session): session opened for user root', 'GET /api/documents/ 200 512 "-" "Mozilla/5.0"',
					'Started Daily apt download activities.', 'kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP'])[1 + (g * 7) % 6] || ' id=' || g,
				decode(md5(g::text), 'hex')
			FROM generate_series($1::bigint, $2::bigint) g`, done, min(done+1000000, n)-1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `ANALYZE device_logs`); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d lines loaded in %s", n, time.Since(start).Round(time.Second))
	day := url.QueryEscape(now.Add(-24 * time.Hour).Format(time.RFC3339))
	week := url.QueryEscape(now.AddDate(0, 0, -7).Format(time.RFC3339))
	for _, c := range []struct{ name, path string }{
		{"newest 200, last hour", "/api/v1/logs"},
		{"phrase, 24 h", "/api/v1/logs?from=" + day + "&q=" + url.QueryEscape(`"connection refused"`)},
		{"phrase, 7 days", "/api/v1/logs?from=" + week + "&q=" + url.QueryEscape(`"connection refused"`)},
		{"rare word, 7 days", "/api/v1/logs?from=" + week + "&q=" + url.QueryEscape(`id=4242424`)},
		{"unit and prio, 24 h", "/api/v1/logs?from=" + day + "&q=" + url.QueryEscape(`unit:postfix* prio<=err`)},
		{"regex, 24 h", "/api/v1/logs?from=" + day + "&q=" + url.QueryEscape(`/session opened for user \w+/`)},
		{"tag, 7 days", "/api/v1/logs?from=" + week + "&q=" + url.QueryEscape(`tag:mail "refused"`)},
		{"one device, 7 days", "/api/v1/logs?from=" + week + "&device=dev42"},
		{"histogram, 24 h", "/api/v1/logs/histogram?from=" + day},
		{"histogram phrase, 7 days", "/api/v1/logs/histogram?from=" + week + "&q=" + url.QueryEscape(`"connection refused"`)},
		{"facets, 24 h", "/api/v1/logs/facets?from=" + day},
	} {
		t0 := time.Now()
		code, body := call(dashAuditor, "GET", c.path, "")
		if code != 200 {
			t.Fatalf("%s: %d %s", c.name, code, body)
		}
		t.Logf("%-26s %8s", c.name, time.Since(t0).Round(time.Millisecond))
	}
}
