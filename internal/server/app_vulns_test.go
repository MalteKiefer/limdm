package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCVSSAndSeverity(t *testing.T) {
	for v, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1, // CVE-2024-6387
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		if got, ok := cvss3Score(v); !ok || got != want {
			t.Errorf("%s: %v %v", v, got, ok)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X"} {
		if _, ok := cvss3Score(bad); ok {
			t.Errorf("%q passed", bad)
		}
	}
	if sql := sevRankSQL("c.severity"); !strings.Contains(sql, "WHEN 'important' THEN 3") || !strings.Contains(sql, "WHEN 'negligible' THEN 1") {
		t.Fatal(sql)
	}
	if cvssLevel(9.8) != 4 || cvssLevel(7) != 3 || cvssLevel(5.5) != 2 || cvssLevel(0.1) != 1 || cvssLevel(0) != 0 {
		t.Fatal("cvss levels")
	}
	// a feed downloads only while a device runs the distribution; KEV always
	if got := activeFeeds([]string{"debian", "ubuntu", "kev"}, []string{"debian", "fedora"}); !slices.Equal(got, []string{"debian", "kev"}) {
		t.Fatal(got)
	}
}

const kevFixture = `{"title": "CISA Catalog", "vulnerabilities": [
 {"cveID": "CVE-2024-5535", "vulnerabilityName": "OpenSSL SSL_select_next_proto", "dateAdded": "2024-07-01", "dueDate": "2024-07-22", "knownRansomwareCampaignUse": "Known"},
 {"cveID": "not a cve"}]}`

func TestVulnerabilities(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// d1 Debian 13: postgresql 17+278+deb13u1 is built from postgresql-common
	// 278+deb13u1, the tracker lists the source fix 178 (CVE-2016-1255);
	// libssl3 (openssl) is really behind. d2 Fedora names CVEs in its
	// pending updates.
	exec(`UPDATE devices SET inventory='{"os_id":"debian","os_version":"13"}' WHERE id='d1';
		UPDATE devices SET inventory='{"os_id":"fedora","os_version":"41"}', updates='{"pending":[{"name":"curl","current":"8.9.1-1","candidate":"8.9.1-3","source":"os_all","security":true,"severity":"Important","cves":["CVE-2024-9681"]}]}' WHERE id='d2';
		INSERT INTO cve_fixes(distro, release, package, cve, fixed, severity) VALUES
			('debian', 'trixie', 'postgresql-common', 'CVE-2016-1255', '178', 'low'),
			('debian', 'trixie', 'openssl', 'CVE-2024-5535', '3.0.14-1', 'medium'),
			('debian', 'trixie', 'openssl', 'CVE-2024-0727', '3.0.13-1', '');
		INSERT INTO cve_scores(cve, cvss, vector, source) VALUES ('CVE-2024-0727', 9.1, 'x', 'ubuntu');
		INSERT INTO device_packages(device_id, name, version, arch, source) VALUES
			('d1', 'postgresql', '17+278+deb13u1', 'all', 'postgresql-common'), ('d1', 'libssl3', '3.0.11-1', 'amd64', 'openssl')`)
	if err := s.matchAllCVEs(ctx); err != nil {
		t.Fatal(err)
	}
	count := func(where string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM device_cves WHERE `+where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// without the source version the binary version stands in: the old false positive
	if count(`cve='CVE-2016-1255' AND remediated_at IS NULL`) != 1 || count(`device_id='d2' AND cve='CVE-2024-9681'`) != 1 {
		t.Fatal("initial matches")
	}
	// the agent reports the source version: the finding is dropped, not remediated
	exec(`UPDATE device_packages SET source_version='278+deb13u1' WHERE name='postgresql'`)
	if err := s.matchAllCVEs(ctx); err != nil {
		t.Fatal(err)
	}
	if count(`cve='CVE-2016-1255'`) != 0 {
		t.Fatal("the false positive stayed")
	}
	// KEV list
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(kevFixture)) }))
	defer srv.Close()
	if err := s.importFeed(ctx, "kev", srv.URL, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(ctx, "kev", srv.URL, 10); err == nil {
		t.Fatal("kev limit passed")
	}

	code, body := call(dashAuditor, "GET", "/api/v1/vulnerabilities?sort=-cvss", ``)
	if code != 200 || !strings.Contains(body, `"total":3`) || !strings.Contains(body, `"cve":"CVE-2024-0727","severity":"critical","cvss":9.1`) ||
		!strings.Contains(body, `"cve":"CVE-2024-5535","severity":"medium","cvss":null,"kev":true`) || !strings.Contains(body, `"cve":"CVE-2024-9681","severity":"high"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	if strings.Index(body, "CVE-2024-0727") > strings.Index(body, "CVE-2024-5535") {
		t.Fatal("sort by cvss")
	}
	for q, want := range map[string]string{"severity=high": `"total":1`, "q=ssl3": `"total":2`, "kev=true": `"total":1`, "os=fedora": `"total":1`, "limit=1": `"next_cursor":"1"`} {
		if code, body := call(dashAuditor, "GET", "/api/v1/vulnerabilities?"+q, ``); code != 200 || !strings.Contains(body, want) {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
	if code, _ := call(dashAuditor, "GET", "/api/v1/vulnerabilities?severity=bad", ``); code != 400 {
		t.Fatal("bad severity")
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/vulnerabilities?format=csv&sort=cve", ``); code != 200 || !strings.HasPrefix(body, "cve,severity,cvss") || !strings.Contains(body, "CVE-2024-9681,high,,false,curl,") {
		t.Fatalf("csv: %d %s", code, body)
	}

	// the package is updated: remediated, with the date
	exec(`UPDATE device_packages SET version='3.0.14-1' WHERE name='libssl3'`)
	if err := s.matchAllCVEs(ctx); err != nil {
		t.Fatal(err)
	}
	if count(`device_id='d1' AND remediated_at IS NOT NULL`) != 2 {
		t.Fatal("not remediated")
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/vulnerabilities?status=remediated", ``); code != 200 || !strings.Contains(body, `"total":2`) || !strings.Contains(body, `"remediated_devices":1`) {
		t.Fatalf("remediated: %d %s", code, body)
	}

	// risk acceptance: admin only, audited, reopen revokes it, expiry ends it
	day := time.Now().AddDate(0, 1, 0).Format(time.DateOnly)
	if code, _ := call(dashAuditor, "POST", "/api/v1/vulnerabilities/CVE-2024-9681/accept", `{"reason":"lab","expires":"`+day+`"}`); code != 403 {
		t.Fatalf("auditor accept: %d", code)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/vulnerabilities/CVE-2024-9681/accept", `{"reason":"","expires":"`+day+`"}`); code != 422 || !strings.Contains(body, "reason") {
		t.Fatalf("empty reason: %d %s", code, body)
	}
	if code, body := call(dashAdmin, "POST", "/api/v1/vulnerabilities/CVE-2024-9681/accept", `{"reason":"no internet access","expires":"`+day+`","device_id":"d2"}`); code != 201 {
		t.Fatalf("accept: %d %s", code, body)
	}
	code, body = call(dashAuditor, "GET", "/api/v1/vulnerabilities/summary", ``)
	if code != 200 || !strings.Contains(body, `"findings":{"accepted":1,"active":0,"remediated":2}`) || !strings.Contains(body, `"top_packages":[]`) ||
		!strings.Contains(body, `"os":["debian","fedora"]`) || !strings.Contains(body, `"hostname":"beta"`) {
		t.Fatalf("summary: %d %s", code, body)
	}
	code, body = call(dashHelpdesk, "GET", "/api/v1/vulnerabilities/CVE-2024-9681", ``)
	if code != 200 || !strings.Contains(body, `"status":"accepted"`) || !strings.Contains(body, `"reason":"no internet access"`) || !strings.Contains(body, `"sources":["package manager"]`) ||
		!strings.Contains(body, `"hostname":"beta"`) || !strings.Contains(body, `"fixed":["8.9.1-3"]`) {
		t.Fatalf("detail: %d %s", code, body)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='vulnerability.accept' AND target='d2'`).Scan(&n)
	if n != 1 {
		t.Fatal("accept not audited")
	}
	if code, _ := call(dashAdmin, "POST", "/api/v1/vulnerabilities/CVE-2024-9681/reopen", ``); code != 204 {
		t.Fatalf("reopen: %d", code)
	}
	if code, _ := call(dashAdmin, "POST", "/api/v1/vulnerabilities/CVE-2024-9681/reopen", ``); code != 404 {
		t.Fatalf("reopen twice: %d", code)
	}
	exec(`INSERT INTO cve_acceptances(cve, reason, expires_at, created_by) VALUES ('CVE-2024-9681', 'old', now() - interval '1 day', 'x')`)
	if code, body := call(dashAuditor, "GET", "/api/v1/vulnerabilities", ``); code != 200 || !strings.Contains(body, `"cve":"CVE-2024-9681"`) || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("expired acceptance: %d %s", code, body)
	}
	if code, _ := call(dashAuditor, "GET", "/api/v1/vulnerabilities/CVE-2099-0001", ``); code != 404 {
		t.Fatal("unknown cve")
	}

	// feed state: Ubuntu switched on without Ubuntu devices is skipped
	off := s.rt.Load()
	on := *off
	on.set.CVEFeeds = CVEFeedSettings{Debian: true, Ubuntu: true}
	s.rt.Store(&on)
	defer s.rt.Store(off)
	code, body = call(dashAuditor, "GET", "/api/v1/updates/cve-feeds", ``)
	if code != 200 || !strings.Contains(body, `"distro":"ubuntu","enabled":true`) || !strings.Contains(body, `"skipped":true`) || strings.Contains(body, `"distro":"debian","enabled":true,"url":"https://security-tracker.debian.org/tracker/data/json","fetched_at":null,"rows":0,"bytes":0,"error":"","error_at":null,"skipped":true`) {
		t.Fatalf("feeds: %d %s", code, body)
	}
}
