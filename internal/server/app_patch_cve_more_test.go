package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const archFixture = `[
 {"name": "AVG-2843", "packages": ["openssl", "lib32-openssl"], "status": "Fixed", "severity": "High", "type": "denial of service",
  "affected": "3.3.1-1", "fixed": "3.3.2-1", "ticket": null, "issues": ["CVE-2024-6119"], "advisories": ["ASA-202409-1"]},
 {"name": "AVG-2900", "packages": ["curl"], "status": "Vulnerable", "severity": "Medium", "affected": "8.10.0-1", "fixed": null, "issues": ["CVE-2024-9681"]},
 {"name": "AVG-2901", "packages": ["vim"], "status": "Fixed", "severity": "Unknown", "affected": "9.1.0-1", "fixed": "1:9.1.0700-1", "issues": ["CVE-2024-43802"]}
]`

const alpineMain = `{"distroversion": "v3.20", "reponame": "main", "packages": [
 {"pkg": {"name": "openssl", "secfixes": {"3.3.2-r0": ["CVE-2024-6119"], "3.1.4-r1": ["CVE-2023-5678 CVE-2023-5363"], "0": ["CVE-2022-1343"]}}},
 {"pkg": {"name": "musl", "secfixes": {"1.2.2_pre2-r0": ["CVE-2020-28928"]}}}
]}`

func TestCVEArchAlpine(t *testing.T) {
	var got []cveFix
	collectFix := func(f cveFix) error { got = append(got, f); return nil }
	if err := parseArchTracker(strings.NewReader(archFixture), collectFix); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Package != "openssl" || got[1].Package != "lib32-openssl" || got[0].Fixed != "3.3.2-1" || got[0].Severity != "high" || got[2].Severity != "" || got[0].Release != "rolling" {
		t.Fatalf("arch: %+v", got)
	}
	got = nil
	if err := parseAlpineSecdb(strings.NewReader(alpineMain), "v3.20", collectFix); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("alpine: %+v", got)
	}
	for v, want := range map[string]string{"3.20.3": "v3.20", "3.21.0": "v3.21", "3.21_alpha20240923": "edge", "3": "edge"} {
		if b := alpineBranch(v); b != want {
			t.Errorf("%s: %s", v, b)
		}
	}

	s, db, call := dashServer(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/arch":
			w.Write([]byte(archFixture))
		case "/secdb/v3.20/main.json":
			w.Write([]byte(alpineMain))
		case "/secdb/v3.20/community.json":
			w.Write([]byte(`{"packages": []}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := s.importFeed(ctx, "alpine", srv.URL+"/secdb", 1<<20); err == nil || !strings.Contains(err.Error(), "no Alpine device") {
		t.Fatalf("alpine without devices: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE devices SET inventory='{"os_id":"arch","os_version":""}' WHERE id='d3';
		INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, last_seen) VALUES ('d4', 's', now(), 'delta', '{"os_id":"alpine","os_version":"3.20.3"}', now());
		INSERT INTO device_packages(device_id, name, version, arch, source) VALUES
			('d3', 'openssl', '3.3.1-1', 'x86_64', ''), ('d3', 'vim', '9.1.0800-1', 'x86_64', ''),
			('d4', 'libcrypto3', '3.3.1-r3', 'x86_64', 'openssl'), ('d4', 'musl', '1.2.5-r0', 'x86_64', '')`); err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(ctx, "arch", srv.URL+"/arch", 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(ctx, "alpine", srv.URL+"/secdb", 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(ctx, "alpine", srv.URL+"/secdb", 10); err == nil {
		t.Fatal("alpine limit passed")
	}
	if err := s.matchAllCVEs(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, `SELECT device_id || ' ' || cve || ' ' || package FROM device_cves WHERE device_id IN ('d3','d4') ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var matched []string
	for rows.Next() {
		var x string
		rows.Scan(&x)
		matched = append(matched, x)
	}
	// d3: openssl 3.3.1-1 < 3.3.2-1, vim without epoch older than 1:9.1.0700-1;
	// d4: libcrypto3 (origin openssl) 3.3.1-r3 < 3.3.2-r0, musl is fixed
	if strings.Join(matched, ",") != "d3 CVE-2024-43802 vim,d3 CVE-2024-6119 openssl,d4 CVE-2024-6119 libcrypto3" {
		t.Fatalf("%v", matched)
	}
	code, body := call(dashAuditor, "GET", "/api/v1/updates/cve-feeds", ``)
	if code != 200 || !strings.Contains(body, `"distro":"arch","enabled":false`) || !strings.Contains(body, `"distro":"alpine"`) {
		t.Fatalf("feeds: %d %s", code, body)
	}
	if (CVEFeedSettings{Arch: true, Alpine: true}).enabled()[1] != "alpine" || len((CVEFeedSettings{}).enabled()) != 0 {
		t.Fatal("enabled")
	}
}
