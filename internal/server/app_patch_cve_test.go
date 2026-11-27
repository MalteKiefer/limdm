package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const debianFixture = `{
 "openssl": {
  "CVE-2024-5535": {"description": "x", "releases": {
    "bookworm": {"status": "resolved", "fixed_version": "3.0.14-1~deb12u2", "urgency": "medium"},
    "trixie": {"status": "open", "urgency": "medium"},
    "sid": {"status": "resolved", "fixed_version": "3.3.1-1", "urgency": "medium"}}},
  "CVE-2023-0001": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "0", "urgency": "low"}}},
  "TEMP-0000000-ABCDEF": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.1-1", "urgency": "low"}}}
 },
 "glibc": {
  "CVE-2024-2961": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "2.36-9+deb12u7", "urgency": "high**"}}},
  "CVE-2010-4756": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "2.36-1", "urgency": "unimportant"}}}
 }
}`

const osvFixture = `{"id": "UBUNTU-CVE-2024-6387", "upstream": ["CVE-2024-6387"], "severity": [{"type": "Ubuntu", "score": "High"}],
 "affected": [
  {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssh"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.6p1-3ubuntu13.3"}]}]},
  {"package": {"ecosystem": "Ubuntu:Pro:18.04:LTS", "name": "openssh"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:7.6p1-4ubuntu0.7+esm3"}]}]},
  {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssh"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
 ]}`

func TestParseCVEFeeds(t *testing.T) {
	var got []cveFix
	if err := parseDebianTracker(strings.NewReader(debianFixture), func(f cveFix) error { got = append(got, f); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	for _, f := range got {
		switch f.CVE {
		case "CVE-2024-5535":
			if f.Release != "bookworm" || f.Package != "openssl" || f.Fixed != "3.0.14-1~deb12u2" || f.Severity != "medium" {
				t.Errorf("%+v", f)
			}
		case "CVE-2024-2961":
			if f.Severity != "high" {
				t.Errorf("%+v", f)
			}
		default:
			t.Errorf("unexpected %+v", f)
		}
	}
	if parseDebianTracker(strings.NewReader(`[]`), func(cveFix) error { return nil }) == nil {
		t.Error("an array passed")
	}
	var rec osvRecord
	if err := json.Unmarshal([]byte(osvFixture), &rec); err != nil {
		t.Fatal(err)
	}
	fx := rec.fixes()
	if len(fx) != 1 || fx[0].CVE != "CVE-2024-6387" || fx[0].Release != "24.04" || fx[0].Package != "openssh" || fx[0].Severity != "high" {
		t.Fatalf("%+v", fx)
	}
	for _, c := range []struct {
		os, ver, distro, rel string
		ok                   bool
	}{{"debian", "12", "debian", "bookworm", true}, {"ubuntu", "24.04", "ubuntu", "24.04", true}, {"debian", "", "debian", "", false}, {"fedora", "41", "", "", false}} {
		if d, r, ok := cveRelease(c.os, c.ver); d != c.distro || r != c.rel || ok != c.ok {
			t.Errorf("%s %s: %s %s %v", c.os, c.ver, d, r, ok)
		}
	}
	if (CVEFeedSettings{DebianURL: "http://x"}).validate() == "" || (CVEFeedSettings{MaxMB: 5000}).validate() == "" || (CVEFeedSettings{UbuntuURL: "https://mirror.example/all.zip"}).validate() != "" {
		t.Error("validate")
	}
}

func osvZip(t *testing.T) []byte {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("UBUNTU-CVE-2024-6387.json")
	w.Write([]byte(osvFixture))
	w, _ = z.Create("broken.json")
	w.Write([]byte("{"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCVEImportAndMatch(t *testing.T) {
	s, db, call := dashServer(t)
	ctx := context.Background()
	zipped := osvZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/debian":
			w.Write([]byte(debianFixture))
		case "/ubuntu":
			w.Write(zipped)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := s.importFeed(ctx, "debian", srv.URL+"/debian", 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := s.importFeed(ctx, "ubuntu", srv.URL+"/ubuntu", 1<<20); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM cve_fixes`).Scan(&n)
	if n != 3 {
		t.Fatalf("%d fixes", n)
	}
	// too large and unreachable: the error is recorded, the data stays
	if err := s.importFeed(ctx, "debian", srv.URL+"/debian", 100); !errors.Is(err, errFeedTooLarge) {
		t.Fatalf("limit: %v", err)
	}
	if err := s.importFeed(ctx, "ubuntu", srv.URL+"/gone", 1<<20); err == nil {
		t.Fatal("404 passed")
	}
	db.QueryRow(ctx, `SELECT count(*) FROM cve_fixes`).Scan(&n)
	if n != 3 {
		t.Fatalf("failed import changed the data: %d", n)
	}
	// d1 Debian 12 with an old libssl3 (source openssl) and a fixed glibc; d2 Ubuntu 24.04 with old openssh
	if _, err := db.Exec(ctx, `UPDATE devices SET inventory='{"os_id":"debian","os_version":"12"}' WHERE id='d1';
		UPDATE devices SET inventory='{"os_id":"ubuntu","os_version":"24.04"}' WHERE id='d2';
		INSERT INTO device_packages(device_id, name, version, arch, source) VALUES
			('d1', 'libssl3', '3.0.11-1~deb12u2', 'amd64', 'openssl'), ('d1', 'openssl', '3.0.11-1~deb12u2', 'amd64', ''),
			('d1', 'libc6', '2.36-9+deb12u7', 'amd64', 'glibc'), ('d2', 'openssh-server', '1:9.6p1-3ubuntu13', 'amd64', 'openssh')`); err != nil {
		t.Fatal(err)
	}
	if err := s.matchAllCVEs(ctx); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM device_cves WHERE device_id='d1' AND cve='CVE-2024-5535'`).Scan(&n)
	if n != 2 {
		t.Fatalf("d1 matches: %d", n)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM device_cves WHERE cve='CVE-2024-2961'`).Scan(&n)
	if n != 0 {
		t.Fatal("fixed glibc matched")
	}
	code, body := call(dashHelpdesk, "GET", "/api/v1/devices/d2/updates", ``)
	if code != 200 || !strings.Contains(body, `"cve":"CVE-2024-6387"`) || !strings.Contains(body, `"fixed":"1:9.6p1-3ubuntu13.3"`) {
		t.Fatalf("device: %d %s", code, body)
	}
	code, body = call(dashAuditor, "GET", "/api/v1/updates/fleet", ``)
	if code != 200 || !strings.Contains(body, `"id":"CVE-2024-6387","severity":"high","devices":1`) || !strings.Contains(body, `"id":"CVE-2024-5535","severity":"medium","devices":1`) {
		t.Fatalf("fleet: %d %s", code, body)
	}
	if code, body := call(dashAuditor, "GET", "/api/v1/updates/fleet?cve=CVE-2024-5535", ``); code != 200 || !strings.Contains(body, `"hostname":"alpha"`) || !strings.Contains(body, "libssl3") {
		t.Fatalf("cve devices: %d %s", code, body)
	}
	code, body = call(dashAuditor, "GET", "/api/v1/updates/cve-feeds", ``)
	if code != 200 || !strings.Contains(body, `"rows":2`) || !strings.Contains(body, "HTTP 404") || !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("feeds: %d %s", code, body)
	}
	off := s.rt.Load()
	if due, err := s.cveFeedsDue(ctx); err != nil || due {
		t.Fatalf("due while every feed is off: %v %v", due, err)
	}
	on := *off
	on.set.CVEFeeds = CVEFeedSettings{Debian: true, Ubuntu: true}
	s.rt.Store(&on)
	if due, err := s.cveFeedsDue(ctx); err != nil || due {
		t.Fatalf("due right after an import: %v %v", due, err)
	}
	db.Exec(ctx, `UPDATE cve_feeds SET fetched_at = now() - interval '2 days', error_at = NULL`)
	if due, err := s.cveFeedsDue(ctx); err != nil || !due {
		t.Fatalf("not due after two days: %v %v", due, err)
	}
	on.set.CVEFeeds.Arch = true // switched on, never imported, but no Arch device: skipped
	db.Exec(ctx, `UPDATE cve_feeds SET fetched_at = now()`)
	if due, err := s.cveFeedsDue(ctx); err != nil || due {
		t.Fatalf("a feed without devices is due: %v %v", due, err)
	}
	db.Exec(ctx, `UPDATE devices SET inventory='{"os_id":"arch"}' WHERE id='d3'`)
	if due, err := s.cveFeedsDue(ctx); err != nil || !due {
		t.Fatalf("a new feed is not due: %v %v", due, err)
	}
	s.rt.Store(off)
	if code, _ := call(dashAdmin, "POST", "/api/v1/updates/cve-feeds/refresh", ``); code != 409 {
		t.Fatalf("refresh while off: %d", code)
	}
	if code, _ := call(dashAuditor, "POST", "/api/v1/updates/cve-feeds/refresh", ``); code != 403 {
		t.Fatalf("auditor refresh: %d", code)
	}
}
