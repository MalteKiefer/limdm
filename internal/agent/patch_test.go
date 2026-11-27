package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestUpdateDay(t *testing.T) {
	sat := time.Date(2026, 11, 28, 23, 0, 0, 0, time.Local) // a Saturday
	sunEarly := sat.Add(2 * time.Hour)                      // Sunday 01:00, still Saturday's window
	for _, c := range []struct {
		now    time.Time
		window string
		days   []string
		want   bool
	}{
		{sat, "22:00-04:00", []string{"sat"}, true},
		{sunEarly, "22:00-04:00", []string{"sat"}, true},
		{sunEarly, "22:00-04:00", []string{"sun"}, false},
		{sunEarly, "00:30-04:00", []string{"sun"}, true},
		{sat, "02:00-05:00", nil, true},
	} {
		if got := updateDay(c.now, c.window, c.days); got != c.want {
			t.Errorf("%s %s %v: %v", c.now.Format("Mon 15:04"), c.window, c.days, got)
		}
	}
}

func TestSnapTimer(t *testing.T) {
	if got := snapTimer(api.Updates{Window: "02:00-05:00"}); got != "02:00-05:00" {
		t.Fatal(got)
	}
	if got := snapTimer(api.Updates{Window: "02:00-05:00", Days: []string{"mon", "fri"}}); got != "mon,02:00-05:00,,fri,02:00-05:00" {
		t.Fatal(got)
	}
}

func TestRunDue(t *testing.T) {
	now := time.Date(2026, 11, 28, 3, 0, 0, 0, time.UTC)
	yesterday, hourAgo := now.Add(-24*time.Hour), now.Add(-time.Hour)
	plain, ringed := api.UpdateRule{Source: api.SourceOSAll}, api.UpdateRule{Source: api.SourceOSAll, Rings: true}
	open := &api.UpdateGate{Ring: "broad", Wave: 3, Open: true}
	for name, c := range map[string]struct {
		r    api.UpdateRule
		last api.UpdateRun
		g    *api.UpdateGate
		want bool
	}{
		"daily":              {plain, api.UpdateRun{At: yesterday}, open, true},
		"ran today":          {plain, api.UpdateRun{At: hourAgo}, nil, false},
		"no ring":            {ringed, api.UpdateRun{At: yesterday}, nil, true},
		"new wave":           {ringed, api.UpdateRun{At: hourAgo, Wave: 2}, open, true},
		"wave done":          {ringed, api.UpdateRun{At: yesterday, Wave: 3, Result: "installed"}, open, false},
		"paused":             {ringed, api.UpdateRun{Wave: 2}, &api.UpdateGate{Wave: 3}, false},
		"failed, retry":      {ringed, api.UpdateRun{At: yesterday, Wave: 3, Result: "failed"}, open, true},
		"failed, same day":   {ringed, api.UpdateRun{At: hourAgo, Wave: 3, Result: "failed"}, open, false},
		"ring without waves": {ringed, api.UpdateRun{}, &api.UpdateGate{Open: true}, false},
	} {
		if got, _ := runDue(c.r, c.last, c.g, now); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestUpdateOutcome(t *testing.T) {
	out := cleanUpgradeOutput("Initial blacklist:\nNo packages found that can be upgraded unattended and no pending auto-removals\nNo /usr/bin/mail or /usr/sbin/sendmail, can not send mail. You probably want to install the mailx package.\n")
	if strings.Contains(out, "mail") || !strings.Contains(out, "No packages found") {
		t.Fatal(out)
	}
	before := map[string]string{"a amd64": "1", "b amd64": "1"}
	if n := changedPackages(before, map[string]string{"a amd64": "2", "b amd64": "1", "c amd64": "1"}); n != 2 {
		t.Fatal(n)
	}
	if changedPackages(before, before) != 0 {
		t.Fatal("no change counted")
	}
	if n := len(flatpakDoneRe.FindAllString(" 1. [✓] org.gnome.Platform 47 u flathub\n 2. [✓] org.x 1 u flathub\n", -1)); n != 2 {
		t.Fatal(n)
	}
	if !matchRepo(nil, "x") || !matchRepo([]string{"google-*"}, "google-chrome") || matchRepo([]string{"Docker"}, "docker") {
		t.Fatal("matchRepo")
	}
	if l := parseCheckupdates("linux 6.12.1-1 -> 6.12.2-1\n"); len(l) != 1 || l[0].Candidate != "6.12.2-1" {
		t.Fatal(l)
	}
	if l := parseApkVersion("Installed:                                Available:\nmusl-1.2.5-r8                           < 1.2.5-r9\n"); len(l) != 1 || l[0].Name != "musl" || l[0].Current != "1.2.5-r8" {
		t.Fatal(l)
	}
	for _, c := range [][3]string{{"libssl3", "openssl", "openssl"}, {"libc6", "glibc (2.36-9+deb12u7)", "glibc"}, {"bash", "bash", ""}, {"vim", "", ""}} {
		if got := sourceName(c[0], c[1]); got != c[2] {
			t.Errorf("%s %q: %q", c[0], c[1], got)
		}
	}
	if b := pacmanBase("%NAME%\nlib32-openssl\n\n%VERSION%\n1:3.4.0-1\n\n%BASE%\nlib32-openssl\n\n%DESC%\nx\n"); b != "lib32-openssl" {
		t.Fatal(b)
	}
	if pacmanBase("%NAME%\nx\n") != "" {
		t.Fatal("base without %BASE%")
	}
	l, _ := parseApkList("libcrypto3-3.3.2-r4 x86_64 {openssl} (Apache-2.0) [installed]\nmusl-1.2.5-r8 x86_64 {musl} (MIT) [installed]\nWARNING: something\n", nil)
	if len(l) != 2 || l[0].Name != "libcrypto3" || l[0].Version != "3.3.2-r4" || l[0].Source != "openssl" || l[0].Arch != "x86_64" || l[1].Source != "" {
		t.Fatalf("%+v", l)
	}
}
