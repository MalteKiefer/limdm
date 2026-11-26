package server

import (
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestScheduleNext(t *testing.T) {
	berlin := mustLoc(t, "Europe/Berlin")
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, berlin)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	fmtRuns := func(l []time.Time) []string {
		var out []string
		for _, v := range l {
			out = append(out, v.In(berlin).Format("2006-01-02 15:04 MST"))
		}
		return out
	}
	cases := []struct {
		name string
		sc   BackupSchedule
		from string
		want []string
	}{
		{"weekdays, two times", BackupSchedule{Kind: "weekly", Days: []int{1, 3}, Times: []string{"14:00", "02:00"}}, "2026-11-26 10:00", // a Thursday
			[]string{"2026-11-30 02:00 CET", "2026-11-30 14:00 CET", "2026-12-02 02:00 CET"}},
		{"monthly on the 31st", BackupSchedule{Kind: "monthly", Day: 31, Times: []string{"03:00"}}, "2027-01-31 04:00",
			[]string{"2027-02-28 03:00 CET", "2027-03-31 03:00 CEST", "2027-04-30 03:00 CEST"}},
		{"every 6 hours, offset 30 min", BackupSchedule{Kind: "interval", Every: 6, Offset: 30}, "2026-11-26 10:00",
			[]string{"2026-11-26 12:30 CET", "2026-11-26 18:30 CET", "2026-11-27 00:30 CET"}},
		{"cron weekdays every 20 minutes at 1 h", BackupSchedule{Kind: "cron", Cron: "*/20 1 * * 1-5"}, "2026-11-27 01:30",
			[]string{"2026-11-27 01:40 CET", "2026-11-30 01:00 CET", "2026-11-30 01:20 CET"}},
		// spring forward: 02:30 does not exist on 29 March 2026, it runs once, shifted
		{"DST gap", BackupSchedule{Kind: "weekly", Days: []int{0, 1, 2, 3, 4, 5, 6}, Times: []string{"02:30"}}, "2026-03-28 03:00",
			[]string{"2026-03-29 03:30 CEST", "2026-03-30 02:30 CEST"}},
		{"hourly over the fall back", BackupSchedule{Kind: "cron", Cron: "0 * * * *"}, "2026-10-25 01:30",
			[]string{"2026-10-25 02:00 CET", "2026-10-25 03:00 CET", "2026-10-25 04:00 CET"}},
	}
	for _, c := range cases {
		got := fmtRuns(c.sc.nextRuns(at(c.from), berlin, len(c.want)))
		if len(got) != len(c.want) {
			t.Fatalf("%s: %v", c.name, got)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
	// fall back: 02:30 exists twice on 25 October 2026, it runs once (Go
	// picks one of the two instants)
	daily := BackupSchedule{Kind: "weekly", Days: []int{0, 1, 2, 3, 4, 5, 6}, Times: []string{"02:30"}}
	runs := daily.nextRuns(at("2026-10-24 03:00"), berlin, 2)
	if len(runs) != 2 || runs[0].In(berlin).Format("01-02 15:04") != "10-25 02:30" || runs[1].In(berlin).Format("01-02 15:04") != "10-26 02:30" {
		t.Fatalf("DST overlap: %v", fmtRuns(runs))
	}
	// an interval that does not divide a day counts absolute hours: 5 h apart across DST
	sc := BackupSchedule{Kind: "interval", Every: 5}
	runs = sc.nextRuns(at("2026-10-24 20:00"), berlin, 4)
	for i := 1; i < len(runs); i++ {
		if runs[i].Sub(runs[i-1]) != 5*time.Hour {
			t.Fatalf("absolute interval: %v", fmtRuns(runs))
		}
	}
	if (BackupSchedule{Kind: "cron", Cron: "0 0 30 2 *"}).next(at("2026-01-01 00:00"), berlin) != (time.Time{}) {
		t.Fatal("February 30 must never run")
	}
}

func TestParseCron(t *testing.T) {
	for _, ok := range []string{"0 2 * * *", "*/15 * * * 1-5", "0,30 8-18/2 1,15 * 0", "5 4 * * 7"} {
		if _, err := parseCron(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *",
		"5/10 * * * *", "3-1 * * * *", "@daily", "0 2 * * MON", "0 2 * * * *", "a * * * *"} {
		if _, err := parseCron(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestKeepArchives(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	var times []time.Time // one archive every 6 hours for 400 days, newest first
	for i := range 400 * 4 {
		times = append(times, now.Add(-time.Duration(i)*6*time.Hour))
	}
	count := func(k KeepRule) (n int, oldest time.Time) {
		for i, keep := range keepArchives(times, k, now, time.UTC) {
			if keep {
				n++
				oldest = times[i]
			}
		}
		return
	}
	if n, _ := count(KeepRule{Last: 10}); n != 10 {
		t.Fatalf("keep last: %d", n)
	}
	if n, _ := count(KeepRule{Days: 2}); n != 9 { // 48 hours, both ends included
		t.Fatalf("keep days: %d", n)
	}
	if n, oldest := count(KeepRule{Daily: 7, Monthly: 12, Yearly: 2}); n < 7+11 || n > 7+12+2 || now.Sub(oldest) < 300*24*time.Hour {
		t.Fatalf("gfs: %d, oldest %v", n, oldest)
	}
	// the union: Last 30 keeps more than Daily 2 does on its own
	if a, _ := count(KeepRule{Last: 30, Daily: 2}); a != 30 {
		t.Fatalf("union: %d", a)
	}
	if n, _ := count(KeepRule{}); n != 1 {
		t.Fatal("the newest archive always stays")
	}
	sc := BackupSchedule{Kind: "interval", Every: 24, Keep: KeepRule{Daily: 7, Weekly: 4}}
	if p := sc.preview(now, time.UTC); p.Runs < 364 || p.Kept < 7 || p.Kept > 11 || len(p.Dates) != p.Kept {
		t.Fatalf("preview %+v", p)
	}
}

func TestBackupNames(t *testing.T) {
	s := &Server{cfg: Config{PublicURL: "https://mdm.example.com"}}
	at := time.Date(2026, 11, 26, 2, 0, 0, 0, time.UTC)
	for _, sched := range []string{"", "nightly_s3"} {
		got, gs, ok := parseBackupName(s.backupName(at, sched))
		if !ok || !got.Equal(at) || gs != sched {
			t.Fatalf("%q: %v %q %v", sched, got, gs, ok)
		}
		if !s.ownArchive(s.backupName(at, sched)) {
			t.Fatal("own archive not recognized")
		}
	}
	other := &Server{cfg: Config{PublicURL: "https://mdm.example.com-staging"}}
	if s.ownArchive(other.backupName(at, "")) || s.ownArchive("limdm-mdm.example.com-staging-20261126T020000Z.lbk") {
		t.Fatal("archive of another server counted as own")
	}
}
