package server

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the static image has no zoneinfo; schedules name IANA zones
)

// Backup schedules (docs/backup.md#schedules). Each schedule has its own
// targets and retention. Wall clock kinds (weekly, monthly, cron, and
// intervals that divide a day) are computed per local date in the chosen
// time zone: every date and time of day maps to exactly one instant, so a
// DST change never runs a slot twice; a time in the spring forward gap
// runs once, shifted by the gap. Other intervals count absolute hours.

// BackupSchedule is one schedule.
type BackupSchedule struct {
	Name    string    `json:"name"`
	Paused  bool      `json:"paused,omitempty"`
	Kind    string    `json:"kind"`             // interval | weekly | monthly | cron
	Every   int       `json:"every,omitempty"`  // interval: hours, 1 to 168
	Offset  int       `json:"offset,omitempty"` // interval: minutes after midnight (UTC midnight for intervals that do not divide a day)
	Days    []int     `json:"days,omitempty"`   // weekly: 0 Sunday to 6 Saturday
	Times   []string  `json:"times,omitempty"`  // weekly, monthly: HH:MM
	Day     int       `json:"day,omitempty"`    // monthly: 1 to 31, the last day in shorter months
	Cron    string    `json:"cron,omitempty"`   // cron: minute hour day-of-month month day-of-week
	Targets []string  `json:"targets"`          // target names
	Keep    KeepRule  `json:"keep"`             // retention of this schedule's archives
	Since   time.Time `json:"since,omitzero"`   // first run is the first slot after this
}

// KeepRule keeps an archive when any part keeps it: the newest Last, the
// ones younger than Days, and the newest per day, ISO week, month and year
// for that many of each. The newest archive always stays.
type KeepRule struct {
	Last    int `json:"last,omitempty"`
	Days    int `json:"days,omitempty"`
	Daily   int `json:"daily,omitempty"`
	Weekly  int `json:"weekly,omitempty"`
	Monthly int `json:"monthly,omitempty"`
	Yearly  int `json:"yearly,omitempty"`
}

func (k KeepRule) validate() error {
	for _, v := range []int{k.Last, k.Days, k.Daily, k.Weekly, k.Monthly, k.Yearly} {
		if v < 0 || v > 3660 {
			return errors.New("retention values: 0 to 3660")
		}
	}
	if k == (KeepRule{}) {
		return errors.New("retention: set at least one value (keep last, days or a GFS count)")
	}
	return nil
}

var (
	scheduleNameRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	clockRe        = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
)

func (sc BackupSchedule) validate(targets []StoreTarget) error {
	if !scheduleNameRe.MatchString(sc.Name) {
		return errors.New("schedule name: lowercase letters, digits and _, up to 32 characters")
	}
	switch sc.Kind {
	case "interval":
		if sc.Every < 1 || sc.Every > 168 || sc.Offset < 0 || sc.Offset >= min(sc.Every*60, 24*60) {
			return errors.New("every 1 to 168 hours, with an offset in minutes below the interval (and below a day)")
		}
	case "weekly", "monthly":
		if len(sc.Times) == 0 || len(sc.Times) > 24 {
			return errors.New("set 1 to 24 times of day (HH:MM)")
		}
		for _, t := range sc.Times {
			if !clockRe.MatchString(t) {
				return fmt.Errorf("time %q: HH:MM, 00:00 to 23:59", t)
			}
		}
		if sc.Kind == "weekly" {
			if len(sc.Days) == 0 {
				return errors.New("choose at least one weekday")
			}
			for _, d := range sc.Days {
				if d < 0 || d > 6 {
					return errors.New("weekdays: 0 (Sunday) to 6")
				}
			}
		} else if sc.Day < 1 || sc.Day > 31 {
			return errors.New("day of month: 1 to 31")
		}
	case "cron":
		if _, err := parseCron(sc.Cron); err != nil {
			return err
		}
	default:
		return errors.New("schedule kind: interval, weekly, monthly or cron")
	}
	if len(sc.Targets) == 0 {
		return errors.New("choose at least one target for the schedule")
	}
	for _, t := range sc.Targets {
		if !slices.ContainsFunc(targets, func(x StoreTarget) bool { return x.Name == t }) {
			return fmt.Errorf("schedule %s: unknown target %q", sc.Name, t)
		}
	}
	return sc.Keep.validate()
}

// cronSpec is a parsed five field expression: allowed values per field.
type cronSpec struct {
	min, hour, dom, month, dow [60]bool
	domAny, dowAny             bool
}

// parseCron accepts minute hour day-of-month month day-of-week with *,
// lists, ranges and steps (*/15, 1-5, 0,30). Names, @ shortcuts and
// seconds are refused, so a typo cannot mean something unexpected.
func parseCron(expr string) (*cronSpec, error) {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, errors.New("cron: five fields, minute hour day-of-month month day-of-week")
	}
	var c cronSpec
	fields := []struct {
		set      *[60]bool
		lo, hi   int
		name     string
		anyField *bool
	}{{&c.min, 0, 59, "minute", nil}, {&c.hour, 0, 23, "hour", nil}, {&c.dom, 1, 31, "day of month", &c.domAny},
		{&c.month, 1, 12, "month", nil}, {&c.dow, 0, 7, "day of week", &c.dowAny}}
	for i, fl := range fields {
		if fl.anyField != nil {
			*fl.anyField = f[i] == "*"
		}
		for _, part := range strings.Split(f[i], ",") {
			rng, stepS, hasStep := strings.Cut(part, "/")
			step := 1
			if hasStep {
				n, err := strconv.Atoi(stepS)
				if err != nil || n < 1 || n > fl.hi {
					return nil, fmt.Errorf("cron %s: invalid step in %q", fl.name, part)
				}
				step = n
			}
			lo, hi := fl.lo, fl.hi
			if rng != "*" {
				a, b, isRange := strings.Cut(rng, "-")
				x, err1 := strconv.Atoi(a)
				y := x
				var err2 error
				if isRange {
					y, err2 = strconv.Atoi(b)
				} else if hasStep {
					return nil, fmt.Errorf("cron %s: a step needs * or a range in %q", fl.name, part)
				}
				if err1 != nil || err2 != nil || x < fl.lo || y > fl.hi || x > y {
					return nil, fmt.Errorf("cron %s: %q is outside %d to %d", fl.name, part, fl.lo, fl.hi)
				}
				lo, hi = x, y
			}
			for v := lo; v <= hi; v += step {
				fl.set[v] = true
			}
		}
	}
	if c.dow[7] { // 7 is Sunday as well
		c.dow[0] = true
	}
	return &c, nil
}

// dayMatch follows cron: with both day fields restricted, either may match.
func (c *cronSpec) dayMatch(d time.Time) bool {
	if !c.month[int(d.Month())] {
		return false
	}
	dom, dow := c.dom[d.Day()], c.dow[int(d.Weekday())]
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	}
	return dom || dow
}

// slots returns the times of day (minutes after midnight) the schedule
// runs on a local date, nil for none.
func (sc BackupSchedule) slots(d time.Time, cron *cronSpec) []int {
	var out []int
	clock := func() {
		for _, t := range sc.Times {
			m := clockRe.FindStringSubmatch(t)
			h, _ := strconv.Atoi(m[1])
			mi, _ := strconv.Atoi(m[2])
			out = append(out, h*60+mi)
		}
	}
	switch sc.Kind {
	case "interval": // only intervals that divide a day
		for m := sc.Offset; m < 24*60; m += sc.Every * 60 {
			out = append(out, m)
		}
	case "weekly":
		if slices.Contains(sc.Days, int(d.Weekday())) {
			clock()
		}
	case "monthly":
		last := time.Date(d.Year(), d.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
		if d.Day() == min(sc.Day, last) {
			clock()
		}
	case "cron":
		if cron.dayMatch(d) {
			for h := range 24 {
				for m := range 60 {
					if cron.hour[h] && cron.min[m] {
						out = append(out, h*60+m)
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// next is the first run strictly after t, in loc; zero when there is
// none within five years (a cron for February 30).
func (sc BackupSchedule) next(t time.Time, loc *time.Location) time.Time {
	if sc.Kind == "interval" && 24%sc.Every != 0 {
		step := time.Duration(sc.Every) * time.Hour
		base := time.Unix(0, 0).Add(time.Duration(sc.Offset) * time.Minute)
		n := t.Sub(base)/step + 1
		if t.Before(base) {
			n = 0
		}
		return base.Add(n * step)
	}
	var cron *cronSpec
	if sc.Kind == "cron" {
		var err error
		if cron, err = parseCron(sc.Cron); err != nil {
			return time.Time{}
		}
	}
	lt := t.In(loc)
	day := time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	for i := 0; i < 5*366+2; i++ {
		d := day.AddDate(0, 0, i)
		for _, m := range sc.slots(d, cron) {
			at := time.Date(d.Year(), d.Month(), d.Day(), m/60, m%60, 0, 0, loc)
			if at.After(t) {
				return at
			}
		}
	}
	return time.Time{}
}

// nextRuns lists the next n runs after t (the console shows five).
func (sc BackupSchedule) nextRuns(t time.Time, loc *time.Location, n int) []time.Time {
	var out []time.Time
	for len(out) < n {
		if t = sc.next(t, loc); t.IsZero() {
			break
		}
		out = append(out, t)
	}
	return out
}

// keepArchives decides which archives stay; times are sorted newest first.
func keepArchives(times []time.Time, k KeepRule, now time.Time, loc *time.Location) []bool {
	keep := make([]bool, len(times))
	seen := map[string]bool{}
	counts := map[byte]int{}
	limit := map[byte]int{'d': k.Daily, 'w': k.Weekly, 'm': k.Monthly, 'y': k.Yearly}
	for i, t := range times {
		if i < k.Last || k.Days > 0 && now.Sub(t) <= time.Duration(k.Days)*24*time.Hour {
			keep[i] = true
		}
		lt := t.In(loc)
		y, wk := lt.ISOWeek()
		for _, b := range []struct {
			kind byte
			key  string
		}{{'d', lt.Format("d2006-01-02")}, {'w', fmt.Sprintf("w%d-%02d", y, wk)}, {'m', lt.Format("m2006-01")}, {'y', lt.Format("y2006")}} {
			if !seen[b.key] && counts[b.kind] < limit[b.kind] {
				seen[b.key] = true
				counts[b.kind]++
				keep[i] = true
			}
		}
	}
	if len(keep) > 0 {
		keep[0] = true
	}
	return keep
}

// retentionPreview simulates a year of runs and tells how many archives
// the rule keeps, the oldest one, and the kept dates (newest first, at
// most 40).
type retentionPreview struct {
	Runs, Kept int
	Oldest     time.Time
	Dates      []time.Time
}

func (sc BackupSchedule) preview(now time.Time, loc *time.Location) retentionPreview {
	var runs []time.Time
	for t := sc.next(now.AddDate(-1, 0, 0), loc); !t.IsZero() && !t.After(now) && len(runs) < 20000; t = sc.next(t, loc) {
		runs = append(runs, t)
	}
	slices.Reverse(runs)
	var p retentionPreview
	p.Runs = len(runs)
	for i, k := range keepArchives(runs, sc.Keep, now, loc) {
		if !k {
			continue
		}
		p.Kept++
		p.Oldest = runs[i]
		if len(p.Dates) < 40 {
			p.Dates = append(p.Dates, runs[i])
		}
	}
	return p
}

// describe is the schedule in words for the console list.
func (sc BackupSchedule) describe() string {
	switch sc.Kind {
	case "interval":
		return fmt.Sprintf("every %d h, offset %d min", sc.Every, sc.Offset)
	case "weekly":
		names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
		var d []string
		for _, i := range sc.Days {
			d = append(d, names[i])
		}
		return strings.Join(d, ",") + " " + strings.Join(sc.Times, ",")
	case "monthly":
		return fmt.Sprintf("monthly, day %d, %s", sc.Day, strings.Join(sc.Times, ","))
	}
	return "cron " + sc.Cron
}
