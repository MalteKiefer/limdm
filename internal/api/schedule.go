package api

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// ScriptSchedule runs a recurring script at fixed local times of the
// device, at most once per slot. A slot missed while the device was off or
// asleep runs at the next chance; several missed slots run once.
type ScriptSchedule struct {
	Times []string `json:"times"`          // local "HH:MM", up to 24
	Days  []string `json:"days,omitempty"` // mon..sun, empty is every day
	// JitterMinutes delays every slot by a fixed amount per device and
	// script, 0 to 120, so a fleet does not start at the same second.
	JitterMinutes int `json:"jitter_minutes,omitempty"`
}

var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Validate checks times, days and jitter.
func (s ScriptSchedule) Validate() error {
	var errs []error
	if len(s.Times) == 0 || len(s.Times) > 24 {
		errs = append(errs, errors.New("1 to 24 times are required"))
	}
	for i, t := range s.Times {
		if !hhmmRe.MatchString(t) || slices.Contains(s.Times[:i], t) {
			errs = append(errs, fmt.Errorf("time %q must be HH:MM, each once", t))
		}
	}
	for i, d := range s.Days {
		if !slices.Contains(Weekdays, d) || slices.Contains(s.Days[:i], d) {
			errs = append(errs, fmt.Errorf("days: %q is not one of mon, tue, wed, thu, fri, sat, sun (each once)", d))
		}
	}
	if s.JitterMinutes < 0 || s.JitterMinutes > 120 {
		errs = append(errs, errors.New("jitter_minutes must be 0..120"))
	}
	return errors.Join(errs...)
}

// LastSlot is the latest slot start (jitter included) at or before now in
// now's location, looking back at most eight days; zero when there is none.
func (s ScriptSchedule) LastSlot(now time.Time, jitter time.Duration) time.Time {
	var best time.Time
	for back := 0; back <= 8; back++ {
		day := now.AddDate(0, 0, -back)
		if len(s.Days) > 0 && !slices.Contains(s.Days, Weekdays[day.Weekday()]) {
			continue
		}
		for _, hm := range s.Times {
			t, err := time.ParseInLocation("15:04", hm, now.Location())
			if err != nil {
				continue
			}
			slot := time.Date(day.Year(), day.Month(), day.Day(), t.Hour(), t.Minute(), 0, 0, now.Location()).Add(jitter)
			if !slot.After(now) && slot.After(best) {
				best = slot
			}
		}
		if !best.IsZero() {
			return best
		}
	}
	return best
}
