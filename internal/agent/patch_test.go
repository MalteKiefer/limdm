package agent

import (
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
