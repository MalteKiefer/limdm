package agent

import (
	"log/slog"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestRebootDeferralIsBounded(t *testing.T) {
	var calls []int
	old := shutdownIn
	t.Cleanup(func() { shutdownIn = old })
	shutdownIn = func(m int) error { calls = append(calls, m); return nil }

	a := &Agent{log: slog.New(slog.DiscardHandler)}
	a.polView.Store(&api.Policy{Updates: api.Updates{RebootDefer: api.RebootDefer{MaxDefers: 2, DeferMinutes: 30, NoticeMinutes: 10}}})
	now := time.Date(2026, 11, 28, 3, 0, 0, 0, time.Local)
	if _, err := a.deferReboot("anna", now); err == nil {
		t.Fatal("nothing scheduled: deferral must be refused")
	}
	if err := a.scheduleReboot(now, a.policy().Updates.RebootDefer); err != nil || a.state.RebootAt != now.Add(10*time.Minute) {
		t.Fatalf("schedule: %v %v", err, a.state.RebootAt)
	}
	for i := range 2 {
		at, err := a.deferReboot("anna", now)
		if err != nil || at != now.Add(30*time.Minute) {
			t.Fatalf("deferral %d: %v %v", i+1, at, err)
		}
	}
	if _, err := a.deferReboot("anna", now); err == nil {
		t.Fatal("a third deferral must be refused")
	}
	if len(calls) != 3 || calls[0] != 10 || calls[1] != 30 {
		t.Fatalf("shutdown calls %v", calls)
	}
	if !a.rebootPending(now.Add(time.Hour)) {
		t.Fatal("a planned reboot must stop the window from planning another")
	}
}
