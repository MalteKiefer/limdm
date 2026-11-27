package agent

import (
	"errors"
	"strconv"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

const rebootText = "LiMDM: rebooting to finish updates"

// shutdownIn (re)schedules the reboot; a new schedule replaces the pending one.
var shutdownIn = func(minutes int) error {
	_, err := sh("shutdown", "-r", "+"+strconv.Itoa(minutes), rebootText)
	return err
}

// rebootDefaults fills the unset deferral fields of the updates declaration.
func rebootDefaults(d api.RebootDefer) api.RebootDefer {
	if d.NoticeMinutes == 0 {
		d.NoticeMinutes = 5
	}
	if d.DeferMinutes == 0 {
		d.DeferMinutes = 60
	}
	return d
}

// scheduleReboot plans the post update reboot NoticeMinutes ahead with
// shutdown (logind keeps the schedule, also across an agent restart) and
// asks the people at the device whether to postpone it.
func (a *Agent) scheduleReboot(now time.Time, d api.RebootDefer) error {
	d = rebootDefaults(d)
	if err := shutdownIn(d.NoticeMinutes); err != nil {
		return err
	}
	at := now.Add(time.Duration(d.NoticeMinutes) * time.Minute).Round(0)
	a.evMu.Lock()
	a.state.RebootPlanned, a.state.RebootAt, a.state.RebootDefers = now.Round(0), at, 0
	a.evMu.Unlock()
	a.event("reboot scheduled at %s after updates", at.Format("15:04"))
	a.announceReboot(at, d.MaxDefers, d)
	return nil
}

// announceReboot notifies every graphical session and, while deferrals are
// left, opens the desktop helper's dialog that offers to postpone.
func (a *Agent) announceReboot(at time.Time, left int, d api.RebootDefer) {
	a.notifyUsers(urgent, "Restart scheduled", "%s restarts this device at %s to finish updates. Save your work.", a.company(), at.Format("15:04"))
	if left <= 0 {
		return
	}
	for _, s := range graphicalSessions() {
		_ = launchInSession(s.user, s.env, "/usr/bin/limdm-desktop", "--reboot-at="+at.Format("15:04"),
			"--reboot-defers="+strconv.Itoa(left), "--reboot-defer-minutes="+strconv.Itoa(d.DeferMinutes))
	}
}

// deferReboot postpones the scheduled reboot by DeferMinutes, at most
// MaxDefers times; the declaration bounds both. who is the local user.
func (a *Agent) deferReboot(who string, now time.Time) (time.Time, error) {
	d := rebootDefaults(a.policy().Updates.RebootDefer)
	a.evMu.Lock()
	at, n := a.state.RebootAt, a.state.RebootDefers
	if at.IsZero() || now.After(at) {
		a.evMu.Unlock()
		return time.Time{}, errors.New("no restart is scheduled")
	}
	if n >= d.MaxDefers {
		a.evMu.Unlock()
		return at, errors.New("the restart cannot be postponed any further")
	}
	at = now.Add(time.Duration(d.DeferMinutes) * time.Minute).Round(0)
	a.state.RebootAt, a.state.RebootDefers = at, n+1
	a.evMu.Unlock()
	// replace the pending shutdown: a new schedule overrides the old one
	if err := shutdownIn(d.DeferMinutes); err != nil {
		return at, err
	}
	a.event("restart postponed to %s by %s (%d of %d)", at.Format("15:04"), who, n+1, d.MaxDefers)
	a.notifyUsers(normal, "Restart postponed", "%s restarts this device at %s.", a.company(), at.Format("15:04"))
	// ask again shortly before the new time, unless the schedule changed meanwhile
	time.AfterFunc(max(at.Sub(now)-time.Duration(d.NoticeMinutes)*time.Minute, 0), func() {
		a.evMu.Lock()
		same := a.state.RebootAt.Equal(at)
		a.evMu.Unlock()
		if same {
			a.announceReboot(at, d.MaxDefers-n-1, d)
		}
	})
	return at, nil
}

// rebootPending reports whether a planned reboot has not happened yet; the
// maintenance window must not plan another one meanwhile (that would reset
// the deferrals).
func (a *Agent) rebootPending(now time.Time) bool {
	a.evMu.Lock()
	defer a.evMu.Unlock()
	return now.Sub(a.state.RebootPlanned) < time.Hour || !a.state.RebootAt.IsZero() && now.Before(a.state.RebootAt.Add(time.Hour))
}
