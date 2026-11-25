package agent

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Tamper protection. The agent unit refuses "systemctl stop" and restarts
// after a kill; limdm-watchdog.timer checks every 5 minutes that the agent is
// enabled, unmasked and running, and the agent checks the timer in turn.
// Package removal needs a release from the console. Everything found and
// fixed is reported as a tamper event. root can still defeat all of this
// (for example by deleting the binaries); the server then sees the device go
// silent and marks it stale.

const (
	tamperLog        = stateDir + "/tamper.log"
	uninstallRelease = stateDir + "/uninstall-allowed"
	agentUnit        = "limdm-agent.service"
	watchdogTimer    = "limdm-watchdog.timer"
)

// TamperReport queues a tamper event and wakes the agent (used by the
// package scripts and the watchdog).
func TamperReport(msg string) error {
	f, err := os.OpenFile(tamperLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), strings.ReplaceAll(msg, "\n", " "))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	_, _ = run(10*time.Second, "systemctl", "kill", "--signal=SIGUSR1", agentUnit) // check in now, if running
	return err
}

// ensureUnit makes unit enabled, unmasked and active; it reports what it fixed.
func ensureUnit(unit string, start bool) []string {
	var fixed []string
	if state, _ := run(15*time.Second, "systemctl", "is-enabled", unit); strings.TrimSpace(state) == "masked" || strings.TrimSpace(state) == "masked-runtime" {
		if _, err := sh("systemctl", "unmask", unit); err == nil {
			fixed = append(fixed, unit+" was masked, unmasked")
		}
	}
	if _, err := run(15*time.Second, "systemctl", "is-enabled", "--quiet", unit); err != nil {
		if _, err := sh("systemctl", "enable", unit); err == nil {
			fixed = append(fixed, unit+" was disabled, enabled again")
		}
	}
	if start && !unitActive(unit) {
		if _, err := sh("systemctl", "start", unit); err == nil {
			fixed = append(fixed, unit+" was not running, started")
		}
	}
	return fixed
}

// Watchdog is the "watchdog" command run by limdm-watchdog.timer.
func Watchdog() error {
	if !Enrolled() {
		return nil // nothing to protect yet
	}
	for _, msg := range append(ensureUnit(agentUnit, true), ensureUnit(watchdogTimer, true)...) {
		if err := TamperReport("watchdog: " + msg); err != nil {
			return err
		}
	}
	return nil
}

// guardWatchdog is the agent's half: it keeps the watchdog timer in place.
func (a *Agent) guardWatchdog() {
	for _, msg := range ensureUnit(watchdogTimer, true) {
		a.tamperEvent("agent: " + msg)
	}
}

func (a *Agent) tamperEvent(msg string) {
	a.event("tamper: %s", msg)
}

// collectTamper forwards queued tamper events.
func (a *Agent) collectTamper() {
	b, err := os.ReadFile(tamperLog)
	if err != nil || len(b) == 0 {
		return
	}
	if err := os.Remove(tamperLog); err != nil {
		return // keep them for the next cycle rather than sending twice
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if _, msg, ok := strings.Cut(line, " "); ok && msg != "" {
			a.tamperEvent(msg)
		}
	}
}

// allowUninstall is the "allow_uninstall" command: removal is possible for one hour.
func allowUninstall() (string, error) {
	if err := os.WriteFile(uninstallRelease, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600); err != nil {
		return "", err
	}
	return "package removal allowed for one hour", nil
}
