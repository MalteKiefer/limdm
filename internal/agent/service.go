package agent

import (
	"errors"
	"time"
)

// System services through systemd, or OpenRC on Alpine and other systems
// without systemd. Service names are the same in both for what the agent
// manages (sshd, chronyd, auditd, firewalld, nftables).

func systemd() bool { return exists("/run/systemd/system") && hasCmd("systemctl") }
func openrc() bool  { return !systemd() && hasCmd("rc-service") }

func unitActive(name string) bool {
	if openrc() {
		_, err := run(30*time.Second, "rc-service", name, "status")
		return err == nil
	}
	_, err := run(30*time.Second, "systemctl", "is-active", "--quiet", name)
	return err == nil
}

// svc runs one service action: enable-now, disable-now, restart, try-restart, reload-or-restart.
func svc(action, name string) error {
	if openrc() {
		switch action {
		case "enable-now":
			if _, err := sh("rc-update", "add", name, "default"); err != nil {
				return err
			}
			_, err := sh("rc-service", name, "start")
			return err
		case "disable-now":
			_, err1 := sh("rc-service", name, "stop")
			_, err2 := sh("rc-update", "del", name, "default")
			return errors.Join(err1, err2)
		case "restart":
			_, err := sh("rc-service", name, "restart")
			return err
		case "try-restart", "reload-or-restart":
			if !unitActive(name) {
				return nil
			}
			if action == "reload-or-restart" {
				if _, err := sh("rc-service", name, "reload"); err == nil {
					return nil
				}
			}
			_, err := sh("rc-service", name, "restart")
			return err
		}
		return errors.New("unknown service action " + action)
	}
	args := map[string][]string{
		"enable-now": {"enable", "--now"}, "disable-now": {"disable", "--now"}, "restart": {"restart"},
		"try-restart": {"try-restart"}, "reload-or-restart": {"try-reload-or-restart"},
	}[action]
	if args == nil {
		return errors.New("unknown service action " + action)
	}
	_, err := sh("systemctl", append(args, name)...)
	return err
}
