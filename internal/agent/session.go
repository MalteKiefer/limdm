package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// sessionVars are the variables a GUI program needs to reach the user's
// display and session bus.
var sessionVars = []string{"WAYLAND_DISPLAY", "DISPLAY", "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES"}

// graphicalEnv returns the display environment of a running graphical
// program of uid, read from /proc. Works for every desktop and compositor,
// including those without XDG autostart such as sway or Hyprland.
func graphicalEnv(uid string) []string {
	n, err := strconv.Atoi(uid)
	if err != nil {
		return nil
	}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		var st syscall.Stat_t
		if syscall.Stat(d, &st) != nil || int(st.Uid) != n {
			continue
		}
		raw, err := os.ReadFile(d + "/environ")
		if err != nil {
			continue
		}
		vars := map[string]string{}
		for _, kv := range bytes.Split(raw, []byte{0}) {
			k, v, ok := strings.Cut(string(kv), "=")
			if ok {
				vars[k] = v
			}
		}
		if vars["WAYLAND_DISPLAY"] == "" && vars["DISPLAY"] == "" {
			continue
		}
		env := []string{"XDG_RUNTIME_DIR=/run/user/" + uid, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus"}
		for _, k := range sessionVars {
			if v := vars[k]; v != "" && !strings.ContainsAny(v, "\x00\n") {
				env = append(env, k+"="+v)
			}
		}
		return env
	}
	return nil
}

// launchInSession starts a program as user in their graphical session and
// does not wait for it (dialogs stay open until the user answers; an
// unanswered one closes after an hour).
func launchInSession(user string, env []string, prog string, args ...string) error {
	return startInSession(time.Hour, user, env, prog, args...)
}

// startInSession is launchInSession with a lifetime; 0 runs until it exits.
func startInSession(life time.Duration, user string, env []string, prog string, args ...string) error {
	argv := append([]string{"-u", user, "--", "env"}, env...)
	argv = append(argv, prog)
	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if life > 0 {
		ctx, cancel = context.WithTimeout(ctx, life)
	}
	cmd := exec.CommandContext(ctx, "runuser", append(argv, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}
	go func() { _ = cmd.Wait(); cancel() }()
	return nil
}

// company is the branding name for texts on the device.
func (a *Agent) company() string {
	if a.state.Company != "" {
		return a.state.Company
	}
	return "IT"
}

type graphicalSession struct {
	user, uid string
	env       []string
}

// graphicalSessions lists the users with a running graphical session.
func graphicalSessions() []graphicalSession {
	out, err := sh("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil
	}
	var res []graphicalSession
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || seen[f[1]] || !userRe.MatchString(f[2]) {
			continue
		}
		seen[f[1]] = true
		if env := graphicalEnv(f[1]); env != nil {
			res = append(res, graphicalSession{user: f[2], uid: f[1], env: env})
		}
	}
	return res
}

// notifyUsers shows a desktop notification in every graphical session.
func (a *Agent) notifyUsers(title, body, urgency string) bool {
	sent := false
	for _, s := range graphicalSessions() {
		args := append([]string{"-u", s.user, "--", "env"}, s.env...)
		args = append(args, "notify-send", "--urgency="+urgency, "--app-name="+a.company())
		if _, err := os.Stat(brandingLogo); err == nil {
			args = append(args, "--icon="+brandingLogo)
		}
		args = append(args, title, body)
		if _, err := run(15*time.Second, "runuser", args...); err == nil {
			sent = true
		}
	}
	return sent
}

// showMessage is the "message" command: a notification and a dialog in every
// graphical session.
func (a *Agent) showMessage(payload string) (string, error) {
	var m api.Message
	if err := json.Unmarshal([]byte(payload), &m); err != nil || strings.TrimSpace(m.Text) == "" {
		return "", errors.New("message needs a text")
	}
	if m.Title == "" {
		m.Title = "Message from " + a.company()
	}
	sessions := graphicalSessions()
	if len(sessions) == 0 {
		return "", errors.New("nobody is signed in to a graphical session")
	}
	a.notifyUsers(m.Title, m.Text, "normal")
	var shown []string
	for _, s := range sessions {
		if launchInSession(s.user, s.env, "/usr/bin/limdm-desktop", "--message-title="+m.Title, "--message="+m.Text) == nil {
			shown = append(shown, s.user)
		}
	}
	return "shown to " + strings.Join(shown, ", "), nil
}

// ensureHelpers starts the desktop helper (tray) in graphical sessions
// where it does not run: compositors without XDG autostart and without
// graphical-session.target. The helper's lock prevents duplicates.
func (a *Agent) ensureHelpers() {
	running := map[string]bool{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, err := os.ReadFile(d + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "limdm-desktop" {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(d, &st) == nil {
			running[strconv.FormatUint(uint64(st.Uid), 10)] = true
		}
	}
	for _, s := range graphicalSessions() {
		if !running[s.uid] {
			if err := startInSession(0, s.user, s.env, "/usr/bin/limdm-desktop"); err == nil {
				a.log.Info("started the desktop helper", "user", s.user)
			}
		}
	}
}
