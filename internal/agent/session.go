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
// including those without XDG autostart such as sway or Hyprland. With an
// audit session ID only processes of that login session count, so a
// second or stale session of the same user, or an SSH shell with DISPLAY,
// is never taken for this one.
func graphicalEnv(uid, audit string) []string {
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
		if audit != "" && strings.TrimSpace(readFile(d+"/sessionid")) != audit {
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
		bus := vars["DBUS_SESSION_BUS_ADDRESS"] // a session's own bus (dbus-launch) wins over the user bus
		if bus == "" || strings.ContainsAny(bus, "\x00\n") {
			bus = "unix:path=/run/user/" + uid + "/bus"
		}
		env := []string{"XDG_RUNTIME_DIR=/run/user/" + uid, "DBUS_SESSION_BUS_ADDRESS=" + bus}
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
	_, err := startInSession(time.Hour, user, env, prog, args...)
	return err
}

// startInSession is launchInSession with a lifetime; 0 runs until it exits.
// It returns the process, which ends when the program ends.
func startInSession(life time.Duration, user string, env []string, prog string, args ...string) (*os.Process, error) {
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
		return nil, err
	}
	go func() { _ = cmd.Wait(); cancel() }()
	return cmd.Process, nil
}

// company is the branding name for texts on the device.
func (a *Agent) company() string {
	if a.state.Company != "" {
		return a.state.Company
	}
	return "IT"
}

type graphicalSession struct {
	id, user, uid, kind string // kind: x11 or wayland
	env                 []string
	locked              bool // logind's LockedHint: the desktop's locker shows
}

// loginSession is a logind session with what the agent needs from it.
type loginSession struct {
	ID, User, UID, Type, Class, State, Audit string
	Remote, Locked                           bool
}

// loginSessions lists logind sessions in one loginctl call.
func loginSessions() []loginSession {
	out, err := sh("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil
	}
	var ids []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			ids = append(ids, f[0])
		}
	}
	if len(ids) == 0 {
		return nil
	}
	props, err := sh("loginctl", append(append([]string{"show-session"}, ids...),
		"-p", "Id", "-p", "Name", "-p", "User", "-p", "Type", "-p", "Class", "-p", "State", "-p", "Remote", "-p", "LockedHint", "-p", "Audit")...)
	if err != nil {
		return nil
	}
	return parseSessions(props)
}

// parseSessions reads loginctl show-session output: blocks of key=value
// lines separated by blank lines.
func parseSessions(props string) []loginSession {
	var res []loginSession
	for _, block := range strings.Split(strings.TrimSpace(props), "\n\n") {
		kv := map[string]string{}
		for _, l := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
				kv[k] = v
			}
		}
		if kv["Id"] == "" {
			continue
		}
		res = append(res, loginSession{ID: kv["Id"], User: kv["Name"], UID: kv["User"], Type: kv["Type"], Class: kv["Class"],
			State: kv["State"], Audit: kv["Audit"], Remote: kv["Remote"] == "yes", Locked: kv["LockedHint"] == "yes"})
	}
	return res
}

// person: a session of a person's account (not root, a greeter or a user manager).
func (l loginSession) person() bool {
	uid, err := strconv.Atoi(l.UID)
	return err == nil && uid >= 1000 && l.Class == "user" && userRe.MatchString(l.User) && l.State != "closing"
}

// graphicalSessions lists running graphical login sessions of people, one
// entry per session.
func graphicalSessions() []graphicalSession {
	if !hasCmd("loginctl") {
		return procSessions() // systems without systemd-logind
	}
	var res []graphicalSession
	for _, l := range loginSessions() {
		if !l.person() || (l.Type != "x11" && l.Type != "wayland") {
			continue
		}
		audit := l.Audit
		if audit == "0" || audit == "4294967295" {
			audit = "" // no audit session: fall back to the user's processes
		}
		env := graphicalEnv(l.UID, audit)
		if env == nil && audit != "" {
			env = graphicalEnv(l.UID, "")
		}
		if env != nil {
			res = append(res, graphicalSession{id: l.ID, user: l.User, uid: l.UID, kind: l.Type, env: env, locked: l.Locked})
		}
	}
	return res
}

// procSessions finds graphical sessions without logind: one per person
// with a process that has a display, its environment from that process.
func procSessions() []graphicalSession {
	var res []graphicalSession
	seen := map[string]bool{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		var st syscall.Stat_t
		if syscall.Stat(d, &st) != nil || st.Uid < 1000 || st.Uid >= 60000 {
			continue
		}
		uid := strconv.FormatUint(uint64(st.Uid), 10)
		if seen[uid] {
			continue
		}
		env := graphicalEnv(uid, "")
		if env == nil {
			continue
		}
		seen[uid] = true
		name := uid
		for _, l := range strings.Split(readFile("/etc/passwd"), "\n") {
			if f := strings.Split(l, ":"); len(f) > 2 && f[2] == uid {
				name = f[0]
			}
		}
		kind := "x11"
		for _, kv := range env {
			if strings.HasPrefix(kv, "WAYLAND_DISPLAY=") {
				kind = "wayland"
			}
		}
		res = append(res, graphicalSession{id: "proc-" + uid, user: name, uid: uid, kind: kind, env: env})
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
	if len(shown) == 0 {
		return "", errors.New("the message dialog could not be started in any session (limdm-desktop missing?); a notification was sent")
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
		if running[s.uid] {
			continue
		}
		// in the user's own service manager: outside the agent's cgroup (an
		// agent restart must not end it) and with its log in the user journal
		args := []string{"--user", "--machine=" + s.user + "@.host", "--collect", "--quiet", "--unit=limdm-desktop-session"}
		for _, kv := range s.env {
			args = append(args, "--setenv="+kv)
		}
		if _, err := run(30*time.Second, "systemd-run", append(args, "/usr/bin/limdm-desktop")...); err != nil {
			a.log.Warn("starting the desktop helper with systemd-run failed, starting it directly", "user", s.user, "err", err)
			if _, err := startInSession(0, s.user, s.env, "/usr/bin/limdm-desktop"); err != nil {
				a.log.Warn("starting the desktop helper failed", "user", s.user, "err", err)
				continue
			}
		}
		a.log.Info("started the desktop helper", "user", s.user)
	}
}
