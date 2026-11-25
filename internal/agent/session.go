package agent

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
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
// does not wait for it (dialogs stay open until the user answers).
func launchInSession(user string, env []string, prog string, args ...string) error {
	argv := append([]string{"-u", user, "--", "env"}, env...)
	argv = append(argv, prog)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour) // an unanswered dialog closes after an hour
	cmd := exec.CommandContext(ctx, "runuser", append(argv, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}
	go func() { _ = cmd.Wait(); cancel() }()
	return nil
}

var dialogToolTried time.Time

// ensureDialogTool installs the dialog program the desktop helper needs
// (kdialog on KDE Plasma, zenity elsewhere) on devices with a desktop. A
// failed installation is retried after a day.
func (a *Agent) ensureDialogTool() {
	env, dm := desktop()
	if (env == "" && dm == "") || hasCmd("zenity") || hasCmd("kdialog") || time.Since(dialogToolTried) < 24*time.Hour {
		return
	}
	dialogToolTried = time.Now()
	pkg := "zenity"
	if strings.HasPrefix(env, "KDE") {
		pkg = "kdialog"
	}
	if err := a.host.install(pkg); err != nil {
		a.event("installing %s for the desktop helper failed: %v", pkg, err)
		return
	}
	a.event("installed %s for the desktop helper", pkg)
}
