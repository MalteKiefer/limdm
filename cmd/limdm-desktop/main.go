//go:build linux

// limdm-desktop runs in the user's desktop session (XDG autostart). It shows
// a tray icon with the device's state (details, sync, agent log) and asks
// the user for what only they can provide, currently the disk passphrase to
// create a recovery key: that dialog opens by itself and comes back until the
// key is escrowed. Dialogs are libadwaita message dialogs from the GTK
// app (limdm-desktop-ui --dialog); zenity (GNOME) or kdialog (KDE) stand in
// where GTK 4 is missing. The helper needs no GUI libraries and never runs as root.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/agent"
	"github.com/maltekiefer/limdm/internal/locale"
)

const socket = "/run/limdm/agent.sock"

var ctx = context.Background()

// lang follows the session's locale, falling back to the system locale.
var lang = locale.System()

func tr(msg string, args ...any) string { return locale.T(lang, msg, args...) }

func trn(n int, one, other string, args ...any) string {
	return locale.N(lang, n, one, other, args...)
}

func call(req agent.DesktopRequest) (agent.DesktopResponse, error) {
	var resp agent.DesktopResponse
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return resp, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return resp, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return resp, err
	}
	return resp, json.Unmarshal(line, &resp)
}

// ---- dialogs ----
//
// Layout after the GNOME HIG: a short bold heading, a sentence of body text,
// buttons named after their action, the default action on the right.

type dialogs struct {
	tool, icon, title string
	zenity, zenity4   bool
	native            bool // the GTK app shows libadwaita dialogs
}

// dialogSpec is what limdm-desktop-ui --dialog reads on stdin.
type dialogSpec struct {
	Kind    string      `json:"kind"` // message | error | ask | password
	Title   string      `json:"title,omitempty"`
	Heading string      `json:"heading"`
	Body    string      `json:"body,omitempty"`
	Yes     string      `json:"yes,omitempty"`
	No      string      `json:"no,omitempty"`
	Label   string      `json:"label,omitempty"`
	Rows    [][2]string `json:"rows,omitempty"`
	Pre     string      `json:"pre,omitempty"`
}

// nativeDialog runs a libadwaita dialog. handled is false when GTK 4 or
// libadwaita 1.4 is missing (exit code 3); the caller falls back then.
func (d *dialogs) nativeDialog(spec dialogSpec) (out []byte, accepted, handled bool) {
	if !d.native {
		return nil, false, false
	}
	spec.Title = d.title
	in, _ := json.Marshal(spec)
	cmd := exec.CommandContext(ctx, appPath, "--dialog")
	cmd.Stdin = bytes.NewReader(in)
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return bytes.TrimRight(out, "\r\n"), true, true
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return nil, false, true
	}
	d.native = false
	return nil, false, false
}

func newDialogs(company, logo string) (*dialogs, error) {
	d := &dialogs{icon: logo, title: company}
	if _, err := os.Stat(appPath); err == nil {
		d.native = true
	}
	if p, err := exec.LookPath("zenity"); err == nil {
		d.tool, d.zenity = p, true
		out, _ := exec.CommandContext(ctx, p, "--version").Output()
		d.zenity4 = strings.HasPrefix(strings.TrimSpace(string(out)), "4")
		return d, nil
	}
	if p, err := exec.LookPath("kdialog"); err == nil {
		d.tool = p
		return d, nil
	}
	if d.native {
		return d, nil
	}
	return nil, errors.New("neither the LiMDM app, zenity nor kdialog is installed")
}

// text formats heading and body: Pango markup for zenity, plain for kdialog.
func (d *dialogs) text(heading, body string) string {
	if !d.zenity {
		return heading + "\n\n" + body
	}
	return `<span size="large" weight="bold">` + html.EscapeString(heading) + "</span>\n\n" + html.EscapeString(body)
}

func (d *dialogs) zenityArgs(kind, iconName string, extra ...string) []string {
	args := []string{kind, "--title=" + d.title, "--width=400"}
	switch {
	case d.zenity4 && d.icon != "":
		args = append(args, "--icon="+d.icon)
	case d.zenity4:
		args = append(args, "--icon="+iconName)
	case d.icon != "":
		args = append(args, "--window-icon="+d.icon, "--icon-name="+iconName)
	default:
		args = append(args, "--icon-name="+iconName)
	}
	return append(args, extra...)
}

func (d *dialogs) kdialogArgs(extra ...string) []string {
	args := []string{"--title", d.title}
	if d.icon != "" {
		args = append(args, "--icon", d.icon)
	}
	return append(args, extra...)
}

const iconDisk = "drive-harddisk-encrypted"

func (d *dialogs) ask(heading, body, yes, no string) bool {
	if _, ok, handled := d.nativeDialog(dialogSpec{Kind: "ask", Heading: heading, Body: body, Yes: yes, No: no}); handled {
		return ok
	}
	if d.tool == "" {
		return false
	}
	var cmd *exec.Cmd
	if d.zenity {
		cmd = exec.CommandContext(ctx, d.tool, d.zenityArgs("--question", iconDisk, "--text="+d.text(heading, body), "--ok-label="+yes, "--cancel-label="+no)...)
	} else {
		cmd = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--yes-label", yes, "--no-label", no, "--yesno", d.text(heading, body))...)
	}
	return cmd.Run() == nil
}

func (d *dialogs) message(heading, body string, isErr bool) {
	kind := "message"
	if isErr {
		kind = "error"
	}
	if _, _, handled := d.nativeDialog(dialogSpec{Kind: kind, Heading: heading, Body: body}); handled || d.tool == "" {
		return
	}
	if d.zenity {
		kind, icon := "--info", "emblem-ok-symbolic"
		if isErr {
			kind, icon = "--error", "dialog-error"
		}
		_ = exec.CommandContext(ctx, d.tool, d.zenityArgs(kind, icon, "--text="+d.text(heading, body), "--ok-label="+tr("Close"))...).Run() // nothing to do if it fails
		return
	}
	kd := "--msgbox"
	if isErr {
		kd = "--error"
	}
	_ = exec.CommandContext(ctx, d.tool, d.kdialogArgs(kd, d.text(heading, body))...).Run()
}

// sheet shows a read only page with one Close button: a heading, an optional
// sentence and property rows (dim label above its value, like libadwaita
// property rows) or a preformatted block.
func (d *dialogs) sheet(icon, heading, intro string, rows [][2]string, pre string) {
	if _, _, handled := d.nativeDialog(dialogSpec{Kind: "message", Heading: heading, Body: intro, Rows: rows, Pre: pre}); handled || d.tool == "" {
		return
	}
	if !d.zenity {
		var b strings.Builder
		b.WriteString(heading + "\n\n")
		if intro != "" {
			b.WriteString(intro + "\n\n")
		}
		for _, r := range rows {
			b.WriteString(r[0] + ": " + r[1] + "\n")
		}
		b.WriteString(pre)
		_ = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--msgbox", b.String())...).Run()
		return
	}
	var b strings.Builder
	b.WriteString(`<span size="large" weight="bold">` + html.EscapeString(heading) + "</span>")
	if intro != "" {
		b.WriteString("\n" + html.EscapeString(intro))
	}
	for _, r := range rows {
		b.WriteString("\n\n<span size=\"small\" alpha=\"60%\">" + html.EscapeString(r[0]) + "</span>\n" + html.EscapeString(r[1]))
	}
	if pre != "" {
		b.WriteString("\n\n<tt><small>" + html.EscapeString(pre) + "</small></tt>")
	}
	_ = exec.CommandContext(ctx, d.tool, d.zenityArgs("--info", icon, "--width=480", "--text="+b.String(), "--ok-label="+tr("Close"))...).Run()
}

// password returns the entered text; the dialog prints it on stdout, never in argv.
func (d *dialogs) password(heading, body, label, ok string) ([]byte, bool) {
	if out, accepted, handled := d.nativeDialog(dialogSpec{Kind: "password", Heading: heading, Body: body, Label: label, Yes: ok}); handled {
		return out, accepted
	}
	if d.tool == "" {
		return nil, false
	}
	var cmd *exec.Cmd
	if d.zenity {
		cmd = exec.CommandContext(ctx, d.tool, d.zenityArgs("--forms", iconDisk, "--text="+d.text(heading, body),
			"--add-password="+label, "--ok-label="+ok, "--cancel-label="+tr("Cancel"))...)
	} else {
		cmd = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--password", d.text(heading, body))...)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}
	return bytes.TrimRight(out, "\r\n"), true
}

// ---- flow ----

// repromptAfter is how long a closed passphrase dialog stays away while the
// key is still missing.
const repromptAfter = 10 * time.Minute

// escrow walks the user through every volume that needs a key. It returns
// false when the user postponed.
func escrow(st agent.DesktopResponse, d *dialogs, company string) bool {
	for _, v := range st.Need {
		for try := 0; ; try++ {
			pw, ok := d.password(tr("Recovery Key Required"),
				fmt.Sprintf(tr("%s needs a recovery key for the encrypted disk %s, so access can be restored if the passphrase is ever lost. Your passphrase stays unchanged."), company, v.Device)+
					"\n\n"+fmt.Sprintf(tr("The passphrase you type when the computer starts, for %s."), v.Device),
				tr("Passphrase"), tr("Continue"))
			if !ok {
				return false
			}
			resp, err := call(agent.DesktopRequest{Op: "escrow", UUID: v.UUID, Passphrase: string(pw)})
			clear(pw)
			if err == nil && resp.OK {
				d.message(tr("Recovery Key Stored"),
					fmt.Sprintf(tr("The key is being sent to %s. Your passphrase is unchanged."), company), false)
				break
			}
			heading, body := tr("Wrong Passphrase"), tr("The passphrase was not accepted.")
			switch {
			case err != nil:
				heading, body = tr("Agent Not Reachable"), tr("The LiMDM agent does not respond. Try again later.")
			case strings.Contains(resp.Error, "too many"):
				heading, body = tr("Too Many Attempts"), tr("Try again later.")
			}
			if err != nil || try >= 2 || strings.Contains(resp.Error, "too many") {
				d.message(heading, body, true)
				return false
			}
			if !d.ask(heading, body, tr("Try Again"), tr("Cancel")) {
				return false
			}
		}
	}
	return true
}

// needStatus asks the agent which volumes need a key. An answer with an
// error (agent starting, caller not allowed) is an error, never "nothing to do".
func needStatus() (agent.DesktopResponse, error) {
	st, err := call(agent.DesktopRequest{Op: "status"})
	if err == nil && st.Error != "" {
		err = errors.New(st.Error)
	}
	return st, err
}

// prompt asks for the disk passphrase while a volume lacks a recovery key.
// It returns false when nothing was shown: no key needed, or the dialog is
// already open (the prompt lock keeps it to one per user).
func prompt() (bool, error) {
	st, err := needStatus()
	if err != nil || len(st.Need) == 0 {
		return false, err
	}
	lock := takeLock("limdm-desktop-prompt.lock")
	if lock == nil {
		return false, nil
	}
	if lock != os.Stdin { // no runtime directory: no lock either
		defer lock.Close()
	}
	d := dialogsFor(st)
	escrow(st, d, d.title)
	return true, nil
}

func main() {
	noTray := flag.Bool("no-tray", false, "only the reminders, no tray icon")
	msg := flag.String("message", "", "show a message from IT (started by the agent)")
	msgTitle := flag.String("message-title", "", "title of -message")
	rebootAt := flag.String("reboot-at", "", "offer to postpone the restart planned at this time (started by the agent)")
	rebootDefers := flag.Int("reboot-defers", 0, "postponements left")
	rebootMinutes := flag.Int("reboot-defer-minutes", 60, "minutes one postponement adds")
	flag.Parse()
	if *msg != "" {
		showMessage(*msgTitle, *msg)
		return
	}
	if *rebootAt != "" {
		offerRebootDefer(*rebootAt, *rebootDefers, *rebootMinutes)
		return
	}
	lock := takeLock("limdm-desktop.lock")
	if lock == nil {
		return // systemd user unit, XDG autostart and the agent may all start it
	}
	defer lock.Close()
	if *noTray {
		reminders()
		return
	}
	runTray()
}

// takeLock takes a lock in the user's runtime directory, held while the
// returned file stays open; nil means another process of this user holds it.
func takeLock(name string) *os.File {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // the user's own runtime directory, runs as that user
	if err != nil {
		return os.Stdin // no runtime dir: better a second icon than none
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil
	}
	return f
}
