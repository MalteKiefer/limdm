//go:build linux

// limdm-desktop runs in the user's desktop session (XDG autostart). It shows
// a tray icon with the device's state (details, sync, agent log) and asks
// the user for what only they can provide, currently the disk passphrase to
// create a recovery key. Dialogs are libadwaita message dialogs from the GTK
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
)

const socket = "/run/limdm/agent.sock"

var ctx = context.Background()

// de follows the session's locale, falling back to the system locale.
var de = func() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return strings.HasPrefix(v, "de")
		}
	}
	for _, f := range []string{"/etc/locale.conf", "/etc/default/locale"} {
		if b, err := os.ReadFile(f); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(l), "LANG="); ok {
					return strings.HasPrefix(strings.Trim(v, `"'`), "de")
				}
			}
		}
	}
	return false
}()

func tr(en, deText string) string {
	if de {
		return deText
	}
	return en
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
		_ = exec.CommandContext(ctx, d.tool, d.zenityArgs(kind, icon, "--text="+d.text(heading, body), "--ok-label="+tr("Close", "Schließen"))...).Run() // nothing to do if it fails
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
	_ = exec.CommandContext(ctx, d.tool, d.zenityArgs("--info", icon, "--width=480", "--text="+b.String(), "--ok-label="+tr("Close", "Schließen"))...).Run()
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
			"--add-password="+label, "--ok-label="+ok, "--cancel-label="+tr("Cancel", "Abbrechen"))...)
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

func stateFile() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "limdm-desktop", "last-prompt")
}

func lastPrompt() time.Time {
	b, err := os.ReadFile(stateFile())
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	return t
}

func setLastPrompt() {
	f := stateFile()
	if os.MkdirAll(filepath.Dir(f), 0o700) == nil {
		_ = os.WriteFile(f, []byte(time.Now().Format(time.RFC3339)), 0o600) // worst case: asked again
	}
}

// escrow walks the user through every volume that needs a key. It returns
// false when the user postponed.
func escrow(st agent.DesktopResponse, d *dialogs, company string) bool {
	for _, v := range st.Need {
		if !d.ask(tr("Recovery Key Required", "Wiederherstellungsschlüssel erforderlich"),
			fmt.Sprintf(tr("%s needs a recovery key for the encrypted disk %s, so access can be restored if the passphrase is ever lost. Your passphrase stays unchanged.",
				"%s benötigt einen Wiederherstellungsschlüssel für die verschlüsselte Festplatte %s, damit der Zugriff bei verlorener Passphrase wiederhergestellt werden kann. Ihre Passphrase bleibt unverändert."), company, v.Device),
			tr("Set Up", "Einrichten"), tr("Later", "Später")) {
			return false
		}
		for try := 0; ; try++ {
			pw, ok := d.password(tr("Enter Disk Passphrase", "Festplatten Passphrase eingeben"),
				fmt.Sprintf(tr("The passphrase you type when the computer starts, for %s.", "Die Passphrase, die Sie beim Start des Computers eingeben, für %s."), v.Device),
				tr("Passphrase", "Passphrase"), tr("Continue", "Weiter"))
			if !ok {
				return false
			}
			resp, err := call(agent.DesktopRequest{Op: "escrow", UUID: v.UUID, Passphrase: string(pw)})
			clear(pw)
			if err == nil && resp.OK {
				d.message(tr("Recovery Key Stored", "Wiederherstellungsschlüssel gespeichert"),
					fmt.Sprintf(tr("The key is being sent to %s. Your passphrase is unchanged.", "Der Schlüssel wird an %s übermittelt. Ihre Passphrase bleibt unverändert."), company), false)
				break
			}
			heading, body := tr("Wrong Passphrase", "Falsche Passphrase"), tr("The passphrase was not accepted.", "Die Passphrase wurde nicht akzeptiert.")
			switch {
			case err != nil:
				heading, body = tr("Agent Not Reachable", "Agent nicht erreichbar"), tr("The LiMDM agent does not respond. Try again later.", "Der LiMDM Agent antwortet nicht. Versuchen Sie es später erneut.")
			case strings.Contains(resp.Error, "too many"):
				heading, body = tr("Too Many Attempts", "Zu viele Versuche"), tr("Try again later.", "Versuchen Sie es später erneut.")
			}
			if err != nil || try >= 2 || strings.Contains(resp.Error, "too many") {
				d.message(heading, body, true)
				return false
			}
			if !d.ask(heading, body, tr("Try Again", "Erneut versuchen"), tr("Cancel", "Abbrechen")) {
				return false
			}
		}
	}
	return true
}

func run(now bool) error {
	st, err := call(agent.DesktopRequest{Op: "status"})
	if err != nil {
		return err
	}
	company := st.Company
	if company == "" {
		company = tr("Your IT department", "Ihre IT")
	}
	if len(st.Need) == 0 {
		if now {
			if d, err := newDialogs(company, st.Logo); err == nil {
				d.message(tr("All Set", "Alles erledigt"), tr("Every disk has a recovery key.", "Alle Festplatten haben einen Wiederherstellungsschlüssel."), false)
			}
		}
		return nil
	}
	if !now && time.Since(lastPrompt()) < 24*time.Hour {
		return nil
	}
	setLastPrompt()
	// the GTK 4 app asks on its disk page; simple dialogs where it cannot run
	openApp("disk", st, func(st agent.DesktopResponse) {
		if d, err := newDialogs(company, st.Logo); err == nil {
			escrow(st, d, company)
		}
	})
	return nil
}

func main() {
	now := flag.Bool("now", false, "ask right away (menu entry) instead of the daily reminder")
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
	if *now {
		if err := run(true); err != nil {
			fmt.Fprintln(os.Stderr, "limdm-desktop:", err)
			os.Exit(1)
		}
		return
	}
	lock := singleInstance()
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

// singleInstance takes a lock in the user's runtime directory, held while the
// returned file stays open; nil means another helper of this user runs.
func singleInstance() *os.File {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	f, err := os.OpenFile(filepath.Join(dir, "limdm-desktop.lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // the user's own runtime directory, runs as that user
	if err != nil {
		return os.Stdin // no runtime dir: better a second icon than none
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil
	}
	return f
}
