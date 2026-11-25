// limdm-desktop runs in the user's desktop session (XDG autostart) and asks
// the user for what only they can provide, currently the disk passphrase to
// create a recovery key. Dialogs use zenity (GNOME) or kdialog (KDE), so the
// helper needs no GUI libraries and never runs as root.
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
}

func newDialogs(company, logo string) (*dialogs, error) {
	d := &dialogs{icon: logo, title: company}
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
	return nil, errors.New("neither zenity nor kdialog is installed")
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
	var cmd *exec.Cmd
	if d.zenity {
		cmd = exec.CommandContext(ctx, d.tool, d.zenityArgs("--question", iconDisk, "--text="+d.text(heading, body), "--ok-label="+yes, "--cancel-label="+no)...)
	} else {
		cmd = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--yes-label", yes, "--no-label", no, "--yesno", d.text(heading, body))...)
	}
	return cmd.Run() == nil
}

func (d *dialogs) message(heading, body string, isErr bool) {
	if d.zenity {
		kind, icon := "--info", "emblem-ok-symbolic"
		if isErr {
			kind, icon = "--error", "dialog-error"
		}
		_ = exec.CommandContext(ctx, d.tool, d.zenityArgs(kind, icon, "--text="+d.text(heading, body), "--ok-label="+tr("Close", "Schließen"))...).Run() // nothing to do if it fails
		return
	}
	kind := "--msgbox"
	if isErr {
		kind = "--error"
	}
	_ = exec.CommandContext(ctx, d.tool, d.kdialogArgs(kind, d.text(heading, body))...).Run()
}

// password returns the entered text; the dialog prints it on stdout, never in argv.
func (d *dialogs) password(heading, body, label, ok string) ([]byte, bool) {
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
	d, err := newDialogs(company, st.Logo)
	if err != nil {
		return err
	}
	setLastPrompt()
	escrow(st, d, company)
	return nil
}

func main() {
	now := flag.Bool("now", false, "ask right away (menu entry) instead of the daily reminder")
	flag.Parse()
	if *now {
		if err := run(true); err != nil {
			fmt.Fprintln(os.Stderr, "limdm-desktop:", err)
			os.Exit(1)
		}
		return
	}
	time.Sleep(time.Minute) // let the session settle after login
	for {
		if err := run(false); err != nil {
			fmt.Fprintln(os.Stderr, "limdm-desktop:", err)
		}
		time.Sleep(30 * time.Minute)
	}
}
