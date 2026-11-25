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

var de = func() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return strings.HasPrefix(v, "de")
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

type dialogs struct {
	tool, logo, title string
	zenity4           bool
}

func newDialogs(company, logo string) (*dialogs, error) {
	d := &dialogs{logo: logo, title: company + tr(": Disk encryption", ": Festplattenverschlüsselung")}
	if p, err := exec.LookPath("zenity"); err == nil {
		d.tool = p
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

func (d *dialogs) zenityArgs(kind string, extra ...string) []string {
	args := []string{kind, "--title=" + d.title}
	if d.logo != "" {
		if d.zenity4 && kind != "--password" {
			args = append(args, "--icon="+d.logo)
		} else {
			args = append(args, "--window-icon="+d.logo)
		}
	}
	return append(args, extra...)
}

func (d *dialogs) kdialogArgs(extra ...string) []string {
	args := []string{"--title", d.title}
	if d.logo != "" {
		args = append(args, "--icon", d.logo)
	}
	return append(args, extra...)
}

func (d *dialogs) ask(text, yes, no string) bool {
	var cmd *exec.Cmd
	if strings.HasSuffix(d.tool, "zenity") {
		cmd = exec.CommandContext(ctx, d.tool, d.zenityArgs("--question", "--width=420", "--text="+text, "--ok-label="+yes, "--cancel-label="+no)...)
	} else {
		cmd = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--yes-label", yes, "--no-label", no, "--yesno", text)...)
	}
	return cmd.Run() == nil
}

func (d *dialogs) message(text string, isErr bool) {
	if strings.HasSuffix(d.tool, "zenity") {
		kind := "--info"
		if isErr {
			kind = "--error"
		}
		_ = exec.CommandContext(ctx, d.tool, d.zenityArgs(kind, "--width=420", "--text="+text)...).Run() // nothing to do if it fails
		return
	}
	kind := "--msgbox"
	if isErr {
		kind = "--error"
	}
	_ = exec.CommandContext(ctx, d.tool, d.kdialogArgs(kind, text)...).Run()
}

// password returns the entered text; the dialog prints it on stdout, never in argv.
func (d *dialogs) password(prompt string) ([]byte, bool) {
	var cmd *exec.Cmd
	if strings.HasSuffix(d.tool, "zenity") {
		cmd = exec.CommandContext(ctx, d.tool, d.zenityArgs("--password")...)
	} else {
		cmd = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--password", prompt)...)
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
		intro := fmt.Sprintf(tr(
			"%s needs a recovery key for the encrypted disk %s.\n\nWith it, IT can restore access if the passphrase is ever lost. Enter your current disk passphrase once; it stays unchanged.",
			"%s benötigt einen Wiederherstellungsschlüssel für die verschlüsselte Festplatte %s.\n\nDamit kann die IT den Zugriff wiederherstellen, falls die Passphrase verloren geht. Geben Sie dazu einmal Ihre aktuelle Festplatten Passphrase ein; sie bleibt unverändert."),
			company, v.Device)
		if !d.ask(intro, tr("Set up now", "Jetzt einrichten"), tr("Later", "Später")) {
			return false
		}
		for try := 0; ; try++ {
			pw, ok := d.password(tr("Current passphrase for ", "Aktuelle Passphrase für ") + v.Device)
			if !ok {
				return false
			}
			resp, err := call(agent.DesktopRequest{Op: "escrow", UUID: v.UUID, Passphrase: string(pw)})
			clear(pw)
			if err == nil && resp.OK {
				d.message(tr("The recovery key was created and is being sent to ", "Der Wiederherstellungsschlüssel wurde erstellt und wird an ")+company+
					tr(". Your passphrase is unchanged.", " übermittelt. Ihre Passphrase bleibt unverändert."), false)
				break
			}
			msg := tr("The passphrase was not accepted.", "Die Passphrase wurde nicht akzeptiert.")
			if err != nil {
				msg = tr("The LiMDM agent is not reachable.", "Der LiMDM Agent ist nicht erreichbar.")
			} else if strings.Contains(resp.Error, "too many") {
				msg = tr("Too many attempts. Please try again later.", "Zu viele Versuche. Bitte später erneut versuchen.")
			}
			d.message(msg, true)
			if err != nil || try >= 2 || strings.Contains(resp.Error, "too many") {
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
				d.message(tr("No action needed: all disks have a recovery key.", "Nichts zu tun: alle Festplatten haben einen Wiederherstellungsschlüssel."), false)
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
