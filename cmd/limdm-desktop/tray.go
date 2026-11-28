//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"fyne.io/systray"

	"github.com/maltekiefer/limdm/internal/agent"
)

// Tray icon (StatusNotifierItem over D-Bus): sway with waybar, KDE Plasma,
// Xfce, Cinnamon, Ubuntu's GNOME and GNOME with the AppIndicator extension
// show it. Without a tray host the helper still runs its reminders.

type tray struct {
	header, status, checkin                                 *systray.MenuItem
	open, software, compliance, sync, recovery, logs, about *systray.MenuItem
	sso                                                     *systray.MenuItem
	ssoNotified                                             time.Time
	last                                                    agent.DesktopResponse
}

// Menu after the GNOME HIG for status menus: who manages the device and its
// state on top (not clickable), then the actions, then details and version.
func runTray() {
	systray.Run(func() {
		t := &tray{}
		systray.SetIcon(iconWarn)
		systray.SetTitle("LiMDM")
		t.header = systray.AddMenuItem("LiMDM", "")
		t.header.Disable()
		t.status = systray.AddMenuItem(tr("Checking status…"), "")
		t.status.Disable()
		t.checkin = systray.AddMenuItem("", "")
		t.checkin.Disable()
		systray.AddSeparator()
		t.open = systray.AddMenuItem(tr("Open LiMDM…"), "")
		t.software = systray.AddMenuItem(tr("Install Software…"), "")
		t.compliance = systray.AddMenuItem(tr("Compliance…"), "")
		t.recovery = systray.AddMenuItem(tr("Set Up Recovery Key…"), "")
		t.recovery.Hide()
		t.sso = systray.AddMenuItem(tr("Confirm Company Account…"), "")
		t.sso.Hide()
		systray.AddSeparator()
		t.sync = systray.AddMenuItem(tr("Sync Now"), "")
		t.logs = systray.AddMenuItem(tr("Agent Log…"), "")
		systray.AddSeparator()
		t.about = systray.AddMenuItem(tr("Agent version unknown"), "")
		t.about.Disable()
		go t.loop()
		go reminders()
	}, func() {})
}

func (t *tray) loop() {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	t.refresh()
	for {
		select {
		case <-tick.C:
			t.refresh()
		case <-t.open.ClickedCh:
			go openApp("overview", t.last, showDetails)
		case <-t.software.ClickedCh:
			go openApp("software", t.last, showDetails)
		case <-t.compliance.ClickedCh:
			go openApp("compliance", t.last, showDetails)
		case <-t.sync.ClickedCh:
			resp, err := call(agent.DesktopRequest{Op: "sync"})
			d := dialogsFor(t.last)
			go func() {
				switch {
				case err != nil:
					d.message(tr("Agent Not Reachable"), err.Error(), true)
				case !resp.OK:
					d.message(tr("Sync Not Started"), tr(resp.Error), true)
				default:
					d.message(tr("Sync Started"), tr("The device reports to the server within a minute."), false)
				}
			}()
			time.AfterFunc(20*time.Second, t.refresh)
		case <-t.recovery.ClickedCh:
			go func(last agent.DesktopResponse) {
				if _, err := prompt(); err != nil {
					dialogsFor(last).message(tr("Recovery Key"), err.Error(), true)
				}
			}(t.last)
		case <-t.sso.ClickedCh:
			go confirmAccount(t.last)
		case <-t.logs.ClickedCh:
			go openApp("log", t.last, showLog)
		}
	}
}

func (t *tray) refresh() {
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil || resp.Status == nil {
		systray.SetIcon(iconBad)
		systray.SetTooltip(tr("LiMDM agent not reachable"))
		t.status.SetTitle("✕ " + tr("Agent not reachable"))
		t.checkin.SetTitle("")
		t.about.SetTitle(tr("Agent version unknown"))
		return
	}
	t.last = resp
	st := resp.Status
	if resp.Company != "" {
		t.header.SetTitle(fmt.Sprintf(tr("Managed by %s"), resp.Company))
	}
	t.about.SetTitle(fmt.Sprintf(tr("LiMDM agent %s"), st.Version))
	icon, mark, line := iconOK, "✓ ", tr("Device is compliant")
	switch {
	case st.RemoteShell != "":
		icon, mark, line = iconWarn, "! ", tr("IT remote support session running")
	case st.Locked:
		icon, mark, line = iconBad, "✕ ", tr("Device is locked")
	case st.LastError != "":
		icon, mark, line = iconBad, "✕ ", tr("No contact to the server")
	case len(st.Failing) > 0:
		icon, mark, line = iconWarn, "! ", trn(len(st.Failing), "%d check failing", "%d checks failing")
	}
	systray.SetIcon(icon)
	systray.SetTooltip(resp.Company + ": " + line + " · " + tr("LiMDM agent %s", st.Version))
	t.status.SetTitle(mark + line)
	if st.LastCheckin != nil {
		t.checkin.SetTitle(tr("Last sync %s", st.LastCheckin.Local().Format("15:04")))
	} else {
		t.checkin.SetTitle(tr("Not synced yet"))
	}
	if len(resp.Need) > 0 {
		t.recovery.Show()
	} else {
		t.recovery.Hide()
	}
	t.refreshSSO()
}

func dialogsFor(last agent.DesktopResponse) *dialogs {
	company := last.Company
	if company == "" {
		company = tr("Your IT department")
	}
	d, err := newDialogs(company, last.Logo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "limdm-desktop:", err)
		return &dialogs{} // no dialog tool: calls fail quietly
	}
	return d
}

func showDetails(last agent.DesktopResponse) {
	st := last.Status
	d := dialogsFor(last)
	if st == nil {
		d.message(tr("Agent Not Reachable"), tr("The LiMDM agent does not respond."), true)
		return
	}
	seen := tr("never")
	if st.LastCheckin != nil {
		seen = st.LastCheckin.Local().Format("2006-01-02 15:04")
	}
	state := tr("Compliant")
	if len(st.Failing) > 0 {
		failing := make([]string, len(st.Failing))
		for i, f := range st.Failing {
			failing[i] = tr(f)
		}
		state = strings.Join(failing, "\n")
	}
	rows := [][2]string{
		{tr("Device"), st.Hostname},
		{tr("Compliance"), state},
		{tr("Last sync"), seen},
		{tr("Agent version"), st.Version},
		{tr("Server"), st.Server},
		{tr("Recovery keys"), fmt.Sprint(st.Escrowed)},
		{tr("Device ID"), st.DeviceID},
	}
	if st.LastError != "" {
		rows = append(rows, [2]string{tr("Last error"), st.LastError})
	}
	d.sheet("computer", tr("Device Details"), fmt.Sprintf(tr("Managed by %s with LiMDM."), last.Company), rows, "")
}

func showLog(last agent.DesktopResponse) {
	d := dialogsFor(last)
	lines := last.Log
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	if len(lines) == 0 {
		d.sheet("emblem-ok-symbolic", tr("Agent Log"), tr("No warnings or errors recorded."), nil, "")
		return
	}
	d.sheet("utilities-terminal", tr("Agent Log"), tr("Latest warnings and errors of the agent."), nil, strings.Join(lines, "\n"))
}

// showMessage displays a message an admin sent from the console.
func showMessage(title, text string) {
	resp, _ := call(agent.DesktopRequest{Op: "status"})
	d := dialogsFor(resp)
	if title == "" {
		title = tr("Message from IT")
	}
	d.sheet("mail-unread", title, text, nil, "")
}

// offerRebootDefer asks whether to postpone the restart IT planned after
// updates; the agent enforces how often and by how much.
func offerRebootDefer(at string, left, minutes int) {
	resp, _ := call(agent.DesktopRequest{Op: "status"})
	d := dialogsFor(resp)
	body := tr("The device restarts at %s to finish updates. Save your work.", at) + " " +
		trn(left, "You can postpone the restart %d more time.", "You can postpone the restart %d more times.")
	if !d.ask(tr("Restart scheduled"), body, trn(minutes, "Postpone %d minute", "Postpone %d minutes"), tr("Restart as planned")) {
		return
	}
	r, err := call(agent.DesktopRequest{Op: "reboot-defer"})
	switch {
	case err != nil:
		d.message(tr("Restart not postponed"), err.Error(), true)
	case r.Error != "":
		d.message(tr("Restart not postponed"), tr(r.Error), true)
	default:
		d.message(tr("Restart postponed"), fmt.Sprintf(tr("The device restarts at %s."), r.RebootAt), false)
	}
}

const appPath = "/usr/lib/limdm/limdm-desktop-ui"

// openApp opens the GTK 4 window on a page. Without GTK 4 and libadwaita 1.4
// (exit code 3, or the app missing) the simple dialogs are shown instead.
func openApp(page string, last agent.DesktopResponse, fallback func(agent.DesktopResponse)) {
	err := exec.CommandContext(ctx, appPath, "--page", page).Run()
	var exit *exec.ExitError
	if err == nil || (errors.As(err, &exit) && exit.ExitCode() != 3) {
		return
	}
	fallback(last)
}

// reminders asks for what the device needs from the user: shortly after
// login and within a minute of the agent reporting a volume without a
// recovery key, the passphrase dialog opens by itself. Closing it only
// postpones it by repromptAfter, until the key is escrowed.
func reminders() {
	time.Sleep(30 * time.Second) // let the session settle after login
	for {
		shown, err := prompt()
		if err != nil {
			fmt.Fprintln(os.Stderr, "limdm-desktop:", err)
		}
		if shown {
			time.Sleep(repromptAfter)
		} else {
			time.Sleep(time.Minute)
		}
	}
}

// refreshSSO shows the confirmation entry while the company account needs
// one, with a notification once a day.
func (t *tray) refreshSSO() {
	resp, err := call(agent.DesktopRequest{Op: "sso-status"})
	if err != nil || resp.SSO == nil || !resp.SSO.Managed || !resp.SSO.Due {
		t.sso.Hide()
		return
	}
	t.sso.Show()
	if time.Since(t.ssoNotified) < 24*time.Hour {
		return
	}
	t.ssoNotified = time.Now()
	body := tr("Confirm your company account to keep using this device.")
	if dl := resp.SSO.Deadline; dl != nil {
		body += " " + fmt.Sprintf(tr("Without it the password stops working after %s."), dl.Local().Format("2006-01-02 15:04"))
	}
	_ = exec.CommandContext(ctx, "notify-send", "--app-name=LiMDM", "--urgency=normal", tr("Company Account"), body).Run()
}

// confirmAccount runs the confirmation: the agent starts it, the browser
// opens the identity provider's page and a dialog shows the code.
func confirmAccount(last agent.DesktopResponse) {
	d := dialogsFor(last)
	resp, err := call(agent.DesktopRequest{Op: "sso-confirm"})
	switch {
	case err != nil:
		d.message(tr("Agent Not Reachable"), err.Error(), true)
		return
	case resp.Error != "" || resp.SSO == nil || resp.SSO.URI == "":
		d.message(tr("Confirmation Not Started"), firstNonEmpty(tr(resp.Error), tr("The identity provider did not answer.")), true)
		return
	}
	_ = exec.CommandContext(ctx, "xdg-open", resp.SSO.URI).Start()
	go d.message(tr("Confirm Your Company Account"),
		fmt.Sprintf(tr("Sign in on the page that opened (%s) and enter the code %s."), resp.SSO.URI, resp.SSO.Code), false)
	for i := 0; i < 120; i++ { // up to ten minutes
		time.Sleep(5 * time.Second)
		st, err := call(agent.DesktopRequest{Op: "sso-status"})
		if err != nil || st.SSO == nil || st.SSO.Running {
			continue
		}
		if st.SSO.Error != "" {
			d.message(tr("Confirmation Failed"), tr(st.SSO.Error), true)
		} else {
			d.message(tr("Company Account Confirmed"), tr("Thank you. Nothing else to do."), false)
		}
		return
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
