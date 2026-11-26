//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
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

// statusIcon draws the LiMDM logo (shield with prompt on a teal tile, see
// packaging/artwork/limdm.svg) with a status dot: green (compliant), amber
// (checks failing), red (no contact or locked). Drawn in code: the tray
// needs pixels and the binary has no SVG renderer.
func statusIcon(c color.RGBA) []byte {
	const n = 64
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	teal := color.RGBA{0x0f, 0x6e, 0x6e, 0xff}
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	seg := func(px, py, ax, ay, bx, by float64) float64 { // distance point to segment
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((px-ax)*dx+(py-ay)*dy)/(dx*dx+dy*dy)))
		return math.Hypot(px-ax-t*dx, py-ay-t*dy)
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			// coordinates of the 128 unit logo
			px, py := (float64(x)+0.5)*2, (float64(y)+0.5)*2
			// rounded tile 8..120, radius 26
			qx, qy := math.Max(math.Abs(px-64)-30, 0), math.Max(math.Abs(py-64)-30, 0)
			if math.Hypot(qx, qy) > 26 {
				continue
			}
			col := color.RGBA{uint8(0x16 - 10*py/128), uint8(0x85 - 42*py/128), uint8(0x7f - 39*py/128), 0xff}
			// shield
			half := 0.0
			switch {
			case py >= 24 && py < 36:
				half = 34 * (py - 24) / 12
			case py >= 36 && py < 62:
				half = 34
			case py >= 62 && py <= 108:
				k := (py - 62) / 46
				half = 34 * math.Sqrt(1-k*k)
			}
			if math.Abs(px-64) <= half {
				col = white
				if seg(px, py, 49, 55, 61, 65) < 3.5 || seg(px, py, 61, 65, 49, 75) < 3.5 || seg(px, py, 66, 78, 80, 78) < 3.5 {
					col = teal
				}
			}
			// status dot with a white ring
			switch d := math.Hypot(px-102, py-102); {
			case d <= 20:
				col = c
			case d <= 26:
				col = white
			}
			img.SetRGBA(x, y, col)
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img) // in-memory encoding of a valid image cannot fail
	return b.Bytes()
}

var (
	iconOK   = statusIcon(color.RGBA{0x2e, 0xc2, 0x7e, 0xff})
	iconWarn = statusIcon(color.RGBA{0xf5, 0xc2, 0x11, 0xff})
	iconBad  = statusIcon(color.RGBA{0xe0, 0x1b, 0x24, 0xff})
)

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
		t.status = systray.AddMenuItem(tr("Checking status…", "Status wird geprüft…"), "")
		t.status.Disable()
		t.checkin = systray.AddMenuItem("", "")
		t.checkin.Disable()
		systray.AddSeparator()
		t.open = systray.AddMenuItem(tr("Open LiMDM…", "LiMDM öffnen…"), "")
		t.software = systray.AddMenuItem(tr("Install Software…", "Software installieren…"), "")
		t.compliance = systray.AddMenuItem(tr("Compliance…", "Compliance…"), "")
		t.recovery = systray.AddMenuItem(tr("Set Up Recovery Key…", "Wiederherstellungsschlüssel einrichten…"), "")
		t.recovery.Hide()
		t.sso = systray.AddMenuItem(tr("Confirm Company Account…", "Firmenkonto bestätigen…"), "")
		t.sso.Hide()
		systray.AddSeparator()
		t.sync = systray.AddMenuItem(tr("Check In Now", "Jetzt synchronisieren"), "")
		t.logs = systray.AddMenuItem(tr("Agent Log…", "Agent Protokoll…"), "")
		systray.AddSeparator()
		t.about = systray.AddMenuItem(tr("Agent version unknown", "Agent Version unbekannt"), "")
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
					d.message(tr("Agent Not Reachable", "Agent nicht erreichbar"), err.Error(), true)
				case !resp.OK:
					d.message(tr("Check In Not Started", "Synchronisierung nicht gestartet"), resp.Error, true)
				default:
					d.message(tr("Check In Started", "Synchronisierung gestartet"), tr("The device reports to the server within a minute.", "Das Gerät meldet sich innerhalb einer Minute beim Server."), false)
				}
			}()
			time.AfterFunc(20*time.Second, t.refresh)
		case <-t.recovery.ClickedCh:
			go openApp("disk", t.last, func(last agent.DesktopResponse) {
				if err := run(true); err != nil {
					dialogsFor(last).message(tr("Recovery Key", "Wiederherstellungsschlüssel"), err.Error(), true)
				}
			})
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
		systray.SetTooltip(tr("LiMDM agent not reachable", "LiMDM Agent nicht erreichbar"))
		t.status.SetTitle("● " + tr("Agent not reachable", "Agent nicht erreichbar"))
		t.checkin.SetTitle("")
		t.about.SetTitle(tr("Agent version unknown", "Agent Version unbekannt"))
		return
	}
	t.last = resp
	st := resp.Status
	if resp.Company != "" {
		t.header.SetTitle(fmt.Sprintf(tr("Managed by %s", "Verwaltet von %s"), resp.Company))
	}
	t.about.SetTitle(fmt.Sprintf(tr("LiMDM agent %s", "LiMDM Agent %s"), st.Version))
	icon, line := iconOK, tr("Device is compliant", "Gerät ist konform")
	switch {
	case st.RemoteShell != "":
		icon, line = iconWarn, tr("IT remote support session running", "Fernwartung durch die IT läuft")
	case st.Locked:
		icon, line = iconBad, tr("Device is locked", "Gerät ist gesperrt")
	case st.LastError != "":
		icon, line = iconBad, tr("No contact to the server", "Keine Verbindung zum Server")
	case len(st.Failing) > 0:
		icon, line = iconWarn, fmt.Sprintf(tr("%d checks failing", "%d Prüfungen fehlgeschlagen"), len(st.Failing))
	}
	systray.SetIcon(icon)
	systray.SetTooltip(resp.Company + ": " + line + " · " + tr("agent", "Agent") + " " + st.Version)
	t.status.SetTitle("● " + line)
	if st.LastCheckin != nil {
		t.checkin.SetTitle(tr("Last check in ", "Letzte Synchronisierung ") + st.LastCheckin.Local().Format("15:04"))
	} else {
		t.checkin.SetTitle(tr("Not checked in yet", "Noch nicht synchronisiert"))
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
		company = tr("Your IT department", "Ihre IT")
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
		d.message(tr("Agent Not Reachable", "Agent nicht erreichbar"), tr("The LiMDM agent does not respond.", "Der LiMDM Agent antwortet nicht."), true)
		return
	}
	seen := tr("never", "nie")
	if st.LastCheckin != nil {
		seen = st.LastCheckin.Local().Format("2006-01-02 15:04")
	}
	state := tr("Compliant", "Konform")
	if len(st.Failing) > 0 {
		state = strings.Join(st.Failing, "\n")
	}
	rows := [][2]string{
		{tr("Device", "Gerät"), st.Hostname},
		{tr("Compliance", "Compliance"), state},
		{tr("Last check in", "Letzte Synchronisierung"), seen},
		{tr("Agent version", "Agent Version"), st.Version},
		{tr("Server", "Server"), st.Server},
		{tr("Recovery keys", "Wiederherstellungsschlüssel"), fmt.Sprint(st.Escrowed)},
		{tr("Device ID", "Geräte ID"), st.DeviceID},
	}
	if st.LastError != "" {
		rows = append(rows, [2]string{tr("Last error", "Letzter Fehler"), st.LastError})
	}
	d.sheet("computer", tr("Device Details", "Gerätedetails"), fmt.Sprintf(tr("Managed by %s with LiMDM.", "Verwaltet von %s mit LiMDM."), last.Company), rows, "")
}

func showLog(last agent.DesktopResponse) {
	d := dialogsFor(last)
	lines := last.Log
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	if len(lines) == 0 {
		d.sheet("emblem-ok-symbolic", tr("Agent Log", "Agent Protokoll"), tr("No warnings or errors recorded.", "Keine Warnungen oder Fehler aufgezeichnet."), nil, "")
		return
	}
	d.sheet("utilities-terminal", tr("Agent Log", "Agent Protokoll"), tr("Latest warnings and errors of the agent.", "Letzte Warnungen und Fehler des Agenten."), nil, strings.Join(lines, "\n"))
}

// showMessage displays a message an admin sent from the console.
func showMessage(title, text string) {
	resp, _ := call(agent.DesktopRequest{Op: "status"})
	d := dialogsFor(resp)
	if title == "" {
		title = tr("Message from IT", "Nachricht der IT")
	}
	d.sheet("mail-unread", title, text, nil, "")
}

// offerRebootDefer asks whether to postpone the restart IT planned after
// updates; the agent enforces how often and by how much.
func offerRebootDefer(at string, left, minutes int) {
	resp, _ := call(agent.DesktopRequest{Op: "status"})
	d := dialogsFor(resp)
	body := fmt.Sprintf(tr("The device restarts at %s to finish updates. Save your work. You can postpone the restart %d more times.",
		"Das Gerät startet um %s neu, um Updates abzuschließen. Speichern Sie Ihre Arbeit. Sie können den Neustart noch %d Mal verschieben."), at, left)
	if !d.ask(tr("Restart scheduled", "Neustart geplant"), body, fmt.Sprintf(tr("Postpone %d minutes", "%d Minuten verschieben"), minutes), tr("Restart as planned", "Wie geplant neu starten")) {
		return
	}
	r, err := call(agent.DesktopRequest{Op: "reboot-defer"})
	switch {
	case err != nil:
		d.message(tr("Restart not postponed", "Neustart nicht verschoben"), err.Error(), true)
	case r.Error != "":
		d.message(tr("Restart not postponed", "Neustart nicht verschoben"), r.Error, true)
	default:
		d.message(tr("Restart postponed", "Neustart verschoben"), fmt.Sprintf(tr("The device restarts at %s.", "Das Gerät startet um %s neu."), r.RebootAt), false)
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

// reminders is the daily prompt for what the device needs from the user.
func reminders() {
	time.Sleep(time.Minute) // let the session settle after login
	for {
		if err := run(false); err != nil {
			fmt.Fprintln(os.Stderr, "limdm-desktop:", err)
		}
		time.Sleep(30 * time.Minute)
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
	body := tr("Confirm your company account to keep using this device.", "Bestätigen Sie Ihr Firmenkonto, um das Gerät weiter zu nutzen.")
	if dl := resp.SSO.Deadline; dl != nil {
		body += " " + fmt.Sprintf(tr("Without it the password stops working after %s.", "Ohne Bestätigung funktioniert das Passwort ab %s nicht mehr."), dl.Local().Format("2006-01-02 15:04"))
	}
	_ = exec.CommandContext(ctx, "notify-send", "--app-name=LiMDM", "--urgency=normal", tr("Company Account", "Firmenkonto"), body).Run()
}

// confirmAccount runs the confirmation: the agent starts it, the browser
// opens the identity provider's page and a dialog shows the code.
func confirmAccount(last agent.DesktopResponse) {
	d := dialogsFor(last)
	resp, err := call(agent.DesktopRequest{Op: "sso-confirm"})
	switch {
	case err != nil:
		d.message(tr("Agent Not Reachable", "Agent nicht erreichbar"), err.Error(), true)
		return
	case resp.Error != "" || resp.SSO == nil || resp.SSO.URI == "":
		d.message(tr("Confirmation Not Started", "Bestätigung nicht gestartet"), firstNonEmpty(resp.Error, tr("The identity provider did not answer.", "Der Identity Provider hat nicht geantwortet.")), true)
		return
	}
	_ = exec.CommandContext(ctx, "xdg-open", resp.SSO.URI).Start()
	go d.message(tr("Confirm Your Company Account", "Firmenkonto bestätigen"),
		fmt.Sprintf(tr("Sign in on the page that opened (%s) and enter the code %s.", "Melden Sie sich auf der geöffneten Seite (%s) an und geben Sie den Code %s ein."), resp.SSO.URI, resp.SSO.Code), false)
	for i := 0; i < 120; i++ { // up to ten minutes
		time.Sleep(5 * time.Second)
		st, err := call(agent.DesktopRequest{Op: "sso-status"})
		if err != nil || st.SSO == nil || st.SSO.Running {
			continue
		}
		if st.SSO.Error != "" {
			d.message(tr("Confirmation Failed", "Bestätigung fehlgeschlagen"), st.SSO.Error, true)
		} else {
			d.message(tr("Company Account Confirmed", "Firmenkonto bestätigt"), tr("Thank you. Nothing else to do.", "Danke. Es ist nichts weiter zu tun."), false)
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
