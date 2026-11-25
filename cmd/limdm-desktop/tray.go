//go:build linux

package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
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

// statusIcon draws a round status light: green (compliant), amber (checks
// failing), red (no contact or locked).
func statusIcon(c color.RGBA) []byte {
	const n = 64
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)-31.5, float64(y)-31.5
			switch d := dx*dx + dy*dy; {
			case d <= 26*26:
				img.SetRGBA(x, y, c)
			case d <= 30*30:
				img.SetRGBA(x, y, color.RGBA{255, 255, 255, 230})
			}
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
	status, checkin, details, sync, recovery, logs *systray.MenuItem
	last                                           agent.DesktopResponse
}

func runTray() {
	systray.Run(func() {
		t := &tray{}
		systray.SetIcon(iconWarn)
		systray.SetTitle("LiMDM")
		t.status = systray.AddMenuItem(tr("Checking status…", "Status wird geprüft…"), "")
		t.status.Disable()
		t.checkin = systray.AddMenuItem("", "")
		t.checkin.Disable()
		systray.AddSeparator()
		t.details = systray.AddMenuItem(tr("Device Details", "Gerätedetails"), "")
		t.sync = systray.AddMenuItem(tr("Check In Now", "Jetzt synchronisieren"), "")
		t.recovery = systray.AddMenuItem(tr("Set Up Recovery Key…", "Wiederherstellungsschlüssel einrichten…"), "")
		t.recovery.Hide()
		t.logs = systray.AddMenuItem(tr("Agent Log", "Agent Protokoll"), "")
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
		case <-t.details.ClickedCh:
			t.refresh()
			go showDetails(t.last)
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
			if err := run(true); err != nil {
				dialogsFor(t.last).message(tr("Recovery Key", "Wiederherstellungsschlüssel"), err.Error(), true)
			}
			t.refresh()
		case <-t.logs.ClickedCh:
			t.refresh()
			go showLog(t.last)
		}
	}
}

func (t *tray) refresh() {
	resp, err := call(agent.DesktopRequest{Op: "info"})
	if err != nil || resp.Status == nil {
		systray.SetIcon(iconBad)
		systray.SetTooltip(tr("LiMDM agent not reachable", "LiMDM Agent nicht erreichbar"))
		t.status.SetTitle(tr("Agent not reachable", "Agent nicht erreichbar"))
		t.checkin.SetTitle("")
		return
	}
	t.last = resp
	st := resp.Status
	icon, line := iconOK, tr("Device is compliant", "Gerät ist konform")
	switch {
	case st.Locked:
		icon, line = iconBad, tr("Device is locked", "Gerät ist gesperrt")
	case st.LastError != "":
		icon, line = iconBad, tr("No contact to the server", "Keine Verbindung zum Server")
	case len(st.Failing) > 0:
		icon, line = iconWarn, fmt.Sprintf(tr("%d checks failing", "%d Prüfungen fehlgeschlagen"), len(st.Failing))
	}
	systray.SetIcon(icon)
	systray.SetTooltip(resp.Company + ": " + line)
	t.status.SetTitle(line)
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
	if st == nil || d.tool == "" {
		d.message(tr("Agent Not Reachable", "Agent nicht erreichbar"), tr("The LiMDM agent does not respond.", "Der LiMDM Agent antwortet nicht."), true)
		return
	}
	seen := tr("never", "nie")
	if st.LastCheckin != nil {
		seen = st.LastCheckin.Local().Format("2006-01-02 15:04")
	}
	failing := tr("none", "keine")
	if len(st.Failing) > 0 {
		failing = strings.Join(st.Failing, "; ")
	}
	rows := [][2]string{
		{tr("Device", "Gerät"), st.Hostname},
		{tr("Device ID", "Geräte ID"), st.DeviceID},
		{tr("Managed by", "Verwaltet von"), last.Company},
		{tr("Server", "Server"), st.Server},
		{tr("Agent version", "Agent Version"), st.Version},
		{tr("Last check in", "Letzte Synchronisierung"), seen},
		{tr("Checks", "Prüfungen"), fmt.Sprintf(tr("%d evaluated, %d failing", "%d geprüft, %d fehlgeschlagen"), st.Checks, len(st.Failing))},
		{tr("Failing checks", "Fehlgeschlagene Prüfungen"), failing},
		{tr("Recovery keys", "Wiederherstellungsschlüssel"), fmt.Sprint(st.Escrowed)},
	}
	if st.LastError != "" {
		rows = append(rows, [2]string{tr("Last error", "Letzter Fehler"), st.LastError})
	}
	if d.zenity {
		args := d.zenityArgs("--list", "computer", "--height=460", "--column="+tr("Property", "Eigenschaft"), "--column="+tr("Value", "Wert"),
			"--text="+d.text(tr("Device Details", "Gerätedetails"), tr("Managed by LiMDM.", "Verwaltet mit LiMDM.")), "--ok-label="+tr("Close", "Schließen"))
		for _, r := range rows {
			args = append(args, r[0], r[1])
		}
		_ = exec.CommandContext(ctx, d.tool, args...).Run() // read only window
		return
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r[0] + ": " + r[1] + "\n")
	}
	d.message(tr("Device Details", "Gerätedetails"), b.String(), false)
}

func showLog(last agent.DesktopResponse) {
	d := dialogsFor(last)
	text := strings.Join(last.Log, "\n")
	if text == "" {
		text = tr("No warnings or errors recorded.", "Keine Warnungen oder Fehler aufgezeichnet.")
	}
	if d.zenity {
		cmd := exec.CommandContext(ctx, d.tool, d.zenityArgs("--text-info", "utilities-terminal", "--width=820", "--height=480")...)
		cmd.Stdin = strings.NewReader(text)
		_ = cmd.Run()
		return
	}
	f, err := os.CreateTemp("", "limdm-log-*.txt")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(text)
	f.Close()
	_ = exec.CommandContext(ctx, d.tool, d.kdialogArgs("--textbox", f.Name(), "820", "480")...).Run()
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
