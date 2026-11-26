package api

import (
	"encoding/json"
	"testing"
)

// valid reports whether a payload of typ passes validation.
func valid(typ, payload string) error {
	return LibraryItem{Name: "x", Type: typ, Payload: json.RawMessage(payload)}.Validate()
}

func TestUpdatesPatchFields(t *testing.T) {
	ok := `{"mode":"security","window":"22:00-04:00","reboot":true,"days":["sat","sun"],"hold":["linux-image-amd64","nginx"],"autoremove":true,"snap_refresh":"window","reboot_notice_minutes":15,"reboot_max_defers":3,"reboot_defer_minutes":60}`
	if err := valid(TypeUpdates, ok); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"bad day":       `{"mode":"all","window":"02:00-05:00","days":["monday"]}`,
		"duplicate day": `{"mode":"all","window":"02:00-05:00","days":["mon","mon"]}`,
		"bad hold":      `{"mode":"all","window":"02:00-05:00","hold":["-oops"]}`,
		"hold space":    `{"mode":"all","window":"02:00-05:00","hold":["a b"]}`,
		"snap":          `{"mode":"all","window":"02:00-05:00","snap_refresh":"never"}`,
		"snap window":   `{"mode":"off","snap_refresh":"window"}`,
		"defers":        `{"mode":"all","window":"02:00-05:00","reboot_max_defers":9}`,
		"defer minutes": `{"mode":"all","window":"02:00-05:00","reboot_defer_minutes":5}`,
	} {
		if valid(TypeUpdates, p) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSafeFilePath(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/motd": true, "/etc/issue.net": true, "/srv/app/config.yml": true, "/etc/opt/app/app.conf": true, "/etc/motd.d/10-it": true,
		"/etc/cron.d/backup": false, "/etc/sudo.conf": false, "/etc/environment": false, "/etc/dbus-1/system.d/x.conf": false,
		"/etc/xdg/autostart/x.desktop": false, "/usr/lib/systemd/system/x.service": false, "/srv": false, "/srv/": false,
		"/srv/../etc/cron.d/x": false, "/srv/a/../../etc/passwd": false, "/etc/motdx": false, "srv/x": false,
	} {
		if SafeFilePath(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
	if err := valid(TypeFiles, `{"files":[{"path":"/etc/x","content":"x","mode":"0640","owner":"root","group":"ssl-cert"}]}`); err != nil {
		t.Fatal(err)
	}
	if valid(TypeFiles, `{"files":[{"path":"/etc/x","content":"x","owner":"Bad Name"}]}`) == nil {
		t.Fatal("invalid owner accepted")
	}
}
