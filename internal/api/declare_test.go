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
