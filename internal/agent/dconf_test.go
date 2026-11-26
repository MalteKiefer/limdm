package agent

import (
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestDconfFiles(t *testing.T) {
	set, locks := dconfFiles(&api.Dconf{Settings: map[string]string{
		"/org/gnome/desktop/interface/clock-show-seconds": "true",
		"/org/gnome/desktop/background/picture-uri":       "'file:///usr/share/backgrounds/corp.png'",
	}, Locks: []string{"/org/gnome/desktop/background/"}})
	want := managedHeader + "\n[org/gnome/desktop/background]\npicture-uri='file:///usr/share/backgrounds/corp.png'\n\n[org/gnome/desktop/interface]\nclock-show-seconds=true\n"
	if set != want || locks != managedHeader+"/org/gnome/desktop/background/\n" {
		t.Fatalf("settings:\n%s\nlocks:\n%s", set, locks)
	}
	if s, l := dconfFiles(nil); s != "" || l != "" {
		t.Fatal("no declaration must remove the files")
	}
	bad := api.LibraryItem{Name: "x", Type: api.TypeDconf, Payload: []byte(`{"settings":{"/org/x/key":"true\n[other]\nk=v"}}`)}
	if bad.Validate() == nil {
		t.Fatal("multi line value accepted")
	}
	ok := api.LibraryItem{Name: "x", Type: api.TypeDconf, Payload: []byte(`{"settings":{"/org/gnome/desktop/interface/clock-show-seconds":"true"},"locks":["/org/gnome/desktop/interface/"]}`)}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}
