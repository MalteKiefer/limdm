package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func decl(id, typ, payload string) Declaration {
	return Declaration{Identifier: id, Type: typ, Payload: json.RawMessage(payload)}
}

func TestItemValidate(t *testing.T) {
	for _, it := range DefaultLibrary() {
		if err := it.Validate(); err != nil {
			t.Fatalf("default item %s invalid: %v", it.Name, err)
		}
	}
	bad := []LibraryItem{
		{Name: "p", Type: TypePackages, Payload: json.RawMessage(`{"install":["-o Dpkg::Pre-Invoke=evil"]}`)}, // option injection
		{Name: "f", Type: TypeFiles, Payload: json.RawMessage(`{"files":[{"path":"/etc/../root/x","content":""}]}`)},
		{Name: "u", Type: TypeUpdates, Payload: json.RawMessage(`{"mode":"sometimes"}`)},
		{Name: "x", Type: "com.limdm.unknown", Payload: json.RawMessage(`{}`)},
		{Name: "c", Type: TypeCompliance, Payload: json.RawMessage(`{"level":1,"typo":true}`)}, // unknown field
		{Name: "w", Type: TypeFirewall, Payload: json.RawMessage(`{"enforce":true,"allow":["22/tcp; rm -rf /"]}`)},
		{Name: "", Type: TypeAgent, Payload: json.RawMessage(`{"checkin_seconds":300}`)},
	}
	for _, it := range bad {
		if err := it.Validate(); err == nil {
			t.Errorf("%q accepted", it.Name)
		}
	}
}

func TestComposeSkipsInvalid(t *testing.T) {
	p, st := Compose([]Declaration{decl("u", TypeUpdates, `{"mode":"bad"}`), decl("s", TypeScreenLock, `{"idle_seconds":120}`)})
	if p.Updates.Mode != "" || st[0].Valid || p.ScreenLockSeconds != 120 || !st[1].Valid {
		t.Fatalf("got %+v %+v", p, st)
	}
}

func TestDefaultDeclarations(t *testing.T) {
	p, st := Compose(DefaultDeclarations())
	if p.Compliance.Level != 1 || p.Updates.Mode != "security" || p.ScreenLockSeconds != 300 {
		t.Fatalf("baseline: %+v", p)
	}
	for _, s := range st {
		if !s.Valid {
			t.Fatalf("invalid default declaration %+v", s)
		}
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"24.04", "22.04", 1}, {"12", "12.0", 0}, {"v1.10.0", "1.9.9", 1}, {"41", "42", -1}, {"1.2.0-rc1", "1.2.0", 0}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d", c.a, c.b, got)
		}
	}
}

func TestReleaseSums(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := strings.Repeat("ab", 32)
	sums := sum + "  limdm-agent_0.8.0_linux_amd64.deb\n" + strings.Repeat("cd", 32) + "  limdm-server_0.8.0_linux_amd64.deb\n"
	sig := SignSums(priv, sums)
	if VerifySums(pub, sums, sig) != nil {
		t.Fatal("valid signature rejected")
	}
	if VerifySums(pub, sums+"x", sig) == nil || VerifySums(pub, sums, "") == nil {
		t.Fatal("tampered or unsigned sums accepted")
	}
	if got, err := SumsEntry(sums, PackageName("0.8.0", "amd64", "deb")); err != nil || got != sum {
		t.Fatalf("entry: %q %v", got, err)
	}
	if _, err := SumsEntry(sums, "limdm-agent_0.8.0_linux_arm64.rpm"); err == nil {
		t.Fatal("missing entry found")
	}
	if !PackageRe.MatchString("limdm-agent_0.8.0_linux_arm64.rpm") || PackageRe.MatchString("../x.deb") {
		t.Fatal("package name pattern")
	}
}

func TestFilesRejectsDangerousTargets(t *testing.T) {
	for name, payload := range map[string]string{
		"setuid":        `{"files":[{"path":"/usr/local/bin/x","content":"x","mode":"4755"}]}`,
		"user home":     `{"files":[{"path":"/home/anna/.bashrc","content":"x"}]}`,
		"world tmp":     `{"files":[{"path":"/tmp/x","content":"x"}]}`,
		"relative path": `{"files":[{"path":"etc/x","content":"x"}]}`,
	} {
		if (LibraryItem{Name: "x", Type: TypeFiles, Payload: json.RawMessage(payload)}).Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (LibraryItem{Name: "x", Type: TypeFiles, Payload: json.RawMessage(`{"files":[{"path":"/etc/issue","content":"x","mode":"0644"}]}`)}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPrivacyDefault(t *testing.T) {
	p, _ := Compose(nil)
	if !p.Privacy.NetworkInfo || !p.Privacy.LoggedInUsers {
		t.Fatal("without a privacy declaration everything is collected")
	}
	p, _ = Compose([]Declaration{{Identifier: "p", Type: TypePrivacy, Payload: []byte(`{"network_info":false}`)}})
	if p.Privacy.NetworkInfo || !p.Privacy.LoggedInUsers {
		t.Fatalf("declaration switches only network_info off: %+v", p.Privacy)
	}
}

func TestDiskEncryptionExclude(t *testing.T) {
	d := &DiskEncryption{Exclude: []string{"/boot"}}
	for m, want := range map[string]bool{"/boot": true, "/boot/efi": true, "/bootx": false, "/": false, "/home": false} {
		if d.Excluded(m) != want {
			t.Errorf("%s: %v", m, !want)
		}
	}
	for payload, ok := range map[string]bool{
		`{"escrow":true,"rotate_after_view":false,"require_all":true,"exclude":["/boot"]}`: true,
		`{"escrow":true,"rotate_after_view":false,"exclude":["/"]}`:                        false,
		`{"escrow":true,"rotate_after_view":false,"exclude":["boot"]}`:                     false,
		`{"escrow":true,"rotate_after_view":false,"exclude":["/boot/../etc"]}`:             false,
	} {
		_, st := Compose([]Declaration{{Identifier: "d", Type: TypeDiskEncryption, Payload: []byte(payload)}})
		if st[0].Valid != ok {
			t.Errorf("%s: valid=%v", payload, st[0].Valid)
		}
	}
}

func TestFlatpakScope(t *testing.T) {
	for payload, ok := range map[string]bool{
		`{"remotes":[{"name":"flathub","url":"https://dl.flathub.org/repo/flathub.flatpakrepo","scope":"user"}],"install":[],"remove":[]}`:  true,
		`{"remotes":[{"name":"flathub","url":"https://dl.flathub.org/repo/flathub.flatpakrepo","scope":"other"}],"install":[],"remove":[]}`: false,
		`{"remotes":[{"name":"flathub","url":"https://dl.flathub.org/repo/","disabled":true}],"install":[],"remove":[]}`:                    true,
	} {
		_, st := Compose([]Declaration{{Identifier: "f", Type: TypeFlatpak, Payload: []byte(payload)}})
		if st[0].Valid != ok {
			t.Errorf("%s: valid=%v", payload, st[0].Valid)
		}
	}
}

func TestCatalogRemotes(t *testing.T) {
	for r, ok := range map[CatalogRemote]bool{
		{Name: "flathub", URL: "https://dl.flathub.org/repo/flathub.flatpakrepo", State: "allowed"}: true,
		{Name: "fedora", URL: "oci+https://registry.fedoraproject.org", State: "blocked"}:           true,
		{Name: "evil", URL: "http://plain.example/repo", State: "allowed"}:                          false,
		{Name: "bad name", URL: "https://x.example", State: "allowed"}:                              false,
		{Name: "x", URL: "https://x.example", State: "maybe"}:                                       false,
		{Name: "x", URL: "https://x.example/a b", State: "allowed"}:                                 false,
	} {
		if (r.Validate() == nil) != ok {
			t.Errorf("%+v: valid=%v", r, !ok)
		}
	}
	c := Catalog{Apps: []CatalogApp{
		{Sources: []AppSource{{Kind: "flatpak", Flatpak: "org.mozilla.firefox"}}},
		{Sources: []AppSource{{Kind: "flatpak", Flatpak: "org.fedoraproject.Thing", Remote: "fedora"}}},
	}}
	if f := c.Flatpaks("flathub"); len(f) != 1 || f[0] != "org.mozilla.firefox" {
		t.Fatalf("flathub: %v", f)
	}
	if f := c.Flatpaks("fedora"); len(f) != 1 || f[0] != "org.fedoraproject.Thing" {
		t.Fatalf("fedora: %v", f)
	}
}

func TestUserAndSoftwareCommands(t *testing.T) {
	ok := UserCommand{Username: "anna", FullName: "Anna Muster", Password: "correct horse battery"}
	if err := ok.Validate("user_create"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []UserCommand{{Username: "root", Password: "correct horse battery"}, {Username: "Anna", Password: "correct horse battery"},
		{Username: "anna", Password: "short"}, {Username: "anna", FullName: "a:b", Password: "correct horse battery"}} {
		if bad.Validate("user_create") == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (UserCommand{Username: "anna"}).Validate("user_admin") != nil {
		t.Fatal("admin change needs no password")
	}
	for _, r := range []SoftwareRemove{{Kind: "package", Name: "vlc"}, {Kind: "snap", Name: "firefox"}, {Kind: "flatpak", Name: "org.gimp.GIMP", Installation: "system"},
		{Kind: "flatpak", Name: "org.gimp.GIMP", Installation: "anna"}, {Kind: "appimage", Name: "/home/anna/Applications/Obsidian.AppImage"}} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range []SoftwareRemove{{Kind: "package", Name: "-rf /"}, {Kind: "appimage", Name: "/etc/passwd"}, {Kind: "appimage", Name: "/home/anna/../../etc/x.AppImage"},
		{Kind: "flatpak", Name: "org.gimp.GIMP", Installation: "../root"}, {Kind: "rpm", Name: "vlc"}} {
		if r.Validate() == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestLoginCanBeSwitchedOff(t *testing.T) {
	on := Declaration{Identifier: "sso", Type: TypeLogin, Payload: []byte(`{"issuer":"https://accounts.google.com","client_id":"x","local_password":true,"reverify_hours":24,"offline_grace_hours":360}`)}
	off := Declaration{Identifier: "servers", Type: TypeLogin, Payload: []byte(`{"enabled":false}`)}
	p, st := Compose([]Declaration{on})
	if !p.Login.Enabled || p.Login.Grace() != 360*time.Hour || !st[0].Valid {
		t.Fatalf("on: %+v %+v", p.Login, st)
	}
	p, st = Compose([]Declaration{on, off})
	if p.Login.Enabled || !st[1].Valid {
		t.Fatalf("off must win: %+v %+v", p.Login, st)
	}
	if _, st := Compose([]Declaration{{Identifier: "bad", Type: TypeLogin, Payload: []byte(`{"issuer":"https://a","client_id":"x","offline_grace_hours":9999}`)}}); st[0].Valid {
		t.Fatal("grace above 720 hours accepted")
	}
}
