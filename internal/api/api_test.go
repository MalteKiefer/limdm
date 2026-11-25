package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
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

func TestReleaseSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := Release{Version: "1.2.0", Arch: "amd64", File: "f", SHA256: "abc"}
	r.Sig = hex.EncodeToString(ed25519.Sign(priv, r.SignedBytes()))
	if r.Verify(pub) != nil {
		t.Fatal("valid signature rejected")
	}
	r.SHA256 = "abd"
	if r.Verify(pub) == nil {
		t.Fatal("tampered release accepted")
	}
}
