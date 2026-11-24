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

func TestBlueprintValidate(t *testing.T) {
	if err := DefaultBlueprint().Validate(); err != nil {
		t.Fatalf("default blueprint invalid: %v", err)
	}
	bad := []Declaration{
		decl("p", TypePackages, `{"install":["-o Dpkg::Pre-Invoke=evil"]}`), // option injection
		decl("f", TypeFiles, `{"files":[{"path":"/etc/../root/x","content":""}]}`),
		decl("u", TypeUpdates, `{"mode":"sometimes"}`),
		decl("x", "com.limdm.unknown", `{}`),
		decl("c", TypeCompliance, `{"level":1,"typo":true}`), // unknown field
		decl("w", TypeFirewall, `{"enforce":true,"allow":["22/tcp; rm -rf /"]}`),
	}
	for _, d := range bad {
		if err := (Blueprint{Name: "t", Declarations: []Declaration{d}}).Validate(); err == nil {
			t.Errorf("%s accepted", d.Identifier)
		}
	}
}

func TestEffectivePriority(t *testing.T) {
	strict := Blueprint{Name: "strict", Priority: 10, Declarations: []Declaration{decl("c2", TypeCompliance, `{"level":2,"remediate":true}`)}}
	eff := Effective([]Blueprint{strict, DefaultBlueprint()})
	p, st := Compose(eff)
	if p.Compliance.Level != 2 {
		t.Fatalf("higher priority blueprint must win, got level %d", p.Compliance.Level)
	}
	if p.Updates.Mode != "security" || p.ScreenLockSeconds != 300 {
		t.Fatal("default declarations of other types must still apply")
	}
	for _, s := range st {
		if !s.Valid || s.ServerToken == "" {
			t.Fatalf("status %+v", s)
		}
	}
	if DeclarationsToken(eff) == DeclarationsToken(Effective([]Blueprint{DefaultBlueprint()})) {
		t.Fatal("token must change when declarations change")
	}
}

func TestComposeSkipsInvalid(t *testing.T) {
	p, st := Compose([]Declaration{decl("u", TypeUpdates, `{"mode":"bad"}`), decl("s", TypeScreenLock, `{"idle_seconds":120}`)})
	if p.Updates.Mode != "" || st[0].Valid || p.ScreenLockSeconds != 120 || !st[1].Valid {
		t.Fatalf("got %+v %+v", p, st)
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
