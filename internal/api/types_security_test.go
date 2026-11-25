package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityTypes(t *testing.T) {
	for typ, ex := range map[string]string{TypeDiskEncryption: Types[TypeDiskEncryption], TypePolkit: Types[TypePolkit], TypeSudo: Types[TypeSudo]} {
		if err := (LibraryItem{Name: "x", Type: typ, Payload: json.RawMessage(ex)}).Validate(); err != nil {
			t.Errorf("%s example rejected: %v", typ, err)
		}
	}
	// the boot loader example carries a plain password, which only the console turns into a hash
	if (LibraryItem{Name: "x", Type: TypeBootloader, Payload: json.RawMessage(Types[TypeBootloader])}).Validate() == nil {
		t.Error("plain boot loader password accepted")
	}
	p, err := PrepareBootloader(json.RawMessage(`{"superuser":"bootadmin","password":"correct horse battery","unrestricted":true}`))
	if err != nil || strings.Contains(string(p), "correct horse") {
		t.Fatalf("prepare: %v %s", err, p)
	}
	if err := (LibraryItem{Name: "x", Type: TypeBootloader, Payload: p}).Validate(); err != nil {
		t.Fatalf("hashed boot loader rejected: %v", err)
	}
	if _, err := PrepareBootloader(json.RawMessage(`{"superuser":"b","password":"short"}`)); err == nil {
		t.Error("short password accepted")
	}
	bad := map[string][2]string{
		"pkexec":           {TypePolkit, `{"rules":[{"name":"x","actions":["org.freedesktop.policykit.exec"],"groups":[],"result":"yes","local_active_only":true}]}`},
		"js injection":     {TypePolkit, `{"rules":[{"name":"x","actions":["org.a.b\") || true || (\""],"groups":[],"result":"yes","local_active_only":false}]}`},
		"broad namespace":  {TypePolkit, `{"rules":[{"name":"x","actions":["org.*"],"groups":[],"result":"yes","local_active_only":false}]}`},
		"bad result":       {TypePolkit, `{"rules":[{"name":"x","actions":["org.a.b"],"groups":[],"result":"root","local_active_only":false}]}`},
		"sudo comma":       {TypeSudo, `{"rules":[{"name":"x","principals":["%dev"],"run_as":"","commands":["/bin/ls, /bin/sh"],"nopasswd":false}]}`},
		"sudo wildcard":    {TypeSudo, `{"rules":[{"name":"x","principals":["%dev"],"run_as":"","commands":["/bin/cat *"],"nopasswd":false}]}`},
		"sudo relative":    {TypeSudo, `{"rules":[{"name":"x","principals":["%dev"],"run_as":"","commands":["sh"],"nopasswd":false}]}`},
		"sudo all users":   {TypeSudo, `{"rules":[{"name":"x","principals":["ALL"],"run_as":"","commands":["ALL"],"nopasswd":true}]}`},
		"sudo dotted name": {TypeSudo, `{"rules":[{"name":"a.b","principals":["%dev"],"run_as":"","commands":["ALL"],"nopasswd":false}]}`},
		"sudo newline":     {TypeSudo, `{"rules":[{"name":"x","principals":["%dev"],"run_as":"root\nALL ALL=(ALL) NOPASSWD: ALL","commands":["ALL"],"nopasswd":false}]}`},
		"sudo timeout":     {TypeSudo, `{"rules":[],"timestamp_timeout":999}`},
		"grub bad hash":    {TypeBootloader, `{"superuser":"b","password_pbkdf2":"x\nset superusers=\"\"","unrestricted":true}`},
	}
	for name, c := range bad {
		if (LibraryItem{Name: "x", Type: c[0], Payload: json.RawMessage(c[1])}).Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSecurityMerge(t *testing.T) {
	decls, err := Merge([]LibraryItem{
		{Name: "a", Type: TypeSudo, Payload: json.RawMessage(`{"rules":[{"name":"dev","principals":["%dev"],"run_as":"","commands":["ALL"],"nopasswd":false}],"timestamp_timeout":5}`)},
		{Name: "b", Type: TypeSudo, Payload: json.RawMessage(`{"rules":[{"name":"ops","principals":["%ops"],"run_as":"","commands":["ALL"],"nopasswd":false}]}`)},
		{Name: "c", Type: TypePolkit, Payload: json.RawMessage(`{"rules":[{"name":"n","actions":["org.a.b"],"groups":[],"result":"no","local_active_only":false}]}`)},
		{Name: "d", Type: TypePolkit, Payload: json.RawMessage(`{"rules":[{"name":"n","actions":["org.a.b"],"groups":[],"result":"yes","local_active_only":false}]}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, st := Compose(decls)
	for _, x := range st {
		if !x.Valid {
			t.Fatalf("%s invalid: %v", x.Identifier, x.Reasons)
		}
	}
	if s := p.Extra.Sudo; s == nil || len(s.Rules) != 2 || s.TimestampTimeout == nil || *s.TimestampTimeout != 5 {
		t.Fatalf("sudo merge: %+v", p.Extra.Sudo)
	}
	if len(p.Extra.Polkit) != 1 || p.Extra.Polkit[0].Result != "yes" {
		t.Fatalf("polkit merge: %+v", p.Extra.Polkit)
	}
}

func TestRecoveryKey(t *testing.T) {
	k := RecoveryKey{UUID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", Device: "/dev/nvme0n1p3", Key: NewRecoveryKey()}
	if !k.Valid() || len(k.Key) != 71 {
		t.Fatalf("generated key invalid: %q", k.Key)
	}
	if NewRecoveryKey() == k.Key {
		t.Fatal("keys repeat")
	}
	k.UUID = "../../etc"
	if k.Valid() {
		t.Fatal("bad uuid accepted")
	}
}
