package agent

import (
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestPasswdShell(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nsvc:x:1500:1500::/home/svc:/usr/bin/zsh\n"
	if passwdShell(passwd, "svc") != "/usr/bin/zsh" || passwdShell(passwd, "nobody") != "" {
		t.Fatal("passwd shell")
	}
}

func TestLocalUsersValidation(t *testing.T) {
	item := func(p string) api.LibraryItem {
		return api.LibraryItem{Name: "x", Type: api.TypeLocalUsers, Payload: []byte(p)}
	}
	if err := item(`{"users":[{"name":"svc-backup","uid":1500,"groups":["backup"],"shell":"/bin/sh","locked":true,"authorized_keys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq backup@example.com"]}]}`).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"root":        `{"users":[{"name":"root"}]}`,
		"uid 0 range": `{"users":[{"name":"svc","uid":500}]}`,
		"twice":       `{"users":[{"name":"svc"},{"name":"svc"}]}`,
		"key options": `{"users":[{"name":"svc","authorized_keys":["command=\"/bin/sh\" ssh-ed25519 AAAA x"]}]}`,
		"key newline": `{"users":[{"name":"svc","authorized_keys":["ssh-ed25519 AAAA x\nssh-rsa BBBB y"]}]}`,
		"shell":       `{"users":[{"name":"svc","shell":"bash"}]}`,
	} {
		if item(p).Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
