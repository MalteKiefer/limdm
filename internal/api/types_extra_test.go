package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func caPEM(t *testing.T, isCA bool) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "c"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestExtraTypesValidate(t *testing.T) {
	ca, _ := json.Marshal(caPEM(t, true))
	leaf, _ := json.Marshal(caPEM(t, false))
	good := map[string]string{
		TypeRepositories:  `{"repositories":[{"name":"vendor","family":"debian","url":"https://r.example/apt","suites":"stable","components":"main","key":"-----BEGIN PGP PUBLIC KEY BLOCK-----\nx"}]}`,
		TypeCertificates:  `{"certificates":[{"name":"corp-root","pem":` + string(ca) + `}]}`,
		TypeSysctl:        `{"settings":{"vm.swappiness":"10","net.ipv4.conf.all.rp_filter":"1"}}`,
		TypeKernelModules: `{"block":["firewire_core"]}`,
		TypeSSH:           `{"options":{"AllowGroups":"ssh-users","Ciphers":"chacha20-poly1305@openssh.com"}}`,
		TypeBanner:        `{"issue":"Authorized use only.\nAll access is logged.","motd":"Managed by IT."}`,
		TypeDNS:           `{"servers":["10.0.0.53","2001:db8::53"],"domains":["corp.example.com"],"dnssec":true}`,
		TypeNTP:           `{"servers":["ntp1.example.com","192.0.2.1"]}`,
		TypeProxy:         `{"http":"http://proxy:3128","https":"http://proxy:3128","no_proxy":"localhost,.example.com"}`,
		TypeFlatpak:       `{"remotes":[{"name":"flathub","url":"https://dl.flathub.org/repo/flathub.flatpakrepo"}],"install":["org.mozilla.firefox"],"remove":[]}`,
		TypeScripts:       `{"scripts":[{"name":"cleanup","interval_hours":24,"body":"#!/bin/sh\ntrue"}]}`,
	}
	for typ, payload := range good {
		if err := (LibraryItem{Name: "x", Type: typ, Payload: json.RawMessage(payload)}).Validate(); err != nil {
			t.Errorf("%s rejected: %v", typ, err)
		}
		if _, ok := Types[typ]; !ok {
			t.Errorf("%s has no example", typ)
		}
	}
	bad := map[string]string{
		"unsigned repository":   `{"repositories":[{"name":"vendor","family":"debian","url":"https://r/apt","suites":"stable","key":""}]}`,
		"http repository":       `{"repositories":[{"name":"vendor","family":"debian","url":"http://r/apt","suites":"s","key":"-----BEGIN PGP PUBLIC KEY BLOCK-----"}]}`,
		"leaf certificate":      `{"certificates":[{"name":"leaf","pem":` + string(leaf) + `}]}`,
		"sysctl injection":      `{"settings":{"vm.swappiness":"10\nkernel.modules_disabled = 1"}}`,
		"weakening ssh option":  `{"options":{"PermitRootLogin":"yes"}}`,
		"ssh value injection":   `{"options":{"Banner":"/etc/issue\nPermitRootLogin yes"}}`,
		"dns hostname":          `{"servers":["dns.example.com"]}`,
		"proxy quote injection": `{"http":"http://p:3128\" ; rm -rf /"}`,
		"flatpak option":        `{"install":["--user"]}`,
		"script interval":       `{"scripts":[{"name":"x","interval_hours":0,"body":"true"}]}`,
	}
	types := map[string]string{"unsigned repository": TypeRepositories, "http repository": TypeRepositories, "leaf certificate": TypeCertificates,
		"sysctl injection": TypeSysctl, "weakening ssh option": TypeSSH, "ssh value injection": TypeSSH, "dns hostname": TypeDNS,
		"proxy quote injection": TypeProxy, "flatpak option": TypeFlatpak, "script interval": TypeScripts}
	for name, payload := range bad {
		if (LibraryItem{Name: "x", Type: types[name], Payload: json.RawMessage(payload)}).Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestExtraMerge(t *testing.T) {
	decls, err := Merge([]LibraryItem{
		item(1, TypeSysctl, `{"settings":{"vm.swappiness":"10","a.b":"1"}}`),
		item(2, TypeSysctl, `{"settings":{"vm.swappiness":"5"}}`),
		item(3, TypeKernelModules, `{"block":["a"]}`),
		item(4, TypeKernelModules, `{"block":["b","a"]}`),
		item(5, TypeScripts, `{"scripts":[{"name":"x","interval_hours":1,"body":"old"}]}`),
		item(6, TypeScripts, `{"scripts":[{"name":"x","interval_hours":2,"body":"new"},{"name":"y","interval_hours":1,"body":"y"}]}`),
		item(7, TypeBanner, `{"issue":"one","motd":""}`),
		item(8, TypeBanner, `{"issue":"two","motd":""}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	p, st := Compose(decls)
	for _, s := range st {
		if !s.Valid {
			t.Fatalf("invalid merged declaration %+v", s)
		}
	}
	if p.Extra.Sysctl["vm.swappiness"] != "5" || p.Extra.Sysctl["a.b"] != "1" {
		t.Fatalf("sysctl: %v", p.Extra.Sysctl)
	}
	if !slices.Equal(p.Extra.KernelModules, []string{"a", "b"}) {
		t.Fatalf("modules: %v", p.Extra.KernelModules)
	}
	if len(p.Extra.Scripts) != 2 || p.Extra.Scripts[0].Body != "new" || p.Extra.Banner.Issue != "two" {
		t.Fatalf("scripts by name / banner last wins: %+v %+v", p.Extra.Scripts, p.Extra.Banner)
	}
	if !strings.HasPrefix(decls[0].Type, "com.limdm.") {
		t.Fatal("declaration type")
	}
}
