package agent

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestNoProxyMatch(t *testing.T) {
	list := "localhost, .corp.example.com,example.org:8443,10.0.0.0/8,192.168.1.5"
	for host, want := range map[string]bool{
		"a.corp.example.com": true, "corp.example.com": true, "example.org": true, "x.example.org": true,
		"10.1.2.3": true, "192.168.1.5": true, "192.168.1.6": false, "mdm.example.net": false, "notexample.org": false,
	} {
		if got := noProxyMatch(host, list); got != want {
			t.Errorf("%s: %v, want %v", host, got, want)
		}
	}
	if !noProxyMatch("anything", "*") {
		t.Error("* matches every host")
	}
}

func TestAgentProxyFollowsDeclaration(t *testing.T) {
	t.Cleanup(func() { declaredProxy.Store(nil) })
	declaredProxy.Store(&api.Proxy{HTTPS: "http://proxy:3128", NoProxy: ".internal"})
	req := func(u string) *http.Request { r, _ := http.NewRequest(http.MethodGet, u, nil); return r }
	if u, _ := agentProxy(req("https://mdm.example.com:8444/api")); u == nil || u.Host != "proxy:3128" {
		t.Fatalf("https request must use the declared proxy, got %v", u)
	}
	if u, _ := agentProxy(req("https://mdm.internal/")); u != nil {
		t.Fatalf("no_proxy host must go direct, got %v", u)
	}
	declaredProxy.Store(&api.Proxy{}) // declaration removed
	if u, _ := agentProxy(req("https://mdm.example.com/")); u != nil {
		t.Fatalf("a removed declaration must not keep the proxy, got %v", u)
	}
}

func TestSyncINIKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dnf.conf")
	if err := os.WriteFile(p, []byte("[main]\ngpgcheck=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	owned, err := syncINIKey(p, "main", "proxy", "http://proxy:3128", "")
	if b, _ := os.ReadFile(p); err != nil || owned != "http://proxy:3128" || !strings.Contains(string(b), "proxy=http://proxy:3128") {
		t.Fatalf("set: %v %q\n%s", err, owned, b)
	}
	owned, err = syncINIKey(p, "main", "proxy", "", owned)
	if b, _ := os.ReadFile(p); err != nil || owned != "" || strings.Contains(string(b), "proxy") || !strings.Contains(string(b), "gpgcheck=1") {
		t.Fatalf("remove: %v %q\n%s", err, owned, b)
	}
	// a proxy set by hand is never removed
	os.WriteFile(p, []byte("[main]\nproxy=http://own:8080\n"), 0o644)
	if owned, _ = syncINIKey(p, "main", "proxy", "", "http://proxy:3128"); owned != "" {
		t.Fatalf("owned %q", owned)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "proxy=http://own:8080") {
		t.Fatalf("hand made proxy removed:\n%s", b)
	}
}

func TestSyncSysconfigProxy(t *testing.T) {
	orig := "## Path: Network/Proxy\nPROXY_ENABLED=\"no\"\nHTTP_PROXY=\"\"\nHTTPS_PROXY=\"\"\nNO_PROXY=\"localhost, 127.0.0.1\"\n"
	s, owned := syncSysconfig(orig, suseProxyValues(&api.Proxy{HTTP: "http://p:3128", HTTPS: "http://p:3128", NoProxy: ".corp"}), nil)
	for _, want := range []string{`PROXY_ENABLED="yes"`, `HTTP_PROXY="http://p:3128"`, `HTTPS_PROXY="http://p:3128"`, `NO_PROXY=".corp"`, "## Path"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	// a second apply keeps the values found before the first one
	s, owned = syncSysconfig(s, suseProxyValues(&api.Proxy{HTTPS: "http://q:8080"}), owned)
	if owned.Orig["NO_PROXY"] != "localhost, 127.0.0.1" || !strings.Contains(s, `HTTP_PROXY=""`) {
		t.Fatalf("second apply: %+v\n%s", owned, s)
	}
	// removal restores the original, except a key changed by hand since
	s = setSysconfigValue(s, "NO_PROXY", "hand.example")
	s, owned = syncSysconfig(s, nil, owned)
	if owned != nil || !strings.Contains(s, `PROXY_ENABLED="no"`) || !strings.Contains(s, `HTTPS_PROXY=""`) || !strings.Contains(s, `NO_PROXY="hand.example"`) {
		t.Fatalf("cleanup: %+v\n%s", owned, s)
	}
}
