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

func TestSyncDNFConf(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dnf.conf")
	if err := os.WriteFile(p, []byte("[main]\ngpgcheck=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	owned, err := syncDNFConf(p, "http://proxy:3128", "")
	if b, _ := os.ReadFile(p); err != nil || owned != "http://proxy:3128" || !strings.Contains(string(b), "proxy=http://proxy:3128") {
		t.Fatalf("set: %v %q\n%s", err, owned, b)
	}
	owned, err = syncDNFConf(p, "", owned)
	if b, _ := os.ReadFile(p); err != nil || owned != "" || strings.Contains(string(b), "proxy") || !strings.Contains(string(b), "gpgcheck=1") {
		t.Fatalf("remove: %v %q\n%s", err, owned, b)
	}
	// a proxy set by hand is never removed
	os.WriteFile(p, []byte("[main]\nproxy=http://own:8080\n"), 0o644) //nolint:errcheck,gosec // test file
	if owned, _ = syncDNFConf(p, "", "http://proxy:3128"); owned != "" {
		t.Fatalf("owned %q", owned)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "proxy=http://own:8080") {
		t.Fatalf("hand made proxy removed:\n%s", b)
	}
}
