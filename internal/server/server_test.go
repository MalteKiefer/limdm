package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"image"
	"image/png"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestAuditHashChain(t *testing.T) {
	at := time.Unix(1700000000, 0)
	h1 := auditHash(make([]byte, 32), at, "admin@x", "policy.save", "p", "doc")
	h2 := auditHash(h1, at, "admin@x", "login", "", "admin")
	if bytes.Equal(auditHash(make([]byte, 32), at, "admin@x", "policy.save", "p", "doc!"), h1) {
		t.Fatal("detail change not detected")
	}
	if bytes.Equal(auditHash(make([]byte, 32), at, "admin@xp", "olicy.save", "p", "doc"), h1) {
		t.Fatal("field boundaries must be part of the hash")
	}
	if bytes.Equal(auditHash(h2, at, "a", "b", "c", "d"), auditHash(h1, at, "a", "b", "c", "d")) {
		t.Fatal("prev hash must be chained")
	}
}

func TestCSVSafe(t *testing.T) {
	if csvSafe("=cmd|' /C calc'!A0") != "'=cmd|' /C calc'!A0" || csvSafe("host1") != "host1" {
		t.Fatal("formula injection not neutralised")
	}
}

func TestParseUsers(t *testing.T) {
	u, err := parseUsers("mm max@firma.de admin\n\nanna anna@firma.de\n")
	if err != nil || len(u) != 2 || !u[0].Admin || u[1].Admin {
		t.Fatalf("%v %v", u, err)
	}
	for _, bad := range []string{"root r@x.de", "mm m@x.de superuser", "Bad m@x.de", "a a@x.de\na b@x.de"} {
		if _, err := parseUsers(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
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
	leaf, _ := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
	if leaf.VerifyHostname("mdm.example.com") != nil || leaf.VerifyHostname("192.0.2.10") != nil {
		t.Fatalf("names: %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
}

func TestLineChartEscapes(t *testing.T) {
	now := time.Now()
	out := string(lineChart(`<script>`, "%", 100, now.Add(-time.Hour), now, []series{{`"><x`, "ok", []point{{now.Add(-time.Hour), 10}, {now, 250}}}}))
	if strings.Contains(out, "<script>") || strings.Contains(out, `"><x`) {
		t.Fatalf("unescaped label: %s", out)
	}
	if !strings.Contains(out, ">250%<") { // axis grows to the max value
		t.Fatalf("axis not scaled: %s", out)
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

func TestAddUploadedCerts(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	one := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("pem_file", "Corp Root CA.pem")
	fw.Write(append(append([]byte{}, one...), one...)) // a bundle of two
	mw.Close()
	r := httptest.NewRequest("POST", "/library", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	out, err := addUploadedCerts(r, json.RawMessage(`{"certificates":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Certificates []api.Certificate }
	json.Unmarshal(out, &v)
	if len(v.Certificates) != 2 || v.Certificates[0].Name != "corp-root-ca" || v.Certificates[1].Name != "corp-root-ca-2" {
		t.Fatalf("uploaded: %+v", v.Certificates)
	}
	d := api.Declaration{Identifier: "c", Type: api.TypeCertificates, Payload: out}
	if _, st := api.Compose([]api.Declaration{d}); !st[0].Valid {
		t.Fatalf("uploaded certificates must validate: %v", st[0].Reasons)
	}
}
