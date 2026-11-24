package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
