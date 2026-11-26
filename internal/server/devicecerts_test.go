package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

func testCSR(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker chosen"},
		DNSNames: []string{"evil.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestSignNetworkCSR(t *testing.T) {
	dir := t.TempDir()
	devCA, err := loadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	netCA, err := loadOrCreateNetworkCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, row, err := netCA.signNetworkCSR(testCSR(t), "dev1", "pc-1", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "dev1" || len(c.DNSNames) != 1 || c.DNSNames[0] != "pc-1" || c.EmailAddresses[0] != "alice@example.com" ||
		c.URIs[0].String() != "urn:limdm:device:dev1" || row.Serial != c.SerialNumber.Text(16) {
		t.Fatalf("template not applied: %v %v %v %v", c.Subject, c.DNSNames, c.EmailAddresses, c.URIs)
	}
	if time.Until(c.NotAfter) > networkCertTTL || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("validity or key usage")
	}
	opts := x509.VerifyOptions{Roots: netCA.pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := c.Verify(opts); err != nil {
		t.Fatalf("does not chain to the network CA: %v", err)
	}
	opts.Roots = devCA.pool()
	if _, err := c.Verify(opts); err == nil {
		t.Fatal("a network certificate must not pass as a device mTLS certificate")
	}
	if _, _, err := netCA.signNetworkCSR("garbage", "dev1", "", ""); err == nil {
		t.Fatal("garbage CSR signed")
	}
	// invalid host names and addresses stay out of the certificate
	certPEM, _, _ = netCA.signNetworkCSR(testCSR(t), "dev1", "bad host", "not an email")
	b, _ = pem.Decode([]byte(certPEM))
	c, _ = x509.ParseCertificate(b.Bytes)
	if len(c.DNSNames)+len(c.EmailAddresses) != 0 {
		t.Fatalf("invalid SANs taken: %v %v", c.DNSNames, c.EmailAddresses)
	}
}

func TestNetworkCertsIssueRevokeCRL(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	netCA, err := loadOrCreateNetworkCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, cmdKey: testCmdKey, netCA: netCA, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: Config{PublicURL: "https://mdm.test", SessionKey: bytes.Repeat([]byte{3}, 32)}}
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, users) VALUES ('d1','s',now(),'pc1','[{"username":"bob","email":"bob@example.com"}]')`); err != nil {
		t.Fatal(err)
	}
	issue := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(api.RenewRequest{CSR: testCSR(t)})
		r := httptest.NewRequest("POST", "/api/v1/network-cert", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), deviceKey, "d1"))
		w := httptest.NewRecorder()
		s.networkCert(w, r)
		return w
	}
	if w := issue(); w.Code != http.StatusForbidden {
		t.Fatalf("issued without an EAP-TLS profile: %d", w.Code)
	}
	payload := `{"profiles":[{"name":"lan","type":"ethernet","security":"802.1x","eap":{"method":"tls","ca_cert":"corp","server_domain":"radius.example.com"}}]}`
	var itemID int64
	if err := db.QueryRow(ctx, `INSERT INTO library_items(name, type, payload, signature) VALUES ('lan', $1, $2, $3) RETURNING id`,
		api.TypeNetwork, payload, signItem("lan", api.TypeNetwork, []byte(payload))).Scan(&itemID); err != nil {
		t.Fatal(err)
	}
	tree, _ := json.Marshal([]api.Node{{Kind: "assign", Items: []int64{itemID}}})
	if _, err := db.Exec(ctx, `UPDATE blueprints SET tree=$1 WHERE name='default'`, string(tree)); err != nil {
		t.Fatal(err)
	}
	w := issue()
	if w.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", w.Code, w.Body)
	}
	var resp api.EnrollResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	b, _ := pem.Decode([]byte(resp.Cert))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil || cert.EmailAddresses[0] != "bob@example.com" {
		t.Fatalf("certificate: %v %v", err, cert)
	}
	crlOf := func(t *testing.T) *x509.RevocationList {
		t.Helper()
		raw, err := s.networkCRL(ctx)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(raw)
		crl, err := x509.ParseRevocationList(blk.Bytes)
		if err != nil || crl.CheckSignatureFrom(netCA.cert) != nil {
			t.Fatalf("crl: %v", err)
		}
		return crl
	}
	if n := len(crlOf(t).RevokedCertificateEntries); n != 0 {
		t.Fatalf("fresh CRL lists %d", n)
	}
	tx, _ := db.Begin(ctx)
	if err := revokeNetworkCerts(ctx, tx, "d1", "retired"); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	crl := crlOf(t)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("revoked certificate missing from the CRL: %+v", crl.RevokedCertificateEntries)
	}
	// the RADIUS fetch: bearer token only after it was created
	get := func(tok string) int {
		r := httptest.NewRequest("GET", "/network/crl.pem", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.networkCRLDownload(w, r)
		return w.Code
	}
	if code := get("lmc_guess"); code != http.StatusUnauthorized {
		t.Fatalf("CRL without a token: %d", code)
	}
	db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('network_crl', $1)`, `{"token_sha256":"`+hex.EncodeToString(sha("lmc_right"))+`"}`)
	if code := get("lmc_right"); code != http.StatusOK {
		t.Fatalf("CRL with the token: %d", code)
	}
	// the console page renders the issued certificate
	pw := httptest.NewRecorder()
	certs, err := s.networkCerts(ctx, "")
	if err != nil || len(certs) != 1 || certs[0].State() != "revoked" || certs[0].Hostname != "pc1" {
		t.Fatalf("list: %v %+v", err, certs)
	}
	if err := pages["en/iso"]["network"].Execute(pw, map[string]any{"Certs": certs, "Sess": session{Role: "admin"}, "TokenSet": true,
		"CRLURL": "https://mdm.test/network/crl.pem", "CANotAfter": time.Now(), "Brand": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pw.Body.String(), certs[0].Serial) {
		t.Fatal("certificate missing on the page")
	}
}
