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
	"slices"
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
	certPEM, row, err := netCA.signNetworkCSR(testCSR(t), "dev1", netCertDNSName("dev1", "devices.example.com"), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(certPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "dev1" || len(c.DNSNames) != 1 || c.DNSNames[0] != "dev1.devices.example.com" || c.EmailAddresses[0] != "alice@example.com" ||
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
	if netCertDNSName("dev1", "") != "" {
		t.Fatal("no domain: no DNS SAN")
	}
	for d, ok := range map[string]bool{"": true, "devices.example.com": true, "Devices.example.com": false, "a..b": false, "-a.b": false, "a b": false, strings.Repeat("a", 64) + ".com": false} {
		if validCertDomain(d) != ok {
			t.Fatalf("validCertDomain(%q) != %v", d, ok)
		}
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
	s.rt.Store(&runtimeState{set: Settings{NetCertDomain: "dev.example.com"}})
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, users) VALUES ('d1','s',now(),'pc1.evil.example','[{"username":"bob","email":"bob@example.com"}]')`); err != nil {
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
	issued := func() *x509.Certificate {
		t.Helper()
		w := issue()
		if w.Code != http.StatusOK {
			t.Fatalf("issue: %d %s", w.Code, w.Body)
		}
		var resp api.EnrollResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		b, _ := pem.Decode([]byte(resp.Cert))
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	// neither the reported host name nor a reported user reaches the certificate
	if c := issued(); len(c.EmailAddresses) != 0 || len(c.DNSNames) != 1 || c.DNSNames[0] != "d1.dev.example.com" {
		t.Fatalf("SANs from device claims: %v %v", c.DNSNames, c.EmailAddresses)
	}
	if _, err := db.Exec(ctx, `INSERT INTO dir_users(id, source, user_name, email) VALUES (7, 'scim', 'bob', 'bob@example.com');
		UPDATE devices SET primary_user_id=7 WHERE id='d1'`); err != nil {
		t.Fatal(err)
	}
	cert := issued()
	if cert.EmailAddresses[0] != "bob@example.com" {
		t.Fatalf("directory address missing: %v", cert.EmailAddresses)
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
	if len(crl.RevokedCertificateEntries) != 2 || !slices.ContainsFunc(crl.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(cert.SerialNumber) == 0 }) {
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
	// the list the network API shows
	certs, err := s.networkCerts(ctx, "")
	if err != nil || len(certs) != 2 || certs[0].State() != "revoked" || certs[0].Hostname != "pc1.evil.example" {
		t.Fatalf("list: %v %+v", err, certs)
	}
}
