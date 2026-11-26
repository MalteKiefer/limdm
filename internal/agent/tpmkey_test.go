package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dev"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestLoadIdentity(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kb, _ := x509.MarshalECPrivateKey(key)
	cert := selfSigned(t, key)
	file := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})) + cert
	c, err := loadIdentity([]byte(file))
	if err != nil || !samePublicKey(c) || tpmBoundIdentity([]byte(file)) {
		t.Fatalf("file key: %v", err)
	}
	tpm := string(pem.EncodeToMemory(&pem.Block{Type: tpmKeyBlock, Bytes: make([]byte, 32)})) + cert
	c, err = loadIdentity([]byte(tpm))
	if err != nil || !tpmBoundIdentity([]byte(tpm)) || !samePublicKey(c) {
		t.Fatalf("TPM key: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.PrivateKey = &tpmSigner{pub: &other.PublicKey}
	if samePublicKey(c) {
		t.Fatal("a certificate of another key must not pass")
	}
	if _, err := loadIdentity(pem.EncodeToMemory(&pem.Block{Type: tpmKeyBlock, Bytes: []byte{1}})); err == nil {
		t.Fatal("TPM key without certificate accepted")
	}
}
