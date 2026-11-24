package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// deviceCA is the private CA for agent mTLS. Its key never leaves the server;
// agents pin its certificate by SHA-256 fingerprint at enrollment, so neither a
// public CA nor a TLS terminating proxy can sit in the middle.
//
// ponytail: CA key is a 0600 file; move it to an HSM / PKCS#11 when the threat model requires.
type deviceCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

const (
	deviceCertTTL = 90 * 24 * time.Hour
	serverCertTTL = 365 * 24 * time.Hour
)

func loadOrCreateCA(dir string) (*deviceCA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: "LiMDM Device CA", Organization: []string{"LiMDM"}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil { //nolint:gosec // public certificate
			return nil, err
		}
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(keyPath); err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be readable by group/others", keyPath)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("invalid CA files")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &deviceCA{cert: cert, key: key, pem: certPEM}, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// Fingerprint is the SHA-256 of the CA certificate, used for pinning.
func (ca *deviceCA) Fingerprint() string {
	h := sha256.Sum256(ca.cert.Raw)
	return hex.EncodeToString(h[:])
}

func (ca *deviceCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// serverCert issues the TLS certificate of the agent listener.
func (ca *deviceCA) serverCert(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(serverCertTTL),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// signCSR issues a client certificate for deviceID. The subject from the CSR
// is ignored; only the public key is taken, and only strong key types.
func (ca *deviceCA) signCSR(csrPEM, deviceID string) (certPEM string, serialHex string, notAfter time.Time, err error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return "", "", notAfter, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return "", "", notAfter, err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", notAfter, errors.New("CSR signature invalid")
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return "", "", notAfter, errors.New("unsupported curve")
		}
	case ed25519.PublicKey:
	default:
		return "", "", notAfter, errors.New("key type must be ECDSA P-256/P-384 or Ed25519")
	}
	sn := serial()
	notAfter = time.Now().Add(deviceCertTTL)
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: deviceID, Organization: []string{"LiMDM device"}},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", "", notAfter, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), sn.Text(16), notAfter, nil
}
