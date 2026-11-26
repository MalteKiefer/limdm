package server

import (
	"crypto"
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
// public CA nor a TLS terminating proxy can sit in the middle. The key comes
// from the key provider (keys.go): a 0600 file or an HSM.
type deviceCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
}

const (
	deviceCertTTL = 90 * 24 * time.Hour
	serverCertTTL = 365 * 24 * time.Hour
)

func loadOrCreateCA(dir string) (*deviceCA, error) {
	return loadRoot(KeyProvider{}, dir, kindCA, "LiMDM Device CA")
}

// loadRoot loads the self signed CA <name>.crt from dir with the key of
// that name from p, creating both on first use (an HSM key must exist).
func loadRoot(p KeyProvider, dir, name, commonName string) (*deviceCA, error) {
	certPath := filepath.Join(dir, name+".crt")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		key, err := p.signer(dir, name, genP384)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: commonName, Organization: []string{"LiMDM"}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
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
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("%s: invalid certificate", certPath)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := p.signer(dir, name, nil)
	if err != nil {
		return nil, err
	}
	if pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(key.Public()) {
		return nil, fmt.Errorf("%s does not belong to the key %q", certPath, name)
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
	// The CA travels in the chain so a new agent can pin it by fingerprint during the handshake.
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// signCSR issues a client certificate for deviceID. The subject from the CSR
// is ignored; only the public key is taken, and only strong key types.
func (ca *deviceCA) signCSR(csrPEM, deviceID string) (certPEM string, serialHex string, notAfter time.Time, err error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return "", "", notAfter, err
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

// parseCSR decodes a PEM CSR, checks its signature and accepts only strong
// key types.
func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR signature invalid")
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, errors.New("unsupported curve")
		}
	case ed25519.PublicKey:
	default:
		return nil, errors.New("key type must be ECDSA P-256/P-384 or Ed25519")
	}
	return csr, nil
}

// loadCommandKey is the Ed25519 key commands are signed with. It lives next
// to the CA key (or in the HSM), never in the database: whoever can only
// write to the database cannot make devices run commands. create makes a
// missing file key.
func loadCommandKey(p KeyProvider, dir, name string, create bool) (crypto.Signer, error) {
	gen := genEd25519
	if !create {
		gen = nil
	}
	key, err := p.signer(dir, name, gen)
	if err != nil {
		return nil, fmt.Errorf("command key %q: %w", name, err)
	}
	if _, ok := key.Public().(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("command key %q: not an Ed25519 key", name)
	}
	return key, nil
}
