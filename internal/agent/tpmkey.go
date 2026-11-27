package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/maltekiefer/limdm/internal/api"
)

// The mTLS key in the TPM. With a TPM 2.0 the agent creates its key as a
// primary key of the owner hierarchy with a random unique value: the TPM
// derives the same key from its seed and the template every time, and the
// private part never leaves it (fixedTPM, fixedParent). device.pem then holds
// the unique value (PEM block tpmKeyBlock) instead of a private key, next to
// the certificate as before, so rotation stays one atomic file write. A TPM
// clear changes the seed and loses the key; the device enrolls again.
//
// The attestation key (AK) is a restricted signing primary key with a fixed
// template: the same AK at every renewal, so the server can pin it.

const (
	tpmDevice   = "/dev/tpmrm0" // the kernel resource manager, flushes what a crashed process left
	tpmKeyBlock = "LIMDM TPM KEY"
)

// tpmMu serializes TPM sessions of this process; the resource manager
// handles other processes.
var tpmMu sync.Mutex

func openTPM() (transport.TPMCloser, error) { return linuxtpm.Open(tpmDevice) }

func eccP256(sign, restricted bool, unique []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, SignEncrypt: sign, Restricted: restricted},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{X: tpm2.TPM2BECCParameter{Buffer: unique}}),
	}
}

// akTemplate is the attestation key: restricted, signs only TPM made structures.
func akTemplate() tpm2.TPMTPublic { return eccP256(true, true, []byte("limdm attestation key")) }

// keyTemplate is the mTLS key with the unique value from device.pem.
func keyTemplate(unique []byte) tpm2.TPMTPublic { return eccP256(true, false, unique) }

type primary struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public []byte // TPMT_PUBLIC
}

func createPrimary(t transport.TPM, hierarchy tpm2.TPMHandle, tmpl tpm2.TPMTPublic) (primary, error) {
	rsp, err := tpm2.CreatePrimary{PrimaryHandle: hierarchy, InPublic: tpm2.New2B(tmpl)}.Execute(t)
	if err != nil {
		return primary{}, err
	}
	return primary{rsp.ObjectHandle, rsp.Name, rsp.OutPublic.Bytes()}, nil
}

func (p primary) flush(t transport.TPM) { tpm2.FlushContext{FlushHandle: p.handle}.Execute(t) } //nolint:errcheck // best effort, the resource manager flushes on close

// withTPM runs fn on an open TPM with the mTLS key (and the AK when ak) loaded.
func withTPM(unique []byte, ak bool, fn func(t transport.TPM, key, ak primary) error) error {
	tpmMu.Lock()
	defer tpmMu.Unlock()
	t, err := openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	key, err := createPrimary(t, tpm2.TPMRHOwner, keyTemplate(unique))
	if err != nil {
		return fmt.Errorf("TPM key: %w", err)
	}
	defer key.flush(t)
	var a primary
	if ak {
		if a, err = createPrimary(t, tpm2.TPMRHOwner, akTemplate()); err != nil {
			return fmt.Errorf("TPM attestation key: %w", err)
		}
		defer a.flush(t)
	}
	return fn(t, key, a)
}

// tpmSigner signs with the mTLS key in the TPM (ECDSA P-256, SHA-256).
type tpmSigner struct {
	unique []byte
	pub    *ecdsa.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("TPM key: hash %v not supported", opts.HashFunc())
	}
	var sig []byte
	err := withTPM(s.unique, false, func(t transport.TPM, key, _ primary) error {
		rsp, err := tpm2.Sign{
			KeyHandle: tpm2.NamedHandle{Handle: key.handle, Name: key.name},
			Digest:    tpm2.TPM2BDigest{Buffer: digest},
			InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(t)
		if err != nil {
			return err
		}
		ec, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return err
		}
		sig, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(ec.SignatureR.Buffer), new(big.Int).SetBytes(ec.SignatureS.Buffer)})
		return err
	})
	return sig, err
}

// hasTPM2 is true when the TPM resource manager can be opened.
func hasTPM2() bool {
	if tpmVersion() != "2.0" {
		return false
	}
	t, err := openTPM()
	if err != nil {
		return false
	}
	t.Close()
	return true
}

// newTPMKey creates a new mTLS key in the TPM and returns its device.pem
// block and signer.
func newTPMKey() ([]byte, *tpmSigner, error) {
	unique := make([]byte, 32)
	if _, err := rand.Read(unique); err != nil {
		return nil, nil, err
	}
	s := &tpmSigner{unique: unique}
	err := withTPM(unique, false, func(_ transport.TPM, key, _ primary) error {
		pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](key.public)
		if err != nil {
			return err
		}
		k, err := tpm2.Pub(*pub)
		if err != nil {
			return err
		}
		var ok bool
		if s.pub, ok = k.(*ecdsa.PublicKey); !ok {
			return errors.New("TPM key is not ECDSA")
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: tpmKeyBlock, Bytes: unique}), s, nil
}

// tpmEvidence certifies the mTLS key with the AK; withEK adds the EK
// public key for credential activation (enrollment).
func tpmEvidence(s *tpmSigner, withEK bool) (*api.TPMEvidence, error) {
	ev := &api.TPMEvidence{}
	err := withTPM(s.unique, true, func(t transport.TPM, key, ak primary) error {
		rsp, err := tpm2.Certify{
			ObjectHandle: tpm2.AuthHandle{Handle: key.handle, Name: key.name, Auth: tpm2.PasswordAuth(nil)},
			SignHandle:   tpm2.AuthHandle{Handle: ak.handle, Name: ak.name, Auth: tpm2.PasswordAuth(nil)},
			InScheme:     tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		}.Execute(t)
		if err != nil {
			return fmt.Errorf("TPM certify: %w", err)
		}
		ev.AKPublic, ev.KeyPublic = ak.public, key.public
		ev.CertifyInfo, ev.CertifySig = rsp.CertifyInfo.Bytes(), tpm2.Marshal(rsp.Signature)
		if withEK {
			ek, err := createPrimary(t, tpm2.TPMRHEndorsement, tpm2.RSAEKTemplate)
			if err != nil {
				return fmt.Errorf("TPM endorsement key: %w", err)
			}
			defer ek.flush(t)
			ev.EKPublic = ek.public
		}
		return nil
	})
	return ev, err
}

// activateCredential decrypts the server's challenge with the EK; the TPM
// releases it only for the AK named in it.
func activateCredential(s *tpmSigner, ch *api.TPMChallenge) ([]byte, error) {
	var out []byte
	err := withTPM(s.unique, true, func(t transport.TPM, _, ak primary) error {
		ek, err := createPrimary(t, tpm2.TPMRHEndorsement, tpm2.RSAEKTemplate)
		if err != nil {
			return err
		}
		defer ek.flush(t)
		ekPolicy := func(t transport.TPM, h tpm2.TPMISHPolicy, nonce tpm2.TPM2BNonce) error {
			_, err := tpm2.PolicySecret{AuthHandle: tpm2.TPMRHEndorsement, PolicySession: h, NonceTPM: nonce}.Execute(t)
			return err
		}
		rsp, err := tpm2.ActivateCredential{
			ActivateHandle: tpm2.AuthHandle{Handle: ak.handle, Name: ak.name, Auth: tpm2.PasswordAuth(nil)},
			KeyHandle:      tpm2.AuthHandle{Handle: ek.handle, Name: ek.name, Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy)},
			CredentialBlob: tpm2.TPM2BIDObject{Buffer: ch.Credential},
			Secret:         tpm2.TPM2BEncryptedSecret{Buffer: ch.Secret},
		}.Execute(t)
		if err != nil {
			return fmt.Errorf("TPM credential activation: %w", err)
		}
		out = rsp.CertInfo.Buffer
		return nil
	})
	return out, err
}

// loadIdentity reads device.pem: a certificate with either a PEM private
// key (file key) or a tpmKeyBlock (key in the TPM).
func loadIdentity(b []byte) (tls.Certificate, error) {
	var unique []byte
	var certs [][]byte
	for rest := b; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		switch blk.Type {
		case tpmKeyBlock:
			unique = blk.Bytes
		case "CERTIFICATE":
			certs = append(certs, blk.Bytes)
		}
	}
	if unique == nil {
		return tls.X509KeyPair(b, b)
	}
	if len(certs) == 0 {
		return tls.Certificate{}, errors.New("identity: no certificate")
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return tls.Certificate{}, errors.New("identity: certificate key is not ECDSA")
	}
	return tls.Certificate{Certificate: certs, PrivateKey: &tpmSigner{unique: unique, pub: pub}, Leaf: leaf}, nil
}

// tpmBoundIdentity reports whether device.pem holds a TPM key.
func tpmBoundIdentity(b []byte) bool {
	c, err := loadIdentity(b)
	if err != nil {
		return false
	}
	_, ok := c.PrivateKey.(*tpmSigner)
	return ok
}

// runTPMKey: the mTLS key of the device is in the TPM. The server's own
// view (attested at enrollment) is shown on the device page as "TPM bound".
func runTPMKey(*Agent) (string, string) {
	if tpmVersion() != "2.0" {
		return na, "no TPM 2.0"
	}
	b, err := os.ReadFile(identityFile)
	if err != nil {
		return fail, "device key unreadable: " + err.Error()
	}
	if tpmBoundIdentity(b) {
		return pass, "the device key cannot leave the TPM"
	}
	return fail, "the device key is a file; the next certificate renewal creates it in the TPM"
}
