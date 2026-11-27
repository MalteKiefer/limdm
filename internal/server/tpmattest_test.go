package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/maltekiefer/limdm/internal/api"
)

// eccPublic is the TPMT_PUBLIC a TPM reports for an ECDSA P-256 key.
func eccPublic(pub *ecdsa.PublicKey, attrs tpm2.TPMAObject) tpm2.TPMTPublic {
	b, _ := pub.Bytes() // 0x04 || X || Y
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256, ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})}}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{X: tpm2.TPM2BECCParameter{Buffer: b[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: b[33:]}}),
	}
}

// fakeTPMEvidence builds what a TPM sends for key: an AK, TPM2_Certify of
// the key signed by it and an RSA EK. No TPM simulator is available in
// the tests, so the AK signs in software.
func fakeTPMEvidence(t *testing.T, key *ecdsa.PublicKey, keyAttrs tpm2.TPMAObject) *api.TPMEvidence {
	t.Helper()
	akKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ak := eccPublic(&akKey.PublicKey, tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, Restricted: true, SignEncrypt: true})
	kp := eccPublic(key, keyAttrs)
	name, err := tpm2.ObjectName(&kp)
	if err != nil {
		t.Fatal(err)
	}
	info := tpm2.Marshal(tpm2.TPMSAttest{Magic: tpm2.TPMGeneratedValue, Type: tpm2.TPMSTAttestCertify,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{Name: *name})})
	sum := sha256.Sum256(info)
	r, s, err := ecdsa.Sign(rand.Reader, akKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := tpm2.Marshal(tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgECDSA, Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA,
		&tpm2.TPMSSignatureECC{Hash: tpm2.TPMAlgSHA256, SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()}, SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()}})})
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := tpm2.RSAEKTemplate
	ek.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: ekKey.N.Bytes()})
	return &api.TPMEvidence{EKPublic: tpm2.Marshal(ek), AKPublic: tpm2.Marshal(ak), KeyPublic: tpm2.Marshal(kp), CertifyInfo: info, CertifySig: sig}
}

var tpmKeyAttrs = tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true}

func TestVerifyTPMEvidence(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ev := fakeTPMEvidence(t, &key.PublicKey, tpmKeyAttrs)
	akName, err := verifyTPMEvidence(ev, &key.PublicKey, nil)
	if err != nil || len(akName) == 0 {
		t.Fatalf("valid evidence refused: %v", err)
	}
	if _, err := verifyTPMEvidence(ev, &key.PublicKey, ev.AKPublic); err != nil {
		t.Fatalf("pinned AK refused: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := verifyTPMEvidence(ev, &other.PublicKey, nil); err == nil {
		t.Fatal("evidence for another key accepted")
	}
	if _, err := verifyTPMEvidence(fakeTPMEvidence(t, &key.PublicKey, tpmKeyAttrs), &key.PublicKey, ev.AKPublic); err == nil {
		t.Fatal("another AK than the pinned one accepted")
	}
	exportable := tpmKeyAttrs
	exportable.FixedTPM = false
	if _, err := verifyTPMEvidence(fakeTPMEvidence(t, &key.PublicKey, exportable), &key.PublicKey, nil); err == nil {
		t.Fatal("exportable key accepted")
	}
	bad := *ev
	bad.CertifySig = append([]byte(nil), ev.CertifySig...)
	bad.CertifySig[len(bad.CertifySig)-1] ^= 1
	if _, err := verifyTPMEvidence(&bad, &key.PublicKey, nil); err == nil {
		t.Fatal("broken signature accepted")
	}

	s := &Server{cfg: Config{SessionKey: make([]byte, 32)}}
	now := time.Now()
	ch, err := s.tpmChallenge([]byte("token"), "csr", ev, akName, now)
	if err != nil || len(ch.Credential) == 0 || len(ch.Secret) == 0 {
		t.Fatalf("challenge: %v", err)
	}
	slot := now.Unix() / int64(tpmChallengeSlot.Seconds())
	ev.Activated = s.tpmCredential([]byte("token"), "csr", ev, slot)
	if !s.tpmActivated([]byte("token"), "csr", ev, now) || !s.tpmActivated([]byte("token"), "csr", ev, now.Add(tpmChallengeSlot)) {
		t.Fatal("credential of this slot refused")
	}
	if s.tpmActivated([]byte("token"), "csr", ev, now.Add(2*tpmChallengeSlot)) || s.tpmActivated([]byte("other"), "csr", ev, now) {
		t.Fatal("stale or foreign credential accepted")
	}
}
