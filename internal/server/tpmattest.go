package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/maltekiefer/limdm/internal/api"
)

// TPM bound device keys. The agent creates its mTLS key in the TPM and
// sends evidence with the CSR (api.TPMEvidence):
//
//  1. TPM2_Certify by an attestation key (AK): a restricted signing key
//     signs only structures the TPM made itself, so a valid signature
//     over a TPMS_ATTEST naming the key shows the key lives in the TPM
//     that holds the AK, with the attributes of its public area
//     (fixedTPM, fixedParent: not exportable).
//  2. Credential activation with the endorsement key (EK): the server
//     encrypts a credential to the EK, bound to the AK's name
//     (TPM2_MakeCredential); only the TPM holding both decrypts it.
//
// The credential is an HMAC of the request, so the server keeps no state
// between the two rounds. The EK certificate is not checked against the
// TPM vendors' roots: a software TPM passes. The server records the SHA-256
// of the EK public area, which ties the device to one TPM, and pins the AK
// for key rotation.

const tpmChallengeSlot = 5 * time.Minute

func unmarshalPublic(b []byte) (*tpm2.TPMTPublic, error) {
	if len(b) == 0 {
		return nil, errors.New("missing public area")
	}
	return tpm2.Unmarshal[tpm2.TPMTPublic](b)
}

// verifyTPMEvidence checks that ev certifies key as a non exportable TPM key.
// pinnedAK, when set, must be the AK of ev (renewal). It returns the AK name.
func verifyTPMEvidence(ev *api.TPMEvidence, key any, pinnedAK []byte) ([]byte, error) {
	ak, err := unmarshalPublic(ev.AKPublic)
	if err != nil {
		return nil, fmt.Errorf("attestation key: %w", err)
	}
	if a := ak.ObjectAttributes; !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.Restricted || !a.SignEncrypt || a.Decrypt {
		return nil, errors.New("attestation key is not a restricted signing key of the TPM")
	}
	if pinnedAK != nil && !bytes.Equal(pinnedAK, ev.AKPublic) {
		return nil, errors.New("attestation key differs from the one pinned at enrollment")
	}
	kp, err := unmarshalPublic(ev.KeyPublic)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	if a := kp.ObjectAttributes; !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.SignEncrypt || a.Decrypt {
		return nil, errors.New("key may leave the TPM or is no signing key")
	}
	pub, err := tpm2.Pub(*kp)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	if eq, ok := pub.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(key) {
		return nil, errors.New("TPM key is not the key of the request")
	}
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](ev.CertifyInfo)
	if err != nil {
		return nil, fmt.Errorf("certify info: %w", err)
	}
	if att.Magic != tpm2.TPMGeneratedValue || att.Type != tpm2.TPMSTAttestCertify {
		return nil, errors.New("certify info was not made by a TPM")
	}
	ci, err := att.Attested.Certify()
	if err != nil {
		return nil, fmt.Errorf("certify info: %w", err)
	}
	keyName, err := tpm2.ObjectName(kp)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ci.Name.Buffer, keyName.Buffer) {
		return nil, errors.New("certify info names another key")
	}
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](ev.CertifySig)
	if err != nil {
		return nil, fmt.Errorf("certify signature: %w", err)
	}
	ec, err := sig.Signature.ECDSA()
	if err != nil || sig.SigAlg != tpm2.TPMAlgECDSA || ec.Hash != tpm2.TPMAlgSHA256 {
		return nil, errors.New("certify signature: ECDSA with SHA-256 expected")
	}
	akPub, err := tpm2.Pub(*ak)
	if err != nil {
		return nil, fmt.Errorf("attestation key: %w", err)
	}
	akEC, ok := akPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("attestation key: ECDSA expected")
	}
	sum := sha256.Sum256(ev.CertifyInfo)
	if !ecdsa.Verify(akEC, sum[:], new(big.Int).SetBytes(ec.SignatureR.Buffer), new(big.Int).SetBytes(ec.SignatureS.Buffer)) {
		return nil, errors.New("certify signature invalid")
	}
	akName, err := tpm2.ObjectName(ak)
	if err != nil {
		return nil, err
	}
	return akName.Buffer, nil
}

// tpmCredential is the value the TPM must decrypt: an HMAC over the token,
// the CSR, EK and AK, valid in one time slot.
func (s *Server) tpmCredential(tokenHash []byte, csr string, ev *api.TPMEvidence, slot int64) []byte {
	m := hmac.New(sha256.New, s.cfg.SessionKey)
	m.Write([]byte("limdm tpm enroll\x00"))
	binary.Write(m, binary.BigEndian, slot) //nolint:errcheck // a hash never fails
	for _, p := range [][]byte{tokenHash, []byte(csr), ev.EKPublic, ev.AKPublic} {
		sum := sha256.Sum256(p) // fixed length parts, no ambiguity
		m.Write(sum[:])
	}
	return m.Sum(nil)
}

// tpmChallenge encrypts the credential to the EK for the AK of ev.
func (s *Server) tpmChallenge(tokenHash []byte, csr string, ev *api.TPMEvidence, akName []byte, now time.Time) (*api.TPMChallenge, error) {
	ek, err := unmarshalPublic(ev.EKPublic)
	if err != nil {
		return nil, fmt.Errorf("endorsement key: %w", err)
	}
	if a := ek.ObjectAttributes; !a.FixedTPM || !a.FixedParent || !a.Restricted || !a.Decrypt || a.SignEncrypt {
		return nil, errors.New("endorsement key is not a restricted decryption key")
	}
	enc, err := tpm2.ImportEncapsulationKey(ek)
	if err != nil {
		return nil, fmt.Errorf("endorsement key: %w", err)
	}
	cred := s.tpmCredential(tokenHash, csr, ev, now.Unix()/int64(tpmChallengeSlot.Seconds()))
	id, secret, err := tpm2.CreateCredential(rand.Reader, enc, akName, cred)
	if err != nil {
		return nil, err
	}
	return &api.TPMChallenge{Credential: id, Secret: secret}, nil
}

// tpmActivated checks the credential of the second round (this or the
// previous slot).
func (s *Server) tpmActivated(tokenHash []byte, csr string, ev *api.TPMEvidence, now time.Time) bool {
	slot := now.Unix() / int64(tpmChallengeSlot.Seconds())
	return hmac.Equal(ev.Activated, s.tpmCredential(tokenHash, csr, ev, slot)) ||
		hmac.Equal(ev.Activated, s.tpmCredential(tokenHash, csr, ev, slot-1))
}

func ekFingerprint(ev *api.TPMEvidence) string {
	sum := sha256.Sum256(ev.EKPublic)
	return fmt.Sprintf("%x", sum)
}
