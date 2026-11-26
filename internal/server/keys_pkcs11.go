//go:build pkcs11 && cgo

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS#11 key provider (go build -tags pkcs11, needs cgo): the private keys
// stay in the token, the server only asks it to sign. Keys are found by
// label (limdm-<name>) and must exist: create them with the token's tools
// (docs/keys.md). Supported: ECDSA P-256/P-384 (CAs) and Ed25519
// (command key, release key; PKCS#11 3.0 CKM_EDDSA).

func init() { openPKCS11 = openHSMKey }

// PKCS#11 3.0 values missing from the 2.40 headers of the library.
const (
	ckkECEdwards = 0x00000040
	ckmEdDSA     = 0x00001057
)

// hsmToken is one logged in session per module and token. PKCS#11 sessions
// must not be used concurrently, hence the lock.
// ponytail: one session, every signature serialized; a session pool if the HSM becomes the bottleneck.
type hsmToken struct {
	mu   sync.Mutex
	ctx  *pkcs11.Ctx
	sess pkcs11.SessionHandle
}

var (
	hsmMu     sync.Mutex
	hsmTokens = map[string]*hsmToken{}
)

func hsmOpen(module, token, pin string) (*hsmToken, error) {
	hsmMu.Lock()
	defer hsmMu.Unlock()
	if t, ok := hsmTokens[module+"\x00"+token]; ok {
		return t, nil
	}
	ctx := pkcs11.New(module)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: cannot load module %s", module)
	}
	if err := ctx.Initialize(); err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		return nil, fmt.Errorf("pkcs11: initialize: %w", err)
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: slots: %w", err)
	}
	for _, slot := range slots {
		ti, err := ctx.GetTokenInfo(slot)
		if err != nil || strings.TrimSpace(ti.Label) != token {
			continue
		}
		sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: open session: %w", err)
		}
		if err := ctx.Login(sess, pkcs11.CKU_USER, pin); err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
			return nil, fmt.Errorf("pkcs11: login to token %q: %w", token, err)
		}
		t := &hsmToken{ctx: ctx, sess: sess}
		hsmTokens[module+"\x00"+token] = t
		return t, nil
	}
	return nil, fmt.Errorf("pkcs11: no token labeled %q in %s", token, module)
}

func (t *hsmToken) find(class uint, label string) (pkcs11.ObjectHandle, error) {
	if err := t.ctx.FindObjectsInit(t.sess, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}); err != nil {
		return 0, err
	}
	objs, _, err := t.ctx.FindObjects(t.sess, 2)
	if ferr := t.ctx.FindObjectsFinal(t.sess); err == nil {
		err = ferr
	}
	switch {
	case err != nil:
		return 0, err
	case len(objs) != 1:
		return 0, fmt.Errorf("pkcs11: %d objects labeled %q, want exactly one", len(objs), label)
	}
	return objs[0], nil
}

// hsmKey is a private key in the token.
type hsmKey struct {
	tok    *hsmToken
	handle pkcs11.ObjectHandle
	pub    crypto.PublicKey
}

func openHSMKey(module, token, pin, label string) (crypto.Signer, error) {
	t, err := hsmOpen(module, token, pin)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	priv, err := t.find(pkcs11.CKO_PRIVATE_KEY, label)
	if err != nil {
		return nil, err
	}
	pubObj, err := t.find(pkcs11.CKO_PUBLIC_KEY, label)
	if err != nil {
		return nil, err
	}
	attrs, err := t.ctx.GetAttributeValue(t.sess, pubObj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil), pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil), pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: public key %q: %w", label, err)
	}
	pub, err := hsmPublicKey(attrs[0].Value, attrs[1].Value, attrs[2].Value)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: public key %q: %w", label, err)
	}
	return &hsmKey{tok: t, handle: priv, pub: pub}, nil
}

// hsmPublicKey decodes CKA_KEY_TYPE, CKA_EC_PARAMS and CKA_EC_POINT.
func hsmPublicKey(keyType, params, point []byte) (crypto.PublicKey, error) {
	var typ uint64
	for i := len(keyType) - 1; i >= 0; i-- { // CK_ULONG in host byte order (little endian on supported hosts)
		typ = typ<<8 | uint64(keyType[i])
	}
	// CKA_EC_POINT is a DER OCTET STRING; some tokens give Ed25519 points raw
	raw := point
	var inner []byte
	if rest, err := asn1.Unmarshal(point, &inner); err == nil && len(rest) == 0 {
		raw = inner
	}
	switch typ {
	case pkcs11.CKK_EC:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(params, &oid); err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch {
		case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}):
			curve = elliptic.P256()
		case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}):
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported curve %v", oid)
		}
		return ecdsa.ParseUncompressedPublicKey(curve, raw)
	case ckkECEdwards:
		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("not an Ed25519 key")
		}
		return ed25519.PublicKey(raw), nil
	}
	return nil, fmt.Errorf("unsupported key type %#x", typ)
}

func (k *hsmKey) Public() crypto.PublicKey { return k.pub }

// Sign signs a digest (ECDSA, returned ASN.1 encoded like crypto/ecdsa) or
// a whole message (Ed25519, opts.HashFunc() == 0).
func (k *hsmKey) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	mech := uint(pkcs11.CKM_ECDSA)
	_, ed := k.pub.(ed25519.PublicKey)
	switch {
	case ed && opts.HashFunc() != 0:
		return nil, errors.New("pkcs11: Ed25519 signs whole messages only")
	case ed:
		mech = ckmEdDSA
	case opts.HashFunc() == 0 || len(msg) != opts.HashFunc().Size():
		return nil, errors.New("pkcs11: ECDSA needs a digest")
	}
	k.tok.mu.Lock()
	defer k.tok.mu.Unlock()
	if err := k.tok.ctx.SignInit(k.tok.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}, k.handle); err != nil {
		return nil, fmt.Errorf("pkcs11: sign: %w", err)
	}
	sig, err := k.tok.ctx.Sign(k.tok.sess, msg)
	if err != nil || ed {
		return sig, err
	}
	if len(sig)%2 != 0 { // r || s
		return nil, errors.New("pkcs11: malformed ECDSA signature")
	}
	n := len(sig) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])})
}
