//go:build pkcs11 && cgo

package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"testing"

	"github.com/miekg/pkcs11"
)

// Public keys come from the token as CKA_KEY_TYPE, CKA_EC_PARAMS and a DER
// wrapped (or, for some Ed25519 tokens, raw) CKA_EC_POINT.
func TestHSMPublicKey(t *testing.T) {
	ulong := func(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	raw, _ := k.PublicKey.Bytes()
	point, _ := asn1.Marshal(raw)
	params, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	pub, err := hsmPublicKey(ulong(pkcs11.CKK_EC), params, point)
	if err != nil || !k.PublicKey.Equal(pub) {
		t.Fatalf("P-384: %v", err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wrapped, _ := asn1.Marshal([]byte(edPub))
	for _, p := range [][]byte{wrapped, edPub} {
		if got, err := hsmPublicKey(ulong(ckkECEdwards), nil, p); err != nil || !edPub.Equal(got) {
			t.Fatalf("Ed25519: %v", err)
		}
	}
	if _, err := hsmPublicKey(ulong(pkcs11.CKK_RSA), nil, nil); err == nil {
		t.Fatal("RSA accepted")
	}
}
