package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Data at rest is sealed with AES-256-GCM. Each purpose gets its own key,
// derived with HKDF from LIMDM_SESSION_KEY, and every ciphertext is bound to
// its field or record through the additional data, so sealed values cannot
// be swapped between fields or rows.

func (s *Server) aead(info string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, s.cfg.SessionKey, nil, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(a cipher.AEAD, plain, ad []byte) []byte {
	nonce := make([]byte, a.NonceSize())
	rand.Read(nonce) // never fails since Go 1.24
	return a.Seal(nonce, nonce, plain, ad)
}

func open(a cipher.AEAD, sealed, ad []byte) ([]byte, error) {
	if len(sealed) < a.NonceSize() {
		return nil, errors.New("sealed value too short")
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], ad)
}

const (
	infoSettings = "limdm settings secrets v1"
	infoRecovery = "limdm recovery keys v1"
	// legacyAD was used for every settings secret before per field binding.
	legacyAD = "oidc_client_secret"
)

// sealField seals a settings secret for the named field ("" stays "").
func (s *Server) sealField(field, plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	a, err := s.aead(infoSettings)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(seal(a, []byte(plain), []byte(field))), nil
}

// openField opens a settings secret; values sealed before per field binding
// are still accepted and get the new binding on their next save.
func (s *Server) openField(field, enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	a, err := s.aead(infoSettings)
	if err != nil {
		return "", err
	}
	plain, err := open(a, raw, []byte(field))
	if err != nil {
		plain, err = open(a, raw, []byte(legacyAD))
	}
	return string(plain), err
}
