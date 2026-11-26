package server

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// The client secret of the desktop login item (com.limdm.login) is stored
// sealed with AES-256-GCM under a key derived from LIMDM_SESSION_KEY, like
// the settings secrets. The item's signature covers the sealed form; the
// secret is opened only when declarations are resolved for a device, and
// travels to the agent over mTLS, which needs it in clear for the device
// authorization grant.

const (
	sealedPrefix = "sealed:v1:"
	infoItems    = "limdm library secrets v1"
	loginAD      = "library.login.client_secret"
)

// itemSecrets seals and opens library secrets; set when the server starts
// (like itemKey). nil leaves payloads as stored (tools without the key).
var itemSecrets cipher.AEAD

// loginSecret decodes a login payload, numbers kept as written.
func loginSecret(payload []byte) (map[string]any, string, bool) {
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	var m map[string]any
	if d.Decode(&m) != nil {
		return nil, "", false
	}
	v, ok := m["client_secret"].(string)
	return m, v, ok
}

// sealItemSecrets returns the payload with a clear login client secret
// sealed, and whether it changed.
func sealItemSecrets(typ string, payload []byte) ([]byte, bool, error) {
	if typ != api.TypeLogin || itemSecrets == nil {
		return payload, false, nil
	}
	m, secret, ok := loginSecret(payload)
	if !ok || secret == "" || strings.HasPrefix(secret, sealedPrefix) {
		return payload, false, nil
	}
	m["client_secret"] = sealedPrefix + base64.StdEncoding.EncodeToString(seal(itemSecrets, []byte(secret), []byte(loginAD)))
	b, err := json.Marshal(m)
	return b, err == nil, err
}

// openItemSecrets returns the payload with a sealed client secret opened.
func openItemSecrets(typ string, payload []byte) ([]byte, error) {
	if typ != api.TypeLogin || itemSecrets == nil {
		return payload, nil
	}
	m, secret, ok := loginSecret(payload)
	enc, sealed := strings.CutPrefix(secret, sealedPrefix)
	if !ok || !sealed {
		return payload, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	plain, err := open(itemSecrets, raw, []byte(loginAD))
	if err != nil {
		return nil, fmt.Errorf("open login client secret: %w", err)
	}
	m["client_secret"] = string(plain)
	return json.Marshal(m)
}

// sealLoginSecrets seals client secrets stored in clear (items written
// before 0.16) and signs the items again; items with an invalid signature
// are left alone, they are not delivered anyway.
func (s *Server) sealLoginSecrets(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `SELECT id, name, payload, signature FROM library_items WHERE type=$1`, api.TypeLogin)
	if err != nil {
		return err
	}
	type item struct {
		id        int64
		name, sig string
		payload   []byte
	}
	var todo []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.name, &it.payload, &it.sig); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, it := range todo {
		if !itemSignatureOK(it.name, api.TypeLogin, it.payload, it.sig) {
			continue
		}
		sealed, changed, err := sealItemSecrets(api.TypeLogin, it.payload)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		if _, err := s.db.Exec(ctx, `UPDATE library_items SET payload=$2, signature=$3 WHERE id=$1`,
			it.id, string(sealed), signItem(it.name, api.TypeLogin, sealed)); err != nil {
			return err
		}
		s.log.Info("login client secret sealed", "item", it.name)
	}
	return nil
}
