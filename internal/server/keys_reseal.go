package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Session key rotation: LIMDM_SESSION_KEY lists the new key first and the
// old ones after it. Values are opened with any key; reseal seals every
// value the first key cannot open again with it. With dry it only counts.
// Every update compares the old value, so a concurrent save is not lost.

// reseal walks every store of sealed values and returns how many need (or,
// without dry, got) sealing with the first key. A value no key opens is an
// error for its store; the other stores still run.
func (s *Server) reseal(ctx context.Context, dry bool) (int, error) {
	if len(s.cfg.OldSessionKeys) == 0 {
		return 0, nil
	}
	total := 0
	var errs []error
	for _, step := range []func(context.Context, bool) (int, error){
		s.resealSettings, s.resealChannels, s.resealRecovery, s.resealItems, s.resealItemVersions,
	} {
		n, err := step(ctx, dry)
		total += n
		errs = append(errs, err)
	}
	return total, errors.Join(errs...)
}

// resealField seals a settings secret with the first key when needed.
func (s *Server) resealField(field, enc string) (string, bool, error) {
	if enc == "" {
		return enc, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", field, err)
	}
	if s.openableWithPrimary(infoSettings, raw, []byte(field)) {
		return enc, false, nil
	}
	plain, err := s.openField(field, enc)
	if err != nil {
		return "", false, fmt.Errorf("%s: no session key opens it: %w", field, err)
	}
	out, err := s.sealField(field, plain)
	return out, true, err
}

// resealSettings: the OIDC client secret and the Google service account key,
// fields of JSON documents in the settings table.
func (s *Server) resealSettings(ctx context.Context, dry bool) (int, error) {
	n := 0
	for _, f := range []struct{ key, json, field string }{
		{"server", "oidc_client_secret_enc", "settings.oidc_client_secret"},
		{"google", "key_enc", "settings.google_service_account_key"},
		{"webhook", "secret_enc", webhookField},
	} {
		var raw []byte
		err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, f.key).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return n, err
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return n, err
		}
		var enc string
		if v, ok := doc[f.json]; !ok || json.Unmarshal(v, &enc) != nil {
			continue
		}
		out, changed, err := s.resealField(f.field, enc)
		if err != nil || !changed {
			if err != nil {
				return n, err
			}
			continue
		}
		n++
		if dry {
			continue
		}
		doc[f.json], _ = json.Marshal(out)
		b, _ := json.Marshal(doc)
		if _, err := s.db.Exec(ctx, `UPDATE settings SET value=$2 WHERE key=$1 AND value=$3::jsonb`, f.key, string(b), string(raw)); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (s *Server) resealChannels(ctx context.Context, dry bool) (int, error) {
	rows, err := s.db.Query(ctx, `SELECT id, secret FROM notification_channels WHERE secret <> ''`)
	if err != nil {
		return 0, err
	}
	type ch struct {
		id     int64
		secret string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ch, error) {
		var c ch
		return c, r.Scan(&c.id, &c.secret)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range list {
		out, changed, err := s.resealField(channelField(c.id), c.secret)
		if err != nil {
			return n, err
		}
		if !changed {
			continue
		}
		n++
		if !dry {
			if _, err := s.db.Exec(ctx, `UPDATE notification_channels SET secret=$2 WHERE id=$1 AND secret=$3`, c.id, out, c.secret); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (s *Server) resealRecovery(ctx context.Context, dry bool) (int, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, uuid, sealed FROM recovery_keys`)
	if err != nil {
		return 0, err
	}
	type rk struct {
		dev, uuid string
		sealed    []byte
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rk, error) {
		var k rk
		return k, r.Scan(&k.dev, &k.uuid, &k.sealed)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range list {
		if s.openableWithPrimary(infoRecovery, k.sealed, []byte(k.dev+"|"+k.uuid)) {
			continue
		}
		n++
		if dry {
			continue
		}
		plain, err := s.openRecovery(k.dev, k.uuid, k.sealed)
		if err != nil {
			return n, fmt.Errorf("recovery key %s %s: no session key opens it: %w", k.dev, k.uuid, err)
		}
		out, err := s.sealRecovery(k.dev, k.uuid, plain)
		if err != nil {
			return n, err
		}
		if _, err := s.db.Exec(ctx, `UPDATE recovery_keys SET sealed=$3 WHERE device_id=$1 AND uuid=$2 AND sealed=$4`, k.dev, k.uuid, out, k.sealed); err != nil {
			return n, err
		}
	}
	return n, nil
}

// resealLogin returns a login payload with its client secret sealed with the
// first key, and whether that was needed.
func (s *Server) resealLogin(payload []byte) ([]byte, bool, error) {
	_, secret, ok := loginSecret(payload)
	enc, sealed := strings.CutPrefix(secret, sealedPrefix)
	if !ok || !sealed {
		return payload, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, false, err
	}
	if s.openableWithPrimary(infoItems, raw, []byte(loginAD)) {
		return payload, false, nil
	}
	plain, err := openItemSecrets(api.TypeLogin, payload)
	if err != nil {
		return nil, false, err
	}
	out, _, err := sealItemSecrets(api.TypeLogin, plain)
	return out, true, err
}

// resealItems seals login client secrets again and signs the items again
// (the signature covers the sealed form). An item whose signature is
// already invalid is left alone: it is withheld from devices anyway.
func (s *Server) resealItems(ctx context.Context, dry bool) (int, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, payload, signature FROM library_items WHERE type=$1`, api.TypeLogin)
	if err != nil {
		return 0, err
	}
	type item struct {
		id        int64
		name, sig string
		payload   []byte
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var it item
		return it, r.Scan(&it.id, &it.name, &it.payload, &it.sig)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range list {
		if !itemSignatureOK(it.name, api.TypeLogin, it.payload, it.sig) {
			continue
		}
		out, changed, err := s.resealLogin(it.payload)
		if err != nil {
			return n, fmt.Errorf("login item %s: %w", it.name, err)
		}
		if !changed {
			continue
		}
		n++
		if !dry {
			if _, err := s.db.Exec(ctx, `UPDATE library_items SET payload=$2, signature=$3 WHERE id=$1 AND signature=$4`,
				it.id, string(out), signItem(it.name, api.TypeLogin, out), it.sig); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// resealItemVersions does the same for the version history, so a rollback
// to an old version still opens; the history is append only except for
// this (schema.sql, E4b).
func (s *Server) resealItemVersions(ctx context.Context, dry bool) (int, error) {
	rows, err := s.db.Query(ctx, `SELECT id, payload FROM library_item_versions WHERE type=$1`, api.TypeLogin)
	if err != nil {
		return 0, err
	}
	type ver struct {
		id      int64
		payload []byte
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ver, error) {
		var v ver
		return v, r.Scan(&v.id, &v.payload)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range list {
		out, changed, err := s.resealLogin(v.payload)
		if err != nil {
			return n, fmt.Errorf("login item version %d: %w", v.id, err)
		}
		if !changed {
			continue
		}
		n++
		if dry {
			continue
		}
		err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('limdm.reseal', 'on', true)`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE library_item_versions SET payload=$2 WHERE id=$1`, v.id, string(out))
			return err
		})
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// resealLoop seals old values again once after a start with old session
// keys, and records it.
func (s *Server) resealLoop(ctx context.Context) {
	if len(s.cfg.OldSessionKeys) > 0 {
		n, err := s.reseal(ctx, false)
		if err != nil {
			s.log.Error("sealing values with the new session key", "err", err)
		}
		if n > 0 {
			if err := s.auditAction(ctx, "system", "keys.reseal", kindSession, fmt.Sprintf("%d values sealed with the first session key", n), nil); err != nil {
				s.log.Error("audit", "err", err)
			}
			s.log.Info("values sealed with the new session key", "count", n)
		}
	}
	<-ctx.Done()
}

// resignItems signs library items again whose signature is from the
// previous command key, while a command key rotation runs. Items whose
// signature no key verifies stay as they are (withheld from devices).
func (s *Server) resignItems(ctx context.Context) error {
	if s.kr.cmdPrev == nil {
		return nil
	}
	prev := s.kr.cmdPrev.Public().(ed25519.PublicKey)
	cur := s.cmdKey.Public().(ed25519.PublicKey)
	rows, err := s.db.Query(ctx, `SELECT id, name, type, payload, signature FROM library_items`)
	if err != nil {
		return err
	}
	type item struct {
		id             int64
		name, typ, sig string
		payload        []byte
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var it item
		return it, r.Scan(&it.id, &it.name, &it.typ, &it.payload, &it.sig)
	})
	if err != nil {
		return err
	}
	for _, it := range list {
		if itemSigValid(cur, it.name, it.typ, it.payload, it.sig) || !itemSigValid(prev, it.name, it.typ, it.payload, it.sig) {
			continue
		}
		sig := signItem(it.name, it.typ, it.payload)
		if sig == "" {
			return fmt.Errorf("signing library item %s failed", it.name)
		}
		if _, err := s.db.Exec(ctx, `UPDATE library_items SET signature=$2 WHERE id=$1 AND signature=$3`, it.id, sig, it.sig); err != nil {
			return err
		}
	}
	return nil
}
