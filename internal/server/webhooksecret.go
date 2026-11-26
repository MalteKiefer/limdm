package server

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The webhook signing secret signs the compliance webhook and signed
// webhook channels (X-LiMDM-Signature). It is its own value, sealed in the
// settings row "webhook", so a session key rotation does not change it.
// Before 0.16 it was derived from the session key; an installation that may
// have receivers keeps that value as its stored secret.

const webhookField = "settings.webhook_secret"

// loadWebhookSecret returns the stored secret and creates it on first use.
func (s *Server) loadWebhookSecret(ctx context.Context) ([]byte, error) {
	key, _, err := s.storedWebhookSecret(ctx)
	if !errors.Is(err, pgx.ErrNoRows) {
		return key, err
	}
	// receivers can only exist once settings were saved or a channel exists
	var used bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='server') OR EXISTS(SELECT 1 FROM notification_channels)`).Scan(&used); err != nil {
		return nil, err
	}
	key = make([]byte, 32)
	if used {
		if key, err = hkdf.Key(sha256.New, s.cfg.SessionKey, nil, "limdm webhook signature v1", 32); err != nil {
			return nil, err
		}
	} else {
		rand.Read(key)
	}
	enc, err := s.sealField(webhookField, hex.EncodeToString(key))
	if err != nil {
		return nil, err
	}
	doc, _ := json.Marshal(map[string]string{"secret_enc": enc})
	// another instance starting at the same time may win: read what is stored
	if _, err := s.db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('webhook', $1) ON CONFLICT (key) DO NOTHING`, doc); err != nil {
		return nil, err
	}
	key, _, err = s.storedWebhookSecret(ctx)
	return key, err
}

// storedWebhookSecret opens the secret in the database.
func (s *Server) storedWebhookSecret(ctx context.Context) ([]byte, time.Time, error) {
	var enc string
	var at time.Time
	if err := s.db.QueryRow(ctx, `SELECT coalesce(value->>'secret_enc', ''), updated_at FROM settings WHERE key='webhook'`).Scan(&enc, &at); err != nil {
		return nil, at, err
	}
	plain, err := s.openField(webhookField, enc)
	if err != nil {
		return nil, at, fmt.Errorf("no session key opens it: %w", err)
	}
	key, err := hex.DecodeString(plain)
	if err == nil && len(key) < 32 {
		err = errors.New("too short")
	}
	return key, at, err
}

// webhookKey is the HMAC key receivers use to verify X-LiMDM-Signature.
func (s *Server) webhookKey() []byte { return s.whKey }

// rotateWebhook stores a new random secret. Like the other keys it is used
// after every server instance restarted; receivers need it before that.
func (s *Server) rotateWebhook(ctx context.Context, actor string) (string, error) {
	key := make([]byte, 32)
	rand.Read(key) // never fails since Go 1.24
	enc, err := s.sealField(webhookField, hex.EncodeToString(key))
	if err != nil {
		return "", err
	}
	doc, _ := json.Marshal(map[string]string{"secret_enc": enc})
	if err := s.auditAction(ctx, actor, "keys.rotate", kindWebhook, "new webhook signing secret "+fingerprint16(key), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('webhook', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, doc)
		return err
	}); err != nil {
		return "", err
	}
	s.keyNotice(notice{Type: "keys.rotate", Severity: "warning", Title: "Key rotation: webhook signing secret",
		Text: actor + " generated a new webhook signing secret; webhook receivers need it."})
	return "New webhook signing secret: " + hex.EncodeToString(key) + ". Give it to every webhook receiver. " + restartNote, nil
}

// webhookStatus is the Keys card row of the webhook secret: a short
// fingerprint, so receivers can be compared without showing the secret.
func (s *Server) webhookStatus(ctx context.Context) (KeyStatus, error) {
	key, at, err := s.storedWebhookSecret(ctx)
	if errors.Is(err, pgx.ErrNoRows) { // created when a server instance starts
		return KeyStatus{Kind: kindWebhook, Active: "-", Location: "database (sealed)"}, nil
	}
	if err != nil {
		return KeyStatus{}, fmt.Errorf("webhook secret: %w", err)
	}
	return KeyStatus{Kind: kindWebhook, Active: fingerprint16(key), Since: at, Location: "database (sealed)",
		Restart: s.whKey != nil && fingerprint16(s.whKey) != fingerprint16(key)}, nil
}

func fingerprint16(key []byte) string { return sha256Hex(key)[:16] }
