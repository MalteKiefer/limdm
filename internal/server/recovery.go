package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// LUKS recovery keys are sealed with AES-256-GCM under a key derived from the
// session key; device and volume are bound as additional data, so a sealed
// key cannot be moved to another row. Every view is audited and can trigger
// a rotation on the device.

func (s *Server) sealRecovery(deviceID, uuid, key string) ([]byte, error) {
	a, err := s.aead(infoRecovery)
	if err != nil {
		return nil, err
	}
	return seal(a, []byte(key), []byte(deviceID+"|"+uuid)), nil
}

func (s *Server) openRecovery(deviceID, uuid string, sealed []byte) (string, error) {
	a, err := s.aead(infoRecovery)
	if err != nil {
		return "", err
	}
	plain, err := open(a, sealed, []byte(deviceID+"|"+uuid))
	return string(plain), err
}

// escrowKeys stores keys from a check in; a new key ends a pending rotation.
func (s *Server) escrowKeys(ctx context.Context, tx pgx.Tx, deviceID string, keys []api.RecoveryKey) error {
	for _, k := range keys {
		if !k.Valid() {
			return errors.New("invalid recovery key")
		}
		sealed, err := s.sealRecovery(deviceID, k.UUID, k.Key)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_keys(device_id, uuid, device_path, sealed, escrowed_at)
			VALUES ($1,$2,$3,$4,now()) ON CONFLICT (device_id, uuid) DO UPDATE SET device_path=EXCLUDED.device_path,
			sealed=EXCLUDED.sealed, escrowed_at=now(), viewed_at=NULL, viewed_by=NULL, rotate=false`,
			deviceID, k.UUID, k.Device, sealed); err != nil {
			return err
		}
		if err := audit(ctx, tx, "device:"+deviceID, "recovery.escrow", deviceID, k.Device+" "+k.UUID); err != nil {
			return err
		}
	}
	return nil
}

// rotations returns the current keys of volumes marked for rotation.
func (s *Server) rotations(ctx context.Context, tx pgx.Tx, deviceID string) ([]api.RecoveryKey, error) {
	rows, err := tx.Query(ctx, `SELECT uuid, device_path, sealed FROM recovery_keys WHERE device_id=$1 AND rotate`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []api.RecoveryKey
	for rows.Next() {
		var k api.RecoveryKey
		var sealed []byte
		if err := rows.Scan(&k.UUID, &k.Device, &sealed); err != nil {
			return nil, err
		}
		if k.Key, err = s.openRecovery(deviceID, k.UUID, sealed); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

type recoveryRow struct {
	UUID, Device string
	Escrowed     time.Time
	ViewedAt     *time.Time
	ViewedBy     *string
	Rotate       bool
}

func (s *Server) recoveryKeys(ctx context.Context, deviceID string) ([]recoveryRow, error) {
	rows, err := s.db.Query(ctx, `SELECT uuid, device_path, escrowed_at, viewed_at, viewed_by, rotate FROM recovery_keys
		WHERE device_id=$1 ORDER BY device_path`, deviceID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (recoveryRow, error) {
		var k recoveryRow
		return k, r.Scan(&k.UUID, &k.Device, &k.Escrowed, &k.ViewedAt, &k.ViewedBy, &k.Rotate)
	})
}

// recoveryView reveals one key to admins and helpdesk (POST with CSRF) and audits it.
func (s *Server) recoveryView(w http.ResponseWriter, r *http.Request, sess session) {
	ctx := r.Context()
	id, uuid := r.PathValue("id"), r.FormValue("uuid")
	tx, err := s.db.Begin(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var path, host string
	var sealed []byte
	err = tx.QueryRow(ctx, `SELECT k.device_path, k.sealed, d.hostname FROM recovery_keys k JOIN devices d ON d.id=k.device_id
		WHERE k.device_id=$1 AND k.uuid=$2`, id, uuid).Scan(&path, &sealed, &host)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	key, err := s.openRecovery(id, uuid, sealed)
	if err != nil {
		s.fail(w, err)
		return
	}
	decls, err := effectiveDeclarations(ctx, tx, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	pol, _ := api.Compose(decls)
	rotate := pol.Extra.DiskEncryption != nil && pol.Extra.DiskEncryption.RotateAfterView
	if _, err := tx.Exec(ctx, `UPDATE recovery_keys SET viewed_at=now(), viewed_by=$3, rotate=$4 WHERE device_id=$1 AND uuid=$2`,
		id, uuid, sess.Email, rotate); err != nil {
		s.fail(w, err)
		return
	}
	if err := audit(ctx, tx, sess.Email, "recovery.view", id, path+" "+uuid); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, sess, "recovery", map[string]any{"ID": id, "Host": host, "Path": path, "UUID": uuid, "Key": key, "Rotate": rotate})
}

// attachRecoveryKeys adds the escrowed keys to "lost" commands at delivery:
// the agent needs them to keep the volumes recoverable while it removes every
// other key slot. They are sent over mTLS and never stored in the command.
func (s *Server) attachRecoveryKeys(ctx context.Context, tx pgx.Tx, deviceID string, cmds []api.Command) error {
	for i, c := range cmds {
		if c.Type != "lost" {
			continue
		}
		var lm api.LostMode
		if err := json.Unmarshal([]byte(c.Payload), &lm); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT uuid, device_path, sealed FROM recovery_keys WHERE device_id=$1`, deviceID)
		if err != nil {
			return err
		}
		type row struct {
			UUID, Path string
			Sealed     []byte
		}
		keys, err := pgx.CollectRows(rows, pgx.RowToStructByPos[row])
		if err != nil {
			return err
		}
		for _, k := range keys {
			plain, err := s.openRecovery(deviceID, k.UUID, k.Sealed)
			if err != nil {
				return err
			}
			lm.Keys = append(lm.Keys, api.RecoveryKey{UUID: k.UUID, Device: k.Path, Key: plain})
		}
		b, err := json.Marshal(lm)
		if err != nil {
			return err
		}
		cmds[i].Payload = string(b)
	}
	return nil
}
