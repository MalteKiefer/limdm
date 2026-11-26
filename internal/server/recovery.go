package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	reason := strings.TrimSpace(r.FormValue("reason"))
	if len(reason) > 500 || strings.ContainsAny(reason, "\x00\r\n") {
		s.errorPage(w, r, sess, http.StatusBadRequest, "reason: up to 500 characters on one line")
		return
	}
	if !s.inScope(ctx, sess, id) {
		http.NotFound(w, r)
		return
	}
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
	view := map[string]any{"ID": id, "Host": host, "Path": path, "UUID": uuid}
	approvedBy := ""
	if s.settings().FourEyesRecovery {
		// an approved request of this viewer for this volume opens the key once
		var aid int64
		var by, aReason string
		err := tx.QueryRow(ctx, `SELECT id, decided_by, reason FROM approvals WHERE action='recovery.view' AND target=$1 AND payload->>'uuid'=$2
			AND requested_by=$3 AND status='approved' AND expires_at > now() ORDER BY id DESC LIMIT 1 FOR UPDATE`, id, uuid, sess.Email).Scan(&aid, &by, &aReason)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			_ = tx.Rollback(ctx)
			var pending bool
			if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM approvals WHERE action='recovery.view' AND target=$1 AND payload->>'uuid'=$2
				AND requested_by=$3 AND status='pending' AND expires_at > now())`, id, uuid, sess.Email).Scan(&pending); err != nil {
				s.fail(w, err)
				return
			}
			switch {
			case pending:
				view["State"] = "pending"
			case reason == "":
				view["State"] = "reason"
			default:
				if _, err := s.requestApproval(ctx, sess, "recovery.view", id, map[string]string{"uuid": uuid, "device": path}, reason); err != nil {
					s.fail(w, err)
					return
				}
				view["State"] = "requested"
			}
			w.Header().Set("Cache-Control", "no-store")
			s.render(w, r, sess, "recovery", view)
			return
		case err != nil:
			s.fail(w, err)
			return
		}
		if _, err := tx.Exec(ctx, `UPDATE approvals SET status='used' WHERE id=$1`, aid); err != nil {
			s.fail(w, err)
			return
		}
		reason, approvedBy = aReason, fmt.Sprintf(" approval #%d by %s", aid, by)
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
	if _, err := tx.Exec(ctx, `UPDATE recovery_keys SET viewed_at=now(), viewed_by=$3, rotate=rotate OR $4 WHERE device_id=$1 AND uuid=$2`,
		id, uuid, sess.Email, rotate); err != nil {
		s.fail(w, err)
		return
	}
	detail := path + " " + uuid
	if reason != "" {
		detail += fmt.Sprintf(" reason=%q", reason)
	}
	if err := audit(ctx, tx, sess.Email, "recovery.view", id, detail+approvedBy); err != nil {
		s.fail(w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.fail(w, err)
		return
	}
	s.notifyDevice(id, []notice{{Type: "recovery.view", Severity: "warning", Title: "Recovery key viewed",
		Text: fmt.Sprintf("%s viewed the recovery key of %s. Reason: %s.", sess.Email, path, firstNonEmpty(reason, "none given"))}})
	w.Header().Set("Cache-Control", "no-store")
	view["Key"], view["Rotate"] = key, rotate
	s.render(w, r, sess, "recovery", view)
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
			cmds[i].Keys = append(cmds[i].Keys, api.RecoveryKey{UUID: k.UUID, Device: k.Path, Key: plain})
		}
		// the payload stays as signed; the keys travel beside it
	}
	return nil
}
