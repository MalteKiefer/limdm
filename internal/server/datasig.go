package server

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Catalog apps, managed Flatpak remotes and the user list of a device make
// devices act as root (packages, repositories, sudo membership). Like
// library items they are signed with the command key when an admin saves
// them, never when they are delivered: whoever can only write to the
// database cannot have them signed. Delivery checks the signature, and the
// agent checks it again with its pinned key (api.CheckinResponse.SignedData).

// signData signs msg with the command key; "" without a key.
func signData(msg []byte) string {
	if itemKey == nil {
		return ""
	}
	sig, err := signEd25519(itemKey, msg)
	if err != nil {
		slog.Error("signing data", "err", err) // unsigned: withheld from devices
		return ""
	}
	return hex.EncodeToString(sig)
}

// dataSigOK checks a signature against the command key and, while a
// rotation runs, the previous one.
func dataSigOK(msg []byte, sig string) bool {
	if itemKey == nil {
		return true // no key (tools without the CA directory)
	}
	return api.VerifySigned(itemKey.Public().(ed25519.PublicKey), msg, sig) ||
		(itemPrevKey != nil && api.VerifySigned(itemPrevKey, msg, sig))
}

// signCatalogApp signs an app as it reads back from the database, inside
// the transaction of the admin action that wrote it.
func (s *Server) signCatalogApp(ctx context.Context, tx pgx.Tx, slug string) error {
	apps, err := s.catalogApps(ctx, tx, `WHERE slug=$1`, slug)
	if err != nil || len(apps) == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE catalog_apps SET signature=$2 WHERE slug=$1`, slug, signData(api.CatalogAppSigned(apps[0].CatalogApp)))
	return err
}

// errChangedOutside refuses a partial change of a row whose signature does
// not verify: signing it would sign what someone wrote into the database.
var errChangedOutside = &userError{http.StatusConflict, "this entry was changed outside the console; save it again in full"}

// catalogAppIntact is checked before a change that keeps signed fields.
func (s *Server) catalogAppIntact(ctx context.Context, tx pgx.Tx, slug string) error {
	apps, err := s.catalogApps(ctx, tx, `WHERE slug=$1`, slug)
	if err != nil || len(apps) == 0 || dataSigOK(api.CatalogAppSigned(apps[0].CatalogApp), apps[0].Signature) {
		return err
	}
	return errChangedOutside
}

// catalogRemoteIntact is catalogAppIntact for a managed remote.
func (s *Server) catalogRemoteIntact(ctx context.Context, tx pgx.Tx, name string) error {
	var r api.CatalogRemote
	err := tx.QueryRow(ctx, `SELECT name, url, title, state, catalog_only, signature FROM catalog_remotes WHERE name=$1`, name).
		Scan(&r.Name, &r.URL, &r.Title, &r.State, &r.CatalogOnly, &r.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // the caller answers not found
	}
	if err != nil || dataSigOK(api.CatalogRemoteSigned(r), r.Signature) {
		return err
	}
	return errChangedOutside
}

// signCatalogRemote signs a managed remote like signCatalogApp.
func (s *Server) signCatalogRemote(ctx context.Context, tx pgx.Tx, name string) error {
	var r api.CatalogRemote
	err := tx.QueryRow(ctx, `SELECT name, url, title, state, catalog_only FROM catalog_remotes WHERE name=$1`, name).
		Scan(&r.Name, &r.URL, &r.Title, &r.State, &r.CatalogOnly)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // removed
		}
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE catalog_remotes SET signature=$2 WHERE name=$1`, name, signData(api.CatalogRemoteSigned(r)))
	return err
}

// signDeviceUsers signs the user list of a device like signCatalogApp.
func signDeviceUsers(ctx context.Context, tx pgx.Tx, id string) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT users FROM devices WHERE id=$1`, id).Scan(&raw); err != nil {
		return err
	}
	var users []api.User
	if err := json.Unmarshal(raw, &users); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE devices SET users_sig=$2 WHERE id=$1`, id, signData(api.UsersSigned(id, users)))
	return err
}

// storedData is one signed row: its table key, what is signed and the signature.
type storedData struct {
	table, key string
	id         any
	msg        []byte
	sig        string
}

// signedRows reads every catalog app, managed remote and device user list.
func (s *Server) signedRows(ctx context.Context) ([]storedData, error) {
	var out []storedData
	apps, err := s.catalogApps(ctx, s.db, ``)
	if err != nil {
		return nil, err
	}
	for _, a := range apps {
		out = append(out, storedData{"catalog_apps", "slug", a.ID, api.CatalogAppSigned(a.CatalogApp), a.Signature})
	}
	remotes, err := s.catalogRemotes(ctx, s.db)
	if err != nil {
		return nil, err
	}
	for _, r := range remotes {
		out = append(out, storedData{"catalog_remotes", "name", r.Name, api.CatalogRemoteSigned(r), r.Signature})
	}
	rows, err := s.db.Query(ctx, `SELECT id, users, users_sig FROM devices WHERE NOT retired`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sig string
		var raw []byte
		if err := rows.Scan(&id, &raw, &sig); err != nil {
			return nil, err
		}
		var users []api.User
		if err := json.Unmarshal(raw, &users); err != nil {
			return nil, fmt.Errorf("device %s users: %w", id, err)
		}
		out = append(out, storedData{"devices", "id", id, api.UsersSigned(id, users), sig})
	}
	return out, rows.Err()
}

// resignRows signs again the rows need selects, comparing the old
// signature so a concurrent save is not overwritten.
func (s *Server) resignRows(ctx context.Context, need func(storedData) bool) error {
	list, err := s.signedRows(ctx)
	if err != nil {
		return err
	}
	for _, d := range list {
		if !need(d) {
			continue
		}
		sig := signData(d.msg)
		if sig == "" {
			return fmt.Errorf("signing %s %v failed", d.table, d.id)
		}
		col := map[string]string{"devices": "users_sig"}[d.table]
		if col == "" {
			col = "signature"
		}
		if _, err := s.db.Exec(ctx, `UPDATE `+d.table+` SET `+col+`=$2 WHERE `+d.key+`=$1 AND `+col+`=$3`, d.id, sig, d.sig); err != nil {
			return err
		}
	}
	return nil
}

// signExistingData signs the unsigned rows once per installation, on the
// upgrade that introduced these signatures and on a fresh installation
// (seeded apps and remotes). The database records it (settings key
// data-signed-v1), so an instance added or rebuilt later never signs rows
// written into the database meanwhile; the caller holds lockStartup.
// Migrations that seed such rows later must sign them themselves.
func (s *Server) signExistingData(ctx context.Context) error {
	if itemKey == nil {
		return nil
	}
	var done bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='data-signed-v1')`).Scan(&done); err != nil || done {
		return err
	}
	// pre-release builds recorded it in a file next to the key
	if _, err := os.Stat(filepath.Join(s.cfg.CADir, "data-signed-v1")); err != nil {
		if err := s.resignRows(ctx, func(d storedData) bool { return d.sig == "" }); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('data-signed-v1', to_jsonb(now())) ON CONFLICT (key) DO NOTHING`)
	return err
}

// resignData signs again what carries a signature of the previous command
// key only, while a command key rotation runs (like resignItems).
func (s *Server) resignData(ctx context.Context) error {
	if s.kr.cmdPrev == nil {
		return nil
	}
	prev := s.kr.cmdPrev.Public().(ed25519.PublicKey)
	cur := s.cmdKey.Public().(ed25519.PublicKey)
	return s.resignRows(ctx, func(d storedData) bool {
		return !api.VerifySigned(cur, d.msg, d.sig) && api.VerifySigned(prev, d.msg, d.sig)
	})
}
