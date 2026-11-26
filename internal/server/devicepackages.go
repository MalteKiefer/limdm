package server

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// savePackages replaces the package list of a device by writing only the
// difference: a check in after an update touches the changed rows, not the
// thousands of unchanged ones (and no large JSONB row with its TOAST).
func savePackages(ctx context.Context, tx pgx.Tx, id string, pkgs []api.Package, hash string) error {
	names, versions, archs := make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		names, versions, archs = append(names, truncate(p.Name, 200)), append(versions, truncate(p.Version, 200)), append(archs, truncate(p.Arch, 50))
	}
	_, err := tx.Exec(ctx, `WITH n(name, version, arch) AS (SELECT * FROM unnest($2::text[], $3::text[], $4::text[])),
		gone AS (DELETE FROM device_packages p WHERE p.device_id = $1
			AND NOT EXISTS (SELECT 1 FROM n WHERE n.name = p.name AND n.version = p.version AND n.arch = p.arch))
		INSERT INTO device_packages(device_id, name, version, arch) SELECT $1, name, version, arch FROM n ON CONFLICT DO NOTHING`,
		id, names, versions, archs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE devices SET packages_hash=$2 WHERE id=$1`, id, hash)
	return err
}

// devicePackages lists the packages of a device by name.
func devicePackages(ctx context.Context, q querier, id string) ([]api.Package, error) {
	rows, err := q.Query(ctx, `SELECT name, version, arch FROM device_packages WHERE device_id=$1 ORDER BY name, arch, version`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[api.Package])
}
