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
	names, versions, archs, sources := make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		names, versions, archs = append(names, truncate(p.Name, 200)), append(versions, truncate(p.Version, 200)), append(archs, truncate(p.Arch, 50))
		sources = append(sources, truncate(p.Source, 200))
	}
	// the source package (Debian, for the security trackers) is updated in
	// place: rows of agents that did not send it yet get it once they do
	_, err := tx.Exec(ctx, `WITH n(name, version, arch, source) AS (SELECT DISTINCT ON (u.name, u.version, u.arch) * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS u(name, version, arch, source)),
		gone AS (DELETE FROM device_packages p WHERE p.device_id = $1
			AND NOT EXISTS (SELECT 1 FROM n WHERE n.name = p.name AND n.version = p.version AND n.arch = p.arch))
		INSERT INTO device_packages(device_id, name, version, arch, source) SELECT $1, name, version, arch, source FROM n
		ON CONFLICT (device_id, name, version, arch) DO UPDATE SET source = EXCLUDED.source WHERE device_packages.source <> EXCLUDED.source`,
		id, names, versions, archs, sources)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE devices SET packages_hash=$2 WHERE id=$1`, id, hash)
	return err
}

// devicePackages lists the packages of a device by name.
func devicePackages(ctx context.Context, q querier, id string) ([]api.Package, error) {
	rows, err := q.Query(ctx, `SELECT name, version, arch, source FROM device_packages WHERE device_id=$1 ORDER BY name, arch, version`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[api.Package])
}
