package server

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Compliance history: devices report only changes (DDM), and the server
// keeps one row per change of a check result, so the state of any device at
// any date can be reconstructed for audits.

// checkChanges returns the results whose status differs from the previous
// report, and the checks no longer reported with status "removed". Detail
// changes alone (pending update counts, versions) are not history.
func checkChanges(old, cur []api.CheckResult) []api.CheckResult {
	prev := make(map[string]string, len(old))
	for _, c := range old {
		prev[c.ID] = c.Status
	}
	var out []api.CheckResult
	seen := make(map[string]bool, len(cur))
	for _, c := range cur {
		seen[c.ID] = true
		if st, ok := prev[c.ID]; !ok || st != c.Status {
			out = append(out, c)
		}
	}
	for _, c := range old {
		if !seen[c.ID] {
			out = append(out, api.CheckResult{ID: c.ID, Status: "removed"})
		}
	}
	return out
}

// recordCheckChanges stores what changed against the checks the device row
// holds; call it before the row is updated with cur.
func recordCheckChanges(ctx context.Context, tx pgx.Tx, deviceID string, cur []api.CheckResult, catalog string) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT checks FROM devices WHERE id=$1`, deviceID).Scan(&raw); err != nil {
		return err
	}
	var old []api.CheckResult
	_ = json.Unmarshal(raw, &old) // a broken old report counts as none
	ch := checkChanges(old, cur)
	if len(ch) == 0 {
		return nil
	}
	ids, st, det := make([]string, len(ch)), make([]string, len(ch)), make([]string, len(ch))
	for i, c := range ch {
		ids[i], st[i], det[i] = truncate(c.ID, 100), truncate(c.Status, 20), truncate(c.Detail, 1000)
	}
	_, err := tx.Exec(ctx, `INSERT INTO compliance_changes(device_id, at, check_id, status, detail, catalog_version)
		SELECT $1::text, now(), i, s, d, $5::text FROM unnest($2::text[], $3::text[], $4::text[]) AS c(i, s, d)`, deviceID, ids, st, det, truncate(catalog, 32))
	return err
}

// historyStateSQL is the last known result per device and check before $1
// ($2: one device ID, or ” for all).
const historyStateSQL = `SELECT * FROM (SELECT DISTINCT ON (c.device_id, c.check_id) c.device_id, c.check_id, c.status, c.detail, c.at, c.catalog_version
	FROM compliance_changes c WHERE c.at < $1 AND ($2::text = '' OR c.device_id = $2)
	ORDER BY c.device_id, c.check_id, c.id DESC) s WHERE s.status <> 'removed'`

// historyParams reads the report date (default today) and device. The state
// is the one at the end of that day, server time.
func historyParams(q url.Values) (cutoff time.Time, device string, ok bool) {
	day := time.Now()
	if v := q.Get("at"); v != "" {
		d, err := time.ParseInLocation("2006-01-02", v, time.Local)
		if err != nil {
			return time.Time{}, "", false
		}
		day = d
	}
	y, m, d := day.Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.Local), q.Get("device"), true
}

type historyRow struct {
	DeviceID, Hostname, CheckID, Status, Detail string
	Since                                       time.Time
	Catalog                                     string
}

type historyDevice struct {
	ID, Hostname      string
	Pass, Fail, Other int
}

// historyState is the state of the devices in the scope of sess at cutoff,
// summed per device, and for one device also its changes (newest first, at
// most 500). The console page and the app API share it.
func (s *Server) historyState(ctx context.Context, sess session, cutoff time.Time, device string) (devices []*historyDevice, state, changes []historyRow, err error) {
	cond, sargs := scopeCond(sess, 2)
	rows, err := s.db.Query(ctx, `SELECT h.device_id, d.hostname, h.check_id, h.status, h.detail, h.at, h.catalog_version
		FROM (`+historyStateSQL+`) h JOIN devices d ON d.id = h.device_id WHERE `+cond+` ORDER BY d.hostname, h.device_id, h.check_id`, append([]any{cutoff, device}, sargs...)...)
	if err != nil {
		return nil, nil, nil, err
	}
	if state, err = pgx.CollectRows(rows, pgx.RowToStructByPos[historyRow]); err != nil {
		return nil, nil, nil, err
	}
	for _, h := range state {
		if len(devices) == 0 || devices[len(devices)-1].ID != h.DeviceID {
			devices = append(devices, &historyDevice{ID: h.DeviceID, Hostname: h.Hostname})
		}
		d := devices[len(devices)-1]
		switch h.Status {
		case "pass":
			d.Pass++
		case "fail":
			d.Fail++
		default:
			d.Other++
		}
	}
	if device != "" {
		rows, err := s.db.Query(ctx, `SELECT c.device_id, d.hostname, c.check_id, c.status, c.detail, c.at, c.catalog_version
			FROM compliance_changes c JOIN devices d ON d.id = c.device_id WHERE c.device_id = $1 AND c.at < $2 ORDER BY c.id DESC LIMIT 500`, device, cutoff)
		if err != nil {
			return nil, nil, nil, err
		}
		if changes, err = pgx.CollectRows(rows, pgx.RowToStructByPos[historyRow]); err != nil {
			return nil, nil, nil, err
		}
	}
	return devices, state, changes, nil
}
