package server

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	maxDiagnostics  = 1 << 20 // the agent sends at most 512 KiB
	diagnosticsKept = 10      // bundles per device
)

// diagRow is a collected diagnostics bundle on the device page.
type diagRow struct {
	CommandID int64
	Size      int
	At        time.Time
}

// storeDiagnostics keeps the log bundles of this device's own diagnostics
// commands, the newest diagnosticsKept per device.
func storeDiagnostics(ctx context.Context, tx pgx.Tx, id string, results []api.CommandResult) error {
	stored := false
	for _, r := range results {
		if r.Diagnostics == "" {
			continue
		}
		tag, err := tx.Exec(ctx, `INSERT INTO diagnostics(device_id, command_id, content)
			SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM commands WHERE id=$2 AND device_id=$1 AND type='diagnostics')
			ON CONFLICT (command_id) DO NOTHING`, id, r.ID, truncate(r.Diagnostics, maxDiagnostics))
		if err != nil {
			return err
		}
		stored = stored || tag.RowsAffected() > 0
	}
	if !stored {
		return nil
	}
	_, err := tx.Exec(ctx, `DELETE FROM diagnostics WHERE device_id=$1 AND command_id NOT IN
		(SELECT command_id FROM diagnostics WHERE device_id=$1 ORDER BY command_id DESC LIMIT $2)`, id, diagnosticsKept)
	return err
}

// diagnosticsList lists a device's bundles without their content.
func (s *Server) diagnosticsList(ctx context.Context, id string) ([]diagRow, error) {
	rows, err := s.db.Query(ctx, `SELECT command_id, length(content), created_at FROM diagnostics WHERE device_id=$1 ORDER BY command_id DESC`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[diagRow])
}

var fileNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// diagnosticsDownload hands out one bundle to admins and the helpdesk and
// records who read it.
func (s *Server) diagnosticsDownload(w http.ResponseWriter, r *http.Request, sess session) {
	if sess.Role != "admin" && sess.Role != "helpdesk" {
		http.Error(w, "diagnostics are available to admins and the helpdesk", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var content, host string
	err = s.db.QueryRow(ctx, `SELECT g.content, d.hostname FROM diagnostics g JOIN devices d ON d.id=g.device_id
		WHERE g.device_id=$1 AND g.command_id=$2`, id, cid).Scan(&content, &host)
	if errors.Is(err, pgx.ErrNoRows) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.auditAction(ctx, sess.Email, "device.diagnostics.download", id, "command "+strconv.FormatInt(cid, 10), func(pgx.Tx) error { return nil }); err != nil {
		s.fail(w, err)
		return
	}
	name := fileNameUnsafe.ReplaceAllString(host, "_") + "-diagnostics-" + strconv.FormatInt(cid, 10) + ".txt"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(content))
}
