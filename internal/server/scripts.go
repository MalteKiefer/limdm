package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// scriptResultsKept is how many script results a device keeps.
const scriptResultsKept = 200

// storeScriptResults keeps the structured results of script commands and
// recurring scripts a check in carries, the newest scriptResultsKept per device.
func storeScriptResults(ctx context.Context, tx pgx.Tx, id string, req api.CheckinRequest) error {
	var results []api.ScriptResult
	for _, r := range req.Results {
		if r.Script != nil {
			res := *r.Script
			res.CommandID, res.Name = r.ID, "" // the command it answers, not what the device claims
			results = append(results, res)
		}
	}
	for _, r := range req.ScriptResults {
		r.CommandID = 0
		results = append(results, r)
	}
	if len(results) > 100 {
		results = results[len(results)-100:]
	}
	for _, r := range results {
		var cmd *int64
		if r.CommandID != 0 {
			cmd = &r.CommandID
		}
		// a command result only for this device's own script commands
		if _, err := tx.Exec(ctx, `INSERT INTO script_results(device_id, command_id, name, exit_code, stdout, stderr, started_at, ended_at)
			SELECT $1, $2::bigint, $3, $4, $5, $6, $7, $8
			WHERE $2::bigint IS NULL OR EXISTS (SELECT 1 FROM commands WHERE id=$2::bigint AND device_id=$1 AND type='script')`, id, cmd, truncate(r.Name, 64), r.ExitCode,
			truncate(r.Stdout, api.MaxScriptOutput), truncate(r.Stderr, api.MaxScriptOutput), r.Start, r.End); err != nil {
			return err
		}
	}
	if len(results) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `DELETE FROM script_results WHERE device_id=$1 AND id NOT IN
		(SELECT id FROM script_results WHERE device_id=$1 ORDER BY id DESC LIMIT $2)`, id, scriptResultsKept)
	return err
}

// scriptCommandPayload builds the payload of a script command from the
// form: the plain body (understood by every agent) or, with parameters
// ("NAME=value" lines) or a timeout, an api.ScriptCommand.
func scriptCommandPayload(r *http.Request) (string, error) {
	body := r.FormValue("payload")
	if strings.TrimSpace(body) == "" {
		return "", errors.New("the script is empty")
	}
	sc := api.ScriptCommand{Body: body, Params: map[string]string{}}
	for _, line := range strings.Split(r.FormValue("params"), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return "", fmt.Errorf("parameter line %q: NAME=value", line)
		}
		sc.Params[strings.TrimSpace(k)] = v
	}
	if t := strings.TrimSpace(r.FormValue("timeout_minutes")); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil {
			return "", errors.New("timeout: minutes as a number")
		}
		sc.TimeoutMinutes = n
	}
	if err := api.ValidateScriptParams(sc.Params, sc.TimeoutMinutes); err != nil {
		return "", err
	}
	if len(sc.Params) == 0 && sc.TimeoutMinutes == 0 {
		return body, nil
	}
	b, err := json.Marshal(sc)
	return string(b), err
}
