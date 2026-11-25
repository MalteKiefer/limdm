package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Agent updates. The server fetches releases from LIMDM_RELEASE_REPO on
// GitHub, verifies every agent package against the release's SHA256SUMS and
// keeps them in LIMDM_RELEASE_DIR. An admin approves a version; devices tagged
// "pilot" (configurable) get it at once, all others after delay_days. The
// agent installs the package itself and rolls back to the previous binary
// when the new one does not check in (see internal/agent/update.go); after
// rollbackLimit rollbacks a version is blocked automatically.

const rollbackLimit = 3

// UpdatePolicy is the rollout configuration (settings key "agent_updates").
type UpdatePolicy struct {
	Auto      bool   `json:"auto"`
	DelayDays int    `json:"delay_days"`
	PilotTag  string `json:"pilot_tag"`
}

func (s *Server) updatePolicy(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (UpdatePolicy, error) {
	p := UpdatePolicy{DelayDays: 7, PilotTag: "pilot"}
	var raw []byte
	err := q.QueryRow(ctx, `SELECT value FROM settings WHERE key='agent_updates'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(raw, &p)
}

type agentRelease struct {
	Version       string
	PublishedAt   time.Time
	Sums, SumsSig string
	ApprovedAt    *time.Time
	ApprovedBy    *string
	Blocked       bool
	BlockedReason string
}

const agentReleaseCols = `version, published_at, sums, sums_sig, approved_at, approved_by, blocked, blocked_reason`

// offerUpdate decides whether a device gets an agent version in this check in.
func (s *Server) offerUpdate(ctx context.Context, tx pgx.Tx, deviceID, running string) (*api.AgentUpdate, error) {
	pol, err := s.updatePolicy(ctx, tx)
	if err != nil {
		return nil, err
	}
	var tags []string
	var requested bool
	if err := tx.QueryRow(ctx, `SELECT tags, update_requested FROM devices WHERE id=$1`, deviceID).Scan(&tags, &requested); err != nil {
		return nil, err
	}
	if !pol.Auto && !requested {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+agentReleaseCols+` FROM agent_releases WHERE approved_at IS NOT NULL AND NOT blocked`)
	if err != nil {
		return nil, err
	}
	rels, err := pgx.CollectRows(rows, pgx.RowToStructByPos[agentRelease])
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rels, func(a, b agentRelease) int { return api.CompareVersions(b.Version, a.Version) })
	pilot := pol.PilotTag != "" && slices.ContainsFunc(tags, func(t string) bool { return strings.EqualFold(t, pol.PilotTag) })
	for _, r := range rels {
		due := requested || pilot || time.Since(*r.ApprovedAt) >= time.Duration(pol.DelayDays)*24*time.Hour
		if !due || !api.NewerVersion(r.Version, running) {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET update_state='offered', update_version=$2, update_at=now() WHERE id=$1
			AND (update_state <> 'offered' OR update_version <> $2)`, deviceID, r.Version); err != nil {
			return nil, err
		}
		return &api.AgentUpdate{Version: r.Version, Sums: r.Sums, SumsSig: r.SumsSig}, nil
	}
	return nil, nil
}

// recordUpdateResult stores what the agent reports and blocks a version that
// keeps rolling back.
func (s *Server) recordUpdateResult(ctx context.Context, tx pgx.Tx, deviceID string, res *api.UpdateResult) error {
	if res == nil || !api.PackageRe.MatchString(api.PackageName(res.To, "amd64", "deb")) {
		return nil
	}
	state := "failed"
	switch {
	case res.OK:
		state = "ok"
	case res.RolledBack:
		state = "rolled_back"
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET update_state=$2, update_version=$3, update_at=now(), update_requested=false WHERE id=$1`,
		deviceID, state, res.To); err != nil {
		return err
	}
	if err := audit(ctx, tx, "device:"+deviceID, "agent.update", deviceID, fmt.Sprintf("%s -> %s: %s %s", res.From, res.To, state, truncate(res.Detail, 500))); err != nil {
		return err
	}
	if state == "ok" {
		return nil
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE update_version=$1 AND update_state IN ('rolled_back','failed')`, res.To).Scan(&n); err != nil {
		return err
	}
	if n < rollbackLimit {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_releases SET blocked=true, blocked_reason=$2 WHERE version=$1 AND NOT blocked`,
		res.To, fmt.Sprintf("%d devices failed or rolled back", n))
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return audit(ctx, tx, "system", "agent_release.block", res.To, fmt.Sprintf("blocked automatically after %d failed updates", n))
}

// agentPackage serves a package of an approved release to devices (mTLS).
func (s *Server) agentPackage(w http.ResponseWriter, r *http.Request) {
	version, file := r.PathValue("version"), r.PathValue("file")
	m := api.PackageRe.FindStringSubmatch(file)
	if m == nil || m[1] != version {
		http.NotFound(w, r)
		return
	}
	var sums string
	err := s.db.QueryRow(r.Context(), `SELECT sums FROM agent_releases WHERE version=$1 AND approved_at IS NOT NULL AND NOT blocked`, version).Scan(&sums)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := api.SumsEntry(sums, file); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filepath.Join(s.cfg.ReleaseDir, version, file))
}

// ---- fetching releases ----

type ghRelease struct {
	Tag         string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

var releaseClient = &http.Client{Timeout: 5 * time.Minute}

func (s *Server) releaseLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if n, err := s.fetchReleases(ctx); err != nil {
			s.log.Error("agent releases", "err", err)
		} else if n > 0 {
			s.log.Info("agent releases fetched", "new", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// fetchReleases downloads agent packages of new releases and verifies them
// against the release checksums. It returns the number of new versions.
func (s *Server) fetchReleases(ctx context.Context) (int, error) {
	if !repoNameRe.MatchString(s.cfg.ReleaseRepo) {
		return 0, nil
	}
	var rels []ghRelease
	if err := getJSON(ctx, "https://api.github.com/repos/"+s.cfg.ReleaseRepo+"/releases?per_page=5", &rels); err != nil {
		return 0, err
	}
	n := 0
	for _, rel := range rels {
		version := strings.TrimPrefix(rel.Tag, "v")
		if rel.Draft || rel.Prerelease || !api.PackageRe.MatchString(api.PackageName(version, "amd64", "deb")) {
			continue
		}
		var exists bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_releases WHERE version=$1)`, version).Scan(&exists); err != nil {
			return n, err
		}
		if exists {
			continue
		}
		if err := s.fetchRelease(ctx, version, rel); err != nil {
			return n, fmt.Errorf("%s: %w", version, err)
		}
		n++
	}
	return n, nil
}

func (s *Server) fetchRelease(ctx context.Context, version string, rel ghRelease) error {
	assets := map[string]string{}
	for _, a := range rel.Assets {
		assets[a.Name] = a.URL
	}
	sumsName := "limdm_" + version + "_SHA256SUMS"
	sums, err := getBytes(ctx, assets[sumsName], 1<<20)
	if err != nil {
		return fmt.Errorf("%s: %w", sumsName, err)
	}
	var sig []byte
	if u := assets[sumsName+".sig"]; u != "" {
		if sig, err = getBytes(ctx, u, 4<<10); err != nil {
			return err
		}
	}
	dir := filepath.Join(s.cfg.ReleaseDir, version)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	found := 0
	for name, u := range assets {
		if m := api.PackageRe.FindStringSubmatch(name); m == nil || m[1] != version {
			continue
		}
		want, err := api.SumsEntry(string(sums), name)
		if err != nil {
			return err
		}
		if err := download(ctx, u, filepath.Join(dir, name), want); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		found++
	}
	if found == 0 {
		return errors.New("release has no agent packages")
	}
	_, err = s.db.Exec(ctx, `INSERT INTO agent_releases(version, published_at, sums, sums_sig) VALUES ($1,$2,$3,$4) ON CONFLICT (version) DO NOTHING`,
		version, rel.PublishedAt, string(sums), strings.TrimSpace(string(sig)))
	return err
}

func githubRequest(ctx context.Context, u string) (*http.Response, error) {
	if !strings.HasPrefix(u, "https://") {
		return nil, errors.New("asset URL missing or not https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "limdm-server")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := releaseClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return resp, nil
}

func getJSON(ctx context.Context, u string, v any) error {
	b, err := getBytes(ctx, u, 4<<20)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func getBytes(ctx context.Context, u string, limit int64) ([]byte, error) {
	resp, err := githubRequest(ctx, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// download writes u to path when its SHA-256 matches; nothing is kept otherwise.
func download(ctx context.Context, u, path, wantHex string) error {
	resp, err := githubRequest(ctx, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 200<<20)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		return fmt.Errorf("checksum mismatch: %s", got)
	}
	return os.Rename(tmp.Name(), path)
}

// ---- console ----

type releaseView struct {
	agentRelease
	Devices, Failed int
}

func (s *Server) agentsPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderAgents(w, r, sess, "", "")
}

func (s *Server) renderAgents(w http.ResponseWriter, r *http.Request, sess session, msg, errMsg string) {
	ctx := r.Context()
	pol, err := s.updatePolicy(ctx, s.db)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, err := s.db.Query(ctx, `SELECT `+agentReleaseCols+`,
		(SELECT count(*) FROM devices d WHERE NOT d.retired AND split_part(d.agent_version, '-', 1) = r.version),
		(SELECT count(*) FROM devices d WHERE d.update_version = r.version AND d.update_state IN ('rolled_back','failed'))
		FROM agent_releases r`)
	if err != nil {
		s.fail(w, err)
		return
	}
	rels, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (releaseView, error) {
		var v releaseView
		return v, row.Scan(&v.Version, &v.PublishedAt, &v.Sums, &v.SumsSig, &v.ApprovedAt, &v.ApprovedBy, &v.Blocked, &v.BlockedReason, &v.Devices, &v.Failed)
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	slices.SortFunc(rels, func(a, b releaseView) int { return api.CompareVersions(b.Version, a.Version) })
	type versionCount struct {
		Version string
		N       int
	}
	rows, err = s.db.Query(ctx, `SELECT agent_version, count(*) FROM devices WHERE NOT retired GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		s.fail(w, err)
		return
	}
	fleet, err := pgx.CollectRows(rows, pgx.RowToStructByPos[versionCount])
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, sess, "agents", map[string]any{"Policy": pol, "Releases": rels, "Fleet": fleet, "Repo": s.cfg.ReleaseRepo,
		"Msg": msg, "Error": errMsg})
}

func (s *Server) agentsPolicy(w http.ResponseWriter, r *http.Request, sess session) {
	delay, err := strconv.Atoi(r.FormValue("delay_days"))
	pol := UpdatePolicy{Auto: r.FormValue("auto") == "on", DelayDays: delay, PilotTag: strings.ToLower(strings.TrimSpace(r.FormValue("pilot_tag")))}
	if err != nil || delay < 0 || delay > 90 || (pol.PilotTag != "" && (!identOK(pol.PilotTag) || len(pol.PilotTag) > 32)) {
		s.renderAgents(w, r, sess, "", "The delay must be 0 to 90 days and the pilot tag a simple word.")
		return
	}
	doc, _ := json.Marshal(pol)
	err = s.auditAction(r.Context(), sess.Email, "agent_updates.policy", "agent", string(doc), func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO settings(key, value) VALUES ('agent_updates', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderAgents(w, r, sess, "Settings saved and active.", "")
}

func (s *Server) agentsFetch(w http.ResponseWriter, r *http.Request, sess session) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if _, err := s.fetchReleases(ctx); err != nil {
		s.log.Warn("agent releases", "err", err)
		s.renderAgents(w, r, sess, "", "Fetching the releases failed, see the server log.")
		return
	}
	s.renderAgents(w, r, sess, "Versions checked.", "")
}

// deviceAgentUpdate lets the device take the newest approved version at its
// next check in, regardless of policy and delay.
func (s *Server) deviceAgentUpdate(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	err := s.auditAction(r.Context(), sess.Email, "agent_update.request", id, "", func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE devices SET update_requested=true WHERE id=$1 AND NOT retired`, id)
		if err == nil && tag.RowsAffected() == 0 {
			err = errNotFound
		}
		return err
	})
	if errors.Is(err, errNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/devices/"+id, http.StatusSeeOther)
}

var (
	errNotFound       = errors.New("not found")
	errUnknownVersion = errors.New("unknown version")
)

// agentsRelease approves, blocks or unblocks a version.
func (s *Server) agentsRelease(w http.ResponseWriter, r *http.Request, sess session) {
	version, op := r.PathValue("version"), r.PathValue("op")
	q := map[string]string{
		"approve": `UPDATE agent_releases SET approved_at=now(), approved_by=$2, blocked=false, blocked_reason='' WHERE version=$1`,
		"block":   `UPDATE agent_releases SET blocked=true, blocked_reason='blocked by ' || $2 WHERE version=$1`,
	}[op]
	if q == "" {
		http.NotFound(w, r)
		return
	}
	err := s.auditAction(r.Context(), sess.Email, "agent_release."+op, version, "", func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), q, version, sess.Email)
		if err == nil && tag.RowsAffected() == 0 {
			err = errUnknownVersion
		}
		return err
	})
	if errors.Is(err, errUnknownVersion) {
		s.renderAgents(w, r, sess, "", "Unknown version.")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}
