package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// Agent updates. The server fetches releases from LIMDM_RELEASE_REPO on
// GitHub, verifies every agent package against the release's SHA256SUMS and
// keeps them in LIMDM_RELEASE_DIR. An admin approves a version; devices tagged
// "pilot" (configurable) get it at once, all others after delay_days plus a
// fixed offset per device within spread_hours (rolloutOffset). The
// agent installs the package itself and rolls back to the previous binary
// when the new one does not check in (see internal/agent/update.go); after
// rollbackLimit rollbacks a version is blocked automatically.

const rollbackLimit = 3

// UpdatePolicy is the rollout configuration (settings key "agent_updates").
type UpdatePolicy struct {
	Auto      bool   `json:"auto"`
	DelayDays int    `json:"delay_days"`
	PilotTag  string `json:"pilot_tag"`
	// SpreadHours spreads the devices after the delay over this window, each
	// at its own fixed offset, so a release does not reach the whole fleet in
	// the same minute (downloads, check ins with results, audit entries)
	SpreadHours int `json:"spread_hours"`
}

// rolloutOffset is the fixed point of a device within the rollout window of
// a version: the same device gets the same offset at every check in, and the
// devices are spread evenly over the window.
func rolloutOffset(deviceID, version string, spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(deviceID + "\x00" + version))
	return time.Duration(h.Sum64() % uint64(spread)) //nolint:gosec // spread is positive
}

func (s *Server) updatePolicy(ctx context.Context, q querier) (UpdatePolicy, error) {
	p := UpdatePolicy{DelayDays: 7, PilotTag: "pilot", SpreadHours: 24}
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

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// dueUpdate decides which agent version a device running "running" should
// install now, without changing anything: the version an admin picked for
// it, otherwise the newest approved version that is due by policy. A version
// that already failed on this device is not offered again unless an admin
// requests it. clearTarget reports a picked version that is already running.
func (s *Server) dueUpdate(ctx context.Context, q querier, deviceID, running string) (rel *agentRelease, clearTarget bool, err error) {
	pol, rels, err := s.rollout(ctx, q)
	if err != nil {
		return nil, false, err
	}
	var tags []string
	var requested bool
	var target, state, lastVersion string
	if err := q.QueryRow(ctx, `SELECT tags, update_requested, update_target, update_state, update_version FROM devices WHERE id=$1`, deviceID).
		Scan(&tags, &requested, &target, &state, &lastVersion); err != nil {
		return nil, false, err
	}
	if requested && target != "" {
		// a version an admin picked for this device counts as its approval;
		// agents never downgrade, so an older pick is dropped instead of
		// being offered (and making the device poll) forever
		if target == running || !api.NewerVersion(target, running) {
			return nil, true, nil
		}
		var r agentRelease
		err := q.QueryRow(ctx, `SELECT `+agentReleaseCols+` FROM agent_releases WHERE version=$1 AND NOT blocked`, target).
			Scan(&r.Version, &r.PublishedAt, &r.Sums, &r.SumsSig, &r.ApprovedAt, &r.ApprovedBy, &r.Blocked, &r.BlockedReason)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil // blocked meanwhile
		}
		if err != nil {
			return nil, false, err
		}
		return &r, false, nil
	}
	if !pol.Auto && !requested {
		return nil, false, nil
	}
	pilot := pol.PilotTag != "" && slices.ContainsFunc(tags, func(t string) bool { return strings.EqualFold(t, pol.PilotTag) })
	for _, r := range rels {
		due := requested || pilot ||
			time.Since(*r.ApprovedAt) >= time.Duration(pol.DelayDays)*24*time.Hour+rolloutOffset(deviceID, r.Version, time.Duration(pol.SpreadHours)*time.Hour)
		failedHere := !requested && r.Version == lastVersion && (state == "failed" || state == "rolled_back")
		if !due || failedHere || !api.NewerVersion(r.Version, running) {
			continue
		}
		return &r, false, nil
	}
	return nil, false, nil
}

// rolloutCache is the update policy and the approved releases, newest
// first, as the poll of every device needs them (rollout).
type rolloutCache struct {
	at   time.Time
	pol  UpdatePolicy
	rels []agentRelease
}

// rollout loads the update policy and the approved, unblocked releases.
// Reads through the pool (the minute poll of every device) share a copy for
// up to 30 seconds; changes on this instance drop it at once (forgetRollout),
// those of other instances arrive within that time. Reads inside a
// transaction (the check in) always read fresh.
func (s *Server) rollout(ctx context.Context, q querier) (UpdatePolicy, []agentRelease, error) {
	_, pooled := q.(*pgxpool.Pool)
	if c := s.rolloutC.Load(); pooled && c != nil && time.Since(c.at) < 30*time.Second {
		return c.pol, c.rels, nil
	}
	pol, err := s.updatePolicy(ctx, q)
	if err != nil {
		return pol, nil, err
	}
	rows, err := q.Query(ctx, `SELECT `+agentReleaseCols+` FROM agent_releases WHERE approved_at IS NOT NULL AND NOT blocked`)
	if err != nil {
		return pol, nil, err
	}
	rels, err := pgx.CollectRows(rows, pgx.RowToStructByPos[agentRelease])
	if err != nil {
		return pol, nil, err
	}
	slices.SortFunc(rels, func(a, b agentRelease) int { return api.CompareVersions(b.Version, a.Version) })
	if pooled {
		s.rolloutC.Store(&rolloutCache{time.Now(), pol, rels})
	}
	return pol, rels, nil
}

// forgetRollout drops the cached rollout after a change of releases or policy.
func (s *Server) forgetRollout() { s.rolloutC.Store(nil) }

// offerUpdate hands the due version to the device in this check in.
func (s *Server) offerUpdate(ctx context.Context, tx pgx.Tx, deviceID, running string) (*api.AgentUpdate, error) {
	r, clearTarget, err := s.dueUpdate(ctx, tx, deviceID, running)
	if err != nil {
		return nil, err
	}
	if clearTarget {
		_, err := tx.Exec(ctx, `UPDATE devices SET update_requested=false, update_target='' WHERE id=$1`, deviceID)
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET update_state='offered', update_version=$2, update_at=now() WHERE id=$1
		AND (update_state <> 'offered' OR update_version <> $2)`, deviceID, r.Version); err != nil {
		return nil, err
	}
	return &api.AgentUpdate{Version: r.Version, Sums: r.Sums, SumsSig: r.SumsSig}, nil
}

// recordUpdateResult stores what the agent reports and blocks a version that
// keeps rolling back.
func (s *Server) recordUpdateResult(ctx context.Context, tx pgx.Tx, deviceID string, res *api.UpdateResult) error {
	if res == nil || !api.PackageRe.MatchString(api.PackageName(res.To, "amd64", "deb")) {
		return nil
	}
	// agents before 0.17 report a download refused for load (503) as a failed
	// update; it says nothing about the version and must not block it
	if !res.OK && !res.RolledBack && strings.Contains(res.Detail, "503 Service Unavailable") {
		return nil
	}
	state := "failed"
	switch {
	case res.OK:
		state = "ok"
	case res.RolledBack:
		state = "rolled_back"
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET update_state=$2, update_version=$3, update_at=now(), update_requested=false, update_target='' WHERE id=$1`,
		deviceID, state, truncate(res.To, 32)); err != nil {
		return err
	}
	if err := audit(ctx, tx, "device:"+deviceID, "agent.update", deviceID, fmt.Sprintf("%s -> %s: %s %s", truncate(res.From, 32), truncate(res.To, 32), state, truncate(res.Detail, 500))); err != nil {
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
	s.forgetRollout()
	tag, err := tx.Exec(ctx, `UPDATE agent_releases SET blocked=true, blocked_reason=$2 WHERE version=$1 AND NOT blocked`,
		res.To, fmt.Sprintf("%d devices failed or rolled back", n))
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return audit(ctx, tx, "system", "agent_release.block", res.To, fmt.Sprintf("blocked automatically after %d failed updates", n))
}

// agentPackage serves a package of an approved release to devices (mTLS).
// downloadWait is how long a package download waits for a free slot.
var downloadWait = 20 * time.Second

func (s *Server) agentPackage(w http.ResponseWriter, r *http.Request) {
	version, file := r.PathValue("version"), r.PathValue("file")
	m := api.PackageRe.FindStringSubmatch(file)
	if m == nil || m[1] != version {
		http.NotFound(w, r)
		return
	}
	var sums string
	device, _ := r.Context().Value(deviceKey).(string)
	err := s.db.QueryRow(r.Context(), `SELECT sums FROM agent_releases WHERE version=$1 AND NOT blocked
		AND (approved_at IS NOT NULL OR EXISTS (SELECT 1 FROM devices WHERE id=$2 AND update_target=$1))`, version, device).Scan(&sums)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := api.SumsEntry(sums, file); err != nil {
		http.NotFound(w, r)
		return
	}
	// a bounded number of downloads at once: the rest waits a little, then is
	// asked to come back (the agent honors Retry-After and retries later)
	if sem := s.downloads.get(); sem != nil {
		t := time.NewTimer(downloadWait)
		defer t.Stop()
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-t.C:
			retryLater(w, 60+mrand.IntN(240), "too many agent package downloads, retry later") //nolint:gosec // jitter, not a secret
			return
		case <-r.Context().Done():
			return
		}
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
		if time.Since(rel.PublishedAt) < 10*time.Minute {
			continue // the release workflow uploads the signature after publishing
		}
		var sig *string
		if err := s.db.QueryRow(ctx, `SELECT sums_sig FROM agent_releases WHERE version=$1`, version).Scan(&sig); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return n, err
		}
		// imported by another instance but not here yet: every instance
		// keeps its own copy of the packages it serves
		_, statErr := os.Stat(filepath.Join(s.cfg.ReleaseDir, version, api.PackageName(version, "amd64", "deb")))
		if sig != nil && statErr == nil {
			if *sig == "" { // fetched before the signature was uploaded
				if err := s.addReleaseSignature(ctx, version, rel); err != nil {
					s.log.Warn("release signature", "version", version, "err", err)
				}
			}
			continue
		}
		if err := s.fetchRelease(ctx, version, rel); err != nil {
			return n, fmt.Errorf("%s: %w", version, err)
		}
		n++
	}
	return n, nil
}

// addReleaseSignature stores the SHA256SUMS signature of a release that was
// imported without one.
func (s *Server) addReleaseSignature(ctx context.Context, version string, rel ghRelease) error {
	name := "limdm_" + version + "_SHA256SUMS.sig"
	for _, a := range rel.Assets {
		if a.Name == name {
			sig, err := getBytes(ctx, a.URL, 4<<10)
			if err != nil {
				return err
			}
			_, err = s.db.Exec(ctx, `UPDATE agent_releases SET sums_sig=$2 WHERE version=$1 AND sums_sig=''`, version, strings.TrimSpace(string(sig)))
			return err
		}
	}
	return nil
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
	// callers pass GitHub release assets or dl.flathub.org icons (flathubIconURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // fixed hosts, see above
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "limdm-server")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := releaseClient.Do(req) //nolint:gosec // fixed hosts, see above
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

// outdatedDevice is a device behind the newest approved agent version.
type outdatedDevice struct {
	ID, Hostname, Version string
	LastSeen              *time.Time
}

// agentsView is what the agents page shows; the admin API serves it too.
type agentsView struct {
	Policy   UpdatePolicy
	Releases []releaseView // newest first
	Fleet    []versionCount
	Latest   string
	Outdated []outdatedDevice
}

// agentsOverview reads the update policy, the releases with their spread
// and the devices behind the newest approved version.
func (s *Server) agentsOverview(ctx context.Context) (agentsView, error) {
	var v agentsView
	var err error
	if v.Policy, err = s.updatePolicy(ctx, s.db); err != nil {
		return v, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+agentReleaseCols+`,
		(SELECT count(*) FROM devices d WHERE NOT d.retired AND split_part(d.agent_version, '-', 1) = r.version),
		(SELECT count(*) FROM devices d WHERE d.update_version = r.version AND d.update_state IN ('rolled_back','failed'))
		FROM agent_releases r`)
	if err != nil {
		return v, err
	}
	v.Releases, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (releaseView, error) {
		var v releaseView
		return v, row.Scan(&v.Version, &v.PublishedAt, &v.Sums, &v.SumsSig, &v.ApprovedAt, &v.ApprovedBy, &v.Blocked, &v.BlockedReason, &v.Devices, &v.Failed)
	})
	if err != nil {
		return v, err
	}
	slices.SortFunc(v.Releases, func(a, b releaseView) int { return api.CompareVersions(b.Version, a.Version) })
	rows, err = s.db.Query(ctx, `SELECT agent_version, count(*) FROM devices WHERE NOT retired GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return v, err
	}
	if v.Fleet, err = pgx.CollectRows(rows, pgx.RowToStructByPos[versionCount]); err != nil {
		return v, err
	}
	// devices behind the newest approved version (or the newest known one)
	for _, rel := range v.Releases {
		if !rel.Blocked && (rel.ApprovedAt != nil || v.Latest == "") {
			v.Latest = rel.Version
			if rel.ApprovedAt != nil {
				break
			}
		}
	}
	if v.Latest != "" {
		rows, err = s.db.Query(ctx, `SELECT id, hostname, agent_version, last_seen FROM devices WHERE NOT retired ORDER BY hostname`)
		if err != nil {
			return v, err
		}
		all, err := pgx.CollectRows(rows, pgx.RowToStructByPos[outdatedDevice])
		if err != nil {
			return v, err
		}
		for _, d := range all {
			if api.NewerVersion(v.Latest, d.Version) {
				v.Outdated = append(v.Outdated, d)
			}
		}
	}
	return v, nil
}

// saveUpdatePolicy validates and stores the agent update policy.
func (s *Server) saveUpdatePolicy(ctx context.Context, sess session, pol UpdatePolicy) error {
	pol.PilotTag = strings.ToLower(strings.TrimSpace(pol.PilotTag))
	if pol.DelayDays < 0 || pol.DelayDays > 90 || (pol.PilotTag != "" && (!identOK(pol.PilotTag) || len(pol.PilotTag) > 32)) {
		return &userError{http.StatusUnprocessableEntity, "The delay must be 0 to 90 days and the pilot tag a simple word."}
	}
	if pol.SpreadHours < 0 || pol.SpreadHours > 720 {
		return &userError{http.StatusUnprocessableEntity, "The rollout window must be 0 to 720 hours."}
	}
	doc, _ := json.Marshal(pol)
	defer s.forgetRollout()
	return s.auditAction(ctx, sess.Email, "agent_updates.policy", "agent", string(doc), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('agent_updates', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, string(doc))
		return err
	})
}

// versionCount is the number of devices running an agent version.
type versionCount struct {
	Version string
	N       int
}

// splitOlder moves versions below the oldest agent in use, and not running
// anywhere, out of the default list (rels sorted newest first). Without
// devices the three newest stay.
func splitOlder(rels []releaseView, fleet []versionCount) (current, older []releaseView) {
	oldest := ""
	for _, v := range fleet {
		if v.Version != "" && (oldest == "" || api.NewerVersion(oldest, v.Version)) {
			oldest = v.Version
		}
	}
	for i, r := range rels {
		old := r.Devices == 0 && r.Failed == 0
		if oldest != "" {
			old = old && api.NewerVersion(oldest, r.Version)
		} else {
			old = old && i >= 3
		}
		if old {
			older = append(older, r)
		} else {
			current = append(current, r)
		}
	}
	return current, older
}

// requestAgentUpdate marks a device for an agent update at its next check
// in: target is an approved, unblocked version, or empty for the newest.
// errNotFound when the device is unknown or retired.
func (s *Server) requestAgentUpdate(ctx context.Context, actor, id, target string) error {
	if target != "" {
		var ok bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_releases WHERE version=$1 AND NOT blocked)`, target).Scan(&ok); err != nil || !ok {
			return &userError{http.StatusBadRequest, "unknown or blocked version"}
		}
	}
	return s.auditAction(ctx, actor, "agent_update.request", id, target, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET update_requested=true, update_target=$2 WHERE id=$1 AND NOT retired`, id, target)
		if err == nil && tag.RowsAffected() == 0 {
			err = errNotFound
		}
		return err
	})
}

var (
	errNotFound       = errors.New("not found")
	errUnknownVersion = errors.New("unknown version")
)

// releaseOp approves or blocks an agent version.
func (s *Server) releaseOp(ctx context.Context, sess session, version, op string) error {
	q := map[string]string{
		"approve": `UPDATE agent_releases SET approved_at=now(), approved_by=$2, blocked=false, blocked_reason='' WHERE version=$1`,
		"block":   `UPDATE agent_releases SET blocked=true, blocked_reason='blocked by ' || $2 WHERE version=$1`,
	}[op]
	if q == "" {
		return &userError{http.StatusNotFound, "not found"}
	}
	defer s.forgetRollout()
	err := s.auditAction(ctx, sess.Email, "agent_release."+op, version, "", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, q, version, sess.Email)
		if err == nil && tag.RowsAffected() == 0 {
			err = errUnknownVersion
		}
		return err
	})
	if errors.Is(err, errUnknownVersion) {
		return &userError{http.StatusNotFound, "Unknown version."}
	}
	return err
}
