package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// CVE data for Debian and Ubuntu (docs/patching.md#debian-and-ubuntu-cves).
// apt does not know which CVEs an update fixes, so the server imports the
// distributions' security data once a day (leader only) and matches the
// installed package versions the devices report against the fixed versions
// of their release. Nothing is requested on the devices.
//
// Sources: the Debian Security Tracker JSON (source package, CVE, release,
// fixed version, urgency), and for Ubuntu the OSV export Canonical
// publishes (UBUNTU-CVE records: source package, release, fixed version,
// Ubuntu priority). OSV is JSON with one record per CVE and plain fixed
// versions per release; OVAL is XML per release and the USN database has
// no priorities, so OSV is the most practical maintained source.
//
// Only what the matching needs is kept: distribution, release, source
// package, CVE, fixed version, severity. Downloads are bounded (size
// limit, timeout) and parsed as streams; a failed import keeps the last
// data and records the error.

const (
	defaultDebianFeed = "https://security-tracker.debian.org/tracker/data/json"
	defaultUbuntuFeed = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"
	defaultFeedMB     = 1024
	feedTimeout       = 30 * time.Minute
	cveFeedPeriod     = 24 * time.Hour
	cveRetryAfter     = 6 * time.Hour
	cveRecordMax      = 4 << 20 // one OSV record
	cveBatch          = 5000
)

// CVEFeedSettings is the settings section cve_feeds (Settings, CVE data).
// The feeds are off by default: they download from third parties.
type CVEFeedSettings struct {
	Enabled   bool   `json:"enabled"`
	DebianURL string `json:"debian_url,omitempty"` // empty: defaultDebianFeed
	UbuntuURL string `json:"ubuntu_url,omitempty"` // empty: defaultUbuntuFeed
	MaxMB     int    `json:"max_mb,omitempty"`     // download limit per feed, defaultFeedMB when 0
}

func (c CVEFeedSettings) urls() map[string]string {
	return map[string]string{"debian": firstNonEmpty(c.DebianURL, defaultDebianFeed), "ubuntu": firstNonEmpty(c.UbuntuURL, defaultUbuntuFeed)}
}

func (c CVEFeedSettings) limit() int64 {
	if c.MaxMB <= 0 {
		return defaultFeedMB << 20
	}
	return int64(c.MaxMB) << 20
}

// validate checks a saved section; it returns the message of the problem.
func (c CVEFeedSettings) validate() string {
	for _, u := range []string{c.DebianURL, c.UbuntuURL} {
		if u == "" {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "https" || p.Host == "" || len(u) > 500 {
			return "feed URLs must be https URLs"
		}
	}
	if c.MaxMB < 0 || c.MaxMB > 4096 {
		return "max_mb must be 0 (1024) to 4096"
	}
	return ""
}

// debianReleases maps Debian's VERSION_ID to the codename the tracker uses.
var debianReleases = map[string]string{"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}

// cveRelease is the distribution and release key a device's fixes are
// stored under (Debian: codename, Ubuntu: VERSION_ID such as 24.04).
func cveRelease(osID, version string) (string, string, bool) {
	switch osID {
	case "debian":
		major, _, _ := strings.Cut(version, ".")
		c, ok := debianReleases[major]
		return "debian", c, ok
	case "ubuntu":
		return "ubuntu", version, version != ""
	}
	return "", "", false
}

type cveFix struct {
	Release, Package, CVE, Fixed, Severity string
}

// debianUrgency maps the tracker's urgency to a severity; skip reports
// entries that are not worth showing (unimportant, end of life).
func debianUrgency(u string) (sev string, skip bool) {
	u = strings.TrimRight(strings.TrimSpace(u), "*")
	switch u {
	case "unimportant", "end-of-life":
		return "", true
	case "low", "medium", "high":
		return u, false
	}
	return "", false // not yet assigned
}

// parseDebianTracker streams the tracker JSON ({"source": {"CVE-…":
// {"releases": {"bookworm": {"status", "fixed_version", "urgency"}}}}})
// and hands every resolved fix of a known release to fn, one source
// package in memory at a time.
func parseDebianTracker(r io.Reader, fn func(cveFix) error) error {
	dec := json.NewDecoder(r)
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("debian tracker: %w", err)
	}
	if t != json.Delim('{') {
		return errors.New("debian tracker: not a JSON object")
	}
	known := map[string]bool{}
	for _, c := range debianReleases {
		known[c] = true
	}
	type rel struct {
		Status  string `json:"status"`
		Fixed   string `json:"fixed_version"`
		Urgency string `json:"urgency"`
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("debian tracker: %w", err)
		}
		pkg, _ := t.(string)
		var cves map[string]struct {
			Releases map[string]rel `json:"releases"`
		}
		if err := dec.Decode(&cves); err != nil {
			return fmt.Errorf("debian tracker %s: %w", pkg, err)
		}
		for id, c := range cves {
			if !cveRe.MatchString(id) {
				continue // TEMP- entries
			}
			for name, r := range c.Releases {
				sev, skip := debianUrgency(r.Urgency)
				if !known[name] || r.Status != "resolved" || r.Fixed == "" || r.Fixed == "0" || skip {
					continue
				}
				if err := fn(cveFix{Release: name, Package: pkg, CVE: id, Fixed: r.Fixed, Severity: sev}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// osvRecord is the part of an OSV record the Ubuntu import reads.
type osvRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixes turns an Ubuntu OSV record into fixes: the CVE ID, per affected
// release ("Ubuntu:24.04:LTS"; Ubuntu Pro releases are left out) the last
// fixed version of the source package.
func (o osvRecord) fixes() []cveFix {
	id := strings.TrimPrefix(o.ID, "UBUNTU-")
	if !cveRe.MatchString(id) {
		id = ""
		for _, a := range slices.Concat(o.Aliases, o.Upstream) {
			if cveRe.MatchString(a) {
				id = a
				break
			}
		}
	}
	if id == "" {
		return nil
	}
	sev := ""
	for _, s := range o.Severity {
		if s.Type == "Ubuntu" {
			sev = strings.ToLower(s.Score)
		}
	}
	var out []cveFix
	for _, a := range o.Affected {
		parts := strings.Split(a.Package.Ecosystem, ":")
		if len(parts) < 2 || parts[0] != "Ubuntu" || parts[1] == "Pro" || a.Package.Name == "" {
			continue
		}
		fixed := ""
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					fixed = f
				}
			}
		}
		if fixed != "" {
			out = append(out, cveFix{Release: parts[1], Package: a.Package.Name, CVE: id, Fixed: fixed, Severity: sev})
		}
	}
	return out
}

// parseOSVZip reads every JSON record of an OSV zip export, each bounded.
func parseOSVZip(path string, fn func(cveFix) error) error {
	z, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("ubuntu osv: %w", err)
	}
	defer func() { _ = z.Close() }()
	for _, f := range z.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > cveRecordMax {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("ubuntu osv %s: %w", f.Name, err)
		}
		var rec osvRecord
		err = json.NewDecoder(io.LimitReader(rc, cveRecordMax)).Decode(&rec)
		rc.Close()
		if err != nil {
			continue // one broken record does not stop the import
		}
		for _, fx := range rec.fixes() {
			if err := fn(fx); err != nil {
				return err
			}
		}
	}
	return nil
}

var feedClient = &http.Client{Timeout: feedTimeout}

// countingReader counts what it reads.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

var errFeedTooLarge = errors.New("the download is larger than the limit (Settings, CVE data)")

// openFeed starts a bounded download.
func openFeed(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "LiMDM security data import")
	resp, err := feedClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return resp, nil
}

// fetchFixes downloads and parses one feed, handing fixes to fn. It
// returns the bytes downloaded.
func fetchFixes(ctx context.Context, distro, u string, limit int64, fn func(cveFix) error) (int64, error) {
	resp, err := openFeed(ctx, u)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	cr := &countingReader{r: io.LimitReader(resp.Body, limit+1)}
	if distro == "debian" {
		err := parseDebianTracker(cr, fn)
		if cr.n > limit {
			return cr.n, errFeedTooLarge
		}
		return cr.n, err
	}
	// a zip needs random access: a temporary file, removed afterwards
	f, err := os.CreateTemp("", "limdm-osv-*.zip")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	_, err = io.Copy(f, cr)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return cr.n, err
	}
	if cr.n > limit {
		return cr.n, errFeedTooLarge
	}
	return cr.n, parseOSVZip(f.Name(), fn)
}

// importFeed replaces the fixes of one distribution with a fresh download;
// on failure the old data stays and the error is recorded.
func (s *Server) importFeed(ctx context.Context, distro, u string, limit int64) error {
	err := s.importFeedTx(ctx, distro, u, limit)
	if err != nil {
		_, _ = s.db.Exec(ctx, `INSERT INTO cve_feeds(distro, url, error, error_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (distro) DO UPDATE SET url=EXCLUDED.url, error=EXCLUDED.error, error_at=now()`, distro, u, truncate(err.Error(), 500))
	}
	return err
}

func (s *Server) importFeedTx(ctx context.Context, distro, u string, limit int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE cve_import (release TEXT, package TEXT, cve TEXT, fixed TEXT, severity TEXT) ON COMMIT DROP`); err != nil {
		return err
	}
	var batch [][]any
	rows := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_import"}, []string{"release", "package", "cve", "fixed", "severity"}, pgx.CopyFromRows(batch))
		batch = batch[:0]
		return err
	}
	n, err := fetchFixes(ctx, distro, u, limit, func(f cveFix) error {
		rows++
		batch = append(batch, []any{truncate(f.Release, 32), truncate(f.Package, 200), f.CVE, truncate(f.Fixed, 200), truncate(f.Severity, 20)})
		if len(batch) >= cveBatch {
			return flush()
		}
		return nil
	})
	if err == nil {
		err = flush()
	}
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("the feed holds no fixes for known releases")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cve_fixes WHERE distro=$1`, distro); err != nil {
		return err
	}
	var kept int
	if err := tx.QueryRow(ctx, `WITH ins AS (INSERT INTO cve_fixes(distro, release, package, cve, fixed, severity)
			SELECT DISTINCT ON (release, package, cve) $1, release, package, cve, fixed, severity FROM cve_import ORDER BY release, package, cve, fixed DESC
			RETURNING 1) SELECT count(*)::int FROM ins`, distro).Scan(&kept); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cve_feeds(distro, url, fetched_at, rows, bytes, error, error_at) VALUES ($1, $2, now(), $3, $4, '', NULL)
		ON CONFLICT (distro) DO UPDATE SET url=EXCLUDED.url, fetched_at=now(), rows=EXCLUDED.rows, bytes=EXCLUDED.bytes, error='', error_at=NULL`,
		distro, u, kept, n); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// matchDeviceCVEs compares the installed packages of a Debian or Ubuntu
// device with the fixed versions of its release and stores the CVEs whose
// fix is newer than the installed version. The binary package's version
// stands for the source version (equal, or with a binNMU suffix).
func matchDeviceCVEs(ctx context.Context, tx pgx.Tx, id string) error {
	var osID, version string
	if err := tx.QueryRow(ctx, `SELECT coalesce(inventory->>'os_id', ''), coalesce(inventory->>'os_version', '') FROM devices WHERE id=$1`, id).Scan(&osID, &version); err != nil {
		return err
	}
	distro, release, ok := cveRelease(osID, version)
	if !ok {
		_, err := tx.Exec(ctx, `DELETE FROM device_cves WHERE device_id=$1`, id)
		return err
	}
	rows, err := tx.Query(ctx, `SELECT p.name, p.version, f.cve, f.fixed, f.severity FROM device_packages p
		JOIN cve_fixes f ON f.distro=$2 AND f.release=$3 AND f.package = CASE WHEN p.source <> '' THEN p.source ELSE p.name END
		WHERE p.device_id=$1`, id, distro, release)
	if err != nil {
		return err
	}
	var pkgs, cves, inst, fixed, sevs []string
	seen := map[string]bool{}
	var name, ver, cve, fix, sev string
	_, err = pgx.ForEachRow(rows, []any{&name, &ver, &cve, &fix, &sev}, func() error {
		if debCompare(ver, fix) < 0 && !seen[cve+" "+name] {
			seen[cve+" "+name] = true
			pkgs, cves, inst, fixed, sevs = append(pkgs, name), append(cves, cve), append(inst, ver), append(fixed, fix), append(sevs, sev)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM device_cves WHERE device_id=$1`, id); err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO device_cves(device_id, package, cve, installed, fixed, severity)
		SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])`, id, pkgs, cves, inst, fixed, sevs)
	return err
}

// matchAllCVEs refreshes the matches of every Debian and Ubuntu device.
func (s *Server) matchAllCVEs(ctx context.Context) error {
	ids, err := collect(ctx, s.db, pgx.RowTo[string], `SELECT id FROM devices WHERE NOT retired AND inventory->>'os_id' IN ('debian', 'ubuntu')`)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error { return matchDeviceCVEs(ctx, tx, id) }); err != nil {
			return err
		}
	}
	return nil
}

// cveRunning keeps one import per instance; the leader loop and the
// refresh action share it.
var cveRunning atomic.Bool

// refreshCVEFeeds imports both feeds and matches the devices again. A
// feed that fails keeps its last data.
func (s *Server) refreshCVEFeeds(ctx context.Context) error {
	if !cveRunning.CompareAndSwap(false, true) {
		return errors.New("an import is running")
	}
	defer cveRunning.Store(false)
	set := s.settings().CVEFeeds
	var errs []error
	for _, d := range []string{"debian", "ubuntu"} {
		if err := s.importFeed(ctx, d, set.urls()[d], set.limit()); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, err))
		}
	}
	errs = append(errs, s.matchAllCVEs(ctx))
	return errors.Join(errs...)
}

// cveFeedsDue reports whether the daily import should run: the oldest
// successful import is a day old, and the last failure at least
// cveRetryAfter ago.
func (s *Server) cveFeedsDue(ctx context.Context) (bool, error) {
	var due bool
	err := s.db.QueryRow(ctx, `SELECT count(*) < 2 OR bool_or(coalesce(fetched_at, 'epoch') < now() - make_interval(secs => $1) AND coalesce(error_at, 'epoch') < now() - make_interval(secs => $2))
		FROM cve_feeds WHERE distro IN ('debian', 'ubuntu')`, cveFeedPeriod.Seconds(), cveRetryAfter.Seconds()).Scan(&due)
	return due, err
}

func (s *Server) cveLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if s.settings().CVEFeeds.Enabled {
			if due, err := s.cveFeedsDue(ctx); err != nil {
				s.log.Error("cve feeds", "err", err)
			} else if due {
				if err := s.refreshCVEFeeds(ctx); err != nil {
					s.log.Error("cve feeds", "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type cveFeedState struct {
	Distro    string     `json:"distro"`
	URL       string     `json:"url"`
	FetchedAt *time.Time `json:"fetched_at"`
	Rows      int        `json:"rows"`
	Bytes     int64      `json:"bytes"`
	Error     string     `json:"error"`
	ErrorAt   *time.Time `json:"error_at"`
}

func (s *Server) apiCVEFeeds(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[cveFeedState], `SELECT distro, url, fetched_at, rows, bytes, error, error_at FROM cve_feeds ORDER BY distro`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	set := s.settings().CVEFeeds
	for d, u := range set.urls() { // feeds never fetched yet
		if !slices.ContainsFunc(list, func(f cveFeedState) bool { return f.Distro == d }) {
			list = append(list, cveFeedState{Distro: d, URL: u})
		}
	}
	slices.SortFunc(list, func(a, b cveFeedState) int { return strings.Compare(a.Distro, b.Distro) })
	writeJSON(w, map[string]any{"enabled": set.Enabled, "running": cveRunning.Load(), "items": list})
}

// apiCVEFeedsRefresh starts an import now (admin); it runs in the
// background and its outcome shows in the feed state.
func (s *Server) apiCVEFeedsRefresh(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if !s.settings().CVEFeeds.Enabled {
		problem(w, http.StatusConflict, "switch the CVE data on first (Settings, CVE data)")
		return
	}
	if cveRunning.Load() {
		problem(w, http.StatusConflict, "an import is running")
		return
	}
	if err := s.auditAction(r.Context(), c.actor(), "cve_feeds.refresh", "debian,ubuntu", "", func(pgx.Tx) error { return nil }); err != nil {
		s.apiFail(w, err)
		return
	}
	// outlives the request: the import takes minutes
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*feedTimeout)
	go func() {
		defer cancel()
		if err := s.refreshCVEFeeds(ctx); err != nil {
			s.log.Error("cve feeds", "err", err)
		}
	}()
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"running": true})
}
