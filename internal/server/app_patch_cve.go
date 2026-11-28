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
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// CVE data for Debian, Ubuntu, Arch and Alpine
// (docs/patching.md#cve-data-for-debian-ubuntu-arch-and-alpine). Their
// package managers do not know which CVEs an update fixes, so the server
// imports the distributions' security data once a day (leader only) and
// matches the installed package versions the devices report against the
// fixed versions of their release. Nothing is requested on the devices.
//
// Sources: the Debian Security Tracker JSON (source package, CVE, release,
// fixed version, urgency); for Ubuntu the OSV export Canonical publishes
// (UBUNTU-CVE records: source package, release, fixed version, Ubuntu
// priority; OVAL is XML per release and the USN database has no
// priorities); the Arch Security Tracker's list of AVGs, issues/all.json
// (packages, fixed version, severity and CVEs in one record; the ASA list
// has no fixed versions per package); the Alpine secdb per release branch
// and repository (origin package, fixed version, CVEs, no severity).
//
// Only what the matching needs is kept: distribution, release, source
// package, CVE, fixed version, severity. Downloads are bounded (size
// limit, timeout) and parsed as streams; a failed import keeps the last
// data and records the error.

const (
	defaultDebianFeed = "https://security-tracker.debian.org/tracker/data/json"
	defaultUbuntuFeed = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"
	defaultArchFeed   = "https://security.archlinux.org/issues/all.json"
	defaultAlpineFeed = "https://secdb.alpinelinux.org" // + /v3.20/main.json, /v3.20/community.json
	defaultKEVFeed    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultFeedMB     = 1024
	feedTimeout       = 30 * time.Minute
	cveFeedPeriod     = 24 * time.Hour
	cveRetryAfter     = 6 * time.Hour
	cveRecordMax      = 4 << 20 // one OSV record
	cveBatch          = 5000
)

// CVEFeedSettings is the settings section cve_feeds (Settings, CVE data).
// Every feed is off by default: they download from third parties.
type CVEFeedSettings struct {
	Debian    bool   `json:"debian"`
	Ubuntu    bool   `json:"ubuntu"`
	Arch      bool   `json:"arch"`
	Alpine    bool   `json:"alpine"`
	KEV       bool   `json:"kev"`                  // CISA Known Exploited Vulnerabilities (app_vulns.go)
	DebianURL string `json:"debian_url,omitempty"` // empty: defaultDebianFeed
	UbuntuURL string `json:"ubuntu_url,omitempty"` // empty: defaultUbuntuFeed
	ArchURL   string `json:"arch_url,omitempty"`   // empty: defaultArchFeed
	AlpineURL string `json:"alpine_url,omitempty"` // base URL of the secdb, empty: defaultAlpineFeed
	KEVURL    string `json:"kev_url,omitempty"`    // empty: defaultKEVFeed
	MaxMB     int    `json:"max_mb,omitempty"`     // download limit per feed, defaultFeedMB when 0
}

// cveDistros are the feeds in display order.
var cveDistros = []string{"debian", "ubuntu", "arch", "alpine", "kev"}

func (c CVEFeedSettings) urls() map[string]string {
	return map[string]string{"debian": firstNonEmpty(c.DebianURL, defaultDebianFeed), "ubuntu": firstNonEmpty(c.UbuntuURL, defaultUbuntuFeed),
		"arch": firstNonEmpty(c.ArchURL, defaultArchFeed), "alpine": strings.TrimRight(firstNonEmpty(c.AlpineURL, defaultAlpineFeed), "/"),
		"kev": firstNonEmpty(c.KEVURL, defaultKEVFeed)}
}

// enabled lists the feeds that are switched on.
func (c CVEFeedSettings) enabled() []string {
	on := map[string]bool{"debian": c.Debian, "ubuntu": c.Ubuntu, "arch": c.Arch, "alpine": c.Alpine, "kev": c.KEV}
	var out []string
	for _, d := range cveDistros {
		if on[d] {
			out = append(out, d)
		}
	}
	return out
}

func (c CVEFeedSettings) limit() int64 {
	if c.MaxMB <= 0 {
		return defaultFeedMB << 20
	}
	return int64(c.MaxMB) << 20
}

// validate checks a saved section; it returns the message of the problem.
func (c CVEFeedSettings) validate() string {
	for _, u := range []string{c.DebianURL, c.UbuntuURL, c.ArchURL, c.AlpineURL, c.KEVURL} {
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

// ubuntuReleases maps an Ubuntu codename to its VERSION_ID, the release
// key of the Ubuntu feed, for derivatives that name their base in
// UBUNTU_CODENAME.
var ubuntuReleases = map[string]string{"jammy": "22.04", "noble": "24.04", "oracular": "24.10", "plucky": "25.04", "questing": "25.10", "resolute": "26.04"}

// cveRelease is the distribution and release key a device's fixes are
// stored under (Debian: codename, Ubuntu: VERSION_ID such as 24.04). A
// derivative (like: ID_LIKE, baseCodename: UBUNTU_CODENAME, else
// DEBIAN_CODENAME) is matched against its base, which via names: Ubuntu
// derivatives by the base codename, Debian derivatives by a known Debian
// codename, the Arch family always. Kali (rolling on Debian testing) and
// Raspbian are not matched.
func cveRelease(osID, version, like, baseCodename string) (distro, release, via string, ok bool) {
	switch osID {
	case "debian":
		major, _, _ := strings.Cut(version, ".")
		c, ok := debianReleases[major]
		return "debian", c, "", ok
	case "ubuntu":
		return "ubuntu", version, "", version != ""
	case "arch":
		return "arch", "rolling", "", true // no releases
	case "alpine":
		return "alpine", alpineBranch(version), "", version != ""
	case "kali", "raspbian":
		return "", "", "", false
	}
	likes := strings.Fields(like)
	switch {
	case slices.Contains(likes, "ubuntu"):
		v, ok := ubuntuReleases[baseCodename]
		return "ubuntu", v, "ubuntu", ok
	case slices.Contains(likes, "debian"):
		for _, c := range debianReleases {
			if c == baseCodename {
				return "debian", c, "debian", true
			}
		}
	case slices.Contains(likes, "arch") || slices.Contains(likes, "manjaro"):
		return "arch", "rolling", "arch", true
	}
	return "", "", "", false
}

// alpineBranch is the secdb branch of an Alpine VERSION_ID: "3.20.3" is
// v3.20, a development snapshot ("3.21_alpha20240923") is edge.
func alpineBranch(version string) string {
	if strings.Contains(version, "_") {
		return "edge"
	}
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return "edge"
	}
	return "v" + parts[0] + "." + parts[1]
}

// parseArchTracker streams the Arch tracker's AVG list and hands every
// fixed group to fn, one fix per package and CVE.
func parseArchTracker(r io.Reader, fn func(cveFix) error) error {
	dec := json.NewDecoder(r)
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("arch tracker: %w", err)
	}
	if t != json.Delim('[') {
		return errors.New("arch tracker: not a JSON list")
	}
	for dec.More() {
		var avg struct {
			Packages []string `json:"packages"`
			Status   string   `json:"status"`
			Severity string   `json:"severity"`
			Fixed    *string  `json:"fixed"`
			Issues   []string `json:"issues"`
		}
		if err := dec.Decode(&avg); err != nil {
			return fmt.Errorf("arch tracker: %w", err)
		}
		if avg.Status != "Fixed" || avg.Fixed == nil || *avg.Fixed == "" {
			continue
		}
		sev := strings.ToLower(avg.Severity)
		if sev == "unknown" {
			sev = ""
		}
		for _, pkg := range avg.Packages {
			for _, id := range avg.Issues {
				if !cveRe.MatchString(id) {
					continue
				}
				if err := fn(cveFix{Release: "rolling", Package: pkg, CVE: id, Fixed: *avg.Fixed, Severity: sev}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var cveInText = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,7}`)

// parseAlpineSecdb reads one secdb file ({"packages": [{"pkg": {"name",
// "secfixes": {"3.1.4-r1": ["CVE-…"]}}}]}) of a branch. "0" lists CVEs
// the package was never affected by.
func parseAlpineSecdb(r io.Reader, branch string, fn func(cveFix) error) error {
	var db struct {
		Packages []struct {
			Pkg struct {
				Name     string              `json:"name"`
				Secfixes map[string][]string `json:"secfixes"`
			} `json:"pkg"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(r).Decode(&db); err != nil {
		return fmt.Errorf("alpine secdb %s: %w", branch, err)
	}
	for _, p := range db.Packages {
		for ver, ids := range p.Pkg.Secfixes {
			if ver == "0" || p.Pkg.Name == "" {
				continue
			}
			for _, text := range ids {
				for _, id := range cveInText.FindAllString(text, -1) {
					if err := fn(cveFix{Release: branch, Package: p.Pkg.Name, CVE: id, Fixed: ver}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

type cveFix struct {
	Release, Package, CVE, Fixed, Severity string
	Vector                                 string // CVSS v3 vector where the source has one (Ubuntu OSV)
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
	sev, vector := "", ""
	for _, s := range o.Severity {
		switch s.Type {
		case "Ubuntu":
			sev = strings.ToLower(s.Score)
		case "CVSS_V3":
			vector = s.Score
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
			out = append(out, cveFix{Release: parts[1], Package: a.Package.Name, CVE: id, Fixed: fixed, Severity: sev, Vector: vector})
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
func fetchFixes(ctx context.Context, distro, u string, releases []string, limit int64, fn func(cveFix) error) (int64, error) {
	if distro == "alpine" { // one small file per branch and repository, all within the limit
		var total int64
		for _, branch := range releases {
			for _, repo := range []string{"main", "community"} {
				resp, err := openFeed(ctx, u+"/"+branch+"/"+repo+".json")
				if err != nil {
					return total, err
				}
				cr := &countingReader{r: io.LimitReader(resp.Body, limit-total+1)}
				err = parseAlpineSecdb(cr, branch, fn)
				resp.Body.Close()
				if total += cr.n; total > limit {
					return total, errFeedTooLarge
				}
				if err != nil {
					return total, err
				}
			}
		}
		return total, nil
	}
	resp, err := openFeed(ctx, u)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	cr := &countingReader{r: io.LimitReader(resp.Body, limit+1)}
	if distro == "debian" || distro == "arch" {
		parse := parseDebianTracker
		if distro == "arch" {
			parse = parseArchTracker
		}
		err := parse(cr, fn)
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
	imp := s.importFeedTx
	if distro == "kev" {
		imp = s.importKEV // app_vulns.go
	}
	err := imp(ctx, distro, u, limit)
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
	scores := map[string]string{} // CVE: CVSS v3 vector
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_import"}, []string{"release", "package", "cve", "fixed", "severity"}, pgx.CopyFromRows(batch))
		batch = batch[:0]
		return err
	}
	var releases []string
	if distro == "alpine" { // the branches the Alpine devices run
		versions, err := collect(ctx, s.db, pgx.RowTo[string], `SELECT DISTINCT inventory->>'os_version' FROM devices
			WHERE NOT retired AND inventory->>'os_id' = 'alpine' AND coalesce(inventory->>'os_version', '') <> ''`)
		if err != nil {
			return err
		}
		for _, v := range versions {
			if b := alpineBranch(v); alpineBranchRe.MatchString(b) && !slices.Contains(releases, b) {
				releases = append(releases, b)
			}
		}
		if len(releases) == 0 {
			return errors.New("no Alpine device reports its release yet")
		}
		slices.Sort(releases)
	}
	n, err := fetchFixes(ctx, distro, u, releases, limit, func(f cveFix) error {
		rows++
		if f.Vector != "" {
			scores[f.CVE] = f.Vector
		}
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
	if err := storeScores(ctx, tx, distro, scores); err != nil { // app_vulns.go
		return err
	}
	return tx.Commit(ctx)
}

// matchDeviceCVEs records the vulnerabilities of a device: the CVEs of
// its release whose fixed version is newer than the installed source
// version (Debian, Ubuntu, Arch, Alpine security data) and the CVEs of the
// pending updates its package manager names (dnf, zypper). Findings keep
// their history (app_vulns.go): one that no longer matches is remediated
// when its package changed or went away, and dropped when the package is
// unchanged, because then the data was corrected and it never applied.
func matchDeviceCVEs(ctx context.Context, tx pgx.Tx, id string) error {
	var osID, version, like, base string
	var pendingRaw []byte
	if err := tx.QueryRow(ctx, `SELECT `+osReleaseCols+`,
		CASE WHEN jsonb_typeof(updates->'pending') = 'array' THEN updates->'pending' ELSE '[]' END FROM devices WHERE id=$1`, id).Scan(&osID, &version, &like, &base, &pendingRaw); err != nil {
		return err
	}
	var pkgs, cves, inst, fixed, sevs, vias []string
	seen := map[string]bool{}
	add := func(pkg, cve, installed, fix, sev, via string) {
		if !seen[cve+" "+pkg] {
			seen[cve+" "+pkg] = true
			pkgs, cves, inst, fixed, sevs, vias = append(pkgs, pkg), append(cves, cve), append(inst, installed), append(fixed, fix), append(sevs, sev), append(vias, via)
		}
	}
	if distro, release, via, ok := cveRelease(osID, version, like, base); ok {
		// the trackers list source packages and versions (Debian, Ubuntu,
		// Alpine origin) or package names and pkgbase (Arch): the source
		// when the agent sent it, else the package itself. A Debian binary
		// package can carry its own version (postgresql 17+278 built from
		// postgresql-common 278), so the source version is compared.
		// Proxmox VE packages (pve-*, proxmox-*, the kernel included) are
		// not Debian's and never matched against the Debian tracker.
		rows, err := tx.Query(ctx, `SELECT p.name, p.version, CASE WHEN p.source_version <> '' THEN p.source_version ELSE p.version END, f.cve, f.fixed, f.severity
			FROM device_packages p
			JOIN cve_fixes f ON f.distro=$2 AND f.release=$3 AND (f.package = CASE WHEN p.source <> '' THEN p.source ELSE p.name END OR $2 = 'arch' AND f.package = p.name)
			WHERE p.device_id=$1 AND NOT ($2 = 'debian' AND (p.name ~ '^(pve|proxmox)-' OR p.source ~ '^(pve|proxmox)-'))`, id, distro, release)
		if err != nil {
			return err
		}
		cmp := versionCompare(distro)
		var name, ver, srcVer, cve, fix, sev string
		if _, err := pgx.ForEachRow(rows, []any{&name, &ver, &srcVer, &cve, &fix, &sev}, func() error {
			if cmp(srcVer, fix) < 0 {
				add(name, cve, ver, fix, sev, via)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	var pending []api.PendingUpdate
	if err := json.Unmarshal(pendingRaw, &pending); err != nil {
		return fmt.Errorf("pending updates: %w", err)
	}
	for _, p := range pending {
		for _, c := range p.CVEs {
			if cveRe.MatchString(c) {
				add(truncate(p.Name, 200), c, p.Current, p.Candidate, p.Severity, "")
			}
		}
	}
	// gone: dropped when the package is unchanged, else remediated
	gone := `c.device_id=$1 AND c.remediated_at IS NULL AND (c.cve, c.package) NOT IN (SELECT u.c, u.p FROM unnest($2::text[], $3::text[]) u(c, p))`
	if _, err := tx.Exec(ctx, `DELETE FROM device_cves c WHERE `+gone+`
		AND EXISTS (SELECT 1 FROM device_packages p WHERE p.device_id = c.device_id AND p.name = c.package AND p.version = c.installed)`, id, cves, pkgs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE device_cves c SET remediated_at = now() WHERE `+gone, id, cves, pkgs); err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO device_cves(device_id, package, cve, installed, fixed, severity, via)
		SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
		ON CONFLICT (device_id, cve, package) DO UPDATE SET installed = EXCLUDED.installed, fixed = EXCLUDED.fixed, severity = EXCLUDED.severity, via = EXCLUDED.via,
			last_seen = now(), first_seen = CASE WHEN device_cves.remediated_at IS NULL THEN device_cves.first_seen ELSE now() END, remediated_at = NULL`,
		id, pkgs, cves, inst, fixed, sevs, vias)
	return err
}

// matchAllCVEs refreshes the matches of every device.
func (s *Server) matchAllCVEs(ctx context.Context) error {
	ids, err := collect(ctx, s.db, pgx.RowTo[string], `SELECT id FROM devices WHERE NOT retired`)
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

// osReleaseCols are the inventory fields cveRelease resolves.
const osReleaseCols = `coalesce(inventory->>'os_id', ''), coalesce(inventory->>'os_version', ''), coalesce(inventory->>'os_like', ''), coalesce(inventory->>'os_base_codename', '')`

// fleetDistros are the os_id values of the devices in service and the
// feeds cveRelease resolves them to: a feed loads when only derivatives
// of its base are in service.
func (s *Server) fleetDistros(ctx context.Context) ([]string, error) {
	type osRelease struct{ ID, Version, Like, Base string }
	list, err := collect(ctx, s.db, pgx.RowToStructByPos[osRelease], `SELECT DISTINCT `+osReleaseCols+` FROM devices WHERE NOT retired AND inventory->>'os_id' IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range list {
		out = append(out, o.ID)
		if d, _, _, ok := cveRelease(o.ID, o.Version, o.Like, o.Base); ok {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// activeFeeds are the switched on feeds worth a download: a distribution
// feed only while at least one device runs that distribution (the Ubuntu
// export alone is far beyond 500 MB a day); the KEV list always.
func activeFeeds(on, fleet []string) []string {
	return slices.DeleteFunc(slices.Clone(on), func(d string) bool { return d != "kev" && !slices.Contains(fleet, d) })
}

// refreshCVEFeeds imports the active feeds and matches the devices again.
// A feed that fails keeps its last data.
func (s *Server) refreshCVEFeeds(ctx context.Context) error {
	if !cveRunning.CompareAndSwap(false, true) {
		return errors.New("an import is running")
	}
	defer cveRunning.Store(false)
	set := s.settings().CVEFeeds
	fleet, err := s.fleetDistros(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range activeFeeds(set.enabled(), fleet) {
		if err := s.importFeed(ctx, d, set.urls()[d], set.limit()); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, err))
		}
	}
	errs = append(errs, s.matchAllCVEs(ctx))
	return errors.Join(errs...)
}

// cveFeedsDue reports whether the daily import should run: an active
// feed was never imported, or its last import is a day old and its last
// failure at least cveRetryAfter ago.
func (s *Server) cveFeedsDue(ctx context.Context) (bool, error) {
	fleet, err := s.fleetDistros(ctx)
	if err != nil {
		return false, err
	}
	on := activeFeeds(s.settings().CVEFeeds.enabled(), fleet)
	if len(on) == 0 {
		return false, nil
	}
	var due bool
	err = s.db.QueryRow(ctx, `SELECT count(*) < cardinality($3::text[]) OR coalesce(bool_or(coalesce(fetched_at, 'epoch') < now() - make_interval(secs => $1)
			AND coalesce(error_at, 'epoch') < now() - make_interval(secs => $2)), false)
		FROM cve_feeds WHERE distro = ANY($3)`, cveFeedPeriod.Seconds(), cveRetryAfter.Seconds(), on).Scan(&due)
	return due, err
}

func (s *Server) cveLoop(ctx context.Context) {
	// the due check is one cheap query: a feed switched on in the settings
	// starts within minutes, not at the next full hour
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// once per start: findings follow a changed matching after an upgrade
	if err := s.matchAllCVEs(ctx); err != nil {
		s.log.Error("cve match", "err", err)
	}
	for {
		if len(s.settings().CVEFeeds.enabled()) > 0 {
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
	Enabled   bool       `json:"enabled"`
	URL       string     `json:"url"`
	FetchedAt *time.Time `json:"fetched_at"`
	Rows      int        `json:"rows"`
	Bytes     int64      `json:"bytes"`
	Error     string     `json:"error"`
	ErrorAt   *time.Time `json:"error_at"`
	Skipped   bool       `json:"skipped"` // switched on, but no device runs the distribution: not downloaded
}

func (s *Server) apiCVEFeeds(w http.ResponseWriter, r *http.Request, _ apiCaller) {
	list, err := collect(r.Context(), s.db, pgx.RowToStructByPos[cveFeedState], `SELECT distro, false, url, fetched_at, rows, bytes, error, error_at, false FROM cve_feeds ORDER BY distro`)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	fleet, err := s.fleetDistros(r.Context())
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
	on := set.enabled()
	active := activeFeeds(on, fleet)
	for i := range list {
		list[i].Enabled = slices.Contains(on, list[i].Distro)
		list[i].Skipped = list[i].Enabled && !slices.Contains(active, list[i].Distro)
	}
	slices.SortFunc(list, func(a, b cveFeedState) int {
		return slices.Index(cveDistros, a.Distro) - slices.Index(cveDistros, b.Distro)
	})
	writeJSON(w, map[string]any{"enabled": len(on) > 0, "running": cveRunning.Load(), "items": list})
}

// apiCVEFeedsRefresh starts an import now (admin); it runs in the
// background and its outcome shows in the feed state.
func (s *Server) apiCVEFeedsRefresh(w http.ResponseWriter, r *http.Request, c apiCaller) {
	if len(s.settings().CVEFeeds.enabled()) == 0 {
		problem(w, http.StatusConflict, "switch the CVE data on first (Settings, CVE data)")
		return
	}
	if cveRunning.Load() {
		problem(w, http.StatusConflict, "an import is running")
		return
	}
	if err := s.auditAction(r.Context(), c.actor(), "cve_feeds.refresh", strings.Join(s.settings().CVEFeeds.enabled(), ","), "", func(pgx.Tx) error { return nil }); err != nil {
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

var alpineBranchRe = regexp.MustCompile(`^(v[0-9]+\.[0-9]+|edge)$`)
