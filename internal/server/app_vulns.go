package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Vulnerabilities (docs/vulnerabilities.md): the fleet view of the CVE
// findings app_patch_cve.go records per device, one row per CVE with
// severity, CVSS score, CISA KEV, first detection, devices and status.
//
// A finding is one CVE in one package of one device. It is active while it
// matches, remediated once a later package report no longer matches
// (remediated_at), and accepted while an active risk acceptance covers it:
// per CVE, optionally limited to one device or package, with reason,
// expiry and actor, audited. An expired or revoked acceptance stops
// covering at once, the finding is active again. A CVE is active when any
// of its findings is, else accepted when any is, else remediated.

func init() {
	auditActions["vulnerability.accept"] = "Vulnerability risk accepted"
	auditActions["vulnerability.reopen"] = "Vulnerability reopened"
}

func (s *Server) appVulnRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/v1/vulnerabilities", s.need("read", s.apiVulns))
	m.HandleFunc("GET /api/v1/vulnerabilities/summary", s.need("read", s.apiVulnSummary))
	m.HandleFunc("GET /api/v1/vulnerabilities/{cve}", s.need("read", s.apiVuln))
	m.HandleFunc("POST /api/v1/vulnerabilities/{cve}/accept", s.need("admin", s.apiVulnAccept))
	m.HandleFunc("POST /api/v1/vulnerabilities/{cve}/reopen", s.need("admin", s.apiVulnReopen))
}

// severityLevels maps what the sources state to a level: Debian urgency
// (low, medium, high), Ubuntu priority (negligible to critical), Arch
// severity (low to critical), Red Hat, Fedora and SUSE advisories (low,
// moderate, important, critical). Anything else is unknown (0).
var severityLevels = map[string]int{"negligible": 1, "low": 1, "medium": 2, "moderate": 2, "high": 3, "important": 3, "critical": 4}

// severityNames are the levels the console shows.
var severityNames = []string{"unknown", "low", "medium", "high", "critical"}

// sevRankSQL is severityLevels as an SQL expression over col.
func sevRankSQL(col string) string {
	keys := make([]string, 0, len(severityLevels))
	for k := range severityLevels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	b.WriteString("CASE lower(" + col + ")")
	for _, k := range keys {
		fmt.Fprintf(&b, " WHEN '%s' THEN %d", k, severityLevels[k])
	}
	b.WriteString(" ELSE 0 END")
	return b.String()
}

// cvssLevel is the level of a CVSS v3 base score (FIRST's rating scale);
// it stands in when no source states a severity.
func cvssLevel(score float64) int {
	switch {
	case score >= 9:
		return 4
	case score >= 7:
		return 3
	case score >= 4:
		return 2
	case score > 0:
		return 1
	}
	return 0
}

// cvss3Score computes the base score of a CVSS v3.0 or v3.1 vector
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" is 9.8).
func cvss3Score(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
		"C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0},
	}
	w := map[string]float64{}
	for k, table := range weights {
		v, ok := table[m[k]]
		if !ok {
			return 0, false
		}
		w[k] = v
	}
	changed := m["S"] == "C"
	if !changed && m["S"] != "U" {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	prW, ok := pr[m["PR"]]
	if !ok {
		return 0, false
	}
	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	sum := impact + 8.22*w["AV"]*w["AC"]*prW*w["UI"]
	if changed {
		sum *= 1.08
	}
	return roundUp(math.Min(sum, 10)), true
}

// roundUp is the CVSS v3.1 Roundup: the smallest one decimal number not
// below x, robust against floating point noise.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// storeScores replaces the CVSS scores a feed provides.
func storeScores(ctx context.Context, tx pgx.Tx, source string, vectors map[string]string) error {
	if source != "ubuntu" { // the only feed with CVSS vectors
		return nil
	}
	var cves, vecs []string
	var scores []float64
	for cve, v := range vectors {
		if score, ok := cvss3Score(v); ok {
			cves, vecs, scores = append(cves, cve), append(vecs, truncate(v, 200)), append(scores, score)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cve_scores WHERE source=$1`, source); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO cve_scores(cve, cvss, vector, source) SELECT u.c, u.s, u.v, $1 FROM unnest($2::text[], $3::float8[], $4::text[]) u(c, s, v)
		ON CONFLICT (cve) DO NOTHING`, source, cves, scores, vecs)
	return err
}

// kevCatalog is the part of the CISA KEV JSON the import reads.
type kevCatalog struct {
	Vulnerabilities []struct {
		CVE        string `json:"cveID"`
		Name       string `json:"vulnerabilityName"`
		Added      string `json:"dateAdded"`
		Due        string `json:"dueDate"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// importKEV replaces the Known Exploited Vulnerabilities list (a small
// JSON file) with a fresh download.
func (s *Server) importKEV(ctx context.Context, distro, u string, limit int64) error {
	resp, err := openFeed(ctx, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	cr := &countingReader{r: io.LimitReader(resp.Body, limit+1)}
	var cat kevCatalog
	err = json.NewDecoder(cr).Decode(&cat)
	if cr.n > limit {
		return errFeedTooLarge
	}
	if err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	var cves, names []string
	var added, due []*time.Time
	var ransom []bool
	seen := map[string]bool{}
	date := func(v string) *time.Time {
		if t, err := time.Parse(time.DateOnly, v); err == nil {
			return &t
		}
		return nil
	}
	for _, v := range cat.Vulnerabilities {
		if !cveRe.MatchString(v.CVE) || seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		cves, names = append(cves, v.CVE), append(names, truncate(v.Name, 300))
		added, due, ransom = append(added, date(v.Added)), append(due, date(v.Due)), append(ransom, strings.EqualFold(v.Ransomware, "Known"))
	}
	if len(cves) == 0 {
		return errors.New("the KEV list holds no CVEs")
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM cve_kev`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cve_kev(cve, name, added, due, ransomware) SELECT * FROM unnest($1::text[], $2::text[], $3::date[], $4::date[], $5::bool[])`,
			cves, names, added, due, ransom); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cve_feeds(distro, url, fetched_at, rows, bytes, error, error_at) VALUES ($1, $2, now(), $3, $4, '', NULL)
			ON CONFLICT (distro) DO UPDATE SET url=EXCLUDED.url, fetched_at=now(), rows=EXCLUDED.rows, bytes=EXCLUDED.bytes, error='', error_at=NULL`,
			distro, u, len(cves), cr.n)
		return err
	})
}

// acceptedSQL is true when an active acceptance covers the finding c of
// the device d.
const acceptedSQL = `EXISTS (SELECT 1 FROM cve_acceptances a WHERE a.cve = c.cve AND a.revoked_at IS NULL AND a.expires_at > now()
	AND (a.tenant_id IS NULL OR a.tenant_id = d.tenant_id) AND a.device_id IN ('', c.device_id) AND a.package IN ('', c.package))`

// vulnArgs numbers query arguments after those of the scope condition.
type vulnArgs struct{ list []any }

func (a *vulnArgs) add(v any) string {
	a.list = append(a.list, v)
	return "$" + strconv.Itoa(len(a.list))
}

// vulnCTE is the query part shared by the list and the summary: f the
// findings in scope with their status st, x one row per CVE.
func vulnCTE(sess session, a *vulnArgs, findingWhere string) string {
	scope, args := scopeCond(sess, len(a.list))
	a.list = append(a.list, args...)
	return `WITH f AS (
		SELECT c.cve, c.device_id, c.package, c.first_seen, c.last_seen, c.remediated_at, ` + sevRankSQL("c.severity") + ` AS rank,
			CASE WHEN c.remediated_at IS NOT NULL THEN 'remediated' WHEN ` + acceptedSQL + ` THEN 'accepted' ELSE 'active' END AS st
		FROM device_cves c JOIN devices d ON d.id = c.device_id
		WHERE NOT d.retired AND ` + scope + findingWhere + `
	), v AS (
		SELECT f.cve, max(f.rank) AS rank,
			CASE WHEN bool_or(f.st = 'active') THEN 'active' WHEN bool_or(f.st = 'accepted') THEN 'accepted' ELSE 'remediated' END AS status,
			min(f.first_seen) AS first_seen, max(f.last_seen) AS last_seen, max(f.remediated_at) AS remediated_at,
			count(DISTINCT f.device_id) FILTER (WHERE f.st = 'active')::int AS active,
			count(DISTINCT f.device_id) FILTER (WHERE f.st = 'accepted')::int AS accepted,
			count(DISTINCT f.device_id) FILTER (WHERE f.st = 'remediated')::int AS remediated,
			array_agg(DISTINCT f.package ORDER BY f.package) AS packages
		FROM f GROUP BY f.cve
	), x AS (
		SELECT v.*, sc.cvss::float8 AS cvss, k.cve IS NOT NULL AS kev,
			CASE WHEN v.rank > 0 THEN v.rank WHEN sc.cvss >= 9 THEN 4 WHEN sc.cvss >= 7 THEN 3 WHEN sc.cvss >= 4 THEN 2 WHEN sc.cvss > 0 THEN 1 ELSE 0 END AS sev,
			CASE WHEN v.status = 'remediated' THEN v.remediated ELSE v.active + v.accepted END AS devices
		FROM v LEFT JOIN cve_scores sc ON sc.cve = v.cve LEFT JOIN cve_kev k ON k.cve = v.cve
	)`
}

type vulnRow struct {
	CVE          string     `json:"cve"`
	Severity     string     `json:"severity"` // critical | high | medium | low | unknown
	CVSS         *float64   `json:"cvss"`
	KEV          bool       `json:"kev"`
	Packages     []string   `json:"packages"`
	FirstSeen    time.Time  `json:"first_detected"`
	LastSeen     time.Time  `json:"last_seen"`
	RemediatedAt *time.Time `json:"remediated_at"`
	Status       string     `json:"status"` // active | accepted | remediated
	Devices      int        `json:"devices"`
	Active       int        `json:"active_devices"`
	Accepted     int        `json:"accepted_devices"`
	Remediated   int        `json:"remediated_devices"`
}

var vulnSorts = map[string]string{"cvss": "x.cvss", "first_detected": "x.first_seen", "devices": "x.devices", "severity": "x.sev", "cve": "x.cve"}

// splitList is a comma separated query value, each item one of allowed.
func splitList(v string, allowed []string) ([]string, bool) {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !slices.Contains(allowed, p) {
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

// apiVulns lists the CVEs of the devices in scope. Filters: q (CVE or
// package, part of it), severity and status (comma lists; status active
// by default, all for every one), device, os (os_id), package (exact),
// from and to (first detection, YYYY-MM-DD), kev=true. Sort by cvss,
// first_detected, devices, severity or cve (- for descending); limit and
// an opaque cursor page through it; format=csv exports up to 10000 rows.
func (s *Server) apiVulns(w http.ResponseWriter, r *http.Request, c apiCaller) {
	q := r.URL.Query()
	a := &vulnArgs{}
	var fw, xw []string
	if v := q.Get("device"); v != "" {
		fw = append(fw, "c.device_id = "+a.add(v))
	}
	if v := q.Get("os"); v != "" {
		fw = append(fw, "d.inventory->>'os_id' = "+a.add(v))
	}
	if v := q.Get("package"); v != "" {
		fw = append(fw, "c.package = "+a.add(v))
	}
	findingWhere := ""
	for _, x := range fw {
		findingWhere += " AND " + x
	}
	cte := vulnCTE(c.sess(), a, findingWhere)
	status := q.Get("status")
	if status == "" {
		status = "active"
	}
	if status != "all" {
		list, ok := splitList(status, []string{"active", "accepted", "remediated"})
		if !ok {
			problemField(w, http.StatusBadRequest, "status", "status: active, accepted, remediated or all")
			return
		}
		xw = append(xw, "x.status = ANY("+a.add(list)+"::text[])")
	}
	if v := q.Get("severity"); v != "" {
		list, ok := splitList(v, severityNames)
		if !ok {
			problemField(w, http.StatusBadRequest, "severity", "severity: critical, high, medium, low or unknown")
			return
		}
		var levels []int
		for _, n := range list {
			levels = append(levels, slices.Index(severityNames, n))
		}
		xw = append(xw, "x.sev = ANY("+a.add(levels)+"::int[])")
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		if len(v) > 200 {
			problemField(w, http.StatusBadRequest, "q", "q: at most 200 characters")
			return
		}
		n := a.add(v)
		xw = append(xw, "(strpos(lower(x.cve), lower("+n+")) > 0 OR EXISTS (SELECT 1 FROM unnest(x.packages) p WHERE strpos(lower(p), lower("+n+")) > 0))")
	}
	for _, d := range []struct{ key, cond string }{{"from", "x.first_seen >= %s::date"}, {"to", "x.first_seen < %s::date + 1"}} {
		if v := q.Get(d.key); v != "" {
			day, err := time.Parse(time.DateOnly, v)
			if err != nil {
				problemField(w, http.StatusBadRequest, d.key, d.key+": YYYY-MM-DD")
				return
			}
			xw = append(xw, fmt.Sprintf(d.cond, a.add(day.Format(time.DateOnly))))
		}
	}
	if q.Get("kev") == "true" {
		xw = append(xw, "x.kev")
	}
	sortKey, desc := q.Get("sort"), false
	if sortKey == "" {
		sortKey, desc = "severity", true
	} else if strings.HasPrefix(sortKey, "-") {
		sortKey, desc = sortKey[1:], true
	}
	col, ok := vulnSorts[sortKey]
	if !ok {
		problemField(w, http.StatusBadRequest, "sort", "sort: cvss, first_detected, devices, severity or cve")
		return
	}
	order := col + " ASC NULLS FIRST"
	if desc {
		order = col + " DESC NULLS LAST"
	}
	csvOut := q.Get("format") == "csv"
	limit, maxLimit := 50, 500
	if csvOut {
		limit, maxLimit = 10000, 10000
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLimit {
			problemField(w, http.StatusBadRequest, "limit", fmt.Sprintf("limit: 1 to %d", maxLimit))
			return
		}
		limit = n
	}
	offset := 0
	if v := q.Get("cursor"); v != "" && !csvOut {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problemField(w, http.StatusBadRequest, "cursor", "cursor: the next_cursor of the previous page")
			return
		}
		offset = n
	}
	where := "TRUE"
	if len(xw) > 0 {
		where = strings.Join(xw, " AND ")
	}
	rows, err := s.db.Query(r.Context(), cte+`
		SELECT x.cve, x.sev, x.cvss, x.kev, x.packages, x.first_seen, x.last_seen, CASE WHEN x.status = 'remediated' THEN x.remediated_at END,
			x.status, x.devices, x.active, x.accepted, x.remediated, count(*) OVER ()::int
		FROM x WHERE `+where+` ORDER BY `+order+`, x.cve DESC LIMIT `+strconv.Itoa(limit)+` OFFSET `+strconv.Itoa(offset), a.list...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	total := 0
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (vulnRow, error) {
		var v vulnRow
		var sev int
		err := row.Scan(&v.CVE, &sev, &v.CVSS, &v.KEV, &v.Packages, &v.FirstSeen, &v.LastSeen, &v.RemediatedAt, &v.Status, &v.Devices, &v.Active, &v.Accepted, &v.Remediated, &total)
		v.Severity = severityNames[sev]
		return v, err
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if csvOut {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="vulnerabilities.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"cve", "severity", "cvss", "known_exploited", "packages", "first_detected", "devices", "status"})
		for _, v := range list {
			cvss := ""
			if v.CVSS != nil {
				cvss = strconv.FormatFloat(*v.CVSS, 'f', 1, 64)
			}
			_ = cw.Write([]string{v.CVE, v.Severity, cvss, strconv.FormatBool(v.KEV), csvSafe(strings.Join(v.Packages, " ")),
				v.FirstSeen.UTC().Format(time.RFC3339), strconv.Itoa(v.Devices), v.Status})
		}
		cw.Flush()
		return
	}
	out := struct {
		Items      []vulnRow `json:"items"`
		Total      int       `json:"total"`
		NextCursor string    `json:"next_cursor,omitempty"`
	}{Items: nonNilSlice(list), Total: total}
	if offset+len(list) < total {
		out.NextCursor = strconv.Itoa(offset + len(list))
	}
	writeJSON(w, out)
}

// apiVulnSummary feeds the three cards: open CVEs by severity, findings
// by status (device and CVE pairs) and the packages with the most open
// CVEs.
func (s *Server) apiVulnSummary(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	type count struct {
		Key string
		N   int
	}
	out := struct {
		Severity     map[string]int   `json:"severity"` // active CVEs per level
		Findings     map[string]int   `json:"findings"` // device and CVE pairs per status
		TopPackages  []vulnTopPackage `json:"top_packages"`
		FeedsEnabled bool             `json:"feeds_enabled"` // any CVE data switched on (Settings, CVE data)
		OS           []string         `json:"os"`            // os_id of the devices with findings, for the filter
		Devices      []vulnDeviceRef  `json:"devices"`       // up to 500 devices with findings, for the filter
	}{Severity: map[string]int{}, Findings: map[string]int{}}
	for _, n := range severityNames {
		out.Severity[n] = 0
	}
	for _, st := range []string{"active", "accepted", "remediated"} {
		out.Findings[st] = 0
	}
	a := &vulnArgs{}
	cte := vulnCTE(c.sess(), a, "")
	sev, err := collect(ctx, s.db, pgx.RowToStructByPos[count], cte+` SELECT x.sev::text, count(*)::int FROM x WHERE x.status = 'active' GROUP BY 1`, a.list...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for _, x := range sev {
		i, _ := strconv.Atoi(x.Key)
		out.Severity[severityNames[i]] = x.N
	}
	st, err := collect(ctx, s.db, pgx.RowToStructByPos[count], cte+` SELECT p.st, count(*)::int FROM (
			SELECT CASE WHEN bool_or(f.st = 'active') THEN 'active' WHEN bool_or(f.st = 'accepted') THEN 'accepted' ELSE 'remediated' END AS st
			FROM f GROUP BY f.cve, f.device_id) p GROUP BY 1`, a.list...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	for _, x := range st {
		out.Findings[x.Key] = x.N
	}
	top, err := collect(ctx, s.db, pgx.RowToStructByPos[vulnTopPackage], cte+` SELECT f.package, count(DISTINCT f.cve)::int, count(DISTINCT f.device_id)::int
		FROM f WHERE f.st = 'active' GROUP BY 1 ORDER BY 2 DESC, 3 DESC, 1 LIMIT 8`, a.list...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	out.TopPackages = nonNilSlice(top)
	out.FeedsEnabled = len(s.settings().CVEFeeds.enabled()) > 0
	scope, args := scopeCond(c.sess(), 0)
	withFindings := `FROM devices d WHERE NOT d.retired AND EXISTS (SELECT 1 FROM device_cves c WHERE c.device_id = d.id) AND ` + scope
	if out.OS, err = collect(ctx, s.db, pgx.RowTo[string], `SELECT DISTINCT d.inventory->>'os_id' `+withFindings+` AND d.inventory->>'os_id' IS NOT NULL ORDER BY 1`, args...); err != nil {
		s.apiFail(w, err)
		return
	}
	if out.Devices, err = collect(ctx, s.db, pgx.RowToStructByPos[vulnDeviceRef], `SELECT d.id, d.hostname `+withFindings+` ORDER BY d.hostname, d.id LIMIT 500`, args...); err != nil {
		s.apiFail(w, err)
		return
	}
	out.OS, out.Devices = nonNilSlice(out.OS), nonNilSlice(out.Devices)
	writeJSON(w, out)
}

type vulnDeviceRef struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

type vulnTopPackage struct {
	Name    string `json:"name"`
	CVEs    int    `json:"cves"`    // open CVEs
	Devices int    `json:"devices"` // devices with one of them
}

type vulnDevice struct {
	ID           string     `json:"id"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	Package      string     `json:"package"`
	Installed    string     `json:"installed"`
	Fixed        string     `json:"fixed"`
	Severity     string     `json:"severity"` // as the source states it
	FirstSeen    time.Time  `json:"first_detected"`
	LastSeen     time.Time  `json:"last_seen"`
	RemediatedAt *time.Time `json:"remediated_at"`
	Status       string     `json:"status"`
	Via          string     `json:"via,omitempty"` // base feed a derivative was matched through
}

type vulnPackage struct {
	Name      string   `json:"name"`
	Installed []string `json:"installed"`
	Fixed     []string `json:"fixed"`
	Devices   int      `json:"devices"` // with an open finding
}

type cveAcceptance struct {
	ID        int64      `json:"id"`
	Tenant    *int64     `json:"tenant_id"`
	DeviceID  string     `json:"device_id"` // empty: every device
	Package   string     `json:"package"`   // empty: every package
	Reason    string     `json:"reason"`
	Expires   time.Time  `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	Created   time.Time  `json:"created_at"`
	Revoked   *time.Time `json:"revoked_at"`
	RevokedBy string     `json:"revoked_by"`
	State     string     `json:"state"` // active | expired | revoked
}

type vulnRef struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// vulnRefs links the CVE at the sources that know it.
func vulnRefs(cve string, sources []string, kev bool) []vulnRef {
	refs := []vulnRef{{"CVE.org", "https://www.cve.org/CVERecord?id=" + cve}, {"NVD", "https://nvd.nist.gov/vuln/detail/" + cve}}
	links := map[string]vulnRef{
		"debian": {"Debian Security Tracker", "https://security-tracker.debian.org/tracker/" + cve},
		"ubuntu": {"Ubuntu CVE Tracker", "https://ubuntu.com/security/" + cve},
		"arch":   {"Arch Linux Security Tracker", "https://security.archlinux.org/" + cve},
		"alpine": {"Alpine Security Tracker", "https://security.alpinelinux.org/vuln/" + cve},
	}
	for _, s := range sources {
		if l, ok := links[s]; ok {
			refs = append(refs, l)
		}
	}
	if kev {
		refs = append(refs, vulnRef{"CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + cve})
	}
	return refs
}

// apiVuln is one CVE: severity, CVSS, KEV entry, the packages with
// installed and fixed versions, the devices in scope, the sources, links
// and the risk acceptances.
func (s *Server) apiVuln(w http.ResponseWriter, r *http.Request, c apiCaller) {
	ctx := r.Context()
	cve := r.PathValue("cve")
	if !cveRe.MatchString(cve) {
		problem(w, http.StatusNotFound, "vulnerability not found")
		return
	}
	scope, args := scopeCond(c.sess(), 1)
	devices, err := collect(ctx, s.db, pgx.RowToStructByPos[vulnDevice], `SELECT d.id, d.hostname, coalesce(d.inventory->>'os_name', d.inventory->>'os_id', ''),
			c.package, c.installed, c.fixed, c.severity, c.first_seen, c.last_seen, c.remediated_at,
			CASE WHEN c.remediated_at IS NOT NULL THEN 'remediated' WHEN `+acceptedSQL+` THEN 'accepted' ELSE 'active' END, c.via
		FROM device_cves c JOIN devices d ON d.id = c.device_id WHERE c.cve = $1 AND NOT d.retired AND `+scope+`
		ORDER BY (c.remediated_at IS NOT NULL), d.hostname, c.package LIMIT 1000`, append([]any{cve}, args...)...)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if len(devices) == 0 {
		problem(w, http.StatusNotFound, "vulnerability not found")
		return
	}
	out := struct {
		CVE         string          `json:"cve"`
		Severity    string          `json:"severity"`
		CVSS        *float64        `json:"cvss"`
		Vector      string          `json:"vector"`
		KEV         *kevEntry       `json:"kev"`
		Status      string          `json:"status"`
		FirstSeen   time.Time       `json:"first_detected"`
		Packages    []vulnPackage   `json:"packages"`
		Devices     []vulnDevice    `json:"devices"`
		Sources     []string        `json:"sources"`
		References  []vulnRef       `json:"references"`
		Acceptances []cveAcceptance `json:"acceptances"`
	}{CVE: cve, Devices: devices, Status: "remediated", FirstSeen: devices[0].FirstSeen}
	level, pkgs := 0, map[string]*vulnPackage{}
	for _, d := range devices {
		level = max(level, severityLevels[strings.ToLower(d.Severity)])
		if d.FirstSeen.Before(out.FirstSeen) {
			out.FirstSeen = d.FirstSeen
		}
		if d.Status == "active" || d.Status == "accepted" && out.Status != "active" {
			out.Status = d.Status
		}
		p := pkgs[d.Package]
		if p == nil {
			p = &vulnPackage{Name: d.Package, Installed: []string{}, Fixed: []string{}}
			pkgs[d.Package] = p
		}
		if !slices.Contains(p.Installed, d.Installed) {
			p.Installed = append(p.Installed, d.Installed)
		}
		if d.Fixed != "" && !slices.Contains(p.Fixed, d.Fixed) {
			p.Fixed = append(p.Fixed, d.Fixed)
		}
		if d.Status != "remediated" {
			p.Devices++
		}
	}
	out.Packages = []vulnPackage{}
	for _, p := range pkgs {
		out.Packages = append(out.Packages, *p)
	}
	slices.SortFunc(out.Packages, func(a, b vulnPackage) int { return strings.Compare(a.Name, b.Name) })
	var vector *string
	err = s.db.QueryRow(ctx, `SELECT cvss::float8, vector FROM cve_scores WHERE cve=$1`, cve).Scan(&out.CVSS, &vector)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.apiFail(w, err)
		return
	}
	if vector != nil {
		out.Vector = *vector
	}
	if level == 0 && out.CVSS != nil {
		level = cvssLevel(*out.CVSS)
	}
	out.Severity = severityNames[level]
	kev, err := collectOne(ctx, s.db, pgx.RowToStructByPos[kevEntry], `SELECT name, added, due, ransomware FROM cve_kev WHERE cve=$1`, cve)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.apiFail(w, err)
		return
	}
	if err == nil {
		out.KEV = &kev
	}
	out.Sources, err = collect(ctx, s.db, pgx.RowTo[string], `SELECT DISTINCT distro FROM cve_fixes WHERE cve=$1 ORDER BY 1`, cve)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if len(out.Sources) == 0 { // the CVE came from the advisories of a pending update
		out.Sources = []string{"package manager"}
	}
	out.References = vulnRefs(cve, out.Sources, out.KEV != nil)
	out.Acceptances, err = s.cveAcceptances(ctx, c.sess(), cve)
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSON(w, out)
}

type kevEntry struct {
	Name       string     `json:"name"`
	Added      *time.Time `json:"added"`
	Due        *time.Time `json:"due"`
	Ransomware bool       `json:"ransomware"`
}

// acceptanceCond limits acceptances (alias a) to what the session may see
// and change: its tenant's and, for a tenant session, not the global
// ones; a scoped session only those of its devices.
func acceptanceCond(sess session, n int) (string, []any) {
	cond, args := tenantCond(sess, "a.tenant_id", n)
	if sess.scoped() {
		dcond, dargs := scopeCond(sess, n+len(args))
		cond += ` AND a.device_id IN (SELECT d.id FROM devices d WHERE ` + dcond + `)`
		args = append(args, dargs...)
	}
	return cond, args
}

func (s *Server) cveAcceptances(ctx context.Context, sess session, cve string) ([]cveAcceptance, error) {
	cond, args := acceptanceCond(sess, 1)
	list, err := collect(ctx, s.db, pgx.RowToStructByPos[cveAcceptance], `SELECT a.id, a.tenant_id, a.device_id, a.package, a.reason, a.expires_at, a.created_by,
			a.created_at, a.revoked_at, a.revoked_by, CASE WHEN a.revoked_at IS NOT NULL THEN 'revoked' WHEN a.expires_at <= now() THEN 'expired' ELSE 'active' END
		FROM cve_acceptances a WHERE a.cve = $1 AND `+cond+` ORDER BY a.revoked_at IS NULL DESC, a.expires_at DESC LIMIT 200`, append([]any{cve}, args...)...)
	return nonNilSlice(list), err
}

// apiVulnAccept records a risk acceptance for a CVE: every device of the
// tenant (global for a global admin), or one device and/or one package.
// A scoped admin accepts only for one device in scope.
func (s *Server) apiVulnAccept(w http.ResponseWriter, r *http.Request, c apiCaller) {
	cve := r.PathValue("cve")
	if !cveRe.MatchString(cve) {
		problem(w, http.StatusNotFound, "vulnerability not found")
		return
	}
	var body struct {
		Reason   string `json:"reason"`
		Expires  string `json:"expires"` // last day it applies, YYYY-MM-DD
		DeviceID string `json:"device_id"`
		Package  string `json:"package"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	sess := c.sess()
	body.Reason, body.DeviceID, body.Package = strings.TrimSpace(body.Reason), strings.TrimSpace(body.DeviceID), strings.TrimSpace(body.Package)
	day, err := time.ParseInLocation(time.DateOnly, body.Expires, time.Local)
	expires := day.AddDate(0, 0, 1) // valid through the given day
	switch {
	case body.Reason == "" || len(body.Reason) > 1000:
		problemField(w, http.StatusUnprocessableEntity, "reason", "reason: 1 to 1000 characters")
		return
	case err != nil || !expires.After(time.Now()) || expires.After(time.Now().AddDate(1, 0, 1)):
		problemField(w, http.StatusUnprocessableEntity, "expires", "expires: a date within the next year")
		return
	case len(body.Package) > 200:
		problemField(w, http.StatusUnprocessableEntity, "package", "package: at most 200 characters")
		return
	case body.DeviceID == "" && sess.scoped():
		problemField(w, http.StatusUnprocessableEntity, "device_id", "device_id: a scoped admin accepts for one device")
		return
	}
	var tenant *int64
	if sess.Tenant != 0 {
		tenant = &sess.Tenant
	}
	if body.DeviceID != "" {
		var devTenant int64
		err := s.db.QueryRow(r.Context(), `SELECT tenant_id FROM devices WHERE id=$1`, body.DeviceID).Scan(&devTenant)
		if err != nil || !s.inScope(r.Context(), sess, body.DeviceID) {
			problemField(w, http.StatusUnprocessableEntity, "device_id", "device_id: no such device")
			return
		}
		tenant = &devTenant
	}
	var id int64
	target := cve
	if body.DeviceID != "" {
		target = body.DeviceID
	}
	err = s.auditAction(r.Context(), c.actor(), "vulnerability.accept", target, fmt.Sprintf("cve=%s device=%q package=%q expires=%s reason=%q",
		cve, body.DeviceID, body.Package, day.Format(time.DateOnly), body.Reason), func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `INSERT INTO cve_acceptances(tenant_id, cve, device_id, package, reason, expires_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, tenant, cve, body.DeviceID, body.Package, body.Reason, expires, c.actor()).Scan(&id)
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]int64{"id": id})
}

// apiVulnReopen revokes the risk acceptances of a CVE the session may
// change, or only acceptance_id when given.
func (s *Server) apiVulnReopen(w http.ResponseWriter, r *http.Request, c apiCaller) {
	cve := r.PathValue("cve")
	if !cveRe.MatchString(cve) {
		problem(w, http.StatusNotFound, "vulnerability not found")
		return
	}
	var body struct {
		ID int64 `json:"acceptance_id"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &body) {
		return
	}
	cond, args := acceptanceCond(c.sess(), 3)
	var ids []int64
	err := s.auditActionFn(r.Context(), func(tx pgx.Tx) (string, string, string, string, error) {
		rows, err := tx.Query(r.Context(), `UPDATE cve_acceptances a SET revoked_at = now(), revoked_by = $2
			WHERE a.cve = $1 AND a.revoked_at IS NULL AND a.expires_at > now() AND ($3::bigint = 0 OR a.id = $3::bigint) AND `+cond+` RETURNING a.id`,
			append([]any{cve, c.actor(), body.ID}, args...)...)
		if err == nil {
			ids, err = pgx.CollectRows(rows, pgx.RowTo[int64])
		}
		if err != nil || len(ids) == 0 {
			return "", "", "", "", err
		}
		return c.actor(), "vulnerability.reopen", cve, fmt.Sprintf("acceptances=%v", ids), nil
	})
	if err != nil {
		s.apiFail(w, err)
		return
	}
	if len(ids) == 0 {
		problem(w, http.StatusNotFound, "no active risk acceptance")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
