package server

import (
	"context"
	"errors"
	"html/template"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sqlWhere collects AND conditions with their arguments. Each condition
// numbers its own arguments from $1; add renumbers them.
type sqlWhere struct {
	conds []string
	args  []any
}

var placeholderRe = regexp.MustCompile(`\$(\d+)`)

func (w *sqlWhere) add(cond string, vals ...any) {
	w.conds = append(w.conds, renum(cond, len(w.args)))
	w.args = append(w.args, vals...)
}

// renum shifts the placeholders of cond by base: $1 becomes $(base+1).
func renum(cond string, base int) string {
	return placeholderRe.ReplaceAllStringFunc(cond, func(p string) string {
		n, _ := strconv.Atoi(p[1:])
		return "$" + strconv.Itoa(base+n)
	})
}

func (w sqlWhere) sql() string {
	if len(w.conds) == 0 {
		return "TRUE"
	}
	return strings.Join(w.conds, " AND ")
}

// clone copies w so a caller can add conditions without touching w.
func (w sqlWhere) clone() sqlWhere {
	return sqlWhere{conds: append([]string(nil), w.conds...), args: append([]any(nil), w.args...)}
}

// deviceStatusSQL is the status of device d as status() computes it; $1 is
// the stale age in seconds.
const deviceStatusSQL = `CASE WHEN d.retired THEN 'retired'
	WHEN d.last_seen IS NULL OR d.checks_count = 0 THEN 'pending'
	WHEN d.last_seen < now() - make_interval(secs => $1) THEN 'stale'
	WHEN d.failing > 0 AND d.grace_until > now() THEN 'in grace'
	WHEN d.failing > 0 THEN 'non-compliant'
	ELSE 'compliant' END`

// deviceFrom is the FROM clause every device list query shares; b is the
// effective blueprint.
const deviceFrom = ` FROM devices d LEFT JOIN blueprints b ON b.id = ` + effectiveBlueprintSQL

var deviceStatuses = []string{"compliant", "in grace", "non-compliant", "stale", "pending", "retired"}

// pkgFilterRe is a package filter: a name, optionally an operator and a version.
var pkgFilterRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9.+_-]*)\s*(?:(<=|>=|!=|=|<|>)\s*([A-Za-z0-9][A-Za-z0-9.+~:_-]*))?$`)

var pkgOps = map[string]string{"<": "<", "<=": "<=", "=": "=", "!=": "<>", ">=": ">=", ">": ">"}

// pkgCond turns "openssl < 3.0.13" into a condition on d. Versions compare
// by their runs of digits (limdm_version_key in schema.sql).
// ponytail: numeric runs only, letters and Debian tilde ordering are ignored; a real dpkg/rpm comparison when this misleads.
func pkgCond(v string) (string, []any, error) {
	m := pkgFilterRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", nil, errors.New("package filter: a name, or name operator version, for example openssl < 3.0.13")
	}
	elems := `jsonb_array_elements(CASE WHEN jsonb_typeof(d.packages) = 'array' THEN d.packages ELSE '[]'::jsonb END)`
	if m[2] == "" {
		return `EXISTS (SELECT 1 FROM ` + elems + ` p WHERE p->>'n' = $1)`, []any{m[1]}, nil
	}
	return `EXISTS (SELECT 1 FROM ` + elems + ` p WHERE p->>'n' = $1 AND limdm_version_key(p->>'v') ` + pkgOps[m[2]] + ` limdm_version_key($2))`, []any{m[1], m[3]}, nil
}

type deviceChip struct {
	Key, Label, Val string
	Clear           template.URL // the list without this filter
}

// deviceQuery is a device search: every filter given applies (AND).
type deviceQuery struct {
	filters sqlWhere // all filters except the status
	stale   float64
	Status  string
	Q       string
	Chips   []deviceChip
	Keep    url.Values // filters and search, without status and page
}

// parseDeviceQuery reads the device filters from a query string. Values
// longer than 200 characters are ignored, as before.
func parseDeviceQuery(q url.Values, stale time.Duration) (deviceQuery, error) {
	dq := deviceQuery{stale: stale.Seconds(), Keep: url.Values{}}
	get := func(k string) string {
		if v := strings.TrimSpace(q.Get(k)); len(v) <= 200 {
			return v
		}
		return ""
	}
	for _, f := range deviceFilters {
		if v := get(f.Key); v != "" {
			dq.filters.add(f.Where, v)
			dq.Chips = append(dq.Chips, deviceChip{Key: f.Key, Label: f.Label, Val: v})
			dq.Keep.Set(f.Key, v)
		}
	}
	if v := get("pkg"); v != "" {
		cond, args, err := pkgCond(v)
		if err != nil {
			return dq, err
		}
		dq.filters.add(cond, args...)
		dq.Chips = append(dq.Chips, deviceChip{Key: "pkg", Label: "Package", Val: v})
		dq.Keep.Set("pkg", v)
	}
	if v := strings.ToLower(get("q")); v != "" {
		dq.filters.add(`strpos(lower(d.hostname || ' ' || d.os_name || ' ' || d.id || ' ' || coalesce(b.name, 'default') || ' ' || array_to_string(d.tags, ' ')), $1) > 0`, v)
		dq.Q = v
		dq.Keep.Set("q", v)
	}
	if v := q.Get("status"); v != "" {
		for _, st := range deviceStatuses {
			if v == st {
				dq.Status = v
			}
		}
	}
	for i := range dq.Chips {
		u := url.Values{}
		for k, v := range dq.Keep {
			if k != dq.Chips[i].Key {
				u[k] = v
			}
		}
		if dq.Status != "" {
			u.Set("status", dq.Status)
		}
		dq.Chips[i].Clear = "/devices"
		if len(u) > 0 {
			dq.Chips[i].Clear += template.URL("?" + u.Encode()) //nolint:gosec // url.Values.Encode escapes every key and value
		}
	}
	return dq, nil
}

// where is the full condition, the status included.
func (dq deviceQuery) where() sqlWhere {
	w := dq.filters.clone()
	if dq.Status != "" {
		w.add(deviceStatusSQL+` = $2`, dq.stale, dq.Status)
	}
	return w
}

// deviceCounts counts the devices matching the filters per status.
func (s *Server) deviceCounts(ctx context.Context, dq deviceQuery) (map[string]int, int, error) {
	w := dq.filters.clone()
	status := renum(deviceStatusSQL, len(w.args))
	w.args = append(w.args, dq.stale)
	rows, err := s.db.Query(ctx, `SELECT `+status+`, count(*)`+deviceFrom+` WHERE `+w.sql()+` GROUP BY 1`, w.args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	counts, total := map[string]int{}, 0
	for rows.Next() {
		var st string
		var c int
		if err := rows.Scan(&st, &c); err != nil {
			return nil, 0, err
		}
		counts[st] = c
		total += c
	}
	return counts, total, rows.Err()
}
