package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The list conventions of the admin API, implemented for devices as the
// reference (docs/api.md, "Lists"):
//   filter  the query language below; every token must match
//   sort    a field, "-" in front for descending
//   cursor  opaque keyset cursor from next_cursor
//   facets  GET <list>/facets with the same filter answers counts per value

// filterTokenRe splits a filter into tokens: key:value, key:"quoted value",
// or a bare word.
var filterTokenRe = regexp.MustCompile(`(?:([a-z_]+):)?("[^"]*"|\S+)`)

// filterToken is one token of a list filter; Key is empty for free text.
type filterToken struct{ Key, Value string }

// parseFilterTokens splits a filter of at most 1000 characters into at most
// 20 tokens of at most 200 characters each.
func parseFilterTokens(s string) ([]filterToken, error) {
	if len(s) > 1000 {
		return nil, errors.New("filter: at most 1000 characters")
	}
	var out []filterToken
	for _, m := range filterTokenRe.FindAllStringSubmatch(s, -1) {
		v := m[2]
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > 200 {
			return nil, errors.New("filter: a value has at most 200 characters")
		}
		out = append(out, filterToken{Key: m[1], Value: v})
	}
	if len(out) > 20 {
		return nil, errors.New("filter: at most 20 terms")
	}
	return out, nil
}

// ageRe is a relative age: >7d (older than) or <2h (newer than).
var ageRe = regexp.MustCompile(`^([<>])(\d{1,5})([mhd])$`)

// deviceFilterKeys are the keys of the device filter with a short help
// text, served with the facets so the query bar can suggest them.
var deviceFilterKeys = []struct{ Key, Help string }{
	{"status", "compliant, in-grace, non-compliant, stale, pending, retired"},
	{"os", "part of the operating system name"},
	{"tag", "device tag"},
	{"blueprint", "effective blueprint name"},
	{"agent", "agent version"},
	{"check", "id of a failing compliance check"},
	{"pkg", "installed package, optionally with a version: openssl<3.0.13"},
	{"app", "installed catalog app id"},
	{"flatpak", "installed Flatpak id"},
	{"remote", "Flatpak remote name"},
	{"seen", "last check in: >7d older than, <2h newer than (m, h, d)"},
}

// parseDeviceFilter turns the device filter language into conditions on d.
// Unknown keys and values are errors: ignoring a term would answer with
// more devices than the caller asked for.
func parseDeviceFilter(s string, stale time.Duration) (sqlWhere, error) {
	var w sqlWhere
	toks, err := parseFilterTokens(s)
	if err != nil {
		return w, err
	}
	for _, t := range toks {
		switch t.Key {
		case "":
			w.add(`strpos(lower(d.hostname || ' ' || d.os_name || ' ' || d.id || ' ' || coalesce(b.name, 'default') || ' ' || array_to_string(d.tags, ' ')), $1) > 0`, strings.ToLower(t.Value))
		case "status":
			st := strings.ReplaceAll(t.Value, "-", " ")
			if st == "non compliant" {
				st = "non-compliant"
			}
			if !slices.Contains(deviceStatuses, st) {
				return w, errors.New("status: one of " + deviceFilterKeys[0].Help)
			}
			w.add(deviceStatusSQL+` = $2`, stale.Seconds(), st)
		case "os":
			w.add(`strpos(lower(d.os_name), $1) > 0`, strings.ToLower(t.Value))
		case "pkg":
			cond, args, err := pkgCond(t.Value)
			if err != nil {
				return w, err
			}
			w.add(cond, args...)
		case "seen":
			m := ageRe.FindStringSubmatch(t.Value)
			if m == nil {
				return w, errors.New("seen: >7d or <2h (m, h or d)")
			}
			n, _ := strconv.Atoi(m[2])
			secs := float64(n) * map[string]float64{"m": 60, "h": 3600, "d": 86400}[m[3]]
			if m[1] == ">" {
				w.add(`(d.last_seen IS NULL OR d.last_seen < now() - make_interval(secs => $1))`, secs)
			} else {
				w.add(`d.last_seen >= now() - make_interval(secs => $1)`, secs)
			}
		default:
			key := t.Key
			if key == "check" {
				key = "failing"
			}
			i := slices.IndexFunc(deviceFilters, func(f struct{ Key, Label, Where string }) bool { return f.Key == key })
			if i < 0 {
				return w, fmt.Errorf("unknown filter key %q", t.Key)
			}
			w.add(deviceFilters[i].Where, t.Value)
		}
	}
	return w, nil
}

// deviceSort is a sortable device column: the SQL expression (never NULL,
// so keyset comparisons work), its type for the cursor value, and the value
// of a listed row.
type deviceSort struct {
	expr, cast string
	val        func(d deviceRow) string
}

var deviceSorts = map[string]deviceSort{
	"hostname": {"d.hostname", "text", func(d deviceRow) string { return d.Hostname }},
	"os":       {"d.os_name", "text", func(d deviceRow) string { return d.OS }},
	"agent":    {"d.agent_version", "text", func(d deviceRow) string { return d.AgentVersion }},
	"failing":  {"d.failing", "int", func(d deviceRow) string { return strconv.Itoa(d.Failing) }},
	"last_seen": {"coalesce(d.last_seen, 'epoch'::timestamptz)", "timestamptz", func(d deviceRow) string {
		if d.LastSeen == nil {
			return time.Unix(0, 0).UTC().Format(time.RFC3339Nano)
		}
		return d.LastSeen.UTC().Format(time.RFC3339Nano)
	}},
}

// deviceOrder reads sort (default hostname) and the cursor, adds the keyset
// condition to w and returns the ORDER BY clause and the sort.
func deviceOrder(sortParam, cur string, w *sqlWhere) (string, deviceSort, error) {
	name, desc := strings.CutPrefix(sortParam, "-")
	if name == "" {
		name = "hostname"
	}
	so, ok := deviceSorts[name]
	if !ok {
		keys := make([]string, 0, len(deviceSorts))
		for k := range deviceSorts {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return "", so, errors.New("sort: one of " + strings.Join(keys, ", ") + ", with - for descending")
	}
	dir, op := "ASC", ">"
	if desc {
		dir, op = "DESC", "<"
	}
	if cur != "" {
		var kv [2]string
		err := json.Unmarshal([]byte(cur), &kv)
		switch {
		case err == nil && so.cast == "int":
			_, err = strconv.Atoi(kv[0])
		case err == nil && so.cast == "timestamptz":
			_, err = time.Parse(time.RFC3339Nano, kv[0])
		}
		if err != nil {
			return "", so, errors.New("invalid cursor")
		}
		w.add(fmt.Sprintf(`(%s, d.id) %s ($1::%s, $2)`, so.expr, op, so.cast), kv[0], kv[1])
	}
	return fmt.Sprintf(" ORDER BY %s %s, d.id %s", so.expr, dir, dir), so, nil
}

// deviceCursor is the cursor after row d.
func deviceCursor(so deviceSort, d deviceRow) string {
	b, _ := json.Marshal([2]string{so.val(d), d.ID})
	return cursor(string(b))
}

// apiDeviceWhere is the condition of a device list request: the classic
// query parameters, the filter language and the caller's scope.
func (s *Server) apiDeviceWhere(r *http.Request, c apiCaller) (sqlWhere, error) {
	dq, err := parseDeviceQuery(r.URL.Query(), s.staleAfter())
	if err != nil {
		return sqlWhere{}, err
	}
	where := dq.where()
	f, err := parseDeviceFilter(r.URL.Query().Get("filter"), s.staleAfter())
	if err != nil {
		return sqlWhere{}, err
	}
	where.add(f.sql(), f.args...) // f numbers its arguments from $1 as add expects
	scope, sargs := scopeCond(c.sess(), 0)
	where.add(scope, sargs...)
	return where, nil
}

type facetCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// apiDeviceFacets counts the devices matching the request per status, OS,
// agent version, blueprint and tag (at most 25 values each, most first).
func (s *Server) apiDeviceFacets(w http.ResponseWriter, r *http.Request, c apiCaller) {
	where, err := s.apiDeviceWhere(r, c)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	status := renum(deviceStatusSQL, len(where.args))
	exprs := map[string]string{
		"status": status, "os": "d.os_name", "agent": "d.agent_version",
		"blueprint": "coalesce(b.name, 'default')", "tag": "unnest(d.tags)",
	}
	out := map[string][]facetCount{}
	total := 0
	for name, expr := range exprs {
		args := where.args
		if name == "status" {
			args = append(append([]any(nil), where.args...), s.staleAfter().Seconds())
		}
		list, err := facetQuery(ctx, s, `SELECT `+expr+` AS v, count(*)`+deviceFrom+` WHERE `+where.sql()+` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 25`, args...)
		if err != nil {
			s.apiFail(w, err)
			return
		}
		out[name] = list
		if name == "status" {
			for _, f := range list {
				total += f.Count
			}
		}
	}
	keys := make([]map[string]string, len(deviceFilterKeys))
	for i, k := range deviceFilterKeys {
		keys[i] = map[string]string{"key": k.Key, "help": k.Help}
	}
	writeJSON(w, map[string]any{"total": total, "facets": out, "keys": keys})
}

func facetQuery(ctx context.Context, s *Server, sql string, args ...any) ([]facetCount, error) {
	rows, err := s.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []facetCount{}
	for rows.Next() {
		var f facetCount
		if err := rows.Scan(&f.Value, &f.Count); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
