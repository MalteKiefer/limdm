package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/maltekiefer/limdm/internal/api"
)

// The log query language of the console's Logs page (docs/logs.md):
//
//	device:mail unit:postfix* prio<=err "connection refused" -healthcheck /timeout after \d+/
//
// Terms are combined with AND; a leading - negates one. Keys: device (ID
// or host name, * as wildcard), tag, blueprint, os, source (journald,
// container, file), unit, container, file, host, prio (name or number,
// with : = < <= > >=), field.NAME (a field of the line). A quoted phrase or
// a bare word must occur in the message (case insensitive), /.../ is a
// regular expression (case insensitive, at most 200 characters; the query
// runs under a statement timeout).

// logTerm is one term of a query.
type logTerm struct {
	neg   bool
	key   string // empty: text
	op    string // : = < <= > >=
	value string
	regex bool
}

var logFieldRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// tokenizeLogQuery splits a query into terms; quotes and slashes group.
func tokenizeLogQuery(q string) ([]logTerm, error) {
	var out []logTerm
	rs := []rune(strings.TrimSpace(q))
	for i := 0; i < len(rs); {
		if unicode.IsSpace(rs[i]) {
			i++
			continue
		}
		var t logTerm
		if rs[i] == '-' && i+1 < len(rs) && !unicode.IsSpace(rs[i+1]) {
			t.neg = true
			i++
		}
		readDelim := func(d rune) (string, error) {
			var b strings.Builder
			for i++; i < len(rs); i++ {
				if rs[i] == '\\' && i+1 < len(rs) && rs[i+1] == d {
					if d == '/' {
						b.WriteRune('\\') // a regular expression keeps the escape
					}
					b.WriteRune(d)
					i++
					continue
				}
				if rs[i] == d {
					i++
					return b.String(), nil
				}
				b.WriteRune(rs[i])
			}
			return "", fmt.Errorf("unclosed %c", d)
		}
		switch rs[i] {
		case '"':
			v, err := readDelim('"')
			if err != nil {
				return nil, err
			}
			t.value = v
		case '/':
			v, err := readDelim('/')
			if err != nil {
				return nil, err
			}
			t.value, t.regex = v, true
		default:
			start := i
			for i < len(rs) && !unicode.IsSpace(rs[i]) && rs[i] != '"' {
				i++
			}
			word := string(rs[start:i])
			if k, op, v, ok := splitLogKey(word); ok {
				t.key, t.op, t.value = k, op, v
				if v == "" && i < len(rs) && rs[i] == '"' {
					q, err := readDelim('"')
					if err != nil {
						return nil, err
					}
					t.value = q
				}
			} else {
				t.value = word
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// splitLogKey splits key:value and comparisons; a word without a known
// key form is text (URLs and times contain colons).
func splitLogKey(w string) (key, op, value string, ok bool) {
	i := strings.IndexAny(w, ":=<>")
	if i <= 0 {
		return "", "", "", false
	}
	key = strings.ToLower(w[:i])
	if !logKeys[key] && !strings.HasPrefix(key, "field.") {
		return "", "", "", false
	}
	rest := w[i:]
	for _, o := range []string{"<=", ">=", ":", "=", "<", ">"} {
		if strings.HasPrefix(rest, o) {
			return key, o, rest[len(o):], true
		}
	}
	return "", "", "", false
}

var logKeys = map[string]bool{"device": true, "tag": true, "blueprint": true, "os": true, "source": true, "unit": true,
	"container": true, "file": true, "host": true, "prio": true, "priority": true}

// likeEscape escapes LIKE wildcards; glob turns * into %.
func likeEscape(s string, glob bool) string {
	s = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
	if glob {
		s = strings.ReplaceAll(s, "*", "%")
	}
	return s
}

// logQueryConds turns a query into SQL conditions on device_logs l and
// devices d.
func logQueryConds(q string, a *vulnArgs) ([]string, error) {
	if len(q) > 2000 {
		return nil, &fieldError{"q", "query: at most 2000 characters"}
	}
	terms, err := tokenizeLogQuery(q)
	if err != nil {
		return nil, &fieldError{"q", "query: " + err.Error()}
	}
	var conds []string
	for _, t := range terms {
		c, err := logTermCond(t, a)
		if err != nil {
			return nil, &fieldError{"q", "query: " + err.Error()}
		}
		if t.neg {
			c = "NOT (" + c + ")"
		}
		conds = append(conds, c)
	}
	return conds, nil
}

func logTermCond(t logTerm, a *vulnArgs) (string, error) {
	v := t.value
	if t.key != "prio" && t.key != "priority" && t.op != ":" && t.op != "=" && t.key != "" {
		return "", fmt.Errorf("%s takes : or =", t.key)
	}
	switch {
	case t.regex:
		if v == "" || len(v) > 200 {
			return "", fmt.Errorf("regular expressions: 1 to 200 characters")
		}
		if _, err := regexp.Compile(v); err != nil {
			return "", fmt.Errorf("regular expression: %w", err)
		}
		return "l.message ~* " + a.add(v), nil
	case t.key == "":
		if v == "" {
			return "", fmt.Errorf("empty phrase")
		}
		return "l.message ILIKE " + a.add("%"+likeEscape(v, false)+"%"), nil
	case v == "":
		return "", fmt.Errorf("%s needs a value", t.key)
	case t.key == "device":
		if strings.Contains(v, "*") {
			return "d.hostname ILIKE " + a.add(likeEscape(v, true)), nil
		}
		n := a.add(v)
		return "(d.id = " + n + " OR lower(d.hostname) = lower(" + n + ") OR lower(d.hostname) LIKE lower(" + a.add(likeEscape(v, false)+".%") + "))", nil
	case t.key == "tag":
		return a.add(v) + " = ANY(d.tags)", nil
	case t.key == "blueprint":
		return "d.blueprint_id IN (SELECT b.id FROM blueprints b WHERE lower(b.name) = lower(" + a.add(v) + "))", nil
	case t.key == "os":
		return "d.inventory->>'os_id' = " + a.add(strings.ToLower(v)), nil
	case t.key == "source":
		switch strings.ToLower(v) {
		case api.LogSourceJournald, "journal":
			return "l.source = 'journald'", nil
		case api.LogSourceContainer, "docker", "podman":
			return "l.source = 'container'", nil
		case api.LogSourceFile:
			return "l.source = 'file'", nil
		}
		return "", fmt.Errorf("source: journald, container or file")
	case t.key == "unit", t.key == "container", t.key == "file":
		c := "l.unit LIKE " + a.add(likeEscape(v, true))
		if t.key != "unit" {
			c += " AND l.source = '" + t.key + "'"
		}
		return c, nil
	case t.key == "host":
		return "l.host ILIKE " + a.add(likeEscape(v, true)), nil
	case t.key == "prio", t.key == "priority":
		p := api.LogPriority(v)
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 7 {
			p = n
		}
		if p < 0 {
			return "", fmt.Errorf("prio: %s or 0 to 7", strings.Join(api.LogPriorities, ", "))
		}
		op := t.op
		if op == ":" {
			op = "="
		}
		return "l.priority " + op + " " + strconv.Itoa(p), nil
	case strings.HasPrefix(t.key, "field."):
		name := strings.TrimPrefix(t.key, "field.")
		if !logFieldRe.MatchString(name) {
			return "", fmt.Errorf("field: names of letters, digits, _ . and -")
		}
		return "l.fields->>" + a.add(name) + " = " + a.add(v), nil
	}
	return "", fmt.Errorf("unknown key %s", t.key)
}
