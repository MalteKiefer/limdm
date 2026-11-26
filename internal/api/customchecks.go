package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Custom compliance checks defined by IT. Each check has exactly one test: a
// read only osquery query or a declarative file, sysctl, package or service
// condition. There is no shell: nothing in a check is executed as a program
// except osqueryi with the validated query.

const TypeCustomChecks = "com.limdm.customchecks"

type CustomCheck struct {
	ID       string `json:"id"` // custom.<name>
	Title    string `json:"title"`
	Severity string `json:"severity"` // low | medium | high | critical
	Level    int    `json:"level"`    // 1 or 2, like the built in checks
	Refs     Refs   `json:"refs,omitzero"`

	Query   *QueryTest   `json:"query,omitempty"`
	File    *FileTest    `json:"file,omitempty"`
	Sysctl  *SysctlTest  `json:"sysctl,omitempty"`
	Package *PackageTest `json:"package,omitempty"`
	Service *ServiceTest `json:"service,omitempty"`
}

// QueryTest runs SQL with osqueryi. Expect "rows" passes when the query
// returns at least one row, "no_rows" when it returns none, "compare" when
// it returns rows and Column of every row satisfies Op Value.
type QueryTest struct {
	SQL    string `json:"sql"`
	Expect string `json:"expect"`
	Column string `json:"column,omitempty"`
	Op     string `json:"op,omitempty"`
	Value  string `json:"value,omitempty"`
}

// FileTest: State "present" or "absent". For present files MaxMode (octal)
// forbids permission bits beyond it, Owner and Group name the expected
// owner, Contains and NotContains are RE2 expressions matched per line.
type FileTest struct {
	Path        string `json:"path"`
	State       string `json:"state"`
	MaxMode     string `json:"max_mode,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Group       string `json:"group,omitempty"`
	Contains    string `json:"contains,omitempty"`
	NotContains string `json:"not_contains,omitempty"`
}

type SysctlTest struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type PackageTest struct {
	Name  string `json:"name"`
	State string `json:"state"` // installed | absent
}

type ServiceTest struct {
	Name    string `json:"name"`
	State   string `json:"state"`             // active | inactive
	Enabled *bool  `json:"enabled,omitempty"` // checked only when set (systemd)
}

// CompareOps are the operators of query and sysctl comparisons. lt, le, gt
// and ge compare numbers; matches is an RE2 expression.
var CompareOps = []string{"eq", "ne", "lt", "le", "gt", "ge", "contains", "matches"}

var (
	customIDRe = regexp.MustCompile(`^custom\.[a-z0-9][a-z0-9_.-]{0,55}$`)
	columnRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	severities = []string{"low", "medium", "high", "critical"}
	sqlWordRe  = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	// A single statement starting with SELECT or WITH can only write through
	// WITH ... INSERT/UPDATE/DELETE/REPLACE; the rest are functions and
	// osquery tables with side effects (network requests, file carving).
	sqlForbidden = map[string]bool{
		"insert": true, "update": true, "delete": true, "replace": true, "attach": true, "detach": true, "pragma": true,
		"load_extension": true, "writefile": true, "curl": true, "curl_certificate": true, "carves": true,
	}
)

func init() {
	Types[TypeCustomChecks] = `{"checks": [` +
		`{"id": "custom.no_telnet", "title": "Telnet client is not installed", "severity": "medium", "level": 1, "refs": {"bsi": ["SYS.2.3.A1"]}, "package": {"name": "telnet", "state": "absent"}}, ` +
		`{"id": "custom.shadow_mode", "title": "/etc/shadow is not readable by others", "severity": "high", "level": 1, "file": {"path": "/etc/shadow", "state": "present", "max_mode": "0640", "owner": "root"}}, ` +
		`{"id": "custom.no_uid0", "title": "Only root has UID 0", "severity": "critical", "level": 1, "query": {"sql": "SELECT username FROM users WHERE uid = 0 AND username <> 'root'", "expect": "no_rows"}}]}`
	listTypes[TypeCustomChecks] = true
}

// ValidateOsquerySQL accepts a single read only SELECT (or WITH ... SELECT)
// statement. It runs on the server when an item is saved and on the agent
// before osqueryi sees the query.
func ValidateOsquerySQL(q string) error {
	if strings.TrimSpace(q) == "" || len(q) > 4096 {
		return errors.New("query: 1 to 4096 characters")
	}
	for _, r := range q {
		if r < 0x20 && r != '\n' && r != '\t' && r != '\r' {
			return errors.New("query: control characters are not allowed")
		}
	}
	code, err := sqlCode(q)
	if err != nil {
		return err
	}
	code = strings.TrimRight(strings.TrimSpace(code), ";")
	switch {
	case strings.ContainsAny(code, ";"):
		return errors.New("query: exactly one statement")
	case strings.Contains(code, "--") || strings.Contains(code, "/*"):
		return errors.New("query: comments are not allowed")
	}
	words := sqlWordRe.FindAllStringIndex(code, -1)
	if len(words) == 0 || !slices.Contains([]string{"select", "with"}, strings.ToLower(code[words[0][0]:words[0][1]])) {
		return errors.New("query: must start with SELECT or WITH")
	}
	for _, at := range words {
		w := strings.ToLower(code[at[0]:at[1]])
		if w == "replace" && strings.HasPrefix(strings.TrimLeft(code[at[1]:], " \t\r\n"), "(") {
			continue // the string function replace(), not the statement
		}
		if sqlForbidden[w] {
			return fmt.Errorf("query: %q is not allowed (read only queries)", w)
		}
	}
	return nil
}

// sqlCode blanks string literals and quoted identifiers, so keywords and
// semicolons inside them are not mistaken for code.
func sqlCode(q string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		c := q[i]
		closer := map[byte]byte{'\'': '\'', '"': '"', '`': '`', '[': ']'}[c]
		if closer == 0 {
			b.WriteByte(c)
			continue
		}
		j := i + 1
		for ; j < len(q); j++ {
			if q[j] == closer {
				if closer != ']' && j+1 < len(q) && q[j+1] == closer { // doubled quote escapes itself
					j++
					continue
				}
				break
			}
		}
		if j >= len(q) {
			return "", errors.New("query: unterminated quote")
		}
		b.WriteString(" x ")
		i = j
	}
	return b.String(), nil
}

// Validate checks one custom check with the same rules on server and agent.
func (c CustomCheck) Validate() error {
	var errs []error
	bad := func(f string, a ...any) {
		errs = append(errs, fmt.Errorf("check %q: "+f, append([]any{c.ID}, a...)...))
	}
	if !customIDRe.MatchString(c.ID) {
		bad("id must start with custom. followed by lower case letters, digits, dot, dash or underscore")
	}
	if strings.TrimSpace(c.Title) == "" || !noControl(c.Title, 200) || strings.Contains(c.Title, "\n") {
		bad("title: one line up to 200 characters")
	}
	if !slices.Contains(severities, c.Severity) {
		bad("severity is low, medium, high or critical")
	}
	if c.Level != 1 && c.Level != 2 {
		bad("level must be 1 or 2")
	}
	for _, r := range slices.Concat(c.Refs.BSI, c.Refs.CIS, c.Refs.ISO) {
		if r == "" || !noControl(r, 200) || strings.Contains(r, "\n") {
			bad("framework references: one line up to 200 characters each")
		}
	}
	tests := 0
	for _, set := range []bool{c.Query != nil, c.File != nil, c.Sysctl != nil, c.Package != nil, c.Service != nil} {
		if set {
			tests++
		}
	}
	if tests != 1 {
		bad("exactly one test (query, file, sysctl, package or service) is required")
		return errors.Join(errs...)
	}
	switch {
	case c.Query != nil:
		q := c.Query
		if err := ValidateOsquerySQL(q.SQL); err != nil {
			bad("%v", err)
		}
		switch q.Expect {
		case "rows", "no_rows":
			if q.Column != "" || q.Op != "" || q.Value != "" {
				bad("column, op and value belong to expect compare")
			}
		case "compare":
			if !columnRe.MatchString(q.Column) {
				bad("compare needs a column name")
			}
			if err := validCompare(q.Op, q.Value); err != nil {
				bad("%v", err)
			}
		default:
			bad("expect is rows, no_rows or compare")
		}
	case c.File != nil:
		f := c.File
		if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || len(f.Path) > 1024 || strings.ContainsAny(f.Path, "\x00\n") {
			bad("file path must be absolute and clean")
		}
		switch f.State {
		case "absent":
			if f.MaxMode != "" || f.Owner != "" || f.Group != "" || f.Contains != "" || f.NotContains != "" {
				bad("an absent file has no further conditions")
			}
		case "present":
			if f.MaxMode != "" {
				if _, err := (File{Mode: f.MaxMode}).FileMode(); err != nil {
					bad("max_mode: %v", err)
				}
			}
			if (f.Owner != "" && !groupRe.MatchString(f.Owner)) || (f.Group != "" && !groupRe.MatchString(f.Group)) {
				bad("invalid owner or group")
			}
			for _, re := range []string{f.Contains, f.NotContains} {
				if _, err := regexp.Compile(re); err != nil || len(re) > 1024 {
					bad("invalid expression %q", re)
				}
			}
		default:
			bad("file state is present or absent")
		}
	case c.Sysctl != nil:
		if !sysctlKey.MatchString(c.Sysctl.Key) {
			bad("invalid sysctl key")
		}
		if err := validCompare(c.Sysctl.Op, c.Sysctl.Value); err != nil {
			bad("%v", err)
		}
	case c.Package != nil:
		if !pkgRe.MatchString(c.Package.Name) || (c.Package.State != "installed" && c.Package.State != "absent") {
			bad("package needs a valid name and state installed or absent")
		}
	case c.Service != nil:
		if !unitRe.MatchString(c.Service.Name) || (c.Service.State != "active" && c.Service.State != "inactive") {
			bad("service needs a valid unit name and state active or inactive")
		}
	}
	return errors.Join(errs...)
}

func validCompare(op, value string) error {
	if !slices.Contains(CompareOps, op) {
		return fmt.Errorf("op is one of %s", strings.Join(CompareOps, ", "))
	}
	if !noControl(value, 1024) {
		return errors.New("value: up to 1024 characters")
	}
	if op == "matches" {
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("value: invalid expression: %w", err)
		}
	}
	return nil
}

type customChecksPayload struct {
	Checks []CustomCheck `json:"checks"`
}

func (d Declaration) applyCustom(p *Policy) (bool, error) {
	if d.Type != TypeCustomChecks {
		return false, nil
	}
	var v customChecksPayload
	if err := strict(d.Payload, &v); err != nil {
		return true, err
	}
	var errs []error
	seen := map[string]bool{}
	for _, c := range v.Checks {
		if seen[c.ID] {
			errs = append(errs, fmt.Errorf("check %q is defined twice", c.ID))
		}
		seen[c.ID] = true
		errs = append(errs, c.Validate())
	}
	if len(v.Checks) > 200 {
		errs = append(errs, errors.New("at most 200 custom checks"))
	}
	p.Extra.CustomChecks = v.Checks
	return true, errors.Join(errs...)
}

// mergeCustom combines custom checks by ID; a later item wins.
func mergeCustom(typ string, a, b json.RawMessage) (json.RawMessage, bool, error) {
	if typ != TypeCustomChecks {
		return mergeArtifacts(typ, a, b) // artifacts.go
	}
	var x, y customChecksPayload
	if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
		return nil, true, err
	}
	out := x.Checks
	for _, c := range y.Checks {
		if i := slices.IndexFunc(out, func(e CustomCheck) bool { return e.ID == c.ID }); i >= 0 {
			out[i] = c
		} else {
			out = append(out, c)
		}
	}
	m, err := json.Marshal(customChecksPayload{Checks: out})
	return m, true, err
}
