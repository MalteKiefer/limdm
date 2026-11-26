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
	// Statements a read only query must not contain. Bare words only: a
	// keyword cannot be quoted, a quoted "update" is a name.
	sqlForbidden = map[string]bool{
		"insert": true, "update": true, "delete": true, "replace": true, "attach": true, "detach": true, "pragma": true,
		"vacuum": true, "create": true, "drop": true, "alter": true,
	}
	// Functions and tables refused in any spelling, quoted or not (file
	// access, extensions, network requests, carving).
	sqlForbiddenNames = map[string]bool{
		"load_extension": true, "writefile": true, "readfile": true, "fts3_tokenizer": true, "carve": true,
		"curl": true, "curl_certificate": true, "carves": true,
	}
)

// OsqueryTables are the only tables a custom check may read: local system
// state for compliance. Tables that reach the network (curl, cloud metadata,
// prometheus_metrics), carve files, expose process environments or talk to
// container daemons are not on the list.
var OsqueryTables = []string{
	"apparmor_profiles", "apt_sources", "augeas", "authorized_keys", "block_devices", "cpu_info",
	"crontab", "deb_packages", "disk_encryption", "dns_resolvers", "etc_hosts", "etc_protocols",
	"etc_services", "file", "groups", "hash", "interface_addresses", "interface_details", "iptables",
	"kernel_info", "kernel_modules", "last", "listening_ports", "logged_in_users", "md_devices",
	"memory_info", "mounts", "npm_packages", "os_version", "osquery_info", "pci_devices",
	"platform_info", "portage_packages", "process_open_sockets", "processes", "python_packages",
	"routes", "rpm_packages", "secureboot", "selinux_settings", "shadow", "ssh_configs",
	"startup_items", "sudoers", "suid_bin", "system_controls", "system_info", "systemd_units",
	"time", "tpm_info", "uptime", "usb_devices", "user_groups", "user_ssh_keys", "users", "yum_sources",
}

// OsqueryDeniedTables are also disabled in osqueryi (--disable_tables), a
// second barrier next to the allowlist.
var OsqueryDeniedTables = []string{
	"curl", "curl_certificate", "carves", "ec2_instance_metadata", "ec2_instance_tags",
	"azure_instance_metadata", "azure_instance_tags", "ycloud_instance_metadata", "prometheus_metrics",
}

func init() {
	Types[TypeCustomChecks] = `{"checks": [` +
		`{"id": "custom.no_telnet", "title": "Telnet client is not installed", "severity": "medium", "level": 1, "refs": {"bsi": ["SYS.2.3.A1"]}, "package": {"name": "telnet", "state": "absent"}}, ` +
		`{"id": "custom.shadow_mode", "title": "/etc/shadow is not readable by others", "severity": "high", "level": 1, "file": {"path": "/etc/shadow", "state": "present", "max_mode": "0640", "owner": "root"}}, ` +
		`{"id": "custom.no_uid0", "title": "Only root has UID 0", "severity": "critical", "level": 1, "query": {"sql": "SELECT username FROM users WHERE uid = 0 AND username <> 'root'", "expect": "no_rows"}}]}`
	listTypes[TypeCustomChecks] = true
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
