package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Custom compliance checks (com.limdm.customchecks). They have no automatic
// fix; exceptions and advisory work like for the built in catalog.

// evaluateCustom runs the custom checks of the policy level.
func (a *Agent) evaluateCustom() []api.CheckResult {
	p := a.pol.Compliance
	var out []api.CheckResult
	for _, c := range a.pol.Extra.CustomChecks {
		if c.Level > p.Level {
			continue
		}
		r := api.CheckResult{ID: c.ID, Title: c.Title, Level: c.Level, Refs: c.Refs, Severity: c.Severity}
		if slices.Contains(p.Exclude, c.ID) {
			r.Status, r.Detail = "excepted", "documented exception (risk accepted)"
		} else {
			r.Status, r.Detail = a.runCustom(c)
		}
		if r.Status == fail && slices.Contains(p.Advisory, c.ID) {
			r.Status = "advisory"
		}
		out = append(out, r)
	}
	return out
}

func (a *Agent) runCustom(c api.CustomCheck) (string, string) {
	switch {
	case c.Query != nil:
		// validated with the declaration already; again right before osqueryi
		if err := api.ValidateOsquerySQL(c.Query.SQL); err != nil {
			return fail, err.Error()
		}
		if !hasOsquery() {
			return fail, "osquery is not installed, the query cannot run"
		}
		rows, err := osqWithin(30*time.Second, c.Query.SQL)
		if err != nil {
			return fail, "query failed: " + lastLines(err.Error(), 3)
		}
		return evalQuery(rows, *c.Query)
	case c.File != nil:
		return evalFile(*c.File)
	case c.Sysctl != nil:
		p := sysctlPath(c.Sysctl.Key)
		if !exists(p) {
			return na, c.Sysctl.Key + " does not exist on this kernel"
		}
		got := readTrim(p)
		if ok, err := compare(got, c.Sysctl.Op, c.Sysctl.Value); err != nil || !ok {
			return fail, fmt.Sprintf("%s=%s (want %s %s)", c.Sysctl.Key, got, c.Sysctl.Op, c.Sysctl.Value)
		}
		return pass, c.Sysctl.Key + "=" + got
	case c.Package != nil:
		installed := a.host.isInstalled(c.Package.Name)
		if installed == (c.Package.State == "installed") {
			return pass, c.Package.Name + " " + c.Package.State
		}
		return fail, fmt.Sprintf("%s is %s", c.Package.Name, map[bool]string{true: "installed", false: "not installed"}[installed])
	case c.Service != nil:
		s := c.Service
		active := unitActive(s.Name)
		if active != (s.State == "active") {
			return fail, fmt.Sprintf("%s is %s", s.Name, map[bool]string{true: "active", false: "inactive"}[active])
		}
		if s.Enabled != nil && systemd() {
			_, err := run(30*time.Second, "systemctl", "is-enabled", "--quiet", "--", s.Name)
			if (err == nil) != *s.Enabled {
				return fail, fmt.Sprintf("%s enabled=%v, want %v", s.Name, err == nil, *s.Enabled)
			}
		}
		return pass, s.Name + " " + s.State
	}
	return fail, "check has no test"
}

// evalQuery decides a query test from osquery's rows.
func evalQuery(rows []map[string]string, q api.QueryTest) (string, string) {
	switch q.Expect {
	case "rows":
		if len(rows) == 0 {
			return fail, "no rows"
		}
		return pass, fmt.Sprintf("%d rows", len(rows))
	case "no_rows":
		if len(rows) > 0 {
			return fail, fmt.Sprintf("%d rows, first: %s", len(rows), rowText(rows[0]))
		}
		return pass, "no rows"
	case "compare":
		if len(rows) == 0 {
			return fail, "no rows to compare"
		}
		for _, r := range rows {
			got, ok := r[q.Column]
			if !ok {
				return fail, "column " + q.Column + " not in the result"
			}
			if ok, err := compare(got, q.Op, q.Value); err != nil || !ok {
				return fail, fmt.Sprintf("%s=%q (want %s %q)", q.Column, got, q.Op, q.Value)
			}
		}
		return pass, fmt.Sprintf("%d rows match", len(rows))
	}
	return fail, "unknown expectation " + q.Expect
}

func rowText(r map[string]string) string {
	parts := make([]string, 0, len(r))
	for _, k := range sortedKeys(r) {
		parts = append(parts, k+"="+r[k])
	}
	return truncateText(strings.Join(parts, " "), 300)
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// compare applies a comparison operator; lt, le, gt and ge need numbers.
func compare(got, op, want string) (bool, error) {
	got = strings.TrimSpace(got)
	switch op {
	case "eq":
		return got == want, nil
	case "ne":
		return got != want, nil
	case "contains":
		return strings.Contains(got, want), nil
	case "matches":
		re, err := regexp.Compile(want)
		if err != nil {
			return false, err
		}
		return re.MatchString(got), nil
	}
	g, err1 := strconv.ParseFloat(got, 64)
	w, err2 := strconv.ParseFloat(want, 64)
	if err := errors.Join(err1, err2); err != nil {
		return false, fmt.Errorf("%s needs numbers: %w", op, err)
	}
	switch op {
	case "lt":
		return g < w, nil
	case "le":
		return g <= w, nil
	case "gt":
		return g > w, nil
	case "ge":
		return g >= w, nil
	}
	return false, fmt.Errorf("unknown operator %q", op)
}

// evalFile checks a file condition. Symbolic links are followed, like a
// program reading the path would.
func evalFile(f api.FileTest) (string, string) {
	fi, err := os.Stat(f.Path)
	switch {
	case f.State == "absent" && errors.Is(err, os.ErrNotExist):
		return pass, f.Path + " does not exist"
	case f.State == "absent" && err == nil:
		return fail, f.Path + " exists"
	case err != nil:
		return fail, err.Error()
	}
	var bad []string
	if f.MaxMode != "" {
		max, _ := (api.File{Mode: f.MaxMode}).FileMode()
		if m := uint32(fi.Mode().Perm()); m&^max != 0 || fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			bad = append(bad, fmt.Sprintf("mode %04o exceeds %s", m, f.MaxMode))
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if f.Owner != "" {
			if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err != nil || u.Username != f.Owner {
				bad = append(bad, fmt.Sprintf("owner uid %d is not %s", st.Uid, f.Owner))
			}
		}
		if f.Group != "" {
			if g, err := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); err != nil || g.Name != f.Group {
				bad = append(bad, fmt.Sprintf("group gid %d is not %s", st.Gid, f.Group))
			}
		}
	}
	if f.Contains != "" || f.NotContains != "" {
		if !fi.Mode().IsRegular() {
			return fail, f.Path + " is not a regular file"
		}
		fh, err := os.Open(f.Path)
		if err != nil {
			return fail, err.Error()
		}
		b, err := io.ReadAll(io.LimitReader(fh, 1<<20))
		fh.Close()
		if err != nil {
			return fail, err.Error()
		}
		// (?m): ^ and $ match at line boundaries, so expressions work per line
		reC, err1 := regexp.Compile("(?m)" + f.Contains)
		reN, err2 := regexp.Compile("(?m)" + f.NotContains)
		if err := errors.Join(err1, err2); err != nil {
			return fail, err.Error()
		}
		if f.Contains != "" && !reC.Match(b) {
			bad = append(bad, "no line matches "+f.Contains)
		}
		if f.NotContains != "" && reN.Match(b) {
			bad = append(bad, "a line matches "+f.NotContains)
		}
	}
	if len(bad) > 0 {
		return fail, strings.Join(bad, ", ")
	}
	return pass, f.Path + " ok"
}
