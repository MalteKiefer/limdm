package agent

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		got, op, want string
		ok, err       bool
	}{
		{"2", "eq", "2", true, false}, {" 2\n", "eq", "2", true, false}, {"2", "ne", "2", false, false},
		{"10", "gt", "9", true, false}, {"9", "ge", "9", true, false}, {"1.5", "lt", "2", true, false},
		{"abc", "le", "2", false, true}, {"hello world", "contains", "lo w", true, false},
		{"OpenSSH_9.6", "matches", `^OpenSSH_9\.`, true, false}, {"x", "nope", "x", false, true},
	}
	for _, c := range cases {
		ok, err := compare(c.got, c.op, c.want)
		if ok != c.ok || (err != nil) != c.err {
			t.Errorf("compare(%q %s %q) = %v, %v", c.got, c.op, c.want, ok, err)
		}
	}
}

func TestEvalQuery(t *testing.T) {
	rows := []map[string]string{{"name": "a", "uid": "1000"}, {"name": "b", "uid": "1001"}}
	for _, c := range []struct {
		q    api.QueryTest
		rows []map[string]string
		want string
	}{
		{api.QueryTest{Expect: "rows"}, rows, pass},
		{api.QueryTest{Expect: "rows"}, nil, fail},
		{api.QueryTest{Expect: "no_rows"}, nil, pass},
		{api.QueryTest{Expect: "no_rows"}, rows, fail},
		{api.QueryTest{Expect: "compare", Column: "uid", Op: "ge", Value: "1000"}, rows, pass},
		{api.QueryTest{Expect: "compare", Column: "uid", Op: "gt", Value: "1000"}, rows, fail}, // every row must match
		{api.QueryTest{Expect: "compare", Column: "missing", Op: "eq", Value: "x"}, rows, fail},
		{api.QueryTest{Expect: "compare", Column: "uid", Op: "eq", Value: "1"}, nil, fail},
	} {
		if got, detail := evalQuery(c.rows, c.q); got != c.want {
			t.Errorf("%+v: %s (%s), want %s", c.q, got, detail, c.want)
		}
	}
	// row data never leaves the device, compared values only bounded
	secret := []map[string]string{{"result": "AKIA" + strings.Repeat("x", 500)}}
	if _, d := evalQuery(secret, api.QueryTest{Expect: "no_rows"}); strings.Contains(d, "AKIA") {
		t.Errorf("no_rows detail leaks the row: %s", d)
	}
	if _, d := evalQuery(secret, api.QueryTest{Expect: "compare", Column: "result", Op: "eq", Value: "x"}); len(d) > 120 {
		t.Errorf("compare detail not bounded: %d bytes", len(d))
	}
}

func TestEvalFileAndCustomPolicy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "conf")
	if err := os.WriteFile(p, []byte("PermitRootLogin no\nX11Forwarding yes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	me, _ := user.Current()
	for _, c := range []struct {
		f    api.FileTest
		want string
	}{
		{api.FileTest{Path: p, State: "present", MaxMode: "0644", Owner: me.Username}, pass},
		{api.FileTest{Path: p, State: "present", MaxMode: "0600"}, fail},
		{api.FileTest{Path: p, State: "present", Owner: "nobody-here"}, fail},
		{api.FileTest{Path: p, State: "present", Contains: `^PermitRootLogin no$`}, pass},
		{api.FileTest{Path: p, State: "present", NotContains: `^X11Forwarding yes`}, fail},
		{api.FileTest{Path: p, State: "absent"}, fail},
		{api.FileTest{Path: filepath.Join(dir, "none"), State: "absent"}, pass},
		{api.FileTest{Path: filepath.Join(dir, "none"), State: "present"}, fail},
	} {
		if got, detail := evalFile(c.f); got != c.want {
			t.Errorf("%+v: %s (%s), want %s", c.f, got, detail, c.want)
		}
	}

	fileCheck := func(id string, level int, state string) api.CustomCheck {
		return api.CustomCheck{ID: id, Title: id, Severity: "high", Level: level, File: &api.FileTest{Path: p, State: state}}
	}
	a := &Agent{pol: api.Policy{
		Compliance: api.Compliance{Level: 1, Exclude: []string{"custom.excepted"}, Advisory: []string{"custom.advisory"}},
		Extra: api.ExtraPolicy{CustomChecks: []api.CustomCheck{
			fileCheck("custom.ok", 1, "present"), fileCheck("custom.bad", 1, "absent"), fileCheck("custom.excepted", 1, "absent"),
			fileCheck("custom.advisory", 1, "absent"), fileCheck("custom.level2", 2, "absent"),
		}},
	}}
	got := map[string]string{}
	for _, r := range a.evaluateCustom() {
		got[r.ID] = r.Status
		if r.Severity != "high" {
			t.Errorf("%s: severity %q", r.ID, r.Severity)
		}
	}
	want := map[string]string{"custom.ok": pass, "custom.bad": fail, "custom.excepted": "excepted", "custom.advisory": "advisory"}
	if len(got) != len(want) {
		t.Fatalf("results %v", got)
	}
	for id, st := range want {
		if got[id] != st {
			t.Errorf("%s = %s, want %s", id, got[id], st)
		}
	}
}
