package server

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSQLWhereRenumbers(t *testing.T) {
	var w sqlWhere
	w.add(`a = $1`, 1)
	w.add(`b = $1 AND c > $2`, 2, 3)
	if got := w.sql(); got != `a = $1 AND b = $2 AND c > $3` || len(w.args) != 3 {
		t.Fatalf("%s %v", got, w.args)
	}
	if renum(`x = $1 OR y = $10`, 2) != `x = $3 OR y = $12` {
		t.Fatal("renum")
	}
}

func TestPkgCond(t *testing.T) {
	for _, ok := range []string{"openssl", "openssl < 3.0.13", "libssl3>=3.0.2-0ubuntu1.15", "openssl = 1:3.0.13-1~deb12u1", "g++ != 12"} {
		if _, _, err := pkgCond(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "openssl <", "openssl; DROP", "< 3", "openssl << 3", "-x"} {
		if _, _, err := pkgCond(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	cond, args, _ := pkgCond("openssl != 3")
	if !strings.Contains(cond, "<>") || args[0] != "openssl" || args[1] != "3" {
		t.Fatal(cond, args)
	}
}

func TestParseDeviceQueryCombines(t *testing.T) {
	q, _ := url.ParseQuery("tag=finance&agent=0.15.0&pkg=openssl&q=PC&status=stale&page=2")
	dq, err := parseDeviceQuery(q, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(dq.Chips) != 3 || dq.Q != "pc" || dq.Status != "stale" {
		t.Fatalf("%+v", dq)
	}
	if w := dq.where(); len(w.conds) != 5 || len(w.args) != 6 {
		t.Fatalf("%d conditions %d args", len(w.conds), len(w.args))
	}
	for _, c := range dq.Chips {
		if strings.Contains(string(c.Clear), c.Key+"=") || !strings.Contains(string(c.Clear), "status=stale") {
			t.Errorf("clear %s: %s", c.Key, c.Clear)
		}
	}
	if _, err := parseDeviceQuery(url.Values{"status": {"bogus"}}, time.Hour); err == nil {
		t.Fatal("unknown status accepted")
	}
	// a filter that cannot apply must fail, never widen to the whole fleet
	if _, err := parseDeviceQuery(url.Values{"tag": {strings.Repeat("x", 201)}}, time.Hour); err == nil {
		t.Fatal("over long filter ignored")
	}
	if _, err := parseDeviceQuery(url.Values{"pkg": {"a;b"}}, time.Hour); err == nil {
		t.Fatal("bad package filter accepted")
	}
}
