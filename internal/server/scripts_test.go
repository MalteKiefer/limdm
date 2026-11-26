package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestScriptCommandPayload(t *testing.T) {
	form := func(v url.Values) string {
		r := httptest.NewRequest("POST", "/", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p, err := scriptCommandPayload(r)
		if err != nil {
			return "error: " + err.Error()
		}
		return p
	}
	if got := form(url.Values{"payload": {"echo hi"}}); got != "echo hi" {
		t.Fatalf("plain body must stay plain for older agents: %q", got)
	}
	var sc api.ScriptCommand
	got := form(url.Values{"payload": {"echo $A"}, "params": {"A=1=2\r\n\nB= x "}, "timeout_minutes": {"10"}})
	if err := json.Unmarshal([]byte(got), &sc); err != nil || sc.Params["A"] != "1=2" || sc.Params["B"] != " x " || sc.TimeoutMinutes != 10 {
		t.Fatalf("%q %+v", got, sc)
	}
	for _, v := range []url.Values{
		{"payload": {"x"}, "params": {"LD_PRELOAD=/tmp/x"}},
		{"payload": {"x"}, "params": {"no equals sign"}},
		{"payload": {"x"}, "timeout_minutes": {"1000"}},
		{"payload": {"  "}},
	} {
		if got := form(v); !strings.HasPrefix(got, "error: ") {
			t.Errorf("%v accepted: %q", v, got)
		}
	}
}
