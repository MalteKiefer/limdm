package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestRunScriptResult(t *testing.T) {
	old := scriptDir
	t.Cleanup(func() { scriptDir = old })
	scriptDir = t.TempDir()
	res, err := runScript("echo \"hello $TARGET\"\necho oops >&2\nexit 3\n", map[string]string{"TARGET": "world; rm -rf /"}, 1)
	if err == nil || res.ExitCode != 3 || strings.TrimSpace(res.Stdout) != "hello world; rm -rf /" || strings.TrimSpace(res.Stderr) != "oops" {
		t.Fatalf("%v %+v", err, res)
	}
	if res.End.Before(res.Start) {
		t.Fatal("end before start")
	}
	if _, err := runScript("true", map[string]string{"LD_PRELOAD": "/tmp/x.so"}, 0); err == nil {
		t.Fatal("LD_PRELOAD accepted as a parameter")
	}
	if _, err := runScript("true", nil, 999); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
}

func TestParseScriptCommand(t *testing.T) {
	sc, err := parseScriptCommand(`{"body":"echo $A","params":{"A":"1"},"timeout_minutes":5}`)
	if err != nil || sc.Body != "echo $A" || sc.Params["A"] != "1" || sc.TimeoutMinutes != 5 {
		t.Fatalf("%v %+v", err, sc)
	}
	if sc, _ := parseScriptCommand("#!/bin/sh\necho hi"); sc.Body != "#!/bin/sh\necho hi" {
		t.Fatal("plain body changed")
	}
	tb := &tailBuffer{max: 4}
	tb.Write([]byte("abcdef"))
	if string(tb.b) != "cdef" {
		t.Fatal(string(tb.b))
	}
	if api.ValidateScriptParams(map[string]string{"path": "x"}, 0) == nil {
		t.Fatal("PATH in lower case accepted")
	}
}

func TestScriptDue(t *testing.T) {
	mon0300 := time.Date(2026, 11, 23, 3, 0, 0, 0, time.UTC) // a Monday
	sched := api.Script{Name: "s", Body: "x", Schedule: &api.ScriptSchedule{Times: []string{"02:00", "14:00"}, Days: []string{"mon", "wed"}}}
	sum := scriptSum(sched)
	if scriptDue(sched, time.Time{}, "", sum, mon0300, 0) {
		t.Fatal("a new schedule must wait for its next slot")
	}
	if !scriptDue(sched, mon0300.Add(-2*time.Hour), sum, sum, mon0300, 0) {
		t.Fatal("02:00 slot after a run at 01:00 is due")
	}
	if scriptDue(sched, mon0300.Add(-30*time.Minute), sum, sum, mon0300, 0) {
		t.Fatal("ran in this slot already")
	}
	mon1430 := mon0300.Add(690 * time.Minute)
	if scriptDue(sched, mon1430, sum, sum, mon0300.Add(24*time.Hour), 0) {
		t.Fatal("tuesday has no slot")
	}
	if !scriptDue(sched, mon1430, sum, sum, mon0300.Add(48*time.Hour), 0) {
		t.Fatal("wednesday 02:00 is due")
	}
	if scriptDue(sched, mon0300.Add(-2*time.Hour), sum, sum, mon0300, 90*time.Minute) {
		t.Fatal("jitter moves the slot to 03:30")
	}
	sched.RunOnChange = true
	if !scriptDue(sched, mon0300, "old", sum, mon0300, 0) {
		t.Fatal("changed content runs at once")
	}
	iv := api.Script{Name: "i", Body: "x", IntervalHours: 24}
	if !scriptDue(iv, time.Time{}, "", scriptSum(iv), mon0300, 0) || scriptDue(iv, mon0300.Add(-time.Hour), "", "", mon0300, 0) {
		t.Fatal("interval")
	}
	js := api.Script{Name: "s", Schedule: &api.ScriptSchedule{Times: []string{"01:00"}, JitterMinutes: 10}}
	if j := scriptJitter("dev", js); j < 0 || j >= 10*time.Minute || j != scriptJitter("dev", js) {
		t.Fatal(j)
	}
}
