package agent

import (
	"strings"
	"testing"

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
	tb.Write([]byte("abcdef")) //nolint:errcheck // never fails
	if string(tb.b) != "cdef" {
		t.Fatal(string(tb.b))
	}
	if api.ValidateScriptParams(map[string]string{"path": "x"}, 0) == nil {
		t.Fatal("PATH in lower case accepted")
	}
}
