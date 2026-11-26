package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// scriptDir holds the script file while it runs (a variable for tests).
var scriptDir = stateDir

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

// parseScriptCommand reads a script command payload: a ScriptCommand JSON
// object, or (servers before 0.16, no parameters) the plain body.
func parseScriptCommand(payload string) (api.ScriptCommand, error) {
	var sc api.ScriptCommand
	if strings.HasPrefix(strings.TrimSpace(payload), "{") && json.Unmarshal([]byte(payload), &sc) == nil && sc.Body != "" {
		return sc, api.ValidateScriptParams(sc.Params, sc.TimeoutMinutes)
	}
	return api.ScriptCommand{Body: payload}, nil
}

// runScript runs a script IT sent with its parameters as environment
// variables and a bounded timeout (default 30 minutes). A shebang line
// picks the interpreter (bash, python …); without one it runs with /bin/sh.
func runScript(body string, params map[string]string, timeoutMinutes int) (api.ScriptResult, error) {
	res := api.ScriptResult{ExitCode: -1, Start: time.Now().UTC()}
	if err := api.ValidateScriptParams(params, timeoutMinutes); err != nil { // checked on the agent too: the declaration may come from an old server
		res.End = res.Start
		return res, err
	}
	f, err := os.CreateTemp(scriptDir, "script-*")
	if err != nil {
		res.End = time.Now().UTC()
		return res, err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(strings.ReplaceAll(body, "\r\n", "\n")) // pasted from Windows editors
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		res.End = time.Now().UTC()
		return res, err
	}
	timeout := time.Duration(max(timeoutMinutes, 0)) * time.Minute
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	argv := append(scriptInterpreter(body), f.Name())
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+params[k])
	}
	cmd.Env = env
	out, errOut := &tailBuffer{max: api.MaxScriptOutput}, &tailBuffer{max: api.MaxScriptOutput}
	cmd.Stdout, cmd.Stderr = out, errOut
	cmd.WaitDelay = 5 * time.Second // a background child must not keep the pipes open forever
	err = cmd.Run()
	res.End = time.Now().UTC()
	res.Stdout, res.Stderr = string(out.b), string(errOut.b)
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	switch {
	case errors.Is(err, exec.ErrWaitDelay) && res.ExitCode == 0:
		err = nil // exited fine; a background child it started keeps the output open
	case ctx.Err() != nil:
		res.ExitCode = -1
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return res, err
}

// scriptOutput is the short text a command result shows besides the
// structured result.
func scriptOutput(r api.ScriptResult) string {
	return strings.TrimSpace(lastLines(r.Stdout, 200) + "\n" + lastLines(r.Stderr, 20))
}
