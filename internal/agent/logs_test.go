package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

const journalFixture = `{"__CURSOR":"s=1;i=1","__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"3","_SYSTEMD_UNIT":"postfix@-.service","SYSLOG_IDENTIFIER":"postfix/smtp","_HOSTNAME":"mail","_PID":"42","MESSAGE":"connect to mx: Connection refused"}
{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1700000001000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"kernel","MESSAGE":[104,105]}
{"__CURSOR":"s=1;i=3","__REALTIME_TIMESTAMP":"1700000002`

func TestParseJournal(t *testing.T) {
	lines, cur := parseJournal([]byte(journalFixture))
	if len(lines) != 2 || cur != "s=1;i=2" {
		t.Fatalf("%d lines, cursor %q", len(lines), cur)
	}
	l := lines[0]
	if l.Unit != "postfix@-.service" || l.Priority != 3 || l.Host != "mail" || l.Fields["_PID"] != "42" || l.Source != api.LogSourceJournald ||
		!l.Time.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("line %+v", l)
	}
	if lines[1].Message != "hi" || lines[1].Unit != "kernel" {
		t.Errorf("binary message %+v", lines[1])
	}
}

func stubLogCmd(t *testing.T, fn func(name string, args []string) (string, string, error)) {
	old := runLogCmd
	runLogCmd = func(name string, args []string, max int) ([]byte, []byte, error) {
		o, e, err := fn(name, args)
		return []byte(o), []byte(e), err
	}
	t.Cleanup(func() { runLogCmd = old })
}

func TestContainerLogs(t *testing.T) {
	since := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	stubLogCmd(t, func(name string, args []string) (string, string, error) {
		if name != "docker" || args[0] != "logs" || args[3] != since.Format(time.RFC3339Nano) {
			t.Errorf("call %s %v", name, args)
		}
		return "2026-01-01T10:00:00Z old line\n2026-01-01T10:00:02.5Z GET / 200\n2026-01-01T10:00:03Z ERROR db gone\n",
			"2026-01-01T10:00:01Z starting\n", nil
	})
	ct := logContainer{ID: strings.Repeat("ab", 32), Name: "paperless", Project: "paperless"}
	lines, last, err := containerLogs("docker", ct, since)
	if err != nil || len(lines) != 3 {
		t.Fatalf("%v %+v", err, lines)
	}
	if lines[0].Message != "starting" || lines[0].Priority != 5 || lines[2].Priority != 3 || lines[1].Fields["compose_project"] != "paperless" {
		t.Errorf("lines %+v", lines)
	}
	if !last.Equal(since.Add(3 * time.Second)) {
		t.Errorf("last %v", last)
	}
	cfg := api.Logging{ExcludeContainers: []string{"*-tmp"}, ComposeProjects: []string{"paper*"}}
	if !wantedContainer(cfg, ct) || wantedContainer(cfg, logContainer{Name: "x-tmp", Project: "paperless"}) || wantedContainer(cfg, logContainer{Name: "db"}) {
		t.Error("container filter")
	}
	if !wantedContainer(api.Logging{ContainerLabels: []string{"logs=yes"}}, logContainer{Name: "a", Labels: map[string]string{"logs": "yes"}}) {
		t.Error("label filter")
	}
}

// allowRoot lets the tests read below dir, as /var/log/ is in production.
func allowRoot(t *testing.T, dir string) {
	old := logPathAllowed
	logPathAllowed = func(p string) bool { return strings.HasPrefix(p, dir+"/") }
	t.Cleanup(func() { logPathAllowed = old })
}

func TestLogFilesRotation(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	allowRoot(t, dir)
	p := filepath.Join(dir, "app.log")
	write := func(name, s string) {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(s)
		f.Close()
	}
	write(p, "before collection\n")
	c := newLogCollector(filepath.Join(dir, "spool"))
	os.MkdirAll(c.dir, 0o700)
	if err := c.configure(api.Logging{Enabled: true, Files: []string{p}, MinPriority: "debug"}); err != nil {
		t.Fatal(err)
	}
	c.collectFiles() // starts at the end
	write(p, "one\ntwo partial")
	c.collectFiles()
	write(p, " done\nlast of old\n")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	write(p+".1", "written after rename\n")
	write(p, "new file\n")
	c.collectFiles()
	if err := c.closeSegment(); err != nil {
		t.Fatal(err)
	}
	segs, _ := c.segments()
	var got []string
	for _, s := range segs {
		lines, _ := readSegment(s)
		for _, l := range lines {
			got = append(got, l.Message)
		}
	}
	want := "one|two partial done|last of old|written after rename|new file"
	if strings.Join(got, "|") != want {
		t.Errorf("got %q", strings.Join(got, "|"))
	}
}

func TestLogKeepMaskAndLimits(t *testing.T) {
	c := newLogCollector(t.TempDir())
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	if err := c.configure(api.Logging{LinesPerSecond: 1, Exclude: []string{"healthcheck"}, Mask: []string{`customer-\d+`}, MinPriority: "info"}); err != nil {
		t.Fatal(err)
	}
	l := api.LogLine{Message: "login password=hunter2 Authorization: Bearer abc.def customer-42 jdbc://u:pw@db", Priority: 6, Fields: map[string]string{"x": "token: zzz"}}
	if !c.keep(&l) {
		t.Fatal("dropped")
	}
	if strings.Contains(l.Message, "hunter2") || strings.Contains(l.Message, "abc.def") || strings.Contains(l.Message, "42") || strings.Contains(l.Message, ":pw@") || l.Fields["x"] != "token: ***" {
		t.Errorf("not masked: %q %v", l.Message, l.Fields)
	}
	if c.keep(&api.LogLine{Message: "debug", Priority: 7}) || c.keep(&api.LogLine{Message: "GET /healthcheck", Priority: 6}) {
		t.Error("filters")
	}
	kept := 0
	for range 30 { // burst of ten seconds at one line per second
		if c.keep(&api.LogLine{Message: "x", Priority: 6}) {
			kept++
		}
	}
	if kept != 9 || c.st.Dropped != 21 {
		t.Errorf("kept %d dropped %d", kept, c.st.Dropped)
	}
}

func TestLogSpoolBoundAndShip(t *testing.T) {
	c := newLogCollector(t.TempDir())
	n := int64(0)
	c.now = func() time.Time { n++; return time.Unix(0, n) }
	if err := c.configure(api.Logging{BufferMB: 1, LinesPerSecond: 1000, MinPriority: "debug"}); err != nil {
		t.Fatal(err)
	}
	c.tokens, c.refill = 1e9, time.Unix(0, 1)
	big := strings.Repeat("x", 4000)
	for i := range 600 { // about 2.4 MB: the oldest segments go
		if err := c.add([]api.LogLine{{Message: big, Priority: 6, Cursor: "c" + string(rune('a'+i%26))}}); err != nil {
			t.Fatal(err)
		}
	}
	if c.st.Dropped == 0 {
		t.Fatal("nothing dropped from a full spool")
	}
	dropped := c.st.Dropped
	fail := errors.New("offline")
	calls := 0
	err := c.ship(context.Background(), func(_ context.Context, b api.LogBatch) error {
		calls++
		if calls == 2 {
			return fail
		}
		if calls == 1 && b.Dropped != dropped {
			t.Errorf("dropped %d, want %d", b.Dropped, dropped)
		}
		return nil
	})
	if !errors.Is(err, fail) || c.st.Dropped != 0 {
		t.Fatalf("ship: %v, dropped %d", err, c.st.Dropped)
	}
	left, _ := c.segments()
	if len(left) == 0 {
		t.Error("failed segment removed")
	}
	if err := c.ship(context.Background(), func(context.Context, api.LogBatch) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if left, _ := c.segments(); len(left) != 0 {
		t.Error("segments left after shipping")
	}
	if !ownLine(api.LogLine{Unit: "limdm-agent.service"}) || ownLine(api.LogLine{Unit: "postfix.service"}) {
		t.Error("own lines")
	}
}

func TestLogFileOpenRefusals(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(base, "log")
	secret := filepath.Join(base, "shadow") // outside the allowed root
	os.MkdirAll(root, 0o755)
	os.WriteFile(secret, []byte("root:$6$hash:::\n"), 0o600)
	os.WriteFile(filepath.Join(root, "ok.log"), []byte("fine\n"), 0o644)
	allowRoot(t, root)
	if f, _, err := openLogFile(filepath.Join(root, "ok.log")); err != nil {
		t.Fatalf("plain file: %v", err)
	} else {
		f.Close()
	}
	// a link as the file, and a link as a directory, leading out of the root
	os.Symlink(secret, filepath.Join(root, "app.log"))
	os.Symlink(base, filepath.Join(root, "sub"))
	for _, p := range []string{filepath.Join(root, "app.log"), filepath.Join(root, "sub", "shadow"), secret} {
		if f, _, err := openLogFile(p); err == nil {
			f.Close()
			t.Errorf("%s opened", p)
		}
	}
	// a link inside the root is refused too (no link as last component)
	os.Symlink(filepath.Join(root, "ok.log"), filepath.Join(root, "alias.log"))
	if _, _, err := openLogFile(filepath.Join(root, "alias.log")); err == nil {
		t.Error("link followed")
	}
	// a directory others can write to (not owned by root)
	open := filepath.Join(root, "open")
	os.Mkdir(open, 0o755)
	os.Chmod(open, 0o777)
	os.WriteFile(filepath.Join(open, "x.log"), []byte("x\n"), 0o644)
	if _, _, err := openLogFile(filepath.Join(open, "x.log")); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("world writable directory: %v", err)
	}
	// a file others can write to
	os.WriteFile(filepath.Join(root, "w.log"), []byte("x\n"), 0o644)
	os.Chmod(filepath.Join(root, "w.log"), 0o666)
	if _, _, err := openLogFile(filepath.Join(root, "w.log")); err == nil {
		t.Error("world writable file opened")
	}
	// the real check: outside /var/log/ and /srv/<name>/log/
	logPathAllowed = api.LogFileAllowed
	if _, _, err := openLogFile(filepath.Join(root, "ok.log")); err == nil {
		t.Error("path outside the allowlist opened")
	}
}
