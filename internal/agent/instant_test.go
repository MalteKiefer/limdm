package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// TestPollStartsQuickCheckin measures the way of a command to the agent: the
// first poll after it was queued starts a quick check in, and afterwards the
// agent polls every requestPoll for follow ups.
func TestPollStartsQuickCheckin(t *testing.T) {
	oldEvery, oldJitter := pollEvery, pollJitter
	pollEvery, pollJitter = 100*time.Millisecond, func() time.Duration { return 0 }
	defer func() { pollEvery, pollJitter = oldEvery, oldJitter }()
	var queued atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(api.PollResponse{Pending: queued.Load()})
	}))
	defer srv.Close()
	a := &Agent{cfg: Config{Server: srv.URL}, client: srv.Client(), log: slog.New(slog.DiscardHandler), quick: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.pollLoop(ctx) }()
	defer func() { cancel(); <-done }()
	time.Sleep(250 * time.Millisecond)
	select {
	case <-a.quick:
		t.Fatal("quick check in without a command")
	default:
	}
	created := time.Now()
	queued.Store(true)
	select {
	case <-a.quick:
		d := time.Since(created)
		t.Logf("command queued to quick check in: %v (poll interval %v)", d, pollEvery)
		if d > 3*pollEvery {
			t.Fatalf("delivery took %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending poll did not start a quick check in")
	}
}

// TestWipeReboot runs the restart sequence with a fake clock and runner:
// it waits for the deadline, logs each failed way, and stops once a way
// takes the device down (here: the goroutine ends inside the wait).
func TestWipeReboot(t *testing.T) {
	oldRun, oldWrite, oldNow, oldSleep, oldFile := wipeRun, wipeWrite, wipeNow, wipeSleep, wipedFile
	defer func() {
		wipeRun, wipeWrite, wipeNow, wipeSleep, wipedFile = oldRun, oldWrite, oldNow, oldSleep, oldFile
	}()
	wipedFile = filepath.Join(t.TempDir(), "wiped")
	start := time.Date(2026, 11, 28, 13, 4, 0, 0, time.UTC)
	os.WriteFile(wipedFile, []byte(start.Format(time.RFC3339)), 0o600)

	run := func(fail func(cmd string) bool) (calls, writes []string, events []string) {
		var mu sync.Mutex
		clock := start
		wipeNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
		down := false
		wipeSleep = func(d time.Duration) {
			mu.Lock()
			clock = clock.Add(d)
			gone := down
			mu.Unlock()
			if gone {
				runtime.Goexit() // the device restarted while waiting
			}
		}
		wipeRun = func(_ time.Duration, name string, args ...string) (string, error) {
			cmd := strings.Join(append([]string{name}, args...), " ")
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, cmd)
			if name == "systemctl" && args[0] == "mask" {
				return "", nil
			}
			if fail(cmd) {
				return "", errors.New("refused")
			}
			if clock.Before(start.Add(wipeRebootAfter)) {
				t.Errorf("%s before the deadline: %v", cmd, clock)
			}
			down = true
			return "", nil
		}
		wipeWrite = func(path, data string) error {
			mu.Lock()
			defer mu.Unlock()
			writes = append(writes, data)
			return nil
		}
		a := &Agent{log: slog.New(slog.DiscardHandler)}
		done := make(chan struct{})
		go func() { defer close(done); a.wipeReboot() }()
		<-done
		return calls, writes, a.pendingEvents()
	}

	calls, writes, events := run(func(cmd string) bool { return cmd == "systemctl reboot --force" })
	want := []string{"systemctl mask --runtime sleep.target suspend.target hibernate.target hybrid-sleep.target suspend-then-hibernate.target", "systemctl reboot --force", "systemctl reboot --force --force"}
	if !slices.Equal(calls, want) || len(writes) != 0 {
		t.Fatalf("calls %q writes %q", calls, writes)
	}
	all := strings.Join(events, "\n")
	for _, s := range []string{"wipe restart scheduled at 2026-11-28T13:06:00Z", "wipe restart failed: systemctl reboot --force: refused", "systemctl reboot --force --force accepted"} {
		if !strings.Contains(all, s) {
			t.Errorf("event %q missing in:\n%s", s, all)
		}
	}

	// nothing works: reboot -f, then sync, remount and reboot through sysrq
	calls, writes, events = run(func(string) bool { return true })
	if len(calls) != 4 || calls[3] != "reboot -f" || !slices.Equal(writes, []string{"s", "u", "b"}) {
		t.Fatalf("calls %q writes %q", calls, writes)
	}
	if !strings.Contains(strings.Join(events, "\n"), "the device is still running") {
		t.Fatalf("final failure not reported: %q", events)
	}
}

// TestWipedDesktop: after a wipe the desktop gets no escrow prompt but the
// wiped state, and an escrow attempt is refused.
func TestWipedDesktop(t *testing.T) {
	old := wipedFile
	defer func() { wipedFile = old }()
	wipedFile = filepath.Join(t.TempDir(), "wiped")
	a := &Agent{}
	d := &desktopServer{a: a, queued: map[string]bool{}, inflight: map[string]bool{}, failures: map[uint32][]time.Time{}}
	d.info.Store(&desktopInfo{Company: "ACME", Need: []luksVolume{{"/dev/sda3", "u1"}}})
	if r := d.serve(1000, DesktopRequest{Op: "status"}); len(r.Need) != 1 {
		t.Fatalf("before the wipe: %+v", r)
	}
	os.WriteFile(wipedFile, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
	if r := d.serve(1000, DesktopRequest{Op: "status"}); len(r.Need) != 0 {
		t.Fatalf("escrow prompt after the wipe: %+v", r)
	}
	if r := d.serve(1000, DesktopRequest{Op: "info"}); r.Status == nil || !r.Status.Wiped || len(r.Need) != 0 {
		t.Fatalf("info after the wipe: %+v", r)
	}
	if r := d.serve(1000, DesktopRequest{Op: "escrow", UUID: "u1", Passphrase: "x"}); r.OK || r.Error == "" {
		t.Fatal("escrow accepted on a wiped device")
	}
	if m := a.missingEscrow(); m != nil {
		t.Fatalf("missing escrow on a wiped device: %v", m)
	}
}
