package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestFileAllowed(t *testing.T) {
	if fileAllowed(api.File{Path: "/etc/cron.d/x"}, false) == nil {
		t.Fatal("cron file allowed without allow_scripts")
	}
	if fileAllowed(api.File{Path: "/etc/sudo.conf"}, false) == nil {
		t.Fatal("a path outside the allowlist allowed without allow_scripts")
	}
	if fileAllowed(api.File{Path: "/srv/../etc/cron.d/x"}, false) == nil {
		t.Fatal(".. segments allowed")
	}
	if fileAllowed(api.File{Path: "/etc/cron.d/x"}, true) != nil {
		t.Fatal("allow_scripts must allow it")
	}
	if fileAllowed(api.File{Path: "/etc/motd", Mode: "0755"}, false) == nil {
		t.Fatal("executable file allowed without allow_scripts")
	}
}

func TestWriteNoFollow(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	target := filepath.Join(dir, "cron.d")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// /srv/app -> /etc/cron.d: a write below the link would land in the target (F6)
	link := filepath.Join(dir, "app")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(link, "job"), filepath.Join(link, "new", "job")} {
		if _, err := writeNoFollow(p, []byte("x"), 0o644, uid, gid); err == nil {
			t.Fatalf("%s: symlinked parent not refused", p)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(target, "*")); len(m) != 0 {
		t.Fatalf("written through the link: %v", m)
	}
	if err := os.Symlink(filepath.Join(target, "victim"), filepath.Join(dir, "motd")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeNoFollow(filepath.Join(dir, "motd"), []byte("x"), 0o644, uid, gid); err == nil {
		t.Fatal("symlinked file not refused")
	}
	p := filepath.Join(dir, "plain", "sub", "file")
	if changed, err := writeNoFollow(p, []byte("hello"), 0o640, uid, gid); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if changed, err := writeNoFollow(p, []byte("hello"), 0o640, uid, gid); err != nil || changed {
		t.Fatal("unchanged file rewritten", changed, err)
	}
	if changed, err := writeNoFollow(p, []byte("hello"), 0o600, uid, gid); err != nil || !changed {
		t.Fatal("mode not fixed", changed, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "hello" {
		t.Fatalf("content %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestUndeclaredFilesAreRemoved(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keep, gone, edited, legacy := filepath.Join(dir, "keep"), filepath.Join(dir, "gone"), filepath.Join(dir, "edited"), filepath.Join(dir, "legacy")
	for _, p := range []string{keep, gone, edited, legacy} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// a managed path whose parent was swapped for a link to a victim directory
	victim := filepath.Join(dir, "victim")
	os.Mkdir(victim, 0o755)
	os.WriteFile(filepath.Join(victim, "conf"), []byte("x"), 0o644)
	os.Symlink(victim, filepath.Join(dir, "app"))
	swapped := filepath.Join(dir, "app", "conf")
	sum := contentSum([]byte("x"))
	os.WriteFile(edited, []byte("changed by someone"), 0o644)
	a := &Agent{log: slog.New(slog.DiscardHandler), state: State{ManagedFiles: []string{edited, gone, keep, legacy, swapped},
		ManagedFileSums: map[string]string{gone: sum, keep: sum, edited: sum, swapped: sum}}}
	// an invalid files declaration must not count as "nothing declared"
	a.declStatus = []api.DeclarationStatus{{Type: api.TypeFiles, Valid: false}}
	a.applyFiles(nil)
	if _, err := os.Stat(gone); err != nil {
		t.Fatal("removed while a files declaration is invalid")
	}
	a.removeUndeclared([]string{keep})
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatal("undeclared file not removed")
	}
	for _, p := range []string{keep, edited, legacy, filepath.Join(victim, "conf")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed: %v", p, err)
		}
	}
	if len(a.state.ManagedFiles) != 1 || len(a.state.ManagedFileSums) != 1 {
		t.Fatalf("managed set: %v %v", a.state.ManagedFiles, a.state.ManagedFileSums)
	}
}
