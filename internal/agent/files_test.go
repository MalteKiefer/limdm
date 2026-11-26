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

func TestNoSymlinks(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "cron.d")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// /srv/app -> /etc/cron.d: a write below the link lands in the target
	link := filepath.Join(dir, "app")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if noSymlinks(filepath.Join(link, "job")) == nil || noSymlinks(filepath.Join(link, "new", "job")) == nil {
		t.Fatal("symlinked parent not refused")
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "motd")); err != nil {
		t.Fatal(err)
	}
	if noSymlinks(filepath.Join(dir, "motd")) == nil {
		t.Fatal("symlinked file not refused")
	}
	if err := noSymlinks(filepath.Join(dir, "plain", "file")); err != nil {
		t.Fatal(err)
	}
}

func TestUndeclaredFilesAreRemoved(t *testing.T) {
	dir := t.TempDir()
	keep, gone := filepath.Join(dir, "keep"), filepath.Join(dir, "gone")
	for _, p := range []string{keep, gone} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a := &Agent{log: slog.New(slog.DiscardHandler), state: State{ManagedFiles: []string{gone, keep}}}
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
	if _, err := os.Stat(keep); err != nil || len(a.state.ManagedFiles) != 1 {
		t.Fatalf("declared file touched: %v %v", err, a.state.ManagedFiles)
	}
}
