package agent

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"github.com/maltekiefer/limdm/internal/api"
)

// fileAllowed refuses targets that run as code unless the device allows
// scripts: denylisted paths (also behind a symlinked parent) and files
// with an execute bit.
func fileAllowed(f api.File, allowScripts bool) error {
	if allowScripts {
		return nil
	}
	resolved := f.Path
	if dir, err := filepath.EvalSymlinks(filepath.Dir(f.Path)); err == nil {
		resolved = filepath.Join(dir, filepath.Base(f.Path))
	}
	if api.RootCodePath(f.Path) || api.RootCodePath(resolved) {
		return errors.New("path runs as code (cron, systemd, sudoers, PAM, profile, binaries …); only on devices enrolled with allow_scripts")
	}
	if m, _ := f.FileMode(); m&0o111 != 0 {
		return errors.New("executable files only on devices enrolled with allow_scripts")
	}
	return nil
}

// ids resolves owner and group names (empty: root).
func ids(owner, group string) (int, int, error) {
	uid, gid := 0, 0
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return 0, 0, fmt.Errorf("owner %s: %w", owner, err)
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return 0, 0, fmt.Errorf("group %s: %w", group, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return uid, gid, nil
}

// writeManagedFile writes f with its mode, owner and group.
func writeManagedFile(f api.File) (bool, error) {
	uid, gid, err := ids(f.Owner, f.Group)
	if err != nil {
		return false, err
	}
	mode, _ := f.FileMode()
	changed, err := writeIfChanged(f.Path, f.Content, os.FileMode(mode))
	if err != nil {
		return changed, err
	}
	st, err := os.Lstat(f.Path)
	if err != nil {
		return changed, err
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok && (int(s.Uid) != uid || int(s.Gid) != gid) {
		return true, os.Lchown(f.Path, uid, gid)
	}
	return changed, nil
}

// applyFiles writes the declared files and removes the ones LiMDM wrote
// before that are no longer declared. Nothing is removed while a files
// declaration is invalid: its files would look undeclared.
func (a *Agent) applyFiles(files []api.File) {
	var written []string
	for _, f := range files {
		if err := fileAllowed(f, a.cfg.AllowScripts); err != nil {
			a.problem(api.TypeFiles, "file %s: %v", f.Path, err)
			continue
		}
		written = append(written, f.Path)
		if changed, err := writeManagedFile(f); err != nil {
			a.problem(api.TypeFiles, "file %s: %v", f.Path, err)
		} else if changed {
			a.event("wrote %s", f.Path)
		}
	}
	if slices.ContainsFunc(a.declStatus, func(s api.DeclarationStatus) bool { return s.Type == api.TypeFiles && !s.Valid }) {
		a.state.ManagedFiles = slices.Compact(slices.Sorted(slices.Values(append(a.state.ManagedFiles, written...))))
		return
	}
	a.removeUndeclared(written)
}

// removeUndeclared removes managed files not in written and records written
// as the managed set.
func (a *Agent) removeUndeclared(written []string) {
	keep := slices.Clone(written)
	for _, p := range a.state.ManagedFiles {
		if slices.Contains(written, p) {
			continue
		}
		if err := os.Remove(p); err == nil {
			a.event("removed %s (no longer declared)", p)
		} else if !os.IsNotExist(err) {
			a.problem(api.TypeFiles, "remove %s: %v", p, err)
			keep = append(keep, p) // try again next cycle
		}
	}
	a.state.ManagedFiles = slices.Compact(slices.Sorted(slices.Values(keep)))
}
