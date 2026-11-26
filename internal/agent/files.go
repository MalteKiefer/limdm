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

// fileAllowed limits devices without allow_scripts to the allowlist of
// plain text locations (api.SafeFilePath), refuses files with an execute
// bit there, and makes sure no component of the path is a symlink: a link
// in a parent would redirect the write elsewhere, and a link as the file
// itself would make the mode change follow it.
func fileAllowed(f api.File, allowScripts bool) error {
	if allowScripts {
		return nil
	}
	if !api.SafeFilePath(f.Path) {
		return errors.New("only /etc/motd, /etc/issue, /etc/issue.net, /etc/motd.d, /srv, /etc/opt and /var/opt on devices enrolled without allow_scripts")
	}
	if m, _ := f.FileMode(); m&0o111 != 0 {
		return errors.New("executable files only on devices enrolled with allow_scripts")
	}
	return noSymlinks(f.Path)
}

// noSymlinks fails when the deepest existing directory of p resolves to a
// different path, or p itself is a symlink.
func noSymlinks(p string) error {
	dir := filepath.Dir(p)
	for !exists(dir) && dir != "/" {
		dir = filepath.Dir(dir)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if real != dir {
		return fmt.Errorf("%s is a symlink to %s", dir, real)
	}
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("the file is a symlink")
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
