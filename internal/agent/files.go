package agent

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"

	"github.com/maltekiefer/limdm/internal/api"
)

// fileAllowed limits devices without allow_scripts to the allowlist of
// plain text locations (api.SafeFilePath) and refuses files with an execute
// bit there. Symlinks in the path are refused on every device by the
// writer itself (writeNoFollow): a link in a parent would redirect the
// write elsewhere, a link as the file would make the mode change follow it.
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
	return writeNoFollow(f.Path, []byte(f.Content), os.FileMode(mode), uid, gid)
}

// applyFiles writes the declared files and removes the ones LiMDM wrote
// before that are no longer declared. Nothing is removed while a files
// declaration is invalid: its files would look undeclared.
func (a *Agent) applyFiles(files []api.File) {
	var written []string
	if a.state.ManagedFileSums == nil {
		a.state.ManagedFileSums = map[string]string{}
	}
	for _, f := range files {
		if err := fileAllowed(f, a.cfg.AllowScripts); err != nil {
			a.problem(api.TypeFiles, "file %s: %v", f.Path, err)
			continue
		}
		written = append(written, f.Path)
		if changed, err := writeManagedFile(f); err != nil {
			a.problem(api.TypeFiles, "file %s: %v", f.Path, err)
		} else {
			a.state.ManagedFileSums[f.Path] = contentSum([]byte(f.Content))
			if changed {
				a.event("wrote %s", f.Path)
			}
		}
	}
	if slices.ContainsFunc(a.declStatus, func(s api.DeclarationStatus) bool { return s.Type == api.TypeFiles && !s.Valid }) {
		a.state.ManagedFiles = slices.Compact(slices.Sorted(slices.Values(append(a.state.ManagedFiles, written...))))
		return
	}
	a.removeUndeclared(written)
}

// removeUndeclared removes managed files not in written and records written
// as the managed set. A file is removed only when it is still the regular
// file LiMDM wrote (no symlink on the way, same content); otherwise it
// stays and is no longer managed.
func (a *Agent) removeUndeclared(written []string) {
	keep := slices.Clone(written)
	for _, p := range a.state.ManagedFiles {
		if slices.Contains(written, p) {
			continue
		}
		switch err := removeNoFollow(p, a.state.ManagedFileSums[p]); {
		case err == nil:
			a.event("removed %s (no longer declared)", p)
		case errors.Is(err, errNotOurs):
			a.event("kept %s (no longer declared): %v", p, err)
		default:
			a.problem(api.TypeFiles, "remove %s: %v", p, err)
			keep = append(keep, p) // try again next cycle
		}
	}
	a.state.ManagedFiles = slices.Compact(slices.Sorted(slices.Values(keep)))
	for p := range a.state.ManagedFileSums {
		if !slices.Contains(a.state.ManagedFiles, p) {
			delete(a.state.ManagedFileSums, p)
		}
	}
}
