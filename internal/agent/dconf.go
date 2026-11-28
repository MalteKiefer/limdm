package agent

import (
	"errors"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

const (
	dconfCustom      = "/etc/dconf/db/local.d/70-limdm-custom"
	dconfCustomLocks = "/etc/dconf/db/local.d/locks/70-limdm-custom"
)

// dconfFiles renders a dconf declaration as a keyfile ([dir] key=value)
// and a locks file; empty strings remove them.
func dconfFiles(d *api.Dconf) (settings, locks string) {
	if d == nil || len(d.Settings)+len(d.Locks) == 0 {
		return "", ""
	}
	groups := map[string][]string{}
	for _, k := range sortedKeys(d.Settings) {
		dir, key := path.Split(k)
		groups[strings.Trim(dir, "/")] = append(groups[strings.Trim(dir, "/")], key+"="+d.Settings[k])
	}
	var b strings.Builder
	b.WriteString(managedHeader)
	for _, dir := range slices.Sorted(maps.Keys(groups)) {
		b.WriteString("\n[" + dir + "]\n" + strings.Join(groups[dir], "\n") + "\n")
	}
	settings = b.String()
	if len(d.Locks) > 0 {
		locks = managedHeader + strings.Join(slices.Sorted(slices.Values(d.Locks)), "\n") + "\n"
	}
	return settings, locks
}

// applyDconf writes the declared dconf defaults and locks next to the screen
// lock settings and compiles the database with the same umask repair.
func (a *Agent) applyDconf(d *api.Dconf) error {
	settings, locks := dconfFiles(d)
	c1, e1 := writeOrRemove(dconfCustom, settings, 0o644)
	c2, e2 := writeOrRemove(dconfCustomLocks, locks, 0o644)
	if err := errors.Join(e1, e2); err != nil || !c1 && !c2 {
		return err
	}
	if settings != "" {
		if err := a.installFor("dconf"); err != nil {
			return err
		}
	}
	if !hasCmd("dconf") {
		return nil
	}
	return dconfUpdate(true, settings != "")
}
