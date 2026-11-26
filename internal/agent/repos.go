package agent

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Switching off package sources the agent does not manage. The original file
// is kept in repoBackupDir and restored once the source is no longer listed.
// If a package update rewrites a disabled file, it is backed up and disabled
// again on the next cycle.

const (
	repoBackupDir = stateDir + "/repo-backup"
	disabledMark  = "# Disabled by LiMDM; the original is kept in " + repoBackupDir + "\n"
	disabledLine  = "# limdm-disabled: "
)

var enabledKey = regexp.MustCompile(`(?im)^(enabled)\s*[:=].*\n?`)

func (h *host) repoPath(name string) string {
	switch {
	case h.family == "debian" && name == "sources.list":
		return "/etc/apt/sources.list"
	case h.family == "debian" && (strings.HasSuffix(name, ".list") || strings.HasSuffix(name, ".sources")):
		return "/etc/apt/sources.list.d/" + name
	case (h.family == "fedora" || h.family == "suse") && strings.HasSuffix(name, ".repo"):
		_, dir := h.repoDirs()
		return dir + "/" + name
	}
	return ""
}

// disableRepoContent returns the switched off form of a source file.
func disableRepoContent(name, s string) string {
	var b strings.Builder
	b.WriteString(disabledMark)
	switch {
	case strings.HasSuffix(name, ".sources"): // deb822: Enabled: no in every stanza
		// stanzas end at blank lines (also whitespace only or CRLF); stanzas
		// of comments only stay as they are, apt rejects "Enabled" without Types
		var stanzas [][]string
		cur := []string{}
		for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
			if strings.TrimSpace(line) == "" {
				if len(cur) > 0 {
					stanzas, cur = append(stanzas, cur), []string{}
				}
				continue
			}
			cur = append(cur, line)
		}
		if len(cur) > 0 {
			stanzas = append(stanzas, cur)
		}
		for i, st := range stanzas {
			if i > 0 {
				b.WriteString("\n")
			}
			fields := false
			for _, line := range st {
				if t := strings.TrimSpace(line); !strings.HasPrefix(t, "#") {
					fields = true
				}
			}
			text := strings.Join(st, "\n") + "\n"
			if fields {
				text = strings.TrimRight(enabledKey.ReplaceAllString(text, ""), "\n") + "\nEnabled: no\n"
			}
			b.WriteString(text)
		}
	case strings.HasSuffix(name, ".repo"): // ini: enabled=0 in every section
		for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
			t := strings.TrimSpace(line)
			if k, _, ok := strings.Cut(t, "="); ok && strings.EqualFold(strings.TrimSpace(k), "enabled") {
				continue
			}
			b.WriteString(line + "\n")
			if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
				b.WriteString("enabled=0\n")
			}
		}
	default: // one line format: comment out every source line
		for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
				line = disabledLine + line
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func (a *Agent) applyRepoDisable(files []string) error {
	var errs []error
	changed := false
	want := map[string]bool{}
	for _, name := range files {
		path := a.host.repoPath(name)
		if path == "" {
			continue // other distribution family
		}
		want[name] = true
		cur, err := os.ReadFile(path)
		if err != nil || strings.HasPrefix(string(cur), disabledMark) {
			continue // missing or already off
		}
		if err := os.MkdirAll(repoBackupDir, 0o700); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.WriteFile(filepath.Join(repoBackupDir, name), cur, 0o600); err != nil { //nolint:gosec // name matches repoFileRe (no path separators)
			errs = append(errs, err)
			continue
		}
		if _, err := writeIfChanged(path, disableRepoContent(name, string(cur)), 0o644); err != nil {
			errs = append(errs, err)
			continue
		}
		changed = true
		a.event("package source %s disabled", name)
	}
	backups, _ := filepath.Glob(filepath.Join(repoBackupDir, "*"))
	for _, b := range backups {
		name := filepath.Base(b)
		if want[name] {
			continue
		}
		path := a.host.repoPath(name)
		if path != "" && strings.HasPrefix(readFile(path), disabledMark) {
			orig, err := os.ReadFile(b)
			if err == nil {
				_, err = writeIfChanged(path, string(orig), 0o644)
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			changed = true
			a.event("package source %s enabled again", name)
		}
		errs = append(errs, os.Remove(b))
	}
	if changed {
		a.host.aptStale.Store(true)
	}
	return errors.Join(errs...)
}
