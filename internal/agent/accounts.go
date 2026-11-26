package agent

import (
	"path/filepath"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// adminGroups grant root via sudo on Debian, Ubuntu (sudo, admin) and Fedora (wheel).
var adminGroups = []string{"sudo", "wheel", "admin"}

// repos reads apt sources (one line .list and deb822 .sources) or dnf and zypper .repo files.
func (h *host) repos() []api.Repo {
	if h.family == "debian" {
		var out []api.Repo
		files, _ := filepath.Glob("/etc/apt/sources.list.d/*.list")
		files = append([]string{"/etc/apt/sources.list"}, files...)
		for _, f := range files {
			out = append(out, parseAptList(readFile(f), f)...)
		}
		files, _ = filepath.Glob("/etc/apt/sources.list.d/*.sources")
		for _, f := range files {
			out = append(out, parseDeb822(readFile(f), f)...)
		}
		return out
	}
	_, dir := h.repoDirs()
	files, _ := filepath.Glob(dir + "/*.repo")
	var out []api.Repo
	for _, f := range files {
		out = append(out, parseYumRepo(readFile(f), f)...)
	}
	return out
}

func parseAptList(content, file string) []api.Repo {
	var out []api.Repo
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		enabled := true
		if l, ok := strings.CutPrefix(line, disabledLine); ok { // switched off by LiMDM
			line, enabled = l, false
		}
		if !strings.HasPrefix(line, "deb ") {
			continue // comments, deb-src
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "deb"))
		signed, keyFile := false, ""
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "]")
			if end < 0 {
				continue
			}
			signed = strings.Contains(rest[:end], "signed-by=")
			for _, o := range strings.Fields(rest[1:end]) {
				if v, ok := strings.CutPrefix(o, "signed-by="); ok && strings.HasPrefix(v, "/") {
					keyFile = v
				}
			}
			rest = strings.TrimSpace(rest[end+1:])
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			continue
		}
		out = append(out, api.Repo{Type: "deb", Name: filepath.Base(file), URL: f[0], Suites: f[1], Components: strings.Join(f[2:], " "),
			Enabled: enabled, Signed: signed, KeyFile: keyFile, File: file})
	}
	return out
}

// parseDeb822 handles stanzas separated by blank lines.
func parseDeb822(content, file string) []api.Repo {
	var out []api.Repo
	for _, stanza := range strings.Split(strings.ReplaceAll(content, "\r", ""), "\n\n") {
		kv := map[string]string{}
		for _, line := range strings.Split(stanza, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, " ") {
				kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
		if !strings.Contains(" "+kv["types"]+" ", " deb ") || kv["uris"] == "" {
			continue
		}
		out = append(out, api.Repo{Type: "deb", Name: filepath.Base(file), URL: kv["uris"],
			Suites: kv["suites"], Components: kv["components"], Enabled: !strings.EqualFold(kv["enabled"], "no"),
			Signed: kv["signed-by"] != "", KeyFile: keyPath(kv["signed-by"]), File: file})
	}
	return out
}

func parseYumRepo(content, file string) []api.Repo {
	var out []api.Repo
	var cur *api.Repo
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
		}
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			cur = &api.Repo{Type: "rpm", Name: strings.Trim(line, "[]"), Enabled: true, File: file}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || cur == nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "baseurl", "metalink", "mirrorlist":
			if cur.URL == "" {
				cur.URL = strings.TrimSpace(v)
			}
		case "enabled":
			cur.Enabled = strings.TrimSpace(v) != "0"
		case "gpgkey":
			if f := strings.Fields(v); len(f) > 0 {
				if p, ok := strings.CutPrefix(f[0], "file://"); ok {
					cur.KeyFile = p
				}
			}
		case "gpgcheck":
			cur.Signed = strings.TrimSpace(v) == "1"
		}
	}
	flush()
	return out
}

// keyPath returns a Signed-By value when it names a file (it may also be an inline key).
func keyPath(v string) string {
	if strings.HasPrefix(v, "/") && !strings.ContainsAny(v, " \n") {
		return v
	}
	return ""
}
