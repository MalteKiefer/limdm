package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/maltekiefer/limdm/internal/api"
)

// adminGroups grant root via sudo on Debian, Ubuntu (sudo, admin) and Fedora (wheel).
var adminGroups = []string{"sudo", "wheel", "admin"}

// accounts lists root and every login capable human account with its admin
// rights. Admin rights are security relevant (ISO 27001 A.8.2), so this is
// always collected; who is logged in stays behind the privacy declaration.
func accounts(passwd, group string) []api.Account {
	admins := map[string]bool{}
	for _, line := range strings.Split(group, "\n") {
		f := strings.Split(line, ":")
		if len(f) == 4 && slices.Contains(adminGroups, f[0]) && f[3] != "" {
			for _, m := range strings.Split(f[3], ",") {
				admins[m] = true
			}
		}
	}
	var out []api.Account
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		shell := f[6]
		human := uid >= 1000 && uid < 60000 && !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "false")
		if uid != 0 && !human {
			continue
		}
		out = append(out, api.Account{Name: f[0], UID: uid, Shell: shell, Admin: uid == 0 || admins[f[0]]})
	}
	return out
}

// repos reads apt sources (one line .list and deb822 .sources) or dnf .repo files.
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
	files, _ := filepath.Glob("/etc/yum.repos.d/*.repo")
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
		if !strings.HasPrefix(line, "deb ") {
			continue // comments, deb-src
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "deb"))
		signed := false
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "]")
			if end < 0 {
				continue
			}
			signed = strings.Contains(rest[:end], "signed-by=")
			rest = strings.TrimSpace(rest[end+1:])
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			continue
		}
		out = append(out, api.Repo{Type: "deb", Name: filepath.Base(file), URL: f[0], Suites: strings.Join(f[1:], " "),
			Enabled: true, Signed: signed, File: file})
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
			Suites: strings.TrimSpace(kv["suites"] + " " + kv["components"]), Enabled: !strings.EqualFold(kv["enabled"], "no"),
			Signed: kv["signed-by"] != "", File: file})
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
		case "gpgcheck":
			cur.Signed = strings.TrimSpace(v) == "1"
		}
	}
	flush()
	return out
}

func readPasswdGroup() (string, string) {
	p, _ := os.ReadFile("/etc/passwd")
	g, _ := os.ReadFile("/etc/group")
	return string(p), string(g)
}
