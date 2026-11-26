package server

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// slugs returns the GitHub anchors of a Markdown file's headings.
func slugs(md string) map[string]bool {
	out := map[string]bool{}
	seen := map[string]int{}
	inCode := false
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
		}
		if inCode || !strings.HasPrefix(line, "#") {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "#")))
		var b strings.Builder
		for _, r := range h {
			switch {
			case r == ' ' || r == '-':
				b.WriteRune('-')
			case r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r > 127:
				b.WriteRune(r)
			}
		}
		s := b.String()
		if n := seen[s]; n > 0 {
			out[s+"-"+strconv.Itoa(n)] = true
		} else {
			out[s] = true
		}
		seen[s]++
	}
	return out
}

var mdLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// TestDocsLinks checks every relative link (and anchor) in README.md,
// SECURITY.md, docs/ and the doc links the console renders.
func TestDocsLinks(t *testing.T) {
	files, _ := filepath.Glob("../../docs/*.md")
	files = append(files, "../../README.md", "../../SECURITY.md", "../../CHANGELOG.md")
	anchors := map[string]map[string]bool{}
	read := func(p string) (string, bool) {
		b, err := os.ReadFile(p)
		return string(b), err == nil
	}
	resolve := func(from, target string) string {
		path, frag, _ := strings.Cut(target, "#")
		p := from
		if path != "" {
			p = filepath.Clean(filepath.Join(filepath.Dir(from), path))
		}
		md, ok := read(p)
		if !ok {
			if fi, err := os.Stat(p); err == nil && (fi.IsDir() || frag == "") {
				return ""
			}
			return "missing file " + p
		}
		if frag == "" || !strings.HasSuffix(p, ".md") {
			return ""
		}
		if anchors[p] == nil {
			anchors[p] = slugs(md)
		}
		if !anchors[p][frag] {
			return "missing anchor #" + frag + " in " + p
		}
		return ""
	}
	for _, f := range files {
		md, _ := read(f)
		inCode := false
		for i, line := range strings.Split(md, "\n") {
			if strings.HasPrefix(line, "```") {
				inCode = !inCode
			}
			if inCode {
				continue
			}
			for _, m := range mdLink.FindAllStringSubmatch(line, -1) {
				target := m[1]
				if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
					continue
				}
				if msg := resolve(f, target); msg != "" {
					t.Errorf("%s:%d: %s: %s", f, i+1, target, msg)
				}
			}
		}
	}
	// doc links in Go code and templates ("keys.md", "compliance.md#checks")
	codeLink := regexp.MustCompile(`"([a-z0-9-]+\.md(?:#[a-z0-9-]+)?)"`)
	src, _ := filepath.Glob("*.go")
	tmpl, _ := filepath.Glob("web/*.html")
	for _, f := range append(src, tmpl...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range codeLink.FindAllStringSubmatch(string(b), -1) {
			if msg := resolve("../../docs/x.md", m[1]); msg != "" {
				t.Errorf("%s: %s: %s", f, m[1], msg)
			}
		}
	}
}

// TestDocsComplete: every LIMDM_ variable the code reads is in
// docs/configuration.md and every declaration type in docs/declarations.md.
func TestDocsComplete(t *testing.T) {
	conf, _ := os.ReadFile("../../docs/configuration.md")
	envRe := regexp.MustCompile(`LIMDM_[A-Z0-9_]*[A-Z0-9]`)
	var vars []string
	for _, dir := range []string{"../../cmd", "../../internal"} {
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, _ := os.ReadFile(p)
			vars = append(vars, envRe.FindAllString(string(b), -1)...)
			return nil
		})
	}
	slices.Sort(vars)
	for _, v := range slices.Compact(vars) {
		if !strings.Contains(string(conf), v) {
			t.Errorf("%s is not in docs/configuration.md", v)
		}
	}
	decl, _ := os.ReadFile("../../docs/declarations.md")
	for typ := range api.Types {
		if !strings.Contains(string(decl), typ) {
			t.Errorf("%s is not in docs/declarations.md", typ)
		}
	}
}
