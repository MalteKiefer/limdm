package server

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// The in console help must cover every declaration type, link existing
// documentation sections and be translated completely.
func TestHelpComplete(t *testing.T) {
	doc, err := os.ReadFile("../../docs/declarations.md")
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^### (.+)$`).FindAllStringSubmatch(string(doc), -1) {
		slug := strings.ReplaceAll(regexp.MustCompile(`[^\w\- ]`).ReplaceAllString(strings.ToLower(m[1]), ""), " ", "-")
		anchors[slug] = true
	}
	var keys []string
	for typ := range api.Types {
		info, ok := typeInfo[typ]
		switch {
		case !ok:
			t.Errorf("%s: no description", typ)
		case !anchors[info.Anchor]:
			t.Errorf("%s: anchor %q not in docs/declarations.md", typ, info.Anchor)
		}
		keys = append(keys, info.Desc)
	}
	for _, g := range glossary {
		keys = append(keys, g.Term, g.Text)
	}
	for _, v := range statusHelp {
		keys = append(keys, v)
	}
	for _, v := range auditActions {
		keys = append(keys, v)
	}
	keys = append(keys, checkDetailPrefixes...)
	// compliance check titles come from the agent; the console translates them
	src, err := os.ReadFile("../agent/checks.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`\{ID: "[^"]+", Title: "([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		keys = append(keys, m[1])
	}
	for _, k := range keys {
		if _, ok := deCatalog[k]; !ok {
			t.Errorf("missing German text for %q", k)
		}
	}
}
