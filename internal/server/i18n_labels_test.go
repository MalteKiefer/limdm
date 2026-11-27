package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// auditActionArg is the position of the action in the audit helpers.
var auditActionArg = map[string]int{"audit": 3, "auditAction": 2, "auditSystem": 2}

// literalAuditActions are the audit actions the server writes as literals.
func literalAuditActions(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	files, _ := filepath.Glob("*.go")
	fs := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := c.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			i, ok := auditActionArg[name]
			if !ok || len(c.Args) <= i {
				return true
			}
			if bl, ok := c.Args[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
				s, _ := strconv.Unquote(bl.Value)
				out[s] = fs.Position(bl.Pos()).String()
			}
			return true
		})
	}
	return out
}

// Every audit action, command type and agent event has a label, so the
// activity never shows a raw action code, and every label has a text in
// every language.
func TestLabelsComplete(t *testing.T) {
	for a, pos := range literalAuditActions(t) {
		if _, ok := auditActions[a]; !ok && !strings.HasPrefix(a, "command.") {
			t.Errorf("%s: audit action %q has no label in auditActions", pos, a)
		}
	}
	for _, typ := range append(api.CommandTypes, "shell") {
		if commandLabels[typ] == "" {
			t.Errorf("command type %q has no label in commandLabels", typ)
		}
	}
	for _, l := range langs[1:] {
		for _, m := range []map[string]string{auditActions, commandLabels, api.EventFormats} {
			for _, s := range m {
				if _, ok := catalogs[l][s]; !ok {
					t.Errorf("%s: no translation of %q", l, s)
				}
			}
		}
	}
	if got := auditLabel("de", "command.wipe"); got != "Befehl: "+translate("de", "Wipe") {
		t.Errorf("command label: %q", got)
	}
}
