package agent

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

// Every literal event format of the agent has a key in api.EventFormats, so
// the console can show the event in the reader's language.
func TestEventFormatsComplete(t *testing.T) {
	known := map[string]bool{}
	for _, f := range api.EventFormats {
		known[f] = true
	}
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
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "event" && len(c.Args) > 0 {
				if bl, ok := c.Args[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					s, _ := strconv.Unquote(bl.Value)
					if s != "%s" && !known[s] {
						t.Errorf("%s: event format %q has no key in api.EventFormats", fs.Position(bl.Pos()), s)
					}
				}
			}
			return true
		})
	}
}
