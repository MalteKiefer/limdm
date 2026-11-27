package locale

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// keyArgs names the functions whose string literal arguments are catalog
// keys: the positions among those literals, and whether the key is plural.
var keyArgs = map[string]struct {
	pos    []int
	plural bool
}{
	"T": {pos: []int{0}}, "tr": {pos: []int{0}},
	"N": {pos: []int{1}, plural: true}, "trn": {pos: []int{1}, plural: true},
	"notifyUsers": {pos: []int{0, 1}}, "notifyAs": {pos: []int{0, 1}},
}

// promptConsts are constants the PAM hook prints through the catalog.
var promptConsts = []string{"nologinText", "offlineText"}

// sourceKeys collects every key the Go programs use: calls of keyArgs,
// the titles of the built in compliance checks (the CLI and the tray
// translate them) and promptConsts. The value is true for plural keys.
func sourceKeys(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"../../cmd/limdm", "../../cmd/limdm-desktop", "../agent"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			checks := filepath.Base(f) == "checks.go"
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					name := ""
					switch fn := n.Fun.(type) {
					case *ast.Ident:
						name = fn.Name
					case *ast.SelectorExpr:
						name = fn.Sel.Name
					}
					spec, ok := keyArgs[name]
					if !ok {
						return true
					}
					var lits []string
					for _, a := range n.Args {
						if s, ok := strLit(a); ok {
							lits = append(lits, s)
						}
					}
					for _, p := range spec.pos {
						if p < len(lits) {
							keys[lits[p]] = spec.plural
						}
					}
				case *ast.KeyValueExpr:
					if k, ok := n.Key.(*ast.Ident); ok && checks && k.Name == "Title" {
						if s, ok := strLit(n.Value); ok {
							keys[s] = false
						}
					}
				case *ast.ValueSpec:
					for i, id := range n.Names {
						if slices.Contains(promptConsts, id.Name) && i < len(n.Values) {
							if s, ok := strLit(n.Values[i]); ok {
								keys[s] = false
							}
						}
					}
				}
				return true
			})
		}
	}
	if len(keys) < 100 {
		t.Fatalf("only %d keys found, the scan is broken", len(keys))
	}
	return keys
}

func strLit(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(l.Value)
	return s, err == nil
}

var verb = regexp.MustCompile(`%[-+# 0]*[0-9]*(\.[0-9]+)?[a-zA-Z%]`)

// verbs lists the printf verbs of s, so a translation keeps its arguments.
func verbs(s string) string {
	v := verb.FindAllString(s, -1)
	slices.Sort(v)
	return strings.Join(v, " ")
}

// TestCatalogs fails when a language misses a text the programs use, has
// the wrong number of plural forms or changes the printf verbs.
func TestCatalogs(t *testing.T) {
	keys := sourceKeys(t)
	for _, lang := range Languages[1:] {
		c, err := parse(lang)
		if err != nil {
			t.Fatal(err)
		}
		for k, plural := range keys {
			forms, ok := c[k]
			switch {
			case !ok:
				t.Errorf("%s: missing %q", lang, k)
				continue
			case plural && len(forms) != pluralForms(lang):
				t.Errorf("%s: %q needs %d plural forms", lang, k, pluralForms(lang))
			case !plural && len(forms) != 1:
				t.Errorf("%s: %q is not a plural text", lang, k)
			}
		}
		for k, forms := range c {
			for _, f := range forms {
				if strings.TrimSpace(f) == "" || verbs(f) != verbs(k) {
					t.Errorf("%s: %q: translation %q is empty or changes the printf verbs", lang, k, f)
				}
			}
		}
	}
}

func TestDetect(t *testing.T) {
	for env, want := range map[string]string{
		"LANG=de_DE.UTF-8":                     "de",
		"LANG=ru_RU.UTF-8":                     "ru",
		"LC_ALL=fr_FR@euro LANG=de_DE":         "fr",
		"LC_MESSAGES=es_ES.UTF-8 LANG=de_DE":   "es",
		"LANG=pl_PL.UTF-8":                     "en",
		"LANG=C.UTF-8 LANGUAGE=de":             "en",
		"LANG=en_US.UTF-8 LANGUAGE=it:en":      "it",
		"LANG=en_US.UTF-8 LANGUAGE=pt_BR:ru":   "ru",
		"LANG=en_GB.UTF-8 LANGUAGE=en_GB:en":   "en",
		"LC_ALL=POSIX LANG=de_DE LANGUAGE=de":  "en",
		"LANG=it_IT.UTF-8 XDG_SESSION_TYPE=x1": "it",
	} {
		if got := FromEnv(strings.Fields(env)); got != want {
			t.Errorf("%s: got %s, want %s", env, got, want)
		}
	}
}

func TestPlural(t *testing.T) {
	ru := map[int]int{0: 2, 1: 0, 2: 1, 4: 1, 5: 2, 11: 2, 12: 2, 14: 2, 21: 0, 22: 1, 25: 2, 101: 0, 111: 2}
	for n, want := range ru {
		if got := pluralIndex("ru", n); got != want {
			t.Errorf("ru %d: form %d, want %d", n, got, want)
		}
	}
	if pluralIndex("fr", 0) != 0 || pluralIndex("de", 0) != 1 || pluralIndex("en", 1) != 0 {
		t.Error("fr counts 0 as singular, de and en do not")
	}
	if got := N("en", 1, "%d day ago", "%d days ago"); got != "1 day ago" {
		t.Errorf("en singular: %q", got)
	}
	if got := N("xx", 3, "%d day ago", "%d days ago"); got != "3 days ago" {
		t.Errorf("unknown language: %q", got)
	}
	if got := T("de", "no such text 100%"); got != "no such text 100%" {
		t.Errorf("unknown text: %q", got)
	}
}

// TestPoFiles checks the gettext catalogs of the GTK app the same way: every
// msgid of the app and every compliance check title in every language, with
// the plural forms and printf verbs intact.
func TestPoFiles(t *testing.T) {
	src := readFile(t, "../../packaging/limdm-desktop-ui")
	lit := `"((?:[^"\\\n]|\\.)*)"`
	want := map[string]bool{}
	for _, m := range regexp.MustCompile(`\b_\(`+lit+`\)`).FindAllStringSubmatch(src, -1) {
		want[pyUnquote(t, m[1])] = false
	}
	for _, m := range regexp.MustCompile(`\bngettext\(`+lit+`,\s*`+lit).FindAllStringSubmatch(src, -1) {
		want[pyUnquote(t, m[1])] = true
	}
	if len(want) < 100 {
		t.Fatalf("only %d msgids found, the scan is broken", len(want))
	}
	// the app shows the check titles of the agent through the catalog too
	for _, s := range regexp.MustCompile(`Title:\s*`+lit).FindAllStringSubmatch(readFile(t, "../agent/checks.go"), -1) {
		want[pyUnquote(t, s[1])] = false
	}
	for _, lang := range Languages[1:] {
		po := parsePo(t, readFile(t, "../../packaging/locale/"+lang+".po"))
		if !strings.Contains(po[""][0], "Plural-Forms: nplurals="+strconv.Itoa(pluralForms(lang))+";") {
			t.Errorf("%s.po: Plural-Forms header missing or wrong", lang)
		}
		for k, plural := range want {
			forms, ok := po[k]
			switch {
			case !ok:
				t.Errorf("%s.po: missing %q", lang, k)
			case plural && len(forms) != pluralForms(lang):
				t.Errorf("%s.po: %q needs %d plural forms", lang, k, pluralForms(lang))
			}
			for _, f := range forms {
				if strings.TrimSpace(f) == "" || verbs(f) != verbs(k) {
					t.Errorf("%s.po: %q: translation %q is empty or changes the printf verbs", lang, k, f)
				}
			}
		}
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pyUnquote(t *testing.T, s string) string {
	t.Helper()
	u, err := strconv.Unquote(`"` + s + `"`)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return u
}

// parsePo reads msgid, msgid_plural and msgstr / msgstr[n] entries.
func parsePo(t *testing.T, s string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	var id, field string
	var strs []string
	var cur *string
	flush := func() {
		if field != "" {
			out[id] = strs
		}
		id, field, strs, cur = "", "", nil, nil
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kw, rest, _ := strings.Cut(line, " ")
		if strings.HasPrefix(line, `"`) {
			kw, rest = "", line
		}
		var val string
		if rest != "" {
			v, err := strconv.Unquote(rest)
			if err != nil {
				t.Fatalf("po line %q: %v", line, err)
			}
			val = v
		}
		switch {
		case kw == "":
			if cur == nil {
				t.Fatalf("po continuation without entry: %q", line)
			}
			*cur += val
		case kw == "msgid":
			if field == "msgstr" {
				flush()
			}
			id, field = val, "msgid"
			cur = &id
		case kw == "msgid_plural":
			field = "plural"
			var p string
			cur = &p
		case strings.HasPrefix(kw, "msgstr"):
			field = "msgstr"
			strs = append(strs, val)
			cur = &strs[len(strs)-1]
		}
	}
	flush()
	return out
}
