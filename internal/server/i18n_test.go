package server

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// notifyTexts are the fixed texts and title prefixes of notifications
// (localNotice translates them per channel).
var notifyTexts = []string{"Open in LiMDM", "Agent update failed", "App requested", "Approval requested", "Audit log verification failed",
	"Backup failed", "Command failed", "Console role changed", "Device enrolled", "Device user disabled", "Key rotation finished",
	"Key rotation started", "Key rotation", "Log archive failed", "Log store refuses new lines", "Network CRL token rotated",
	"Recovery key viewed", "Report ready", "Script sent", "Stored backup damaged or missing", "Test notification", "Wipe sent",
	"Lost mode sent", "A new device joined the fleet."}

// problemArg is the position of the message in the problem helpers.
var problemArg = map[string]int{"problem": 2, "problemField": 3, "retryLater": 2, "deny": 3}

// literalProblems are the problem details the server writes as literals:
// problem, problemField, retryLater, deny and the userError and fieldError
// messages, which apiFail turns into problems.
func literalProblems(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	lit := func(e ast.Expr) (string, bool) {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		return s, err == nil && s != ""
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				name := ""
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if i, ok := problemArg[name]; ok && len(n.Args) > i {
					if s, ok := lit(n.Args[i]); ok {
						out[s] = fset.Position(n.Pos()).String()
					}
				}
			case *ast.CompositeLit:
				if id, ok := n.Type.(*ast.Ident); ok && (id.Name == "userError" || id.Name == "fieldError") {
					for _, e := range n.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							e = kv.Value
						}
						if s, ok := lit(e); ok && !(id.Name == "fieldError" && !strings.ContainsAny(s, " :")) {
							out[s] = fset.Position(n.Pos()).String()
						}
					}
				}
			}
			return true
		})
	}
	return out
}

// germanKeys are the texts the server shows that need a German entry.
func germanKeys(t *testing.T) map[string]string {
	t.Helper()
	keys := map[string]string{}
	re := regexp.MustCompile(`\{\{t ("(?:[^"\\]|\\.)*")\}\}`)
	files, _ := fs.Glob(webFS, "web/*.html")
	for _, f := range files {
		b, _ := fs.ReadFile(webFS, f)
		for _, m := range re.FindAllSubmatch(b, -1) {
			k, err := strconv.Unquote(string(m[1]))
			if err != nil {
				t.Fatal(err)
			}
			keys[k] = f
		}
	}
	for _, l := range typeLabels {
		keys[l] = "type label"
	}
	for _, l := range auditActions {
		keys[l] = "audit action"
	}
	for _, l := range commandLabels {
		keys[l] = "command label"
	}
	for _, f := range api.EventFormats {
		keys[f] = "agent event"
	}
	for _, e := range notifyEvents {
		keys[e.Label] = "notification event"
	}
	for _, s := range notifyTexts {
		keys[s] = "notification"
	}
	for s, pos := range literalProblems(t) {
		keys[s] = pos
	}
	return keys
}

// Every text the server shows has a German entry.
func TestGermanCatalogComplete(t *testing.T) {
	for k, where := range germanKeys(t) {
		if _, ok := deCatalog[k]; !ok {
			t.Errorf("%s: missing German text for %q", where, k)
		}
	}
}

// schemaHintTexts are the English texts of the schema hints; German comes
// with them, the other languages translate them through the catalogs.
func schemaHintTexts() []string {
	var out []string
	add := func(t tr) {
		if t[0] != "" {
			out = append(out, t[0])
		}
	}
	for _, hints := range schemaHints {
		for _, x := range hints {
			add(x.T)
			add(x.D)
			add(x.Sec)
			for _, e := range x.EnumT {
				add(e)
			}
		}
	}
	return out
}

var formatVerbs = regexp.MustCompile(`%(?:\[\d+\])?[sdvqx]`)

// French, Spanish, Italian and Russian have every German text and every
// schema hint, with the same format verbs, and nothing else.
func TestCatalogsComplete(t *testing.T) {
	want := map[string]bool{}
	for k := range deCatalog {
		want[k] = true
	}
	for _, s := range schemaHintTexts() {
		want[s] = true
	}
	verbs := func(s string) int { return len(formatVerbs.FindAllString(s, -1)) }
	for _, l := range langs[2:] {
		for k := range want {
			v, ok := catalogs[l][k]
			switch {
			case !ok:
				t.Errorf("%s: missing text for %q", l, k)
			case strings.TrimSpace(v) == "":
				t.Errorf("%s: empty text for %q", l, k)
			case verbs(v) != verbs(k):
				t.Errorf("%s: format verbs of %q differ: %q", l, k, v)
			}
		}
		for k := range catalogs[l] {
			if !want[k] {
				t.Errorf("%s: text %q is used nowhere", l, k)
			}
		}
	}
}

func TestRequestLang(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "pt-BR, fr-CH;q=0.9, de;q=0.8, en;q=0.5")
	if requestLang(r) != "fr" {
		t.Fatal("Accept-Language not honoured")
	}
	r.Header.Set("Cookie", langCookie+"=ru")
	if requestLang(r) != "ru" {
		t.Fatal("cookie must win")
	}
	r.Header.Set("Cookie", langCookie+"=xx")
	if requestLang(r) != "fr" {
		t.Fatal("unknown cookie value must be ignored")
	}
	w := httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/lang/it", nil)
	r.SetPathValue("lang", "it")
	r.Header.Set("Referer", "https://evil.example/x")
	(&Server{}).setLang(w, r)
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("open redirect: %q", loc)
	}
	w = httptest.NewRecorder()
	r.SetPathValue("lang", "xx")
	(&Server{}).setLang(w, r)
	if w.Code != 404 {
		t.Fatalf("unknown language: %d", w.Code)
	}
}

// Problem details of the admin API come in the caller's language.
func TestProblemLanguage(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Language", "de")
	problem(w, 404, "not found")
	var p struct{ Detail string }
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Detail != deCatalog["not found"] {
		t.Fatalf("detail %q, %v", p.Detail, err)
	}
	w = httptest.NewRecorder()
	problem(w, 404, "not found")
	if !strings.Contains(w.Body.String(), `"detail":"not found"`) {
		t.Fatal(w.Body.String())
	}
}

// Agent events and notifications come in the reader's language.
func TestEventAndNoticeText(t *testing.T) {
	k, p, out := eventText("de", "declarations updated (token 7)")
	if k != "declarations_updated_token" || len(p) != 1 || out != api.FormatEvent(deCatalog["declarations updated (token %s)"], p) || !strings.Contains(out, "7") {
		t.Fatalf("%q %q %q", k, p, out)
	}
	if _, _, out := eventText("de", "an unknown line"); out != "an unknown line" {
		t.Fatal(out)
	}
	n := localNotice("de", notice{Title: "Command failed: wipe", Text: "A new device joined the fleet."})
	if n.Title != deCatalog["Command failed"]+": wipe" || n.Text != deCatalog["A new device joined the fleet."] {
		t.Fatalf("%+v", n)
	}
}
