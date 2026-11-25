package server

import (
	"io/fs"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
)

// Every literal passed to t in a template needs a German entry.
func TestGermanCatalogComplete(t *testing.T) {
	re := regexp.MustCompile(`\{\{t ("(?:[^"\\]|\\.)*")\}\}`)
	files, _ := fs.Glob(webFS, "web/*.html")
	for _, f := range files {
		b, _ := fs.ReadFile(webFS, f)
		for _, m := range re.FindAllSubmatch(b, -1) {
			k, err := strconv.Unquote(string(m[1]))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := deCatalog[k]; !ok {
				t.Errorf("%s: missing German text for %q", f, k)
			}
		}
	}
	for _, l := range typeLabels {
		if _, ok := deCatalog[l]; !ok {
			t.Errorf("missing German text for type %q", l)
		}
	}
}

func TestRequestLang(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "fr-CH, de;q=0.8, en;q=0.5")
	if requestLang(r) != "de" {
		t.Fatal("Accept-Language not honoured")
	}
	r.Header.Set("Cookie", langCookie+"=en")
	if requestLang(r) != "en" {
		t.Fatal("cookie must win")
	}
	w := httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/lang/de", nil)
	r.SetPathValue("lang", "de")
	r.Header.Set("Referer", "https://evil.example/x")
	(&Server{}).setLang(w, r)
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Fatalf("open redirect: %q", loc)
	}
}
