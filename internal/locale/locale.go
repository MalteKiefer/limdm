// Package locale translates the user facing texts of the device CLI, the
// desktop helper and the agent's notifications and login prompts. The
// English text is the key, like a gettext msgid; every other language has an
// embedded JSON catalog (catalog/<lang>.json). A text without a translation
// is shown in English, so texts that come from elsewhere (errors of the
// agent, titles set by IT) pass through unchanged.
//
// A catalog value is a string, or for texts with a count (N) the list of
// plural forms of that language: two for de, en, es, fr, it and three
// (one, few, many) for ru.
package locale

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

// Languages are the supported languages, English first (the fallback).
var Languages = []string{"en", "de", "fr", "es", "it", "ru"}

//go:embed catalog/*.json
var files embed.FS

// catalogs maps language and English text to the translated forms.
var catalogs = func() map[string]map[string][]string {
	all := map[string]map[string][]string{}
	for _, l := range Languages[1:] {
		c, err := parse(l)
		if err != nil {
			panic(err) // embedded at build time; TestCatalogs catches it first
		}
		all[l] = c
	}
	return all
}()

func parse(lang string) (map[string][]string, error) {
	b, err := files.ReadFile("catalog/" + lang + ".json")
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("catalog %s: %w", lang, err)
	}
	c := make(map[string][]string, len(raw))
	for k, v := range raw {
		var s string
		if json.Unmarshal(v, &s) == nil {
			c[k] = []string{s}
			continue
		}
		var forms []string
		if err := json.Unmarshal(v, &forms); err != nil {
			return nil, fmt.Errorf("catalog %s, %q: %w", lang, k, err)
		}
		c[k] = forms
	}
	return c, nil
}

// Detect returns the language for a locale environment, in gettext's order:
// LC_ALL, LC_MESSAGES, LANG (then the system locale in /etc/locale.conf or
// /etc/default/locale) and, unless that locale is C, the first supported
// entry of LANGUAGE. Anything unsupported is English.
func Detect(getenv func(string) string) string {
	loc := cmpOr(getenv("LC_ALL"), getenv("LC_MESSAGES"), getenv("LANG"))
	if loc == "" {
		loc = systemLocale()
	}
	if b := base(loc); b != "c" && b != "posix" {
		for _, l := range strings.Split(getenv("LANGUAGE"), ":") {
			if slices.Contains(Languages, base(l)) {
				return base(l)
			}
		}
	}
	if b := base(loc); slices.Contains(Languages, b) {
		return b
	}
	return "en"
}

// FromEnv is Detect for an environment list ("LANG=de_DE.UTF-8", ...), such
// as the one of a user session.
func FromEnv(env []string) string {
	return Detect(func(k string) string {
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, k+"="); ok {
				return v
			}
		}
		return ""
	})
}

// System is the language of this process' environment.
func System() string { return Detect(os.Getenv) }

// base reduces a locale name (de_DE.UTF-8@euro, pt-BR) to its language.
func base(loc string) string {
	loc = strings.ToLower(strings.TrimSpace(loc))
	if i := strings.IndexAny(loc, "_.@-"); i >= 0 {
		loc = loc[:i]
	}
	return loc
}

func systemLocale() string {
	for _, f := range []string{"/etc/locale.conf", "/etc/default/locale"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "LANG="); ok {
				return strings.Trim(v, `"'`)
			}
		}
	}
	return ""
}

func cmpOr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// T translates msg and, with args, formats it like fmt.Sprintf.
func T(lang, msg string, args ...any) string {
	if f := catalogs[lang][msg]; len(f) > 0 && f[0] != "" {
		msg = f[0]
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

// N translates a text with a count: one and other are the English singular
// and plural (other is the key). The result is formatted with n followed by
// args, so every form must use n as its first verb.
func N(lang string, n int, one, other string, args ...any) string {
	s := other
	if n == 1 {
		s = one
	}
	if f := catalogs[lang][other]; len(f) > 0 {
		if i := pluralIndex(lang, n); i < len(f) && f[i] != "" {
			s = f[i]
		}
	}
	return fmt.Sprintf(s, append([]any{n}, args...)...)
}

// pluralIndex picks the plural form like the gettext Plural-Forms of each
// language: fr counts 0 and 1 as singular, ru has one, few and many.
func pluralIndex(lang string, n int) int {
	switch lang {
	case "ru":
		switch {
		case n%10 == 1 && n%100 != 11:
			return 0
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return 1
		}
		return 2
	case "fr":
		if n <= 1 {
			return 0
		}
		return 1
	}
	if n == 1 {
		return 0
	}
	return 1
}

// pluralForms is how many forms a plural entry of lang has.
func pluralForms(lang string) int {
	if lang == "ru" {
		return 3
	}
	return 2
}
