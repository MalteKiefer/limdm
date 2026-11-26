package server

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// TestSchemaHints: every hint names an existing field, every field of every
// type has a title in both languages, and the example payloads stay valid
// under the added choices and limits.
func TestSchemaHints(t *testing.T) {
	for typ, hints := range schemaHints {
		sch, ok := api.PayloadSchema(typ)
		if !ok {
			t.Fatalf("hints for unknown type %s", typ)
		}
		for path, x := range hints {
			if schemaAt(sch, path) == nil {
				t.Errorf("%s: stale hint path %s", typ, path)
			}
			for _, v := range []tr{x.T, x.D, x.Sec} {
				if (v[0] == "") != (v[1] == "") {
					t.Errorf("%s %s: text without translation %q", typ, path, v)
				}
			}
			if len(x.EnumT) > 0 && len(x.EnumT) != len(x.Enum) {
				t.Errorf("%s %s: %d choices, %d titles", typ, path, len(x.Enum), len(x.EnumT))
			}
		}
	}
	for _, typ := range api.PayloadTypes() {
		for _, f := range api.PayloadFields(typ) {
			if schemaHints[typ][f.Path].T[1] == "" {
				t.Errorf("%s: field %s has no title", typ, f.Path)
			}
		}
		for _, lang := range []string{"en", "de"} {
			sch, _ := api.PayloadSchema(typ)
			annotateSchema(sch, typ, lang)
			var v any
			if err := json.Unmarshal([]byte(api.Types[typ]), &v); err != nil {
				t.Fatalf("%s example: %v", typ, err)
			}
			if err := checkHinted(sch, v, typ); err != "" {
				t.Errorf("%s example (%s): %s", typ, lang, err)
			}
		}
	}
}

// checkHinted walks value v along schema s and checks enum and limits.
func checkHinted(s map[string]any, v any, path string) string {
	if e, ok := s["enum"].([]any); ok && !slices.ContainsFunc(e, func(x any) bool { return jsonEq(x, v) }) {
		return path + ": " + strings.Trim(string(must(json.Marshal(v))), `"`) + " not in enum"
	}
	if n, ok := v.(float64); ok {
		if lo, ok := s["minimum"].(int); ok && n < float64(lo) {
			return path + ": below minimum"
		}
		if hi, ok := s["maximum"].(int); ok && n > float64(hi) {
			return path + ": above maximum"
		}
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		for k, sub := range x {
			if p, ok := props[k].(map[string]any); ok {
				if err := checkHinted(p, sub, path+"."+k); err != "" {
					return err
				}
			}
		}
	case []any:
		items, _ := s["items"].(map[string]any)
		for _, sub := range x {
			if items != nil {
				if err := checkHinted(items, sub, path+"[]"); err != "" {
					return err
				}
			}
		}
	}
	return ""
}

func jsonEq(a, b any) bool { return string(must(json.Marshal(a))) == string(must(json.Marshal(b))) }

func must(b []byte, _ error) []byte { return b }
