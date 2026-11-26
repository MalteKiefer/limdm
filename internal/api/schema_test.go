package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPayloadSchema checks that every declaration type has a schema and
// that the schema names every field the field reference lists.
func TestPayloadSchema(t *testing.T) {
	for typ := range Types {
		if _, ok := PayloadSchema(typ); !ok {
			t.Errorf("%s: no schema", typ)
		}
	}
	for _, typ := range PayloadTypes() {
		s, ok := PayloadSchema(typ)
		if !ok || s["type"] != "object" || s["additionalProperties"] != false {
			t.Fatalf("%s: %v", typ, s)
		}
		if _, err := json.Marshal(s); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		seen := map[string]bool{} // shadowed embedded fields appear once
		for _, k := range s["x-order"].([]string) {
			if seen[k] {
				t.Errorf("%s: %s twice in x-order", typ, k)
			}
			seen[k] = true
		}
		for _, f := range PayloadFields(typ) {
			if lookup(s, f.Path) == nil {
				t.Errorf("%s: schema lacks %s", typ, f.Path)
			}
		}
	}
	if _, ok := PayloadSchema("com.example.unknown"); ok {
		t.Fatal("unknown type has a schema")
	}
}

// lookup follows a field path ("rules[].actions") through the schema.
func lookup(s map[string]any, path string) map[string]any {
	cur := s
	for _, part := range strings.Split(path, ".") {
		name, list := strings.CutSuffix(part, "[]")
		props, _ := cur["properties"].(map[string]any)
		next, _ := props[name].(map[string]any)
		if next == nil {
			return nil
		}
		if list {
			next, _ = next["items"].(map[string]any)
		}
		cur = next
	}
	return cur
}
