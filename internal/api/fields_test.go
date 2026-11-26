package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestPayloadShapes keeps the field reference true: every type has a shape,
// the example decodes into it, and the real validation knows every field.
func TestPayloadShapes(t *testing.T) {
	for typ, ex := range Types {
		shape, ok := payloadShapes[typ]
		if !ok {
			t.Errorf("%s: no payload shape", typ)
			continue
		}
		if err := strict(json.RawMessage(ex), reflect.New(reflect.TypeOf(shape)).Interface()); err != nil {
			t.Errorf("%s: example does not fit the shape: %v", typ, err)
		}
		fields := PayloadFields(typ)
		if len(fields) == 0 {
			t.Errorf("%s: no fields", typ)
		}
		for _, f := range fields {
			if typ == TypeBootloader && f.Path == "password" { // replaced by password_pbkdf2 before validation
				continue
			}
			raw := nestedNull(f.Path)
			err := LibraryItem{Name: "x", Type: typ, Payload: raw}.Validate()
			if err != nil && strings.Contains(err.Error(), "unknown field") {
				t.Errorf("%s: field %s unknown to the decoder: %v", typ, f.Path, err)
			}
		}
	}
	for typ := range payloadShapes {
		if _, ok := Types[typ]; !ok {
			t.Errorf("%s: shape without type", typ)
		}
	}
}

// nestedNull builds a payload that sets only the field at path to null,
// e.g. "rules[].actions" -> {"rules":[{"actions":null}]}.
func nestedNull(path string) json.RawMessage {
	parts := strings.Split(path, ".")
	var v any
	for i := len(parts) - 1; i >= 0; i-- {
		name, list := strings.CutSuffix(parts[i], "[]")
		if list {
			v = map[string]any{name: []any{v}}
		} else {
			v = map[string]any{name: v}
		}
	}
	b, _ := json.Marshal(v)
	return b
}
