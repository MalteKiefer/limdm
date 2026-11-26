package api

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"
)

// PayloadTypes lists the declaration types that have a payload schema.
func PayloadTypes() []string {
	out := make([]string, 0, len(payloadShapes))
	for t := range payloadShapes {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// PayloadSchema is the JSON Schema (draft 2020-12) of a declaration
// payload, derived from the Go type the server and the agent decode it into
// (payloadShapes), so the console form and the decoder cannot drift apart.
// Objects refuse unknown properties, as the strict decoder does; "x-order"
// keeps the field order of the Go struct for form renderers.
func PayloadSchema(typ string) (map[string]any, bool) {
	v, ok := payloadShapes[typ]
	if !ok {
		return nil, false
	}
	s := schemaOf(reflect.TypeOf(v), 0)
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	return s, true
}

var (
	timeType = reflect.TypeOf(time.Time{})
	rawType  = reflect.TypeOf(json.RawMessage{})
)

func schemaOf(t reflect.Type, depth int) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if depth > 8 { // recursive types: anything below
		return map[string]any{}
	}
	switch t {
	case timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case rawType:
		return map[string]any{}
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": schemaOf(t.Elem(), depth+1)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem(), depth+1)}
	case reflect.Struct:
		props, order := map[string]any{}, []string{}
		structProps(t, props, &order, depth, false)
		return map[string]any{"type": "object", "properties": props, "additionalProperties": false, "x-order": order}
	}
	return map[string]any{} // interfaces: any value
}

// structProps adds the JSON fields of struct t, embedded structs flattened
// as encoding/json does.
// A field of the struct itself shadows an embedded field of the same name
// (the shallower field wins), and every name appears once in order.
func structProps(t reflect.Type, props map[string]any, order *[]string, depth int, embedded bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if f.Anonymous && name == "" && ft.Kind() == reflect.Struct {
			structProps(ft, props, order, depth, true)
			continue
		}
		if name == "" {
			name = f.Name
		}
		_, dup := props[name]
		if dup && embedded {
			continue
		}
		s := schemaOf(f.Type, depth+1)
		s["title"] = fieldTitle(name)
		props[name] = s
		if !dup {
			*order = append(*order, name)
		}
	}
}

// fieldTitle makes a readable English default title of a JSON name:
// "checkin_seconds" becomes "Checkin seconds".
func fieldTitle(name string) string {
	s := strings.ReplaceAll(name, "_", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
