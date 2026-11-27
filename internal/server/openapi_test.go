package server

import (
	"encoding/json"
	"testing"
)

// Every operation of openapi.json has a declared tag, a summary, a unique
// operationId and its own security list, so Swagger UI groups it and shows
// the lock.
func TestOpenAPIOperations(t *testing.T) {
	var doc struct {
		Tags []struct {
			Name, Description string
		}
		Paths map[string]map[string]json.RawMessage
	}
	if err := json.Unmarshal(openAPIDoc, &doc); err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, tg := range doc.Tags {
		if tg.Description == "" {
			t.Errorf("tag %s has no description", tg.Name)
		}
		tags[tg.Name] = true
	}
	ids := map[string]bool{}
	for path, methods := range doc.Paths {
		for method, raw := range methods {
			if method == "parameters" {
				continue
			}
			var op struct {
				OperationID string
				Summary     string
				Tags        []string
				Security    *[]map[string][]string
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			at := method + " " + path
			if op.Summary == "" {
				t.Errorf("%s: no summary", at)
			}
			if len(op.Tags) != 1 || !tags[op.Tags[0]] {
				t.Errorf("%s: tags %v, want one declared tag", at, op.Tags)
			}
			if op.Security == nil {
				t.Errorf("%s: no security", at)
			}
			if op.OperationID == "" || ids[op.OperationID] {
				t.Errorf("%s: operationId %q missing or used twice", at, op.OperationID)
			}
			ids[op.OperationID] = true
		}
	}
}
