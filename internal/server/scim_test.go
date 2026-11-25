package server

import (
	"encoding/json"
	"testing"
)

func TestSCIMUserPatch(t *testing.T) {
	u := scimUser{UserName: "jane@example.com", Emails: []scimEmail{{Value: "jane@example.com", Primary: true}}}
	ops := []patchOp{
		{Op: "Replace", Path: "active", Value: json.RawMessage(`"False"`)}, // Entra sends string booleans
		{Op: "replace", Path: `emails[type eq "work"].value`, Value: json.RawMessage(`"jane.doe@example.com"`)},
		{Op: "Add", Path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", Value: json.RawMessage(`"Finance"`)},
		{Op: "replace", Value: json.RawMessage(`{"displayName":"Jane Doe","title":"CFO"}`)}, // Okta style without path
		{Op: "replace", Path: "unknownAttr", Value: json.RawMessage(`1`)},
	}
	for _, op := range ops {
		if err := applyUserPatch(&u, op); err != nil {
			t.Fatal(err)
		}
	}
	if u.Active == nil || *u.Active || u.email() != "jane.doe@example.com" || u.Enterprise.Department != "Finance" || u.DisplayName != "Jane Doe" || u.Title != "CFO" {
		t.Fatalf("patched user: %+v %+v", u, u.Enterprise)
	}
	if err := applyUserPatch(&u, patchOp{Op: "replace", Path: "active", Value: json.RawMessage(`"maybe"`)}); err == nil {
		t.Fatal("non boolean active accepted")
	}
}

func TestSCIMFilter(t *testing.T) {
	a, v, err := parseFilter(`userName eq "jane@example.com"`)
	if err != nil || a != "username" || v != "jane@example.com" {
		t.Fatalf("%q %q %v", a, v, err)
	}
	if _, _, err := parseFilter(`userName sw "j" or 1 eq 1`); err == nil {
		t.Fatal("unsupported filter accepted")
	}
	if a, _, _ := parseFilter(""); a != "" {
		t.Fatal("empty filter")
	}
}
