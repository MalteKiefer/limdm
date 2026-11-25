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
		{Op: "replace", Value: json.RawMessage(`{"displayName":"Jane Doe","title":"CFO"}`)},            // Okta style without path
		{Op: "replace", Path: `phoneNumbers[type eq "work"].value`, Value: json.RawMessage(`"+49 1"`)}, // valid but not stored
	}
	for _, op := range ops {
		if err := applyUserPatch(&u, op); err != nil {
			t.Fatal(err)
		}
	}
	if applyUserPatch(&u, patchOp{Op: "replace", Path: "unknownAttr", Value: json.RawMessage(`1`)}) == nil {
		t.Fatal("unknown path accepted")
	}
	if applyUserPatch(&u, patchOp{Op: "remove"}) == nil {
		t.Fatal("remove without path accepted")
	}
	if u.Active == nil || *u.Active || u.email() != "jane.doe@example.com" || u.Enterprise.Department != "Finance" || u.DisplayName != "Jane Doe" || u.Title != "CFO" {
		t.Fatalf("patched user: %+v %+v", u, u.Enterprise)
	}
	if err := applyUserPatch(&u, patchOp{Op: "replace", Path: "active", Value: json.RawMessage(`"maybe"`)}); err == nil {
		t.Fatal("non boolean active accepted")
	}
}

func TestSCIMFilter(t *testing.T) {
	a, v, err := parseFilter("User", `userName eq "jane@example.com"`)
	if err != nil || a != "username" || v != "jane@example.com" {
		t.Fatalf("%q %q %v", a, v, err)
	}
	if _, _, err := parseFilter("User", `userName sw "j" or 1 eq 1`); err == nil {
		t.Fatal("unsupported filter accepted")
	}
	if a, _, _ := parseFilter("User", ""); a != "" {
		t.Fatal("empty filter")
	}
	// user attributes are not valid on groups (RFC 7644 3.4.2.2: 400, not every group)
	if _, _, err := parseFilter("Group", `userName eq "x"`); err == nil {
		t.Fatal("user filter accepted on groups")
	}
	if a, v, err := parseFilter("Group", `id eq "7"`); err != nil || a != "id" || v != "7" {
		t.Fatalf("id filter: %q %q %v", a, v, err)
	}
	if scimType(400, "unsupported filter") != "invalidFilter" || scimType(409, "user exists") != "uniqueness" {
		t.Fatal("scimType mapping")
	}
}
