package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestArtifacts(t *testing.T) {
	sha := strings.Repeat("a", 64)
	good := []Artifact{{SHA256: sha, Name: "vpn", Kind: "deb", Size: 1},
		{SHA256: sha, Name: "lic", Kind: "file", Size: 1, Path: "/etc/opt/v/lic", Mode: "0600"}}
	for _, a := range good {
		if err := a.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	bad := []Artifact{{SHA256: "x", Name: "vpn", Kind: "deb", Size: 1}, {SHA256: sha, Name: "vpn", Kind: "exe", Size: 1},
		{SHA256: sha, Name: "vpn", Kind: "deb", Size: 1, Path: "/etc/x"}, {SHA256: sha, Name: "f", Kind: "file", Size: 1, Path: "/home/u/x"},
		{SHA256: sha, Name: "f", Kind: "file", Size: 1, Path: "/usr/bin/x", Mode: "4755"}}
	for _, a := range bad {
		if a.Validate() == nil {
			t.Fatalf("accepted %+v", a)
		}
	}
	a, _ := json.Marshal(Artifacts{good[:1]})
	b, _ := json.Marshal(Artifacts{[]Artifact{{SHA256: sha, Name: "vpn2", Kind: "deb", Size: 1}, good[1]}})
	m, ok, err := mergeArtifacts(TypeArtifacts, a, b)
	var v Artifacts
	json.Unmarshal(m, &v)
	if !ok || err != nil || len(v.Artifacts) != 2 || v.Artifacts[0].Name != "vpn2" {
		t.Fatalf("merge %s %v", m, err)
	}
	var p Policy
	if err := (Declaration{Identifier: "artifacts", Type: TypeArtifacts, Payload: b}).apply(&p); err != nil || len(p.Extra.Artifacts) != 2 {
		t.Fatalf("apply: %v", err)
	}
}
