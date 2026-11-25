package api

import (
	"encoding/json"
	"slices"
	"testing"
)

func item(id int64, typ, payload string) LibraryItem {
	return LibraryItem{ID: id, Name: typ, Type: typ, Payload: json.RawMessage(payload)}
}

func TestResolveConditionsAndInheritance(t *testing.T) {
	parent := []Node{{Kind: "assign", Items: []int64{1, 2}}}
	child := []Node{
		{Kind: "if", Branches: []Branch{
			{Match: "all", Rules: []Rule{{Field: "os.id", Op: "eq", Value: "Debian"}, {Field: "os.version", Op: "gte", Value: "12"}}, Nodes: []Node{{Kind: "assign", Items: []int64{3}}}},
			{Match: "any", Rules: []Rule{{Field: "tag", Op: "has", Value: "lab"}, {Field: "hostname", Op: "glob", Value: "lab-*"}}, Nodes: []Node{{Kind: "assign", Items: []int64{4}}}},
		}, Else: []Node{{Kind: "assign", Items: []int64{5, 1}}}},
	}
	maps := [][]Node{parent, child}
	cases := []struct {
		f    Facts
		want []int64
	}{
		{Facts{OSID: "debian", OSVersion: "13"}, []int64{1, 2, 3}},
		{Facts{OSID: "debian", OSVersion: "11", Tags: []string{"LAB"}}, []int64{1, 2, 4}},
		{Facts{OSID: "fedora", Hostname: "lab-7"}, []int64{1, 2, 4}},
		{Facts{OSID: "ubuntu"}, []int64{2, 5, 1}}, // later occurrence of 1 counts
	}
	for _, c := range cases {
		if got := Resolve(maps, c.f); !slices.Equal(got, c.want) {
			t.Errorf("%+v: got %v want %v", c.f, got, c.want)
		}
	}
}

func TestValidateTree(t *testing.T) {
	exists := func(id int64) bool { return id < 10 }
	good := []Node{{Kind: "if", Branches: []Branch{{Match: "all", Rules: []Rule{{Field: "desktop", Op: "present"}}, Nodes: []Node{{Kind: "assign", Items: []int64{1}}}}}}}
	if err := ValidateTree(good, exists); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]Node{
		{{Kind: "assign", Items: []int64{99}}},
		{{Kind: "loop"}},
		{{Kind: "if"}},
		{{Kind: "if", Branches: []Branch{{Match: "some"}}}},
		{{Kind: "if", Branches: []Branch{{Match: "all", Rules: []Rule{{Field: "os.id", Op: "gte", Value: "x"}}}}}},
		{{Kind: "if", Branches: []Branch{{Match: "all", Rules: []Rule{{Field: "hostname", Op: "glob", Value: "["}}}}}},
	} {
		if ValidateTree(bad, exists) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	deep := []Node{{Kind: "assign"}}
	for range 20 {
		deep = []Node{{Kind: "if", Branches: []Branch{{Match: "all", Nodes: deep}}}}
	}
	if ValidateTree(deep, exists) == nil {
		t.Fatal("unbounded nesting accepted")
	}
}

func TestMerge(t *testing.T) {
	decls, err := Merge([]LibraryItem{
		item(1, TypePackages, `{"install":["htop","curl"],"remove":[]}`),
		item(2, TypePackages, `{"install":["vim"],"remove":["curl"]}`),
		item(3, TypeUpdates, `{"mode":"security","window":"02:00-04:00"}`),
		item(4, TypeUpdates, `{"mode":"all","window":"01:00-02:00"}`),
		item(5, TypeFirewall, `{"enforce":false,"allow":["22/tcp"]}`),
		item(6, TypeFirewall, `{"enforce":true,"allow":["443/tcp"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	p, st := Compose(decls)
	for _, s := range st {
		if !s.Valid {
			t.Fatalf("merged declaration invalid: %+v", s)
		}
	}
	if !slices.Equal(p.Packages.Install, []string{"htop", "vim"}) || !slices.Equal(p.Packages.Remove, []string{"curl"}) {
		t.Fatalf("packages: %+v (remove must win over install)", p.Packages)
	}
	if p.Updates.Mode != "all" {
		t.Fatal("single valued type: last item must win")
	}
	if !p.Firewall.Enforce || !slices.Equal(p.Firewall.Allow, []string{"22/tcp", "443/tcp"}) {
		t.Fatalf("firewall: %+v", p.Firewall)
	}
	if len(decls) != 3 || decls[0].Identifier == "" || decls[0].ServerToken == "" {
		t.Fatalf("one declaration per type expected: %+v", decls)
	}
}
