package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateOsquerySQL(t *testing.T) {
	ok := []string{
		"SELECT * FROM users",
		"select name, version, release from rpm_packages where name = 'openssl';",
		"WITH a AS (SELECT uid FROM users) SELECT count(*) AS n FROM a",
		"SELECT replace(path, '/', '-') AS p FROM mounts",
		"SELECT * FROM file WHERE path = '/tmp/insert; drop'", // keywords and ; inside a literal
		"SELECT \"update\" FROM t",                            // quoted identifier
	}
	for _, q := range ok {
		if err := ValidateOsquerySQL(q); err != nil {
			t.Errorf("%q rejected: %v", q, err)
		}
	}
	bad := []string{
		"",
		"DELETE FROM users",
		"SELECT 1; SELECT 2",
		"SELECT 1 -- comment",
		"SELECT 1 /* x */",
		"WITH a AS (SELECT 1) INSERT INTO t SELECT * FROM a",
		"WITH a AS (SELECT 1) REPLACE INTO t SELECT * FROM a",
		"ATTACH DATABASE '/etc/x' AS x",
		"SELECT * FROM curl WHERE url = 'http://169.254.169.254/'",
		"SELECT load_extension('/tmp/x.so')",
		"SELECT 'unterminated",
		".shell id",
		"SELECT 1\x00",
		"PRAGMA table_info(users)",
		strings.Repeat("x", 5000),
	}
	for _, q := range bad {
		if ValidateOsquerySQL(q) == nil {
			t.Errorf("%q accepted", q)
		}
	}
}

func TestCustomChecksValidateAndMerge(t *testing.T) {
	var p Policy
	d := Declaration{Identifier: "c", Type: TypeCustomChecks, Payload: json.RawMessage(Types[TypeCustomChecks])}
	if err := d.apply(&p); err != nil || len(p.Extra.CustomChecks) != 3 {
		t.Fatalf("example payload: %v %+v", err, p.Extra.CustomChecks)
	}
	bad := []string{
		`{"checks":[{"id":"no_prefix","title":"t","severity":"low","level":1,"package":{"name":"x","state":"absent"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"urgent","level":1,"package":{"name":"x","state":"absent"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":3,"package":{"name":"x","state":"absent"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"package":{"name":"x","state":"absent"},"service":{"name":"x","state":"active"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"package":{"name":"-x","state":"absent"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"query":{"sql":"DELETE FROM users","expect":"rows"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"query":{"sql":"SELECT 1","expect":"compare","column":"x","op":"like","value":"1"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"file":{"path":"etc/x","state":"present"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"file":{"path":"/etc/x","state":"absent","owner":"root"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"file":{"path":"/etc/x","state":"present","contains":"("}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"sysctl":{"key":"kernel.x","op":"eq","value":"1"}},{"id":"custom.a","title":"t","severity":"low","level":1,"sysctl":{"key":"kernel.x","op":"eq","value":"1"}}]}`,
		`{"checks":[{"id":"custom.a","title":"t","severity":"low","level":1,"shell":"rm -rf /"}]}`,
	}
	for _, b := range bad {
		if err := (Declaration{Identifier: "c", Type: TypeCustomChecks, Payload: json.RawMessage(b)}).apply(&Policy{}); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	a := LibraryItem{Name: "a", Type: TypeCustomChecks, Payload: json.RawMessage(`{"checks":[{"id":"custom.a","title":"A","severity":"low","level":1,"package":{"name":"x","state":"absent"}}]}`)}
	b := LibraryItem{Name: "b", Type: TypeCustomChecks, Payload: json.RawMessage(`{"checks":[{"id":"custom.a","title":"A2","severity":"high","level":2,"package":{"name":"x","state":"absent"}},{"id":"custom.b","title":"B","severity":"low","level":1,"service":{"name":"sshd","state":"active"}}]}`)}
	decls, err := Merge([]LibraryItem{a, b})
	if err != nil || len(decls) != 1 {
		t.Fatal(err, decls)
	}
	pol, st := Compose(decls)
	if !st[0].Valid || len(pol.Extra.CustomChecks) != 2 || pol.Extra.CustomChecks[0].Title != "A2" {
		t.Fatalf("merge: %+v %+v", st, pol.Extra.CustomChecks)
	}
}
