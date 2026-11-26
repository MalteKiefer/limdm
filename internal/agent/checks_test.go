package agent

import (
	"regexp"
	"testing"
)

// The catalog is compliance evidence: every check needs an ID of its own,
// BSI and ISO references, and CIS references in the "number title" form of
// the named benchmark.
func TestCatalogReferences(t *testing.T) {
	cisRef := regexp.MustCompile(`^(\d+(\.\d+)*(-\d+(\.\d+)*)? )?Ensure `)
	bsiRef := regexp.MustCompile(`^[A-Z]{3}\.\d+(\.\d+)*(\.A\d+)?$`)
	seen := map[string]bool{}
	for _, c := range catalog {
		if seen[c.ID] {
			t.Errorf("duplicate check %s", c.ID)
		}
		seen[c.ID] = true
		if len(c.Refs.BSI) == 0 || len(c.Refs.ISO) == 0 {
			t.Errorf("%s: missing BSI or ISO reference", c.ID)
		}
		for _, b := range c.Refs.BSI {
			if !bsiRef.MatchString(b) {
				t.Errorf("%s: BSI reference %q", c.ID, b)
			}
		}
		for _, r := range c.Refs.CIS {
			if !cisRef.MatchString(r) {
				t.Errorf("%s: CIS reference %q", c.ID, r)
			}
		}
		if (len(c.Refs.CIS) > 0) != (c.Refs.CISBenchmark != "") {
			t.Errorf("%s: CIS references need the benchmark name", c.ID)
		}
	}
	if CatalogVersion == "" {
		t.Fatal("catalog version missing")
	}
}
