package agent

import (
	"regexp"
	"testing"
)

func TestInsertPWQuality(t *testing.T) {
	// Arch's system-auth (pambase): the line goes before the first password
	// module, also before pam_systemd_home's jump
	arch := "auth required pam_unix.so\n\n-password  [success=1 default=ignore]  pam_systemd_home.so\npassword   required  pam_unix.so  try_first_pass nullok shadow\n"
	got, err := insertPWQuality(arch)
	want := "auth required pam_unix.so\n\npassword   required   pam_pwquality.so retry=3\n-password  [success=1 default=ignore]  pam_systemd_home.so\npassword   required  pam_unix.so  try_first_pass nullok shadow\n"
	if err != nil || got != want {
		t.Fatalf("insert: %v\n%s", err, got)
	}
	if again, _ := insertPWQuality(got); again != got {
		t.Fatal("not idempotent")
	}
	if _, err := insertPWQuality("auth required pam_unix.so\n"); err == nil {
		t.Fatal("no password module must be an error")
	}
}

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
