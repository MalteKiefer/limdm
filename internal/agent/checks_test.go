package agent

import (
	"regexp"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestVolumeKind(t *testing.T) {
	for _, c := range []struct {
		mount, fs, lsblk, role string
		removable              bool
	}{
		{"/boot", "vfat", "0 0 c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "esp", false}, // CachyOS with Limine
		{"/efi", "vfat", "0 0", "esp", false},                                       // MBR or no type reported
		{"/data", "vfat", "0 0 C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "esp", false}, // by type wherever mounted
		{"/run/media/anna/Ventoy", "exfat", "1 1 ", "", true},                       // USB stick
		{"/mnt/card", "ext4", "0 1 0fc63daf-8483-4772-8e79-3d69d8477de4", "", true}, // hotplugged reader
		{"/", "btrfs", "0 0 ", "", false},                                           // dm device: no part type
		{"/home", "ext4", "", "", false},
	} {
		role, rm := volumeKind(c.mount, c.fs, c.lsblk)
		if role != c.role || rm != c.removable {
			t.Errorf("%s %s %q: role %q removable %v", c.mount, c.fs, c.lsblk, role, rm)
		}
		if v := (api.Volume{Role: role, Removable: rm}); v.EncryptionExpected() != (c.role == "" && !c.removable) {
			t.Errorf("%s: EncryptionExpected %v", c.mount, v.EncryptionExpected())
		}
	}
}

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
