package agent

import (
	"strings"
	"testing"
)

// A user's own disable-lock-screen makes GNOME, Cinnamon and MATE ignore
// the lock request: locked by the system while the device is locked, and
// always with a screen lock declaration.
func TestLockScreenLockdown(t *testing.T) {
	settings, locks := lockdownFiles()
	_, slLocks := dconfLockFiles(300)
	for _, dir := range lockdownDirs {
		if !strings.Contains(settings, "["+dir+"]\ndisable-lock-screen=false") {
			t.Fatalf("%s not set: %s", dir, settings)
		}
		key := "/" + dir + "/disable-lock-screen\n"
		if !strings.Contains(locks, key) || !strings.Contains(slLocks, key) {
			t.Fatalf("%s not locked", dir)
		}
	}
}
