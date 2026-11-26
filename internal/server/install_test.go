package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

// TestInstallScriptVerifiesSums runs the signature check of the generated
// /install.sh with sh and OpenSSL against a signed and a changed SHA256SUMS.
func TestInstallScriptVerifiesSums(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ca: ca, cfg: Config{ReleaseRepo: "o/r", PublicURL: "https://mdm.test", AgentURL: "https://mdm.test:8444"}}
	w := httptest.NewRecorder()
	s.installScript(w, httptest.NewRequest("GET", "/install.sh", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("without a release key the script must not be served: %d", w.Code)
	}
	s.cfg.ReleaseKey = hex.EncodeToString(pub)
	w = httptest.NewRecorder()
	s.installScript(w, httptest.NewRequest("GET", "/install.sh", nil))
	script := w.Body.String()
	if w.Code != 200 || !strings.Contains(script, "RELEASE_KEY='"+s.cfg.ReleaseKey+"'") {
		t.Fatalf("script: %d", w.Code)
	}
	sh, err1 := exec.LookPath("sh")
	_, err2 := exec.LookPath("openssl")
	if err1 != nil || err2 != nil {
		t.Skip("sh or openssl missing")
	}
	start := strings.Index(script, "hex2bin()")
	end := strings.Index(script, "\ncase \"$(uname -m)\"")
	if start < 0 || end < start {
		t.Fatal("verify_sums not found in the script")
	}
	dir := t.TempDir()
	sums := "0123abcd  limdm-agent_1.0.0_linux_amd64.deb\n"
	os.WriteFile(filepath.Join(dir, "sums"), []byte(sums), 0o600)
	os.WriteFile(filepath.Join(dir, "sig"), []byte(api.SignSums(key, sums)+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "bad"), []byte(strings.Replace(sums, "0123", "9999", 1)), 0o600)
	run := func(file string) error {
		c := exec.Command(sh, "-c", script[start:end]+"\nverify_sums \"$0\" \"$1\" \"$2\"", s.cfg.ReleaseKey, filepath.Join(dir, file), filepath.Join(dir, "sig"))
		return c.Run()
	}
	if err := run("sums"); err != nil {
		t.Fatalf("a signed SHA256SUMS must verify: %v", err)
	}
	if run("bad") == nil {
		t.Fatal("a changed SHA256SUMS must not verify")
	}
}
