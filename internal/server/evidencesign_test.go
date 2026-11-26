package server

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// A signed bundle verifies with the command key and fails when changed or
// checked with another key; the PDF is a well formed PDF that names the
// bundle's SHA-256.
func TestEvidenceSignAndPDF(t *testing.T) {
	s := &Server{cmdKey: testCmdKey}
	b := evidenceBundle{Format: evidenceFormat, GeneratedAt: time.Now().UTC(), GeneratedBy: "admin@firma.de", WindowDays: 90, Score: 50,
		Devices:    []evidenceDevice{{ID: "d1", Hostname: "pc1", Checks: []api.CheckResult{{ID: "ssh.baseline", Title: "SSH server is hardened", Status: "fail"}}}},
		Exceptions: []apiException{{CheckID: "net.forwarding", Mode: "exclude", Reason: "Gerät (L) \\", State: "active", Expires: time.Now().AddDate(0, 1, 0)}},
		Frameworks: []statsFramework{{ID: "bsi", Name: "BSI IT-Grundschutz", Pass: 1, Fail: 1, Rate: 50}}}
	file, sig, err := s.signEvidence(b)
	if err != nil {
		t.Fatal(err)
	}
	pub := testCmdKey.Public().(ed25519.PublicKey)
	info, err := VerifyEvidence(file, []ed25519.PublicKey{pub})
	if err != nil || info.Devices != 1 || info.KeyID != sig.KeyID {
		t.Fatalf("verify: %+v %v", info, err)
	}
	if _, err := VerifyEvidence(bytes.Replace(file, []byte(`"pc1"`), []byte(`"pc2"`), 1), []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("a changed bundle verified")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := VerifyEvidence(file, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("verified with another key")
	}
	pdf := string(evidencePDF("de", b, "abc123", sig))
	if !strings.HasPrefix(pdf, "%PDF-1.4") || !strings.HasSuffix(pdf, "%%EOF\n") || !strings.Contains(pdf, "abc123") ||
		!strings.Contains(pdf, "Ger\xe4t \\(L\\) \\\\") || !strings.Contains(pdf, "startxref") {
		t.Fatalf("pdf: %q", pdf[:min(len(pdf), 400)])
	}
}
