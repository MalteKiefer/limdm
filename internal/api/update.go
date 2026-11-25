package api

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Agent updates are delivered by the server as the release's packages. The
// release's SHA256SUMS file travels with the offer; when the agent was built
// with a release key, the file must carry a valid Ed25519 signature, so not
// even a compromised server can install a package the release did not ship.

// AgentUpdate offers an agent version to a device.
type AgentUpdate struct {
	Version string `json:"version"`
	Sums    string `json:"sums"`               // SHA256SUMS of the release
	SumsSig string `json:"sums_sig,omitempty"` // hex Ed25519 signature over SumsSigned(Sums)
}

// UpdateResult is what the agent reports after an update attempt.
type UpdateResult struct {
	From       string `json:"from"`
	To         string `json:"to"`
	OK         bool   `json:"ok"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// PackageRe matches the agent package names a release ships.
var PackageRe = regexp.MustCompile(`^limdm-agent_([0-9][0-9A-Za-z.~+-]*)_linux_(amd64|arm64)\.(deb|rpm|apk|pkg\.tar\.zst)$`)

// SumsSigned is the message the release key signs.
func SumsSigned(sums string) []byte { return []byte("limdm SHA256SUMS v1\n" + sums) }

// SignSums signs a SHA256SUMS file.
func SignSums(key ed25519.PrivateKey, sums string) string {
	return hex.EncodeToString(ed25519.Sign(key, SumsSigned(sums)))
}

// VerifySums checks the signature of a SHA256SUMS file.
func VerifySums(pub ed25519.PublicKey, sums, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, SumsSigned(sums), sig) {
		return errors.New("release signature invalid")
	}
	return nil
}

// SumsEntry returns the SHA-256 the sums file lists for name.
func SumsEntry(sums, name string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			if _, err := hex.DecodeString(f[0]); err == nil {
				return strings.ToLower(f[0]), nil
			}
		}
	}
	return "", fmt.Errorf("%s is not listed in the release checksums", name)
}

// PackageName is the file of version for an architecture and format (deb, rpm).
func PackageName(version, arch, format string) string {
	return "limdm-agent_" + version + "_linux_" + arch + "." + format
}

// CommandSigned is the byte string a command signature covers: the device,
// the command's ID, type, creation time and payload.
func CommandSigned(deviceID string, c Command) []byte {
	return fmt.Appendf(nil, "limdm-command-v1\n%s\n%d\n%s\n%d\n%s", deviceID, c.ID, c.Type, c.CreatedAt.UnixMicro(), c.Payload)
}

func SignCommand(key ed25519.PrivateKey, deviceID string, c Command) string {
	return hex.EncodeToString(ed25519.Sign(key, CommandSigned(deviceID, c)))
}

func VerifyCommand(pub ed25519.PublicKey, deviceID string, c Command) error {
	sig, err := hex.DecodeString(c.Signature)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, CommandSigned(deviceID, c), sig) {
		return errors.New("command signature invalid")
	}
	return nil
}

// ItemSigned is what a library item signature covers: name, type and the
// compact payload. The server signs at saving and checks before delivery.
func ItemSigned(name, typ string, payload []byte) []byte {
	return fmt.Appendf(nil, "limdm-item-v1\n%s\n%s\n%s", name, typ, payload)
}
