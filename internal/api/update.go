package api

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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

// KeyRollover announces a new command signing key, signed with the key the
// agent has pinned, so an agent moves to the new key without re-enrolling.
type KeyRollover struct {
	Key       string `json:"key"`       // new public key (hex)
	Signature string `json:"signature"` // hex Ed25519 signature of the pinned key over RolloverSigned(Key)
}

// RolloverSigned is the byte string a rollover signature covers.
func RolloverSigned(newKeyHex string) []byte {
	return []byte("limdm-command-key-rollover-v1\n" + strings.ToLower(newKeyHex))
}

// VerifyRollover checks that pinned signed the announcement of r.Key.
func VerifyRollover(pinned ed25519.PublicKey, r KeyRollover) error {
	sig, err := hex.DecodeString(r.Signature)
	key, kerr := hex.DecodeString(r.Key)
	if err != nil || kerr != nil || len(key) != ed25519.PublicKeySize || len(pinned) != ed25519.PublicKeySize ||
		!ed25519.Verify(pinned, RolloverSigned(r.Key), sig) {
		return errors.New("command key rollover not signed by the pinned key")
	}
	return nil
}

// ItemSigned is what a library item signature covers: name, type and the
// compact payload. The server signs at saving and checks before delivery.
func ItemSigned(name, typ string, payload []byte) []byte {
	return fmt.Appendf(nil, "limdm-item-v1\n%s\n%s\n%s", name, typ, payload)
}

// Declaration like data outside library items is signed with the command
// key too, when an admin saves it, so a database write alone changes nothing
// a device acts on as root. The agent checks these signatures with the
// pinned key once the server announces SignedData.
//
// SignedSeq: every signature covers a sequence number that grows with
// each signed change of the entry (the server's database clock in
// microseconds; 0 for rows signed before it existed, left out of the
// message). The agent keeps the highest number
// per entry and refuses a lower one, so an older signed state written back
// into the database (an earlier repository, a revoked admin flag) is not
// applied again.

// CatalogAppSigned is what a catalog app signature covers: what decides
// what gets installed (ID, name, mode, sources with their repositories,
// detect names). Summary, category, icon and the device's request state are
// display only and change without an admin (Flathub metadata, requests).
func CatalogAppSigned(a CatalogApp) []byte {
	b, _ := json.Marshal(struct {
		ID      string      `json:"id"`
		Name    string      `json:"name"`
		Mode    string      `json:"mode"`
		Sources []AppSource `json:"sources"`
		Detect  []string    `json:"detect,omitempty"`
		Seq     int64       `json:"seq,omitempty"`
	}{a.ID, a.Name, a.Mode, a.Sources, a.Detect, a.Seq})
	return append([]byte("limdm-catalog-app-v1\n"), b...)
}

// CatalogRemoteSigned is what a managed Flatpak remote signature covers.
func CatalogRemoteSigned(r CatalogRemote) []byte {
	r.Signature = ""
	b, _ := json.Marshal(r)
	return append([]byte("limdm-catalog-remote-v1\n"), b...)
}

// UsersSigned is what the signature of a device's user list covers: the
// device and the list as an admin saved it (no list and an empty one are
// the same), and its sequence number (SignedSeq) when it has one.
func UsersSigned(deviceID string, users []User, seq int64) []byte {
	if users == nil {
		users = []User{}
	}
	b, _ := json.Marshal(users)
	msg := fmt.Appendf(nil, "limdm-users-v1\n%s\n%s", deviceID, b)
	if seq != 0 {
		msg = fmt.Appendf(msg, "\n%d", seq)
	}
	return msg
}

// SignedUsers is the user list of a device as an admin saved it, with its
// signature. The check in answer's Users can be shorter (people disabled
// in the directory), never longer or with other rights.
type SignedUsers struct {
	Users     []User `json:"users"`
	Signature string `json:"signature"`
	Seq       int64  `json:"seq,omitempty"`
}

// VerifySigned checks a hex Ed25519 signature over msg.
func VerifySigned(pub ed25519.PublicKey, msg []byte, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	return err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig)
}
