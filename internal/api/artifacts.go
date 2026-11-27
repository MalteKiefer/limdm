package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Uploaded packages (docs/packages.md). An admin uploads a file to the
// server's package store; this declaration references it by SHA-256. The
// declaration is signed with the command key like every library item, so
// the hash the agent checks before installing comes from signed data.

const TypeArtifacts = "com.limdm.artifacts"

// ArtifactKinds are the kinds an upload can have.
var ArtifactKinds = []string{"deb", "rpm", "apk", "pacman", "flatpak", "script", "file"}

// Artifact is one uploaded file to install on the device.
type Artifact struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	Path   string `json:"path,omitempty"` // file: where it is written
	Mode   string `json:"mode,omitempty"` // file: octal mode, default 0644
}

type Artifacts struct {
	Artifacts []Artifact `json:"artifacts"`
}

var (
	sha256Re       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ArtifactNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
	fileModeRe     = regexp.MustCompile(`^0?[0-7]{3}$`)
)

// FileMode is the declared mode of a file artifact.
func (a Artifact) FileMode() uint32 {
	m, err := strconv.ParseUint(firstOr(a.Mode, "0644"), 8, 32)
	if err != nil {
		return 0o644
	}
	return uint32(m)
}

func firstOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Validate checks the reference; the server also checks that the upload
// exists in the item's tenant.
func (a Artifact) Validate() error {
	switch {
	case !sha256Re.MatchString(a.SHA256):
		return fmt.Errorf("artifact %q: sha256 must be 64 lowercase hex characters", a.Name)
	case !ArtifactNameRe.MatchString(a.Name):
		return fmt.Errorf("artifact %q: invalid name", a.Name)
	case !slices.Contains(ArtifactKinds, a.Kind):
		return fmt.Errorf("artifact %q: kind is one of %s", a.Name, strings.Join(ArtifactKinds, ", "))
	case a.Size < 1:
		return fmt.Errorf("artifact %q: size is required", a.Name)
	}
	if a.Kind != "file" {
		if a.Path != "" || a.Mode != "" {
			return fmt.Errorf("artifact %q: path and mode are for kind file only", a.Name)
		}
		return nil
	}
	if !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || userWritable(a.Path) ||
		strings.HasPrefix(a.Path, "/proc/") || strings.HasPrefix(a.Path, "/sys/") || strings.HasPrefix(a.Path, "/dev/") {
		return fmt.Errorf("artifact %q: path must be absolute, clean and outside user writable and virtual directories", a.Name)
	}
	if a.Mode != "" && !fileModeRe.MatchString(a.Mode) || a.FileMode()&0o7000 != 0 {
		return fmt.Errorf("artifact %q: mode is octal like 0644, without setuid, setgid or sticky bits", a.Name)
	}
	return nil
}

func init() {
	Types[TypeArtifacts] = `{"artifacts": [{"sha256": "<from Software, Packages>", "name": "vendor-vpn", "kind": "deb", "size": 1048576}]}`
	listTypes[TypeArtifacts] = true
	payloadShapes[TypeArtifacts] = Artifacts{}
}

// applyArtifacts decodes and validates the artifacts type.
func (d Declaration) applyArtifacts(p *Policy) (bool, error) {
	if d.Type != TypeArtifacts {
		return d.applyHostname(p) // hostname.go
	}
	var v Artifacts
	if err := strict(d.Payload, &v); err != nil {
		return true, err
	}
	if len(v.Artifacts) > 100 {
		return true, errors.New("at most 100 artifacts")
	}
	var errs []error
	for _, a := range v.Artifacts {
		errs = append(errs, a.Validate())
	}
	p.Extra.Artifacts = v.Artifacts
	return true, errors.Join(errs...)
}

// mergeArtifacts combines lists by hash and path; a later item wins.
func mergeArtifacts(typ string, a, b json.RawMessage) (json.RawMessage, bool, error) {
	if typ != TypeArtifacts {
		return nil, false, nil
	}
	var x, y Artifacts
	if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
		return nil, true, err
	}
	out := slices.Clone(x.Artifacts)
	for _, n := range y.Artifacts {
		if i := slices.IndexFunc(out, func(e Artifact) bool { return e.SHA256 == n.SHA256 && e.Path == n.Path }); i >= 0 {
			out[i] = n
		} else {
			out = append(out, n)
		}
	}
	m, err := json.Marshal(Artifacts{out})
	return m, true, err
}
