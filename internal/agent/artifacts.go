package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Uploaded packages, scripts and files (docs/packages.md). The agent
// downloads each over the mTLS agent API, keeps it only when its SHA-256
// matches the signed declaration, and installs it once per hash. Every
// kind runs as root (package scripts, the script itself, a file anywhere),
// so all of them need allow_scripts, the device's own opt in that the
// server cannot switch on.

const (
	artifactDir  = stateDir + "/artifacts"
	artifactDone = stateDir + "/artifacts-done.json"
)

// artifactFits says whether a package kind installs on a family.
func artifactFits(kind, family string) bool {
	switch kind {
	case "deb":
		return family == "debian"
	case "pacman":
		return family == "arch"
	case "apk":
		return family == "alpine"
	case "rpm":
		return family == "fedora" || family == "suse"
	}
	return true
}

func artifactKey(a api.Artifact) string { return a.SHA256 + ":" + a.Path }

func (a *Agent) applyArtifacts(list []api.Artifact) error {
	if len(list) == 0 {
		return nil
	}
	if !a.cfg.AllowScripts {
		return errors.New("uploaded packages, scripts and files install only on devices enrolled with allow_scripts")
	}
	done := map[string]time.Time{}
	if b, err := os.ReadFile(artifactDone); err == nil {
		_ = json.Unmarshal(b, &done)
	}
	var errs []error
	for _, art := range list {
		if _, ok := done[artifactKey(art)]; ok {
			continue
		}
		if !artifactFits(art.Kind, a.host.family) {
			continue // a deb on an rpm system: the blueprint usually holds both
		}
		if err := a.installArtifact(art); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", art.Name, err))
			continue
		}
		done[artifactKey(art)] = time.Now().UTC()
		b, _ := json.Marshal(done)
		errs = append(errs, os.WriteFile(artifactDone, b, 0o600))
		a.event("installed uploaded %s %s (%s)", art.Kind, art.Name, art.SHA256[:12])
	}
	return errors.Join(errs...)
}

func (a *Agent) installArtifact(art api.Artifact) error {
	if err := art.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		return err
	}
	file := filepath.Join(artifactDir, art.SHA256)
	switch art.Kind {
	case "deb":
		file += ".deb"
	case "rpm":
		file += ".rpm"
	case "apk":
		file += ".apk"
	case "pacman":
		file += ".pkg.tar"
	case "flatpak":
		file += ".flatpak"
	}
	if err := a.downloadVerified(ctx, "/api/v1/artifacts/"+art.SHA256, file, art.SHA256, art.Size); err != nil {
		return err
	}
	defer os.Remove(file)
	var err error
	switch art.Kind {
	case "deb", "rpm", "apk", "pacman":
		cmd := localInstall(a.host.family, file)
		_, err = run(30*time.Minute, cmd[0], cmd[1:]...)
	case "flatpak":
		_, err = run(30*time.Minute, "flatpak", "install", "--system", "--noninteractive", "--bundle", file)
	case "script":
		_, err = run(30*time.Minute, "/bin/sh", file)
	case "file":
		if err = os.MkdirAll(filepath.Dir(art.Path), 0o755); err == nil { //nolint:gosec // system directories such as /etc/opt/vendor are world readable
			err = copyFile(file, art.Path, os.FileMode(art.FileMode()))
		}
	}
	return err
}
