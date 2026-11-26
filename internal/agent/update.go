package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Agent updates with rollback.
//
// The server offers an approved version with the release's SHA256SUMS. The
// agent checks the signature when it was built with a release key, downloads
// the package for its distribution and architecture over mTLS, verifies the
// checksum, keeps a copy of the running binary and writes a marker. The
// package is installed in a transient unit outside the agent's cgroup (the
// package scripts restart the agent). The new agent confirms the update with
// its first start. If it does not, the watchdog script restores the copy
// after 15 minutes and records the rollback (packaging/limdm-watchdog.sh).

const (
	updateMarker = stateDir + "/update-pending.json"
	updateResult = stateDir + "/update-result.json" // written by the watchdog script after a rollback
	rollbackDir  = stateDir + "/rollback"
	updateDir    = stateDir + "/updates"
)

type pendingUpdate struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// checkUpdateOutcome confirms an update with the running version, or picks up
// a rollback the watchdog performed.
func (a *Agent) checkUpdateOutcome() {
	if b, err := os.ReadFile(updateResult); err == nil {
		var res api.UpdateResult
		if json.Unmarshal(b, &res) == nil {
			a.state.UpdateResult = &res
			a.event("agent update to %s rolled back to %s", res.To, res.From)
		}
		os.Remove(updateResult)
	}
	b, err := os.ReadFile(updateMarker)
	if err != nil {
		return
	}
	var m pendingUpdate
	if json.Unmarshal(b, &m) != nil {
		os.Remove(updateMarker)
		return
	}
	if m.To == Version {
		a.state.UpdateResult = &api.UpdateResult{From: m.From, To: m.To, OK: true}
		os.Remove(updateMarker) // confirmed: the watchdog will not roll back
		a.event("agent updated from %s to %s", m.From, m.To)
		return
	}
	// still the old version an hour later: the detached package install failed
	// (OpenRC has no watchdog to clean up); without this the marker would
	// block every later update
	if st, err := os.Stat(updateMarker); err == nil && time.Since(st.ModTime()) > time.Hour {
		a.state.UpdateResult = &api.UpdateResult{From: m.From, To: m.To, Detail: "the package install did not complete"}
		os.Remove(updateMarker)
		a.event("agent update to %s did not complete; it will be offered again", m.To)
	}
}

func packageFormat(family string) string {
	switch family {
	case "debian":
		return "deb"
	case "arch":
		return "pkg.tar.zst"
	case "alpine":
		return "apk"
	}
	return "rpm"
}

func (a *Agent) installUpdate(ctx context.Context, u api.AgentUpdate) error {
	if !api.NewerVersion(u.Version, Version) {
		return nil // never downgrade
	}
	if exists(updateMarker) {
		return nil // an update is in progress
	}
	// fail closed: without a compiled in release key the checksums would only
	// be as trustworthy as the server, so a self update is refused
	if UpdatePubKey == "" {
		return errors.New("this agent was built without a release signing key (UpdatePubKey); self updates are refused, update the package by hand")
	}
	pub, err := hex.DecodeString(UpdatePubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid compiled in release signing key")
	}
	if err := api.VerifySums(ed25519.PublicKey(pub), u.Sums, u.SumsSig); err != nil {
		return err
	}
	file := api.PackageName(u.Version, runtime.GOARCH, packageFormat(a.host.family))
	if !api.PackageRe.MatchString(file) {
		return errors.New("invalid package name")
	}
	want, err := api.SumsEntry(u.Sums, file)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		return err
	}
	pkg := filepath.Join(updateDir, file)
	if err := a.downloadPackage(ctx, u.Version, file, pkg, want); err != nil {
		return err
	}
	// keep the running binary for the watchdog's rollback
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := os.MkdirAll(rollbackDir, 0o700); err != nil {
		return err
	}
	if err := copyFile(exe, filepath.Join(rollbackDir, "limdm-agent"), 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(pendingUpdate{From: Version, To: u.Version, At: time.Now().UTC()})
	if err := os.WriteFile(updateMarker, b, 0o600); err != nil {
		return err
	}
	install := localInstall(a.host.family, pkg)
	if !systemd() { // OpenRC: a detached process outlives the agent's restart
		cmd := exec.CommandContext(context.WithoutCancel(ctx), install[0], install[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			os.Remove(updateMarker)
			return fmt.Errorf("start installation: %w", err)
		}
		return nil
	}
	args := append([]string{"--unit=limdm-agent-update-" + strconv.FormatInt(time.Now().Unix(), 10), "--collect", "--quiet",
		"--setenv=DEBIAN_FRONTEND=noninteractive"}, install...)
	if out, err := sh("systemd-run", args...); err != nil {
		os.Remove(updateMarker)
		return fmt.Errorf("start installation: %s", lastLines(out, 2))
	}
	a.event("installing agent %s", u.Version)
	return nil
}

// localInstall is the command that installs a local package file with the
// family's package manager; dependencies come from the configured sources.
// The callers checked the file's SHA-256 against signed data, so apk and
// zypper may accept it unsigned.
func localInstall(family, pkg string) []string {
	switch family {
	case "debian":
		return []string{"apt-get", "install", "-y", "-q", "-o", "Dpkg::Options::=--force-confold", "--allow-downgrades", pkg}
	case "arch":
		return []string{"pacman", "-U", "--noconfirm", pkg}
	case "alpine":
		return []string{"apk", "add", "--allow-untrusted", "--no-interactive", pkg}
	case "suse": // zypper refuses unsigned local rpms otherwise
		return []string{"zypper", "--non-interactive", "install", "--allow-unsigned-rpm", pkg}
	}
	return []string{"dnf", "install", "-y", "-q", pkg}
}

func (a *Agent) downloadPackage(ctx context.Context, version, file, dst, wantHex string) error {
	return a.downloadVerified(ctx, "/api/v1/agent-packages/"+url.PathEscape(version)+"/"+url.PathEscape(file), dst, wantHex, 200<<20)
}

// downloadVerified fetches path from the server over mTLS into dst and
// keeps it only when its SHA-256 is wantHex.
func (a *Agent) downloadVerified(ctx context.Context, path, dst, wantHex string, limit int64) error {
	file := filepath.Base(dst)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Server+path, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if err := busyOf("download "+file, resp); err != nil {
			return err
		}
		return fmt.Errorf("download %s: %s", file, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".dl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, limit)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		return fmt.Errorf("%s: checksum mismatch", file)
	}
	return os.Rename(tmp.Name(), dst)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
