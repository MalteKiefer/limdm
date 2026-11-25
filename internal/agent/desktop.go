package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// The desktop helper (limdm-desktop) runs in the user's session and talks to
// the agent over a local socket. The agent identifies the caller by its peer
// credentials and only answers users with an active local session. The only
// secret that crosses the socket is the LUKS passphrase of the user's own
// device, used once for cryptsetup and never stored.

const (
	desktopSocket = "/run/limdm/agent.sock"
	brandingDir   = "/var/cache/limdm"
	brandingLogo  = brandingDir + "/logo.png"
)

type desktopInfo struct {
	Company string
	Logo    string
	Need    []luksVolume
}

// DesktopRequest and DesktopResponse are the socket protocol (one JSON line each).
type DesktopRequest struct {
	Op         string `json:"op"` // status | escrow
	UUID       string `json:"uuid,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type DesktopVolume struct {
	Device string `json:"device"`
	UUID   string `json:"uuid"`
}

type DesktopResponse struct {
	Company string          `json:"company,omitempty"`
	Logo    string          `json:"logo,omitempty"`
	Need    []DesktopVolume `json:"need,omitempty"`
	OK      bool            `json:"ok,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type desktopServer struct {
	a        *Agent
	info     atomic.Pointer[desktopInfo]
	mu       sync.Mutex
	queued   map[string]bool        // uuids handed to the agent, not yet escrowed
	failures map[uint32][]time.Time // wrong passphrases per uid
}

// escrowMu serializes access to the escrow request file within the agent.
var escrowMu sync.Mutex

// applyBranding stores name and logo for the desktop helper.
func (a *Agent) applyBranding(b *api.Branding) {
	if b == nil {
		return
	}
	var err error
	if len(b.Logo) > 0 && len(b.Logo) <= 256<<10 && bytes.HasPrefix(b.Logo, []byte("\x89PNG\r\n\x1a\n")) {
		if err = os.MkdirAll(brandingDir, 0o755); err == nil { //nolint:gosec // logo must be readable by the user's session
			_, err = writeIfChanged(brandingLogo, string(b.Logo), 0o644)
		}
	} else {
		_, err = writeOrRemove(brandingLogo, "", 0o644)
	}
	if err != nil {
		a.event("branding: %v", err)
		return
	}
	a.state.Company, a.state.BrandingHash = strings.TrimSpace(b.Name), b.Hash
}

// publishDesktop refreshes what the socket reports; called after each cycle.
func (a *Agent) publishDesktop() {
	if a.desktop == nil {
		return
	}
	info := &desktopInfo{Company: a.state.Company}
	if _, err := os.Stat(brandingLogo); err == nil {
		info.Logo = brandingLogo
	}
	if de := a.pol.Extra.DiskEncryption; de != nil && de.Escrow {
		info.Need = a.missingEscrow()
	}
	a.desktop.mu.Lock()
	for u := range a.desktop.queued {
		if _, ok := a.state.Escrowed[u]; ok {
			delete(a.desktop.queued, u)
		}
	}
	a.desktop.mu.Unlock()
	a.desktop.info.Store(info)
}

func (a *Agent) serveDesktop(ctx context.Context) {
	if err := os.MkdirAll(filepath.Dir(desktopSocket), 0o755); err != nil { //nolint:gosec // socket directory must be reachable by users
		a.log.Error("desktop socket", "err", err)
		return
	}
	os.Remove(desktopSocket)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", desktopSocket)
	if err != nil {
		a.log.Error("desktop socket", "err", err)
		return
	}
	// everyone may connect; authorization happens per connection by peer credentials
	if err := os.Chmod(desktopSocket, 0o666); err != nil { //nolint:gosec // see above
		a.log.Error("desktop socket", "err", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				a.log.Error("desktop socket", "err", err)
			}
			return
		}
		go a.desktop.handle(c.(*net.UnixConn))
	}
}

func (d *desktopServer) handle(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute)) // cryptsetup with argon2 takes a few seconds
	uid, err := peerUID(c)
	if err != nil || !activeLocalUser(uid) {
		json.NewEncoder(c).Encode(DesktopResponse{Error: "not allowed"})
		return
	}
	line, err := bufio.NewReader(&limitedReader{c, 8 << 10}).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req DesktopRequest
	if err := json.Unmarshal(line, &req); err != nil {
		json.NewEncoder(c).Encode(DesktopResponse{Error: "bad request"})
		return
	}
	resp := d.serve(uid, req)
	req.Passphrase = ""
	json.NewEncoder(c).Encode(resp)
}

func (d *desktopServer) serve(uid uint32, req DesktopRequest) DesktopResponse {
	info := d.info.Load()
	if info == nil {
		info = &desktopInfo{}
	}
	d.mu.Lock()
	var need []DesktopVolume
	for _, v := range info.Need {
		if !d.queued[v.UUID] {
			need = append(need, DesktopVolume{Device: v.Path, UUID: v.UUID})
		}
	}
	d.mu.Unlock()
	switch req.Op {
	case "status":
		return DesktopResponse{Company: info.Company, Logo: info.Logo, Need: need}
	case "escrow":
		var vol *DesktopVolume
		for i := range need {
			if need[i].UUID == req.UUID {
				vol = &need[i]
			}
		}
		if vol == nil {
			return DesktopResponse{Error: "no recovery key needed for this volume"}
		}
		if len(req.Passphrase) == 0 || len(req.Passphrase) > 1024 {
			return DesktopResponse{Error: "passphrase not accepted"}
		}
		if !d.allowAttempt(uid) {
			return DesktopResponse{Error: "too many attempts, try again later"}
		}
		key := api.NewRecoveryKey()
		if err := luksAddKey(vol.Device, req.Passphrase, key); err != nil {
			d.recordFailure(uid)
			return DesktopResponse{Error: "passphrase not accepted"}
		}
		if err := queueEscrow(pendingKey{RecoveryKey: api.RecoveryKey{UUID: vol.UUID, Device: vol.Device, Key: key}}); err != nil {
			return DesktopResponse{Error: "could not store the key, contact IT"}
		}
		d.mu.Lock()
		d.queued[vol.UUID] = true
		d.mu.Unlock()
		d.a.event("recovery key created for %s from the desktop (uid %d)", vol.Device, uid)
		select {
		case d.a.kick <- struct{}{}:
		default:
		}
		return DesktopResponse{OK: true}
	}
	return DesktopResponse{Error: "unknown operation"}
}

// allowAttempt limits wrong passphrases to 5 per 15 minutes and user.
func (d *desktopServer) allowAttempt(uid uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	var recent []time.Time
	for _, t := range d.failures[uid] {
		if time.Since(t) < 15*time.Minute {
			recent = append(recent, t)
		}
	}
	d.failures[uid] = recent
	return len(recent) < 5
}

func (d *desktopServer) recordFailure(uid uint32) {
	d.mu.Lock()
	d.failures[uid] = append(d.failures[uid], time.Now())
	d.mu.Unlock()
}

// queueEscrow appends to the request file the agent reads each cycle.
func queueEscrow(k pendingKey) error {
	escrowMu.Lock()
	defer escrowMu.Unlock()
	var req []pendingKey
	if b, err := os.ReadFile(escrowRequest); err == nil {
		if err := json.Unmarshal(b, &req); err != nil {
			return err
		}
	}
	req = append(req, k)
	b, _ := json.Marshal(req)
	return os.WriteFile(escrowRequest, b, 0o600)
}

// activeLocalUser reports whether uid has an active, non-remote session.
func activeLocalUser(uid uint32) bool {
	if uid == 0 {
		return true
	}
	out, err := sh("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[1] != itoa(uid) || !sessionIDRe.MatchString(f[0]) {
			continue
		}
		props, err := sh("loginctl", "show-session", f[0], "-p", "Active", "-p", "Remote")
		if err == nil && strings.Contains(props, "Active=yes") && strings.Contains(props, "Remote=no") {
			return true
		}
	}
	return false
}

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func itoa(u uint32) string { return strconv.FormatUint(uint64(u), 10) }

type limitedReader struct {
	c *net.UnixConn
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("request too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.c.Read(p)
	l.n -= n
	return n, err
}
