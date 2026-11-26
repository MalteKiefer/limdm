package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	Company  string
	Logo     string
	Need     []luksVolume
	Status   DesktopStatus
	Profiles []DesktopProfile
	Certs    []api.CertInfo
	Apps     []DesktopApp // catalog snapshot of the last cycle
	Store    *StoreInfo
	Requests []api.RequestState // requests for apps outside the catalog
}

// DesktopCheck is one compliance check as the desktop app lists it.
type DesktopCheck struct {
	ID     string `json:"id,omitempty"`
	Level  int    `json:"level,omitempty"`
	Title  string `json:"title"`
	Status string `json:"status"` // pass | fail | na | excepted
	Detail string `json:"detail,omitempty"`
}

// DesktopStatus is what the tray shows about the device and the agent.
type DesktopStatus struct {
	Hostname    string         `json:"hostname"`
	DeviceID    string         `json:"device_id"`
	Server      string         `json:"server"`
	Version     string         `json:"version"`
	LastCheckin *time.Time     `json:"last_checkin,omitempty"`
	LastError   string         `json:"last_error,omitempty"`
	Checks      int            `json:"checks"`
	Failing     []string       `json:"failing,omitempty"` // titles of failing checks
	CheckList   []DesktopCheck `json:"check_list,omitempty"`
	Escrowed    int            `json:"escrowed"`
	Locked      bool           `json:"locked,omitempty"`

	// for limdm info
	System        DesktopSystem `json:"system"`
	LostMode      bool          `json:"lost_mode,omitempty"`
	OfflineLocked bool          `json:"offline_locked,omitempty"`
	CheckinEvery  int           `json:"checkin_seconds,omitempty"`
	OfflineLockH  int           `json:"offline_lock_hours,omitempty"`
	Updates       string        `json:"updates,omitempty"` // mode and window
	LastUpdateRun *time.Time    `json:"last_update_run,omitempty"`
	Declarations  int           `json:"declarations"`
	DeclToken     string        `json:"declarations_token,omitempty"`
	ScriptsAllow  bool          `json:"scripts_allowed"`
	DesktopLogin  string        `json:"desktop_login,omitempty"` // off | session | login
	QueuedEvents  int           `json:"queued_events"`
	QueuedResults int           `json:"queued_results"`
	RemoteShell   string        `json:"remote_shell,omitempty"` // running support session: who, user, since
}

// DesktopSystem is the device as the last inventory saw it.
type DesktopSystem struct {
	OS        string `json:"os,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Model     string `json:"model,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Inventory string `json:"inventory,omitempty"` // osquery or native
}

// DesktopRequest and DesktopResponse are the socket protocol (one JSON line each).
type DesktopRequest struct {
	Op         string `json:"op"` // status | info | sync | escrow | catalog | app-install | app-remove | app-request | search | app-request-new | reboot-defer | shell-end
	App        string `json:"app,omitempty"`
	Query      string `json:"query,omitempty"`   // search
	Flatpak    string `json:"flatpak,omitempty"` // app-request-new
	Remote     string `json:"remote,omitempty"`
	Name       string `json:"name,omitempty"`
	Note       string `json:"note,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type DesktopVolume struct {
	Device string `json:"device"`
	UUID   string `json:"uuid"`
}

type DesktopResponse struct {
	Company  string             `json:"company,omitempty"`
	Logo     string             `json:"logo,omitempty"`
	Need     []DesktopVolume    `json:"need,omitempty"`
	OK       bool               `json:"ok,omitempty"`
	Error    string             `json:"error,omitempty"`
	Status   *DesktopStatus     `json:"status,omitempty"`    // info
	Log      []string           `json:"log,omitempty"`       // info: recent warnings and errors of the agent
	LogLines []DesktopLogLine   `json:"log_lines,omitempty"` // info: latest journal entries, every level
	Profiles []DesktopProfile   `json:"profiles,omitempty"`  // info: declarations in force
	Certs    []api.CertInfo     `json:"certificates,omitempty"`
	Apps     []DesktopApp       `json:"apps,omitempty"` // catalog
	Store    *StoreInfo         `json:"store,omitempty"`
	Requests []api.RequestState `json:"requests,omitempty"`  // catalog: requests for apps outside it
	Hits     []DesktopHit       `json:"hits,omitempty"`      // search
	SSO      *SSOStatus         `json:"sso,omitempty"`       // sso-status, sso-confirm
	RebootAt string             `json:"reboot_at,omitempty"` // reboot-defer: the new restart time
}

// SSOStatus tells the desktop app whether the user's company account needs a
// confirmation in the session, and the running confirmation.
type SSOStatus struct {
	Managed   bool       `json:"managed"`
	Email     string     `json:"email,omitempty"`
	Confirmed *time.Time `json:"confirmed,omitempty"`
	Due       bool       `json:"due"`
	Deadline  *time.Time `json:"deadline,omitempty"` // the local password locks after this (when online)
	URI       string     `json:"uri,omitempty"`      // running confirmation
	Code      string     `json:"code,omitempty"`
	Running   bool       `json:"running,omitempty"`
	Error     string     `json:"error,omitempty"` // of the last confirmation
}

// StoreInfo tells the desktop app about the store policy.
type StoreInfo struct {
	RestrictFlathub bool `json:"restrict_flathub"`
	ReadOnly        bool `json:"read_only"`
}

// addKeyFn is cryptsetup luksAddKey; tests replace it.
var addKeyFn = luksAddKey

type desktopServer struct {
	a        *Agent
	info     atomic.Pointer[desktopInfo]
	mu       sync.Mutex
	queued   map[string]bool        // uuids handed to the agent, not yet escrowed
	inflight map[string]bool        // uuids with a cryptsetup run in progress
	failures map[uint32][]time.Time // wrong passphrases per uid
	lastSync time.Time              // last check in requested from the desktop
	searches []time.Time            // recent searches, for the rate limit
	flows    map[string]*ssoFlow    // confirmations in the session, per user
}

type ssoFlow struct {
	uri, code string
	running   bool
	err       string
	started   time.Time
}

// agentLog returns the latest warnings and errors of the agent and its
// watchdog from the journal (the user cannot read the system journal).
func agentLog() []string {
	out, err := run(10*time.Second, "journalctl", "-u", agentUnit, "-u", "limdm-watchdog.service", "-p", "warning",
		"-n", "30", "-o", "short-iso", "--no-pager", "-q")
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(l) > 400 {
				l = l[:400]
			}
			lines = append(lines, l)
		}
	}
	return lines
}

// applyBranding stores name and logo for the desktop helper.
func (a *Agent) applyBranding(b *api.Branding) {
	if b == nil {
		return
	}
	var err error
	if len(b.Logo) > 0 && len(b.Logo) <= 256<<10 && bytes.HasPrefix(b.Logo, []byte("\x89PNG\r\n\x1a\n")) {
		if err = errors.Join(os.MkdirAll(brandingDir, 0o755), os.Chmod(brandingDir, 0o755)); err == nil { //nolint:gosec // logo must be readable by the user's session
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
	info := &desktopInfo{Company: a.state.Company, Status: DesktopStatus{DeviceID: a.cfg.DeviceID, Server: a.cfg.Server,
		Version: Version, LastCheckin: a.lastCheckin, LastError: a.lastError, Checks: len(a.lastChecks), Escrowed: len(a.state.Escrowed)}}
	info.Status.Hostname, _ = os.Hostname()
	info.Profiles = a.desktopProfiles()
	info.Apps = a.desktopCatalog(a.lastFlatpaks)
	if c := a.state.Catalog; c != nil {
		info.Store = &StoreInfo{RestrictFlathub: c.RestrictFlathub, ReadOnly: c.StoresReadOnly}
		info.Requests = slices.Clone(c.Requests)
	}
	info.Certs = certInfo(a.pol.Extra.Certificates)
	for _, c := range a.lastChecks {
		if c.Status == "fail" {
			info.Status.Failing = append(info.Status.Failing, c.Title)
		}
		info.Status.CheckList = append(info.Status.CheckList, DesktopCheck{ID: c.ID, Level: c.Level, Title: c.Title, Status: c.Status, Detail: c.Detail})
	}
	if _, err := os.Stat("/etc/nologin"); err == nil {
		info.Status.Locked = true
	}
	st := &info.Status
	st.System, st.LostMode, st.OfflineLocked = a.lastSystem, inLostMode(), a.state.OfflineLocked
	st.CheckinEvery, st.OfflineLockH = a.pol.CheckinSeconds, a.pol.OfflineLockHours
	if u := a.pol.Updates; u.Mode != "" && u.Mode != "off" {
		st.Updates = u.Mode + ", window " + u.Window
	}
	if !a.state.LastUpdateRun.IsZero() {
		t := a.state.LastUpdateRun
		st.LastUpdateRun = &t
	}
	st.Declarations, st.DeclToken, st.ScriptsAllow = len(a.state.Declarations), a.state.DeclToken, a.cfg.AllowScripts
	st.DesktopLogin = "off"
	if a.pol.Login.Enabled {
		st.DesktopLogin = a.pol.Login.Mode
	}
	a.evMu.Lock()
	st.QueuedEvents, st.QueuedResults = len(a.state.Events), len(a.state.Results)
	a.evMu.Unlock()
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
	// explicit chmod: the service runs with UMask=0077
	if err := errors.Join(os.MkdirAll(filepath.Dir(desktopSocket), 0o755), os.Chmod(filepath.Dir(desktopSocket), 0o755)); err != nil { //nolint:gosec // socket directory must be reachable by users
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

// desktopChangingOps change state on the device or at the server; a peer in
// a remote session (SSH) is refused them.
var desktopChangingOps = []string{"app-install", "app-remove", "app-request", "app-request-new", "escrow", "sso-confirm", "reboot-defer"}

func (d *desktopServer) handle(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute)) // cryptsetup with argon2 takes a few seconds
	uid, pid, err := peerCred(c)
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
	// the active local session is checked per uid; a process of the same
	// user in an SSH session may read but not change anything
	if slices.Contains(desktopChangingOps, req.Op) && remoteProcess(pid) {
		json.NewEncoder(c).Encode(DesktopResponse{Error: "not allowed from a remote session, use the device itself"})
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
	case "info":
		st := info.Status
		st.RemoteShell = d.a.shellInfo() // live, not from the last cycle
		return DesktopResponse{Company: info.Company, Logo: info.Logo, Need: need, Status: &st, Log: agentLog(),
			LogLines: agentJournal(200), Profiles: info.Profiles, Certs: info.Certs}
	case "catalog":
		apps := slices.Clone(info.Apps)
		for i := range apps { // installs and removals run between cycles
			apps[i].Busy, apps[i].Error = "", ""
			if j := d.a.store.job(apps[i].ID); j != nil {
				if j.Err == "" {
					apps[i].Busy = j.Action
				} else {
					apps[i].Error = j.Err
				}
			}
		}
		return DesktopResponse{Company: info.Company, OK: true, Apps: apps, Store: info.Store, Requests: d.a.withQueued(info.Requests)}
	case "search":
		d.mu.Lock()
		d.searches = slices.DeleteFunc(d.searches, func(t time.Time) bool { return time.Since(t) > time.Minute })
		limited := len(d.searches) >= 20
		if !limited {
			d.searches = append(d.searches, time.Now())
		}
		d.mu.Unlock()
		if limited {
			return DesktopResponse{Error: "too many searches, wait a minute"}
		}
		return d.a.searchApps(req.Query)
	case "reboot-defer":
		name := itoa(uid)
		if u, err := user.LookupId(name); err == nil {
			name = u.Username
		}
		at, err := d.a.deferReboot(name, time.Now())
		if err != nil {
			return DesktopResponse{Error: err.Error()}
		}
		return DesktopResponse{OK: true, RebootAt: at.Format("15:04")}
	case "sso-status", "sso-confirm":
		name := itoa(uid)
		u, err := user.LookupId(name)
		if err != nil {
			return DesktopResponse{Error: "unknown user"}
		}
		return d.ssoOp(u.Username, req.Op == "sso-confirm")
	case "app-request-new":
		name := itoa(uid)
		if u, err := user.LookupId(name); err == nil {
			name = u.Username
		}
		return d.a.requestNewApp(api.AppRequest{Flatpak: req.Flatpak, Remote: req.Remote, Name: req.Name, User: name, Note: req.Note})
	case "app-install", "app-remove", "app-request":
		name := itoa(uid)
		if u, err := user.LookupId(name); err == nil {
			name = u.Username
		}
		return d.a.storeAction(strings.TrimPrefix(req.Op, "app-"), req.App, name, req.Note)
	case "shell-end":
		if !d.a.endShell("ended on the device by uid " + itoa(uid)) {
			return DesktopResponse{Error: "no remote support session is running"}
		}
		return DesktopResponse{OK: true}
	case "sync":
		d.mu.Lock()
		recent := time.Since(d.lastSync) < 30*time.Second
		if !recent {
			d.lastSync = time.Now()
		}
		d.mu.Unlock()
		if recent {
			return DesktopResponse{Error: "a check in was requested less than 30 seconds ago"}
		}
		select {
		case d.a.kick <- struct{}{}:
		default: // a check in is already pending
		}
		return DesktopResponse{OK: true}
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
		// Check and reserve in one step: parallel connections must not run more
		// guesses than the limit, nor add two key slots for one volume. The
		// attempt counts as a failure until it succeeded.
		d.mu.Lock()
		if d.inflight[vol.UUID] {
			d.mu.Unlock()
			return DesktopResponse{Error: "a recovery key is being created for this volume"}
		}
		if !d.allowLocked(uid) {
			d.mu.Unlock()
			return DesktopResponse{Error: "too many attempts, try again later"}
		}
		d.failures[uid] = append(d.failures[uid], time.Now())
		d.inflight[vol.UUID] = true
		d.mu.Unlock()
		defer func() {
			d.mu.Lock()
			delete(d.inflight, vol.UUID)
			d.mu.Unlock()
		}()
		key := api.NewRecoveryKey()
		if err := addKeyFn(vol.Device, req.Passphrase, key); err != nil {
			return DesktopResponse{Error: "passphrase not accepted"}
		}
		d.mu.Lock()
		d.failures[uid] = d.failures[uid][:len(d.failures[uid])-1] // succeeded: not a failure
		d.mu.Unlock()
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
	return d.allowLocked(uid)
}

// allowLocked is allowAttempt for callers holding d.mu; it prunes old entries.
func (d *desktopServer) allowLocked(uid uint32) bool {
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
	return withEscrowRequests(func(ks []pendingKey) ([]pendingKey, error) { return append(ks, k), nil })
}

// activeLocalUser reports whether uid has an active, non-remote session.
func activeLocalUser(uid uint32) bool {
	if uid == 0 {
		return true
	}
	if !hasCmd("loginctl") {
		// no logind (OpenRC without elogind): the user must run something on
		// a virtual console, which only someone at the device can. A process
		// environment (DISPLAY) proves nothing: ssh -X or any user sets it.
		return onVirtualConsole(uid)
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

// onVirtualConsole reports whether a process of uid has a virtual console
// (/dev/ttyN, not a pseudo terminal) as its standard input.
func onVirtualConsole(uid uint32) bool {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		var st syscall.Stat_t
		if syscall.Stat(d, &st) != nil || st.Uid != uid {
			continue
		}
		if t, err := os.Readlink(d + "/fd/0"); err == nil && vtRe.MatchString(t) {
			return true
		}
	}
	return false
}

var vtRe = regexp.MustCompile(`^/dev/tty[0-9]+$`)

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

// ssoOp reports the company account state of a user and, with start, begins
// a confirmation: the app shows URI and code, the agent waits for the
// identity provider and records the confirmation.
func (d *desktopServer) ssoOp(name string, start bool) DesktopResponse {
	email, managed := readUsers()[name]
	cfg, ok := readPAMPolicy()
	if !managed || !ok || !cfg.Enabled {
		return DesktopResponse{OK: true, SSO: &SSOStatus{}}
	}
	st := &SSOStatus{Managed: true, Email: email}
	now := time.Now()
	if t, ok := readSSO()[name]; ok {
		st.Confirmed = &t
		st.Due = !cfg.Session() || sessionDue(cfg, t, now)
		if cfg.Session() {
			dl := t.Add(time.Duration(cfg.ReverifyHours+cfg.GraceHours) * time.Hour)
			st.Deadline = &dl
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flows == nil {
		d.flows = map[string]*ssoFlow{}
	}
	f := d.flows[name]
	if start && (f == nil || !f.running) {
		// reserve the flow, then talk to the identity provider without the
		// lock: the agent's main loop and every socket request share it
		f = &ssoFlow{running: true, started: now}
		d.flows[name] = f
		d.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		startCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		flow, err := startDeviceFlow(startCtx, cfg.Login)
		stop()
		d.mu.Lock()
		if err != nil {
			cancel()
			f.running, f.err = false, err.Error()
			return DesktopResponse{Error: err.Error(), SSO: st}
		}
		f.uri, f.code = flow.URI, flow.Code
		go func() {
			defer cancel()
			err := flow.finish(ctx, cfg.Login, email)
			if err == nil {
				err = recordSSO(name, time.Now())
			}
			d.mu.Lock()
			f.running = false
			if err != nil {
				f.err = err.Error()
			}
			d.mu.Unlock()
			recordAuthEvent(name, email, err)
			if err == nil {
				d.a.event("company account of %s confirmed in the session", name)
			}
		}()
	}
	if f != nil {
		st.Running, st.Error = f.running, f.err
		if f.running {
			st.URI, st.Code = f.uri, f.code
		}
	}
	return DesktopResponse{OK: true, SSO: st}
}
