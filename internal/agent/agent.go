// Package agent implements the LiMDM device agent. It receives declarations
// (desired state), converges to them autonomously, also while offline, and
// reports status per declaration plus status items over mTLS.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Set at build time: -ldflags "-X github.com/maltekiefer/limdm/internal/agent.Version=1.0.0 -X github.com/maltekiefer/limdm/internal/agent.UpdatePubKey=<hex>"
var (
	Version      = "0.0.0-dev"
	UpdatePubKey = ""
)

const (
	configDir    = "/etc/limdm"
	configFile   = configDir + "/agent.json"
	identityFile = configDir + "/device.pem" // private key + client certificate, one file for atomic rotation
	caFile       = configDir + "/ca.crt"     // pinned device CA, the only trust anchor
	stateDir     = "/var/lib/limdm"
	stateFile    = stateDir + "/state.json"
	renewBefore  = 30 * 24 * time.Hour
)

type Config struct {
	Server       string `json:"server"`
	DeviceID     string `json:"device_id"`
	AllowScripts bool   `json:"allow_scripts"` // remote scripts are opt in per device
}

// State survives restarts. Declarations are kept so enforcement continues offline.
type State struct {
	Declarations  []api.Declaration    `json:"declarations"`
	DeclToken     string               `json:"declarations_token"`
	Users         []api.User           `json:"users"`
	LastUpdateRun time.Time            `json:"last_update_run"`
	RebootSince   time.Time            `json:"reboot_since"`
	RebootPlanned time.Time            `json:"reboot_planned"`        // when a post update reboot was scheduled
	ScriptRuns    map[string]time.Time `json:"script_runs,omitempty"` // last run of recurring scripts
	Results       []api.CommandResult  `json:"results"`               // not yet reported
	Events        []string             `json:"events"`

	PendingKeys    []pendingKey         `json:"pending_keys,omitempty"` // recovery keys not yet escrowed
	Escrowed       map[string]time.Time `json:"escrowed,omitempty"`     // LUKS UUID: escrowed at
	EscrowNotified time.Time            `json:"escrow_notified"`
	Company        string               `json:"company,omitempty"`
	BrandingHash   string               `json:"branding_hash,omitempty"`
	LastContact    time.Time            `json:"last_contact"`
	DoneCommands   map[int64]time.Time  `json:"done_commands,omitempty"`  // executed command IDs: the server redelivers until it has the result
	RemovePending  map[string]bool      `json:"remove_pending,omitempty"` // removed users whose account lock still has to succeed
	UpdateResult   *api.UpdateResult    `json:"update_result,omitempty"`  // agent update outcome not yet reported
	OfflineLocked  bool                 `json:"offline_locked,omitempty"`
}

type Agent struct {
	cfg    Config
	client *http.Client
	host   *host
	log    *slog.Logger
	state  State

	pol        api.Policy
	desktop    *desktopServer
	evMu       sync.Mutex // guards state.Events: the desktop socket logs from its own goroutines
	kick       chan struct{}
	declStatus []api.DeclarationStatus
	users      []api.User
	reasons    map[string][]string // declaration type -> why it is not active

	sentStatusHash, sentPkgHash string
	failedUpdate                string    // release version whose update already failed, reported once
	osqueryTried                time.Time // last osquery install attempt
	syncNow                     bool
	// for the desktop tray
	lastCheckin *time.Time
	lastError   string
	lastChecks  []api.CheckResult
}

func validServerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("server URL must be https://host:port")
	}
	return nil
}

// pinnedTLS trusts only the device CA, never system roots, and presents the
// device identity when one exists.
func pinnedTLS(caPEM []byte, withIdentity bool) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if withIdentity {
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			b, err := os.ReadFile(identityFile)
			if err != nil {
				return nil, err
			}
			c, err := tls.X509KeyPair(b, b)
			return &c, err
		}
	}
	return tc, nil
}

func newClient(tc *tls.Config) *http.Client {
	return &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}}
}

func newCSR() (keyPEM []byte, csrPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "limdm-device"}}, key)
	if err != nil {
		return nil, "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// fetchPinnedCA downloads the CA and accepts it only if its SHA-256 matches
// the fingerprint shown in the admin UI. The insecure connection is used for
// this single request; the fingerprint is what authenticates the server.
func fetchPinnedCA(server, fingerprint string) ([]byte, error) {
	want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	c := newClient(verifyByFingerprint(want))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/api/v1/ca", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("server sent no CA certificate")
	}
	sum := sha256.Sum256(blk.Bytes)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("CA fingerprint mismatch: got %x, refusing to enroll", sum)
	}
	return b, nil
}

// verifyByFingerprint replaces the system trust store for the very first
// connection: the handshake only succeeds if the server presents a CA
// certificate with the pinned SHA-256 fingerprint and a server certificate that
// chains to it for the requested host. Nothing is read from an unauthenticated peer.
func verifyByFingerprint(fingerprint string) *tls.Config {
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	// Standard verification would consult system roots, which must not be trusted here;
	// VerifyConnection below performs the full chain verification against the pinned CA.
	tc.InsecureSkipVerify = true
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("server sent no certificate")
		}
		roots := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			sum := sha256.Sum256(c.Raw)
			if c.IsCA && hex.EncodeToString(sum[:]) == fingerprint {
				roots.AddCert(c)
			}
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: roots, DNSName: cs.ServerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("server certificate does not chain to the pinned CA %s: %w", fingerprint, err)
		}
		return nil
	}
	return tc
}

// Enroll registers the device: the key is created locally and never leaves
// the device, the server signs a CSR after checking the one time token.
func Enroll(server, token, fingerprint string, allowScripts bool) error {
	server = strings.TrimRight(server, "/")
	if err := validServerURL(server); err != nil {
		return err
	}
	if fingerprint == "" {
		return errors.New("--fingerprint is required (shown on the enrollment page)")
	}
	caPEM, err := fetchPinnedCA(server, fingerprint)
	if err != nil {
		return err
	}
	tc, err := pinnedTLS(caPEM, false)
	if err != nil {
		return err
	}
	keyPEM, csr, err := newCSR()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(api.EnrollRequest{Token: token, CSR: csr, Hostname: hostname, MachineID: readTrim("/etc/machine-id")})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := newClient(tc).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("enroll failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var er api.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}
	if _, err := writeIfChanged(caFile, string(caPEM), 0o644); err != nil {
		return err
	}
	if _, err := writeIfChanged(identityFile, string(keyPEM)+er.Cert, 0o600); err != nil {
		return err
	}
	cfg, _ := json.MarshalIndent(Config{Server: server, DeviceID: er.DeviceID, AllowScripts: allowScripts}, "", "  ")
	_, err = writeIfChanged(configFile, string(cfg)+"\n", 0o600)
	return err
}

func New(log *slog.Logger) (*Agent, error) {
	var cfg Config
	b, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("not enrolled (%w); run: limdm-agent enroll --server URL --fingerprint FP --token TOKEN", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if err := validServerURL(cfg.Server); err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	tc, err := pinnedTLS(caPEM, true)
	if err != nil {
		return nil, err
	}
	h, err := detectHost()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, client: newClient(tc), host: h, log: log}
	if b, err := os.ReadFile(stateFile); err == nil {
		if err := json.Unmarshal(b, &a.state); err != nil {
			log.Warn("state file unreadable, starting from defaults", "err", err)
			a.state = State{}
		}
	}
	if a.state.DeclToken == "" { // never synced: start from the built in baseline
		a.state.Declarations = api.DefaultDeclarations()
	}
	a.compose()
	return a, nil
}

// compose rebuilds the effective policy from the stored declarations.
func (a *Agent) compose() {
	a.pol, a.declStatus = api.Compose(a.state.Declarations)
	a.users = a.state.Users
}

// problem records an event and marks the declaration of typ as not achieved.
func (a *Agent) problem(typ, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.event("%s", msg)
	if a.reasons != nil {
		a.reasons[typ] = append(a.reasons[typ], msg)
	}
}

func (a *Agent) event(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.log.Info(msg)
	a.addEvent(time.Now().UTC().Format(time.RFC3339) + " " + msg)
}

// addEvent queues one line for the next check in (bounded while offline).
func (a *Agent) addEvent(line string) {
	a.evMu.Lock()
	defer a.evMu.Unlock()
	if len(a.state.Events) < 500 {
		a.state.Events = append(a.state.Events, line)
	}
}

// pendingEvents copies the queued events.
func (a *Agent) pendingEvents() []string {
	a.evMu.Lock()
	defer a.evMu.Unlock()
	return slices.Clone(a.state.Events)
}

func (a *Agent) saveState() {
	if err := a.saveStateErr(); err != nil {
		a.log.Error("save state", "err", err)
	}
}

func (a *Agent) saveStateErr() error {
	a.evMu.Lock()
	b, err := json.Marshal(a.state)
	a.evMu.Unlock()
	if err != nil {
		return err
	}
	_, err = writeIfChanged(stateFile, string(b), 0o600)
	return err
}

// Run loops until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent started", "version", Version, "server", a.cfg.Server, "device", a.cfg.DeviceID, "os", a.host.Name)
	wake := make(chan os.Signal, 1)
	signal.Notify(wake, syscall.SIGUSR1) // "recovery-key" asks for an immediate check in
	defer signal.Stop(wake)
	a.kick = make(chan struct{}, 1)
	a.desktop = &desktopServer{a: a, queued: map[string]bool{}, inflight: map[string]bool{}, failures: map[uint32][]time.Time{}}
	go a.serveDesktop(ctx)
	go a.pollLoop(ctx)
	a.enforceOffline(false) // before anything else: the device may have been off for a long time
	for {
		a.cycle(ctx)
		wait := time.Duration(a.pol.CheckinSeconds) * time.Second
		if wait <= 0 {
			wait = 5 * time.Minute
		}
		// jitter spreads the fleet: after a blueprint change every device would
		// otherwise check in at the same moment
		wait += time.Duration(mrand.Int64N(int64(wait/10) + 1)) //nolint:gosec // scheduling jitter, not a secret
		if a.syncNow {
			a.syncNow, wait = false, 5*time.Second+time.Duration(mrand.Int64N(int64(55*time.Second))) //nolint:gosec // scheduling jitter
		}
		select {
		case <-ctx.Done():
			a.saveState()
			return nil
		case <-time.After(wait):
		case <-wake:
		case <-a.kick:
		}
	}
}

// checkToDecl links compliance checks to the declaration whose goal they verify.
var checkToDecl = map[string]string{
	"disk.recovery": api.TypeDiskEncryption, "boot.password": api.TypeBootloader,
	"desktop.screenlock": api.TypeScreenLock, "firewall.active": api.TypeFirewall, "os.supported": api.TypeOSVersion,
	"updates.auto": api.TypeUpdates, "updates.security": api.TypeUpdates, "updates.reboot": api.TypeUpdates, "auth.sso": api.TypeLogin,
	"agent.osquery": api.TypeAgent,
}

// converge enforces every declaration and verifies the result.
func (a *Agent) converge() []api.CheckResult {
	a.reasons = map[string][]string{}
	a.enforce()
	checks := a.evaluate()
	for _, c := range checks {
		if c.Status != fail {
			continue
		}
		typ, ok := checkToDecl[c.ID]
		if !ok {
			typ = api.TypeCompliance
		}
		a.reasons[typ] = append(a.reasons[typ], c.ID+": "+c.Detail)
	}
	return checks
}

func (a *Agent) declarationStatus() []api.DeclarationStatus {
	out := slices.Clone(a.declStatus)
	for i := range out {
		if r := a.reasons[out[i].Type]; out[i].Valid && len(r) > 0 {
			out[i].Active, out[i].Reasons = false, r
		}
	}
	return out
}

func (a *Agent) cycle(ctx context.Context) {
	defer a.saveState()
	defer a.publishDesktop()
	a.renewIdentity(ctx)
	a.takeEscrowRequests()
	a.checkUpdateOutcome()
	a.collectTamper()
	a.guardWatchdog()
	checks := a.converge()
	a.lastChecks = checks
	a.collectAuthEvents()

	status := api.Status{Inventory: a.host.inventory(a.pol.Privacy), Checks: checks, Declarations: a.declarationStatus()}
	sb, _ := json.Marshal(status)
	sum := sha256.Sum256(sb)
	statusHash := hex.EncodeToString(sum[:])
	req := api.CheckinRequest{AgentVersion: Version, Arch: runtime.GOARCH, DeclarationsToken: a.state.DeclToken,
		StatusHash: statusHash, Results: a.state.Results, Events: a.pendingEvents(), Metrics: metrics(), BrandingHash: a.state.BrandingHash,
		UpdateResult: a.state.UpdateResult}
	// an invalid key would make the server reject every check in
	a.state.PendingKeys = slices.DeleteFunc(a.state.PendingKeys, func(k pendingKey) bool { return !k.Valid() })
	sentKeys := slices.Clone(a.state.PendingKeys)
	for _, k := range sentKeys {
		req.RecoveryKeys = append(req.RecoveryKeys, k.RecoveryKey)
	}
	if statusHash != a.sentStatusHash {
		req.Status = &status
	}
	pkgs, pkgHash, err := a.host.installedPackages()
	if err != nil {
		a.log.Error("packages", "err", err)
	}
	req.PackagesHash = pkgHash
	if pkgHash != a.sentPkgHash {
		req.Packages = pkgs
	}

	var resp api.CheckinResponse
	if err := a.post(ctx, "/api/v1/checkin", req, &resp); err != nil {
		a.log.Error("checkin failed, enforcing stored declarations", "err", err)
		a.lastError = err.Error()
		a.enforceOffline(false)
		return
	}
	now := time.Now()
	a.lastCheckin, a.lastError = &now, ""
	a.enforceOffline(true)
	// drop only what was sent: entries added meanwhile (unlock events, desktop) stay
	a.state.Results = a.state.Results[len(req.Results):]
	a.evMu.Lock()
	a.state.Events = a.state.Events[len(req.Events):]
	a.evMu.Unlock()
	if len(sentKeys) > 0 {
		a.escrowConfirmed(sentKeys)
	}
	if req.UpdateResult != nil {
		a.state.UpdateResult = nil // reported
	}
	a.applyBranding(resp.Branding)
	if len(resp.RecoveryRotate) > 0 {
		a.rotateRecovery(resp.RecoveryRotate)
	}
	if req.Status != nil {
		a.sentStatusHash = statusHash
	}
	if req.Packages != nil {
		a.sentPkgHash = pkgHash
	}
	if resp.NeedStatus {
		a.sentStatusHash, a.syncNow = "", true
	}
	if resp.NeedPackages {
		a.sentPkgHash = ""
	}
	// The server omits unchanged declarations; a new token with none means "nothing declared".
	if resp.DeclarationsToken != "" && resp.DeclarationsToken != a.state.DeclToken {
		a.state.Declarations, a.state.DeclToken = resp.Declarations, resp.DeclarationsToken
		a.event("declarations updated (token %s)", resp.DeclarationsToken)
		a.syncNow = true // converge and report right away
	}
	if !slices.Equal(resp.Users, a.state.Users) {
		a.state.Users = resp.Users
		a.syncNow = true
	}
	a.compose()
	a.runCommands(resp.Commands)
	if u := resp.AgentUpdate; u != nil && u.Version != a.failedUpdate {
		if err := a.installUpdate(ctx, *u); err != nil {
			a.failedUpdate = u.Version
			a.state.UpdateResult = &api.UpdateResult{From: Version, To: u.Version, Detail: err.Error()}
			a.event("agent update to %s failed: %v", u.Version, err)
		}
	}
}

// enforce applies the declarations that are not covered by compliance checks.
func (a *Agent) enforce() {
	p := a.pol
	var missing []string
	for _, n := range p.Packages.Install {
		if !a.host.isInstalled(n) {
			missing = append(missing, n)
		}
	}
	if err := a.host.install(missing...); err != nil {
		a.problem(api.TypePackages, "install %v failed: %v", missing, err)
	} else if len(missing) > 0 {
		a.event("installed %v", missing)
	}
	var present []string
	for _, n := range p.Packages.Remove {
		if a.host.isInstalled(n) {
			present = append(present, n)
		}
	}
	if err := a.host.remove(present...); err != nil {
		a.problem(api.TypePackages, "remove %v failed: %v", present, err)
	} else if len(present) > 0 {
		a.event("removed %v", present)
	}
	for _, f := range p.Files {
		mode, _ := f.FileMode()
		if changed, err := writeIfChanged(f.Path, f.Content, os.FileMode(mode)); err != nil {
			a.problem(api.TypeFiles, "file %s: %v", f.Path, err)
		} else if changed {
			a.event("wrote %s", f.Path)
		}
	}
	for _, s := range p.Services.Enable {
		if !unitActive(s) {
			if _, err := sh("systemctl", "enable", "--now", s); err != nil {
				a.problem(api.TypeServices, "enable %s: %v", s, err)
			} else {
				a.event("enabled %s", s)
			}
		}
	}
	for _, s := range p.Services.Disable {
		if unitActive(s) {
			if _, err := sh("systemctl", "disable", "--now", s); err != nil {
				a.problem(api.TypeServices, "disable %s: %v", s, err)
			} else {
				a.event("disabled %s", s)
			}
		}
	}
	if p.Firewall.Enforce {
		if st, _ := runFirewall(a); st != pass {
			if err := a.applyFirewall(); err != nil {
				a.problem(api.TypeFirewall, "firewall: %v", err)
			}
		}
	}
	if err := a.applyUsers(); err != nil {
		a.problem(api.TypeLogin, "users: %v", err)
	}
	a.applyExtra()
	// osquery is mandatory as inventory source; retry hourly, not every cycle
	if !hasOsquery() && time.Since(a.osqueryTried) > time.Hour {
		a.osqueryTried = time.Now()
		if err := a.host.ensureOsquery(); err != nil {
			a.problem(api.TypeAgent, "osquery install: %v", err)
		} else {
			a.event("installed osquery %s", osqueryVersion())
		}
	}
	a.maintenance(time.Now())
}

// inWindow reports whether now falls into "HH:MM-HH:MM" (may wrap midnight).
func inWindow(now time.Time, window string) bool {
	from, to, ok := strings.Cut(window, "-")
	if !ok {
		return false
	}
	parse := func(s string) int {
		t, err := time.Parse("15:04", s)
		if err != nil {
			return -1
		}
		return t.Hour()*60 + t.Minute()
	}
	f, t, m := parse(from), parse(to), now.Hour()*60+now.Minute()
	if f < 0 || t < 0 {
		return false
	}
	if f <= t {
		return m >= f && m < t
	}
	return m >= f || m < t
}

// maintenance installs updates once per window and reboots if declared.
func (a *Agent) maintenance(now time.Time) {
	u := a.pol.Updates
	if u.Mode == "" || u.Mode == "off" || !inWindow(now, u.Window) {
		return
	}
	if now.Sub(a.state.LastUpdateRun) > 20*time.Hour {
		out, err := a.host.upgrade(u.Mode == "security")
		a.state.LastUpdateRun = now
		if err != nil {
			a.problem(api.TypeUpdates, "updates (%s) failed: %v", u.Mode, err)
		} else {
			a.event("updates (%s) installed: %s", u.Mode, lastLines(out, 3))
		}
	}
	// Schedule once: a new shutdown call would replace and postpone the pending one.
	if u.Reboot && now.Sub(a.state.RebootPlanned) > time.Hour && a.host.rebootRequired() {
		if _, err := sh("shutdown", "-r", "+5", "LiMDM: rebooting in 5 minutes to finish updates"); err == nil {
			a.state.RebootPlanned = now
			a.event("reboot scheduled after updates")
		}
	}
}

func (a *Agent) execute(c api.Command) api.CommandResult {
	r := api.CommandResult{ID: c.ID}
	var out string
	var err error
	switch c.Type {
	case "sync":
		out = "ok"
	case "update":
		out, err = a.host.upgrade(false)
		a.state.LastUpdateRun = time.Now()
	case "reboot", "shutdown":
		out, err = a.powerAction(c.Type, c.Payload, c.CreatedAt)
	case "lock":
		a.notifyUsers("Device locked", a.company()+" locked this device. Sessions end and new sign ins are blocked until IT unlocks it.", "critical")
		out, err = lockDevice()
		a.syncPasswordLocks()
	case "unlock":
		out, err = unlockDevice()
		a.syncPasswordLocks()
	case "lost":
		out, err = a.lostMode(c.Payload)
	case "found":
		out, err = a.foundMode()
	case "wipe":
		out, err = a.wipe()
	case "allow_uninstall":
		out, err = allowUninstall()
	case "message":
		out, err = a.showMessage(c.Payload)
	case "script":
		if !a.cfg.AllowScripts {
			err = errors.New("remote scripts are disabled on this device (allow_scripts)")
			break
		}
		out, err = runScript(c.Payload)
	default:
		err = fmt.Errorf("unknown command %q", c.Type)
	}
	a.event("command %d (%s) executed, error=%v", c.ID, c.Type, err)
	r.OK = err == nil
	r.Output = lastLines(out, 200)
	if err != nil {
		r.Output += "\n" + err.Error()
	}
	return r
}

// nologinFile makes pam_nologin refuse every login except root's.
const (
	nologinFile = "/etc/nologin"
	nologinText = "This device is locked by IT (LiMDM). Contact your administrator.\n"
)

// lockDevice blocks new logins and locks running desktop sessions. The agent
// keeps checking in, so the device can be unlocked remotely.
func lockDevice() (string, error) {
	if _, err := writeIfChanged(nologinFile, nologinText, 0o644); err != nil {
		return "", err
	}
	out, _ := sh("loginctl", "lock-sessions") // no sessions on servers is fine
	return "logins blocked, sessions locked " + out, nil
}

func unlockDevice() (string, error) {
	if readFile(nologinFile) != nologinText {
		return "not locked by LiMDM, nothing changed", nil
	}
	if err := os.Remove(nologinFile); err != nil {
		return "", err
	}
	return "logins allowed again", nil
}

func runScript(body string) (string, error) {
	f, err := os.CreateTemp(stateDir, "script-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return run(30*time.Minute, "/bin/sh", f.Name())
}

// collectAuthEvents ships desktop login events written by pam-auth.
func (a *Agent) collectAuthEvents() {
	// Rename first: pam-auth appends to a fresh file meanwhile, nothing is lost.
	sending := authEvents + ".sending"
	if err := os.Rename(authEvents, sending); err != nil && !os.IsNotExist(err) {
		a.log.Error("rotate auth events", "err", err)
	}
	b, err := os.ReadFile(sending)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			a.addEvent(line)
		}
	}
	if err := os.Remove(sending); err != nil {
		a.log.Error("remove auth events", "err", err)
	}
}

func (a *Agent) post(ctx context.Context, path string, in, out any) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// pollLoop asks the server every minute whether commands wait, so a reboot,
// lock or wipe does not wait for the next full check in.
func (a *Agent) pollLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.ensureHelpers() // within a minute of a desktop login
		var resp api.PollResponse
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := a.post(pctx, "/api/v1/poll", struct{}{}, &resp)
		cancel()
		if err == nil && resp.Pending {
			select {
			case a.kick <- struct{}{}:
			default:
			}
		}
	}
}

// renewIdentity rotates key and certificate 30 days before expiry. Key and
// certificate live in one file, so the swap is a single atomic rename.
func (a *Agent) renewIdentity(ctx context.Context) {
	b, err := os.ReadFile(identityFile)
	if err != nil {
		a.log.Error("identity", "err", err)
		return
	}
	c, err := tls.X509KeyPair(b, b)
	if err != nil || c.Leaf == nil || time.Until(c.Leaf.NotAfter) > renewBefore {
		return
	}
	expired := time.Now().After(c.Leaf.NotAfter)
	keyPEM, csr, err := newCSR()
	if err != nil {
		a.log.Error("renew", "err", err)
		return
	}
	var resp api.EnrollResponse
	if err := a.post(ctx, "/api/v1/renew", api.RenewRequest{CSR: csr}, &resp); err != nil {
		a.event("certificate renewal failed: %v", err)
		if expired {
			// the server accepts expired certificates for renewal only within a grace period
			a.log.Error("client certificate expired and renewal failed; re-enroll with: limdm-agent enroll --server URL --fingerprint FP --token TOKEN",
				"expired", c.Leaf.NotAfter)
		}
		return
	}
	if _, err := writeIfChanged(identityFile, string(keyPEM)+resp.Cert, 0o600); err != nil {
		a.event("storing renewed certificate failed: %v", err)
		return
	}
	a.client.CloseIdleConnections()
	a.event("client certificate renewed")
}

// Report runs all checks locally without remediation and without contacting the server.
func Report(w io.Writer, level int) error {
	h, err := detectHost()
	if err != nil {
		return err
	}
	a := &Agent{host: h, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if b, err := os.ReadFile(stateFile); err == nil {
		if err := json.Unmarshal(b, &a.state); err != nil {
			return fmt.Errorf("state file: %w", err)
		}
	}
	if a.state.DeclToken == "" {
		a.state.Declarations = api.DefaultDeclarations()
	}
	a.compose()
	a.pol.Compliance.Remediate = false
	if level > 0 {
		a.pol.Compliance.Level = level
	}
	for _, r := range a.evaluate() {
		fmt.Fprintf(w, "%-9s L%d %-26s %s  %s\n", strings.ToUpper(r.Status), r.Level, r.ID, r.Title, r.Detail)
	}
	return nil
}

// EnrollConfig is the file mass deployments drop before installing the package.
const EnrollConfig = configDir + "/enroll.conf"

// Enrolled reports whether the device has an identity.
func Enrolled() bool {
	_, err := os.Stat(identityFile)
	return err == nil
}

// EnrollFromConfig enrolls with a key = value file (server, fingerprint, token,
// allow_scripts) and removes it afterwards: the token must not stay on disk.
func EnrollFromConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s: invalid line %q", path, line)
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	for _, k := range []string{"server", "fingerprint", "token"} {
		if kv[k] == "" {
			return fmt.Errorf("%s: %s is missing", path, k)
		}
	}
	if err := Enroll(kv["server"], kv["token"], kv["fingerprint"], kv["allow_scripts"] == "true"); err != nil {
		return err
	}
	return os.Remove(path)
}

// powerDelay is the remaining delay in minutes: the admin's delay counts from
// when the command was sent, not from the check in that delivered it. A
// requested delay keeps at least one minute so users get the warning.
func powerDelay(m int, sent, now time.Time) int {
	if m == 0 || sent.IsZero() {
		return m
	}
	left := int(math.Round((time.Duration(m)*time.Minute - now.Sub(sent)).Minutes()))
	return max(left, 1)
}

// powerAction reboots or shuts down after payload minutes (0 = now, empty = 1 for
// commands queued by older servers) and tells logged in users when.
func (a *Agent) powerAction(typ, payload string, sent time.Time) (string, error) {
	m := 1
	if payload != "" {
		var err error
		if m, err = strconv.Atoi(payload); err != nil || m < 0 || m > 1440 {
			return "", errors.New("delay must be 0..1440 minutes")
		}
	}
	m = powerDelay(m, sent, time.Now())
	flag, word, title := "-r", "reboot", "Restart scheduled"
	if typ == "shutdown" {
		flag, word, title = "-h", "shutdown", "Shutdown scheduled"
	}
	when, text := "now", "LiMDM: "+word+" requested by administrator now"
	at := time.Now()
	if m > 0 {
		at = at.Add(time.Duration(m) * time.Minute)
		when, text = "+"+strconv.Itoa(m), fmt.Sprintf("LiMDM: %s requested by administrator in %d minutes", word, m)
	}
	a.notifyUsers(title, fmt.Sprintf("%s requested a %s at %s. Save your work.", a.company(), word, at.Format("15:04")), "critical")
	return sh("shutdown", flag, when, text)
}

// runCommands executes each command once. The server repeats commands until it
// received their result, so IDs already executed are skipped.
func (a *Agent) runCommands(cmds []api.Command) {
	if a.state.DoneCommands == nil {
		a.state.DoneCommands = map[int64]time.Time{}
	}
	for id, at := range a.state.DoneCommands {
		if time.Since(at) > 30*24*time.Hour {
			delete(a.state.DoneCommands, id)
		}
	}
	for _, c := range cmds {
		if _, done := a.state.DoneCommands[c.ID]; done {
			// ran before, but its result never arrived (for example a reboot "now")
			if !slices.ContainsFunc(a.state.Results, func(r api.CommandResult) bool { return r.ID == c.ID }) {
				a.state.Results = append(a.state.Results, api.CommandResult{ID: c.ID, OK: true, Output: "executed; the device restarted before the result was sent"})
			}
			continue
		}
		a.state.DoneCommands[c.ID] = time.Now() // before running: a reboot must not repeat after restart
		a.saveState()
		a.state.Results = append(a.state.Results, a.execute(c))
		a.syncNow = true
	}
}
