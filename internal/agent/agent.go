// Package agent implements the LiMDM device agent. It receives declarations
// (desired state), converges to them autonomously, also while offline, and
// reports status per declaration plus status items over mTLS.
package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"sync/atomic"
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
	// commandKeyGrace: how long commands signed with the previous command
	// key are still accepted after a rollover (commands expire after 7 days)
	commandKeyGrace = 14 * 24 * time.Hour
)

type Config struct {
	Server       string `json:"server"`
	DeviceID     string `json:"device_id"`
	AllowScripts bool   `json:"allow_scripts"` // remote scripts are opt in per device
	// AllowRemoteShell lets IT open an interactive support shell (opt in per device).
	AllowRemoteShell bool `json:"allow_remote_shell,omitempty"`
	// NoFallbackDNS turns off asking Cloudflare and Google (DNS over HTTPS)
	// when the system resolver cannot reach the server.
	NoFallbackDNS bool `json:"no_fallback_dns,omitempty"`
}

// State survives restarts. Declarations are kept so enforcement continues offline.
type State struct {
	Declarations  []api.Declaration    `json:"declarations"`
	DeclToken     string               `json:"declarations_token"`
	Users         []api.User           `json:"users"`
	LastUpdateRun time.Time            `json:"last_update_run"`
	RebootSince   time.Time            `json:"reboot_since"`
	RebootPlanned time.Time            `json:"reboot_planned"`     // when a post update reboot was scheduled
	RebootAt      time.Time            `json:"reboot_at,omitzero"` // when it happens, deferrals included (guarded by evMu)
	RebootDefers  int                  `json:"reboot_defers,omitempty"`
	ScriptRuns    map[string]time.Time `json:"script_runs,omitempty"` // last run of recurring scripts
	ScriptSums    map[string]string    `json:"script_sums,omitempty"` // body, parameters and timeout of the last run (run_on_change)
	Results       []api.CommandResult  `json:"results"`               // not yet reported
	Events        []string             `json:"events"`

	PendingKeys         []pendingKey              `json:"pending_keys,omitempty"`     // recovery keys not yet escrowed
	Escrowed            map[string]time.Time      `json:"escrowed,omitempty"`         // LUKS UUID: escrowed at
	CommandKey          string                    `json:"command_key,omitempty"`      // pinned public key commands are signed with
	CommandKeyPrev      string                    `json:"command_key_prev,omitempty"` // key before the last rollover, accepted until CommandKeyPrevUntil
	CommandKeyPrevUntil time.Time                 `json:"command_key_prev_until,omitzero"`
	SignedSeq           map[string]int64          `json:"signed_seq,omitempty"` // highest accepted sequence number per signed entry (api.SignedSeq)
	Enrollment          string                    `json:"enrollment,omitempty"` // server and device ID this state belongs to
	EscrowNotified      time.Time                 `json:"escrow_notified"`
	Company             string                    `json:"company,omitempty"`
	BrandingHash        string                    `json:"branding_hash,omitempty"`
	Catalog             *api.Catalog              `json:"catalog,omitempty"`      // software catalog for the desktop app
	AppRequests         []api.AppRequest          `json:"app_requests,omitempty"` // requests not yet sent
	LastContact         time.Time                 `json:"last_contact"`
	DoneCommands        map[int64]time.Time       `json:"done_commands,omitempty"`  // executed command IDs: the server redelivers until it has the result
	RemovePending       map[string]bool           `json:"remove_pending,omitempty"` // removed users whose account lock still has to succeed
	UserLocked          map[string]bool           `json:"user_locked,omitempty"`    // accounts IT locked with user_lock; the SSO rules leave them locked
	UpdateResult        *api.UpdateResult         `json:"update_result,omitempty"`  // agent update outcome not yet reported
	OfflineLocked       bool                      `json:"offline_locked,omitempty"`
	FallbackDNS         bool                      `json:"fallback_dns,omitempty"` // server allows the DNS over HTTPS fallback
	DNFProxy            string                    `json:"dnf_proxy,omitempty"`    // proxy= value LiMDM wrote to dnf.conf (dnf4)
	SUSEProxy           *sysconfigOwned           `json:"suse_proxy,omitempty"`   // keys LiMDM manages in /etc/sysconfig/proxy
	Held                []string                  `json:"held,omitempty"`         // packages LiMDM put on apt hold
	DNFExclude          string                    `json:"dnf_exclude,omitempty"`  // excludepkgs= value LiMDM wrote to dnf.conf
	PacmanIgnore        string                    `json:"pacman_ignore,omitempty"`
	SnapRefresh         string                    `json:"snap_refresh,omitempty"`      // "hold" or "timer=..." LiMDM set in snapd
	ScriptResults       []api.ScriptResult        `json:"script_results,omitempty"`    // recurring script runs not yet reported
	ManagedFiles        []string                  `json:"managed_files,omitempty"`     // paths written for com.limdm.files, removed when undeclared
	ManagedFileSums     map[string]string         `json:"managed_file_sums,omitempty"` // path -> SHA-256 of the content written; removal only when it still matches
	FirewallRules       []fwRule                  `json:"firewall_rules,omitempty"`    // rules LiMDM added
	FirewallEgress      string                    `json:"firewall_egress,omitempty"`   // ufw outgoing default LiMDM set: deny or allow
	LocalUsers          map[string]localUserState `json:"local_users,omitempty"`       // accounts com.limdm.localusers manages
	Hostname            *hostState                `json:"hostname,omitempty"`          // com.limdm.hostname (hostname.go)
	UpdateRuns          map[string]api.UpdateRun  `json:"update_runs,omitempty"`       // last run per update source
	UpdateGate          *api.UpdateGate           `json:"update_gate,omitempty"`       // the device's update ring as the server last sent it
	SecuritySince       time.Time                 `json:"security_since,omitzero"`     // security updates pending since
}

type Agent struct {
	cfg    Config
	client *http.Client
	host   *host
	log    *slog.Logger
	state  State

	pol        api.Policy
	polView    atomic.Pointer[api.Policy] // copy of pol for other goroutines
	desktop    *desktopServer
	evMu       sync.Mutex           // guards state.Events and state.AppRequests: the desktop socket works from its own goroutines
	lastSeen   map[string]time.Time // event text -> last time it was queued (repeats are dropped, see event)
	store      store
	kick       chan struct{}
	declStatus []api.DeclarationStatus
	users      []api.User
	reasons    map[string][]string // declaration type -> why it is not active

	sentStatusHash, sentPkgHash string
	failedUpdate                string    // release version whose update already failed, reported once
	busy                        backoff   // the server asked to come back later (503, 429)
	checkinFailures             int       // failed check ins in a row (checkinWait)
	osqueryTried                time.Time // last osquery install attempt
	syncNow                     bool
	renewNow, renewNetNow       bool // the server asked for new certificates (CA rotation)
	proxySet                    bool // a proxy declaration set the environment of this process
	// for the desktop tray
	lastCheckin  *time.Time
	lastError    string
	lastChecks   []api.CheckResult
	lastFlatpaks []api.FlatpakApp // from the last inventory, for the desktop catalog
	lastSystem   DesktopSystem    // from the last inventory, for limdm info
	shell        atomic.Pointer[runningShell]
}

func validServerURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("server URL must be https://host:port")
	}
	return nil
}

// pinnedTLS trusts only the device CA, never system roots, and presents the
// device identity when enrolled (server set). New trust anchors from the
// server apply through swapTransport.setRoots without a restart.
func pinnedTLS(caPEM []byte, server string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if server != "" {
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			b, err := os.ReadFile(identityFile)
			if err != nil {
				return nil, err
			}
			c, err := loadIdentity(b)
			return &c, err
		}
	}
	return tc, nil
}

// swapTransport sends through the current transport; setRoots replaces it
// with one that trusts a new CA pool (standard verification, no skipping).
type swapTransport struct {
	tc  *tls.Config
	cur atomic.Pointer[http.Transport]
}

func newSwapTransport(tc *tls.Config) *swapTransport {
	st := &swapTransport{tc: tc}
	st.cur.Store(st.transport(tc))
	return st
}

func (st *swapTransport) transport(tc *tls.Config) *http.Transport {
	return &http.Transport{TLSClientConfig: tc, Proxy: agentProxy, ForceAttemptHTTP2: true, DialContext: fallbackDial()}
}

func (st *swapTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return st.cur.Load().RoundTrip(r)
}

func (st *swapTransport) CloseIdleConnections() { st.cur.Load().CloseIdleConnections() }

// setRoots makes new connections verify the server against pool.
func (st *swapTransport) setRoots(pool *x509.CertPool) {
	tc := st.tc.Clone()
	tc.RootCAs = pool
	old := st.cur.Swap(st.transport(tc))
	old.CloseIdleConnections()
}

func newClient(tc *tls.Config) *http.Client {
	return &http.Client{Timeout: 2 * time.Minute, Transport: newSwapTransport(tc)}
}

// newCSR creates a file key (ECDSA P-256) and a CSR for it.
func newCSR() (keyPEM []byte, csrPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	if csrPEM, err = csrFor(key); err != nil {
		return nil, "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), csrPEM, nil
}

func csrFor(key crypto.Signer) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "limdm-device"}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// newIdentity creates the key of a device identity with its CSR: in the
// TPM when a TPM 2.0 is usable (with evidence, the EK only for enrollment),
// else as a file key. keyPEM goes into device.pem in front of the certificate.
func newIdentity(log *slog.Logger, enroll bool) (keyPEM []byte, csrPEM string, ev *api.TPMEvidence, ts *tpmSigner, err error) {
	if hasTPM2() {
		if keyPEM, ts, err = newTPMKey(); err == nil {
			if csrPEM, err = csrFor(ts); err == nil {
				if ev, err = tpmEvidence(ts, enroll); err != nil {
					log.Warn("TPM key without attestation", "err", err)
					ev = nil
				}
				return keyPEM, csrPEM, ev, ts, nil
			}
		}
		log.Warn("TPM unusable, using a file key", "err", err)
	}
	keyPEM, csrPEM, err = newCSR()
	return keyPEM, csrPEM, nil, nil, err
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
func Enroll(server, token, fingerprint string, allowScripts, allowShell bool) error {
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
	tc, err := pinnedTLS(caPEM, "")
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	keyPEM, csr, ev, ts, err := newIdentity(log, true)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	client := newClient(tc)
	er, err := postEnroll(client, server, api.EnrollRequest{Token: token, CSR: csr, Hostname: hostname, MachineID: readTrim("/etc/machine-id"), TPM: ev})
	if err != nil {
		return err
	}
	// second round of a TPM enrollment: prove that the AK and EK share the TPM
	if er.TPMChallenge != nil && ts != nil {
		activated, aerr := activateCredential(ts, er.TPMChallenge)
		if aerr != nil {
			log.Warn("enrolling without TPM attestation", "err", aerr)
			ev = nil
		} else {
			ev.Activated = activated
		}
		if er, err = postEnroll(client, server, api.EnrollRequest{Token: token, CSR: csr, Hostname: hostname, MachineID: readTrim("/etc/machine-id"), TPM: ev}); err != nil {
			return err
		}
	}
	if er.Cert == "" {
		return errors.New("enroll failed: the server sent no certificate")
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
	cfg, _ := json.MarshalIndent(Config{Server: server, DeviceID: er.DeviceID, AllowScripts: allowScripts, AllowRemoteShell: allowShell}, "", "  ")
	if _, err = writeIfChanged(configFile, string(cfg)+"\n", 0o600); err != nil {
		return err
	}
	return forgetServerState()
}

// postEnroll sends one enrollment request.
func postEnroll(c *http.Client, server string, er api.EnrollRequest) (api.EnrollResponse, error) {
	var out api.EnrollResponse
	body, _ := json.Marshal(er)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return out, fmt.Errorf("enroll failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// forgetServerState drops what belonged to the previous enrollment: command
// IDs are per server database, so old ones would mark new commands as done,
// and the pinned key of another server would refuse every command.
func forgetServerState() error {
	b, err := os.ReadFile(stateFile)
	if err != nil {
		return nil // first enrollment
	}
	var st map[string]json.RawMessage
	if json.Unmarshal(b, &st) != nil {
		return os.Remove(stateFile)
	}
	for _, k := range []string{"command_key", "command_key_prev", "command_key_prev_until", "done_commands"} {
		delete(st, k)
	}
	out, _ := json.Marshal(st)
	_, err = writeIfChanged(stateFile, string(out), 0o600)
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
	tc, err := pinnedTLS(caPEM, cfg.Server)
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
	// enrolled again (other server, new device ID): the previous server's
	// command key, command IDs and unsent results do not apply any more.
	// Checked here as well, since a running agent writes its state back
	// after "enroll" cleaned the file.
	if enr := cfg.Server + " " + cfg.DeviceID; a.state.Enrollment != enr {
		if a.state.Enrollment != "" {
			log.Info("new enrollment: forgetting the previous server's command key and command IDs")
			a.state.CommandKey, a.state.CommandKeyPrev, a.state.DoneCommands, a.state.Results = "", "", nil, nil
		}
		a.state.Enrollment = enr
	}
	if a.state.DeclToken == "" { // never synced: start from the built in baseline
		a.state.Declarations = api.DefaultDeclarations()
	}
	fallbackDNS.Store(a.state.FallbackDNS && !cfg.NoFallbackDNS)
	a.compose()
	return a, nil
}

// compose rebuilds the effective policy from the stored declarations.
func (a *Agent) compose() {
	a.pol, a.declStatus = api.Compose(a.state.Declarations)
	a.users = a.state.Users
	p := a.pol
	a.polView.Store(&p) // for maintainLoop, which runs beside the check in
}

// policy is the composed policy for code outside the check in goroutine.
func (a *Agent) policy() *api.Policy {
	if p := a.polView.Load(); p != nil {
		return p
	}
	return &api.Policy{}
}

// problem records an event and marks the declaration of typ as not achieved.
func (a *Agent) problem(typ, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.event("%s", msg)
	if a.reasons != nil {
		a.reasons[typ] = append(a.reasons[typ], msg)
	}
}

// eventRepeat: the same event text is reported once in this window. The
// server gets state changes, not a heartbeat of an unchanged state (a
// remediation failing every cycle, a file rewritten every cycle).
const eventRepeat = 6 * time.Hour

func (a *Agent) event(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.log.Info(msg)
	now := time.Now()
	a.evMu.Lock()
	if a.lastSeen == nil {
		a.lastSeen = map[string]time.Time{}
	}
	last, seen := a.lastSeen[msg]
	repeat := seen && now.Sub(last) < eventRepeat && !strings.HasPrefix(msg, "tamper: ")
	if !repeat {
		a.lastSeen[msg] = now
		if len(a.lastSeen) > 2000 { // bounded: forget the window rather than grow
			clear(a.lastSeen)
		}
	}
	a.evMu.Unlock()
	if repeat {
		return
	}
	a.addEvent(now.UTC().Format(time.RFC3339) + " " + msg)
}

// addEvent queues one line for the next check in (bounded while offline).
func (a *Agent) addEvent(line string) {
	a.evMu.Lock()
	defer a.evMu.Unlock()
	if len(a.state.Events) >= 500 {
		// full while offline: drop the oldest routine line, never a tamper report
		i := slices.IndexFunc(a.state.Events, func(e string) bool { return !strings.Contains(e, " tamper: ") })
		if i < 0 {
			i = 0
		}
		a.state.Events = slices.Delete(a.state.Events, i, i+1)
	}
	a.state.Events = append(a.state.Events, line)
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
	a.store.jobs = map[string]*appJob{}
	go a.serveDesktop(ctx)
	go a.pollLoop(ctx)
	a.enforceOffline(false) // before anything else: the device may have been off for a long time
	for {
		a.cycle(ctx)
		interval := time.Duration(a.pol.CheckinSeconds) * time.Second
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		// jitter spreads the fleet: after a blueprint change every device would
		// otherwise check in at the same moment
		wait := checkinWait(interval, a.checkinFailures)
		if a.syncNow {
			a.syncNow, wait = false, 5*time.Second+time.Duration(mrand.Int64N(int64(55*time.Second))) //nolint:gosec // scheduling jitter
		}
		wait = a.busy.wait(wait)
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
	"disk.recovery": api.TypeDiskEncryption, "disk.tpm": api.TypeDiskEncryption, "boot.password": api.TypeBootloader,
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
		if out[i].Type == api.TypeHostname {
			out[i].Info = a.hostnameNotes()
		}
	}
	return out
}

func (a *Agent) cycle(ctx context.Context) {
	defer a.saveState()
	defer a.publishDesktop()
	a.renewIdentity(ctx)
	a.ensureNetworkCert(ctx)
	a.takeEscrowRequests()
	a.checkUpdateOutcome()
	a.collectTamper()
	a.guardWatchdog()
	checks := a.converge()
	a.lastChecks = checks
	a.collectAuthEvents()

	inv := a.host.inventory(a.pol.Privacy)
	inv.Certificates = certInfo(a.pol.Extra.Certificates)
	inv.WireGuardKeys = wireguardKeys(a.pol.Extra.Network)
	inv.HostnameInfo = a.hostnameInfo(a.pol.Privacy)
	a.applyCatalog(inv.Flatpaks)
	inv.Apps = a.catalogStates(inv.Flatpaks)
	a.lastFlatpaks = inv.Flatpaks
	a.lastSystem = DesktopSystem{OS: strings.TrimSpace(inv.OSName + " " + inv.OSVersion), Kernel: inv.Kernel, Arch: inv.Arch,
		Inventory: inv.Source, Vendor: inv.Vendor, Model: inv.Model, Serial: inv.Serial}
	status := api.Status{Inventory: inv, Checks: checks, Declarations: a.declarationStatus(), CatalogVersion: CatalogVersion, Updates: a.updateStatus()}
	statusHash := statusHashOf(status)
	req := api.CheckinRequest{AgentVersion: Version, Arch: runtime.GOARCH, DeclarationsToken: a.state.DeclToken,
		StatusHash: statusHash, Results: a.state.Results, Events: a.pendingEvents(), Metrics: metrics(), BrandingHash: a.state.BrandingHash,
		UpdateResult: a.state.UpdateResult, ScriptResults: a.state.ScriptResults, CommandKey: a.state.CommandKey}
	if b, err := os.ReadFile(caFile); err == nil {
		sum := sha256.Sum256(b)
		req.CAHash = hex.EncodeToString(sum[:])
	}
	if a.state.Catalog != nil {
		req.CatalogHash = a.state.Catalog.Hash
	}
	a.evMu.Lock()
	req.AppRequests = slices.Clone(a.state.AppRequests)
	a.evMu.Unlock()
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
		a.checkinFailures++
		a.log.Error("checkin failed, enforcing stored declarations", "err", err)
		a.lastError = err.Error()
		a.enforceOffline(false)
		return
	}
	now := time.Now()
	a.checkinFailures = 0
	a.lastCheckin, a.lastError = &now, ""
	a.enforceOffline(true)
	// drop only what was sent: entries added meanwhile (unlock events, desktop) stay
	a.state.Results = a.state.Results[len(req.Results):]
	a.state.ScriptResults = a.state.ScriptResults[len(req.ScriptResults):]
	a.evMu.Lock()
	// by content, not by count: a full queue drops its oldest routine line
	// while the check in runs, so the sent lines are no longer a prefix
	for _, sent := range req.Events {
		if i := slices.Index(a.state.Events, sent); i >= 0 {
			a.state.Events = slices.Delete(a.state.Events, i, i+1)
		}
	}
	a.state.AppRequests = a.state.AppRequests[len(req.AppRequests):]
	a.evMu.Unlock()
	if len(sentKeys) > 0 {
		a.escrowConfirmed(sentKeys)
	}
	if req.UpdateResult != nil {
		a.state.UpdateResult = nil // reported
	}
	// pinned first: what follows is checked against it
	a.pinCommandKey(resp.CommandKey, resp.CommandKeyRollover)
	a.applyBranding(resp.Branding)
	a.state.FallbackDNS = resp.FallbackDNS
	fallbackDNS.Store(resp.FallbackDNS && !a.cfg.NoFallbackDNS)
	if resp.Catalog != nil {
		a.verifyCatalog(resp.SignedData, resp.Catalog)
		a.state.Catalog = resp.Catalog
	}
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
	if users, err := a.verifyUsers(resp); err != nil {
		a.refused("device user list (the previous one stays)", err)
	} else if !slices.Equal(users, a.state.Users) {
		a.state.Users = users
		a.syncNow = true
	}
	a.state.UpdateGate = resp.UpdateGate
	a.compose()
	if resp.DeviceCAs != "" {
		a.updateTrustAnchors(resp.DeviceCAs)
	}
	a.renewNow, a.renewNetNow = a.renewNow || resp.RenewCert, a.renewNetNow || resp.RenewNetworkCert
	a.runCommands(resp.Commands)
	if u := resp.AgentUpdate; u != nil && u.Version != a.failedUpdate {
		var busy busyError
		if err := a.installUpdate(ctx, *u); errors.As(err, &busy) {
			a.busy.note(err) // the server limits parallel downloads: offered again later
			a.log.Info("agent update deferred", "version", u.Version, "err", err)
		} else if err != nil {
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
	a.applyFiles(p.Files)
	for _, s := range p.Services.Enable {
		if !unitActive(s) {
			if err := svc("enable-now", s); err != nil {
				a.problem(api.TypeServices, "enable %s: %v", s, err)
			} else {
				a.event("enabled %s", s)
			}
		}
	}
	for _, s := range p.Services.Disable {
		if unitActive(s) {
			if err := svc("disable-now", s); err != nil {
				a.problem(api.TypeServices, "disable %s: %v", s, err)
			} else {
				a.event("disabled %s", s)
			}
		}
	}
	if p.Firewall.Enforce {
		var err error
		if st, _ := runFirewall(a); st != pass {
			err = a.applyFirewall()
		} else {
			err = a.syncFirewallRules() // active: keep its rules in line with the declaration
		}
		if err != nil {
			a.problem(api.TypeFirewall, "firewall: %v", err)
		}
	}
	if err := a.applyUsers(); err != nil {
		a.problem(api.TypeLogin, "users: %v", err)
	}
	if err := a.applyLocalUsers(p.Extra.LocalUsers); err != nil {
		a.problem(api.TypeLocalUsers, "local users: %v", err)
	}
	if err := a.applyHolds(p.Updates.Hold); err != nil {
		a.problem(api.TypeUpdates, "hold: %v", err)
	}
	if err := a.applySnapRefresh(p.Updates); err != nil {
		a.problem(api.TypeUpdates, "snap refresh: %v", err)
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

func (a *Agent) execute(c api.Command) api.CommandResult {
	r := api.CommandResult{ID: c.ID}
	var out string
	var err error
	switch c.Type {
	case "sync":
		out = "ok"
	case "update":
		out, err = a.host.upgrade(false)
		if fo, ferr := flatpakUpgrade(); ferr != nil {
			out += "\nflatpak: " + ferr.Error()
		} else if fo != "" {
			out += "\n" + lastLines(fo, 10)
		}
		out = cleanUpgradeOutput(out)
		a.state.LastUpdateRun = time.Now().Round(0)
	case "package_hold":
		out, err = a.packageHold(c.Payload)
	case "package_downgrade":
		out, err = a.packageDowngrade(c.Payload)
	case "reboot", "shutdown":
		out, err = a.powerAction(c.Type, c.Payload, c.CreatedAt)
	case "lock":
		a.notifyUsers("Device locked", a.company()+" locked this device. Sessions end and new sign ins are blocked until IT unlocks it.", "critical")
		out, err = a.lockDevice()
		a.syncPasswordLocks()
	case "unlock":
		out, err = a.unlockDevice()
		a.syncPasswordLocks()
	case "lost":
		out, err = a.lostMode(c.Payload, c.Keys)
	case "found":
		out, err = a.foundMode()
	case "wipe":
		out, err = a.wipe()
	case "allow_uninstall":
		out, err = allowUninstall()
	case "message":
		out, err = a.showMessage(c.Payload)
	case "software_remove":
		out, err = a.removeSoftware(c.Payload)
	case "diagnostics":
		r.Diagnostics = a.collectDiagnostics()
		out = fmt.Sprintf("diagnostics collected (%d bytes)", len(r.Diagnostics))
	case "user_create", "user_admin", "user_lock", "user_unlock", "user_password", "user_delete":
		out, err = a.userCommand(c.Type, c.Payload)
	case "app_install", "app_remove":
		out, err = a.appCommand(strings.TrimPrefix(c.Type, "app_"), c.Payload)
	case "shell":
		out, err = a.startShell(c)
	case "script":
		if !a.cfg.AllowScripts {
			err = errors.New("remote scripts are disabled on this device (allow_scripts)")
			break
		}
		var sc api.ScriptCommand
		if sc, err = parseScriptCommand(c.Payload); err != nil {
			break
		}
		var res api.ScriptResult
		res, err = runScript(sc.Body, sc.Params, sc.TimeoutMinutes)
		res.CommandID = c.ID
		r.Script, out = &res, scriptOutput(res)
	default:
		err = fmt.Errorf("unknown command %q", c.Type)
	}
	a.event("command %d (%s) executed, error=%v", c.ID, c.Type, err)
	r.OK = err == nil
	r.Output = lastLines(out, 200)
	if r.Script != nil {
		r.Output = out
	}
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

// scriptInterpreter reads the shebang ("#!/usr/bin/env python3",
// "#!/bin/bash -e"); the file itself is never executed, so a noexec
// /var/lib (CIS hardening) does not matter.
func scriptInterpreter(body string) []string {
	first, _, _ := strings.Cut(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	if f := strings.Fields(strings.TrimPrefix(first, "#!")); strings.HasPrefix(first, "#!") && len(f) > 0 {
		return f
	}
	return []string{"/bin/sh"}
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
		if err := busyOf(path, resp); err != nil {
			a.busy.note(err)
			return err
		}
		return apiError(path, resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// pollLoop asks the server every minute whether commands wait, so a reboot,
// lock or wipe does not wait for the next full check in. It runs on its own
// clock: desktop upkeep runs in maintainLoop and can never delay it. A
// random offset spreads devices; after failures it waits longer (up to 5
// minutes) and returns to one minute with the first answer.
func (a *Agent) pollLoop(ctx context.Context) {
	go a.maintainLoop(ctx)
	wait, failures := pollJitter(), 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		var resp api.PollResponse
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := a.post(pctx, "/api/v1/poll", struct{}{}, &resp)
		cancel()
		if err != nil {
			failures++
			if failures == 3 {
				a.log.Warn("poll failing", "err", err)
			}
		} else {
			failures = 0
		}
		if err == nil && resp.Pending {
			a.kickCheckin() // buffered: a check in already running picks it up next
		}
		wait = a.busy.wait(pollWait(failures))
	}
}

// pollWait is one minute, doubling per failure up to five, plus jitter;
// after failures up to half of the wait, so the fleet does not return in
// the same ten seconds when the server is back.
func pollWait(failures int) time.Duration {
	d := min(time.Minute<<min(failures, 3), 5*time.Minute)
	if failures > 0 {
		d += time.Duration(mrand.Int64N(int64(d / 2))) //nolint:gosec // jitter, not a secret
	}
	return d + pollJitter()
}

func pollJitter() time.Duration { return time.Duration(mrand.Int64N(int64(10 * time.Second))) } //nolint:gosec // jitter, not a secret

// maintainLoop keeps desktop helpers, idle locks and a device lock in place
// every minute, independent of the server.
func (a *Agent) maintainLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.ensureHelpers()     // within a minute of a desktop login
		a.ensureIdleLocks()   // compositors without a locker of their own
		a.enforceDeviceLock() // a locked device stays locked
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
	c, err := loadIdentity(b)
	if err != nil || c.Leaf == nil || (time.Until(c.Leaf.NotAfter) > renewBefore && !a.renewNow) {
		return
	}
	expired := time.Now().After(c.Leaf.NotAfter)
	keyPEM, csr, ev, _, err := newIdentity(a.log, false)
	if err != nil {
		a.log.Error("renew", "err", err)
		return
	}
	var resp api.EnrollResponse
	if err := a.post(ctx, "/api/v1/renew", api.RenewRequest{CSR: csr, TPM: ev}, &resp); err != nil {
		a.event("certificate renewal failed: %v", err)
		if expired {
			// the server accepts expired certificates for renewal only within a grace period
			a.log.Error("client certificate expired and renewal failed; re-enroll with: limdm-agent enroll --server URL --fingerprint FP --token TOKEN",
				"expired", c.Leaf.NotAfter)
		}
		return
	}
	// a broken answer must not replace a working identity
	if nc, err := loadIdentity([]byte(string(keyPEM) + resp.Cert)); err != nil || !samePublicKey(nc) {
		a.event("renewed certificate unusable, keeping the current one: %v", err)
		return
	}
	if _, err := writeIfChanged(identityFile, string(keyPEM)+resp.Cert, 0o600); err != nil {
		a.event("storing renewed certificate failed: %v", err)
		return
	}
	a.client.CloseIdleConnections()
	a.renewNow = false
	a.event("client certificate renewed")
}

// samePublicKey: the certificate belongs to the key next to it. tls.X509KeyPair
// checks that for file keys; a TPM key is only known by its public half.
func samePublicKey(c tls.Certificate) bool {
	s, ok := c.PrivateKey.(crypto.Signer)
	if !ok || c.Leaf == nil {
		return false
	}
	pub, ok := s.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(c.Leaf.PublicKey)
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
// allow_scripts, allow_remote_shell) and removes it afterwards: the token must
// not stay on disk.
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
	if err := Enroll(kv["server"], kv["token"], kv["fingerprint"], kv["allow_scripts"] == "true", kv["allow_remote_shell"] == "true"); err != nil {
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
		if time.Since(at) > 30*24*time.Hour { // created (or run) more than 30 days ago
			delete(a.state.DoneCommands, id)
		}
	}
	for _, c := range cmds {
		if at, done := a.state.DoneCommands[c.ID]; done && (at.Equal(c.CreatedAt) || at.After(c.CreatedAt) && at.Sub(c.CreatedAt) < 8*24*time.Hour) {
			// recorded with its creation time (older states: the run time),
			// so a reused ID after a database restore is a new command
			// ran before, but its result never arrived (for example a reboot "now")
			if !slices.ContainsFunc(a.state.Results, func(r api.CommandResult) bool { return r.ID == c.ID }) {
				a.state.Results = append(a.state.Results, api.CommandResult{ID: c.ID, OK: true, Output: "executed; the device restarted before the result was sent"})
			}
			continue
		}
		// before running: a reboot must not repeat after restart
		a.state.DoneCommands[c.ID] = c.CreatedAt
		if c.CreatedAt.IsZero() {
			a.state.DoneCommands[c.ID] = time.Now()
		}
		a.saveState()
		if err := a.verifyCommand(c); err != nil {
			a.event("command %d (%s) refused: %v", c.ID, c.Type, err)
			a.state.Results = append(a.state.Results, api.CommandResult{ID: c.ID, Output: "not executed: " + err.Error()})
			continue
		}
		a.state.Results = append(a.state.Results, a.execute(c))
		a.syncNow = true
	}
}

// getBytes fetches a small file from the server over mTLS.
func (a *Agent) getBytes(path string, limit int64, out *[]byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
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
		return apiError(path, resp)
	}
	*out, err = io.ReadAll(io.LimitReader(resp.Body, limit))
	return err
}

// pinCommandKey keeps the first command key the server sends (over the
// pinned CA and mTLS). A different key later is adopted only with a
// rollover record signed by the pinned key; the old key stays accepted for
// commandKeyGrace. Any other different key is refused.
func (a *Agent) pinCommandKey(hexKey string, ro *api.KeyRollover) {
	switch {
	case hexKey == "" || hexKey == a.state.CommandKey:
	case a.state.CommandKey == "":
		if b, err := hex.DecodeString(hexKey); err == nil && len(b) == ed25519.PublicKeySize {
			a.state.CommandKey = hexKey
			a.event("command signing key pinned; unsigned commands are refused from now on")
		}
	case ro != nil && ro.Key == hexKey:
		pinned, err := hex.DecodeString(a.state.CommandKey)
		if err == nil {
			err = api.VerifyRollover(ed25519.PublicKey(pinned), *ro)
		}
		if err != nil {
			a.event("refused a command key rollover: %v; keeping the pinned key", err)
			return
		}
		a.state.CommandKeyPrev, a.state.CommandKeyPrevUntil = a.state.CommandKey, time.Now().Add(commandKeyGrace)
		a.state.CommandKey = hexKey
		a.event("command signing key rolled over to the key announced by the pinned one")
	default:
		a.event("the server sent a different command signing key; keeping the pinned one")
	}
}

// verifyCommand checks a command's signature once a key is pinned. Before
// that (servers without signing) commands run as before.
func (a *Agent) verifyCommand(c api.Command) error {
	if a.state.CommandKey == "" {
		return nil
	}
	pub, err := hex.DecodeString(a.state.CommandKey)
	if err != nil {
		return err
	}
	if err := api.VerifyCommand(ed25519.PublicKey(pub), a.cfg.DeviceID, c); err != nil {
		prev, perr := hex.DecodeString(a.state.CommandKeyPrev)
		if a.state.CommandKeyPrev == "" || perr != nil || time.Now().After(a.state.CommandKeyPrevUntil) ||
			api.VerifyCommand(ed25519.PublicKey(prev), a.cfg.DeviceID, c) != nil {
			return err
		}
	}
	// the server expires commands after 7 days: an older one, signed or not,
	// is a replay (a row set back to pending in the database)
	if time.Since(c.CreatedAt) > 8*24*time.Hour {
		return errors.New("command older than 8 days")
	}
	return nil
}

// updateTrustAnchors stores the device CAs the server sent over the pinned
// channel. The new set must share a CA with the current one, so a broken
// answer cannot cut the agent off; ca.crt and the running client change.
func (a *Agent) updateTrustAnchors(bundle string) {
	cur, err := os.ReadFile(caFile)
	if err != nil {
		a.log.Error("trust anchors", "err", err)
		return
	}
	certs, err := parseCAs([]byte(bundle))
	if err != nil {
		a.event("refused new device CAs from the server: %v", err)
		return
	}
	old, _ := parseCAs(cur)
	if !slices.ContainsFunc(certs, func(c *x509.Certificate) bool {
		return slices.ContainsFunc(old, func(o *x509.Certificate) bool { return o.Equal(c) })
	}) {
		a.event("refused new device CAs from the server: none of them is trusted now")
		return
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	if _, err := writeIfChanged(caFile, bundle, 0o644); err != nil {
		a.event("storing the device CAs failed: %v", err)
		return
	}
	if st, ok := a.client.Transport.(*swapTransport); ok {
		st.setRoots(pool)
	}
	a.event("trusted device CAs updated (%d)", len(certs))
}

// parseCAs reads PEM CA certificates; every block must be one.
func parseCAs(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || blk.Type != "CERTIFICATE" || !c.IsCA {
			return nil, errors.New("not a CA certificate")
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate")
	}
	return out, nil
}

// apiError reads the server's RFC 9457 problem details, if any.
func apiError(path string, resp *http.Response) error {
	var p struct {
		Detail string `json:"detail"`
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") &&
		json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&p) == nil && p.Detail != "" {
		return fmt.Errorf("%s: %s: %s", path, resp.Status, p.Detail)
	}
	return fmt.Errorf("%s: %s", path, resp.Status)
}
