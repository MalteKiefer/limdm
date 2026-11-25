// Package api holds the wire protocol shared by server and agent.
//
// The model follows Apple's Declarative Device Management: the server publishes
// declarations (desired state), grouped in blueprints. The agent converges to
// them autonomously, also while offline, and reports status per declaration
// plus status items. Imperative commands exist only for one off actions.
package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---- declarations ----

// Declaration is one piece of desired state. ServerToken changes whenever the
// payload changes, so agent and server can detect drift cheaply.
type Declaration struct {
	Identifier  string          `json:"identifier"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	ServerToken string          `json:"server_token,omitempty"`
}

const (
	TypeAgent      = "com.limdm.agent"
	TypeCompliance = "com.limdm.compliance"
	TypeUpdates    = "com.limdm.updates"
	TypePackages   = "com.limdm.packages"
	TypeServices   = "com.limdm.services"
	TypeFiles      = "com.limdm.files"
	TypeFirewall   = "com.limdm.firewall"
	TypeOSVersion  = "com.limdm.osversion"
	TypeScreenLock = "com.limdm.screenlock"
	TypeLogin      = "com.limdm.login"
	TypePrivacy    = "com.limdm.privacy"
)

// Types lists every declaration type with a short description for the UI.
var Types = map[string]string{
	TypeAgent:      `{"checkin_seconds": 300}`,
	TypeCompliance: `{"level": 1, "remediate": true, "exclude": [], "advisory": ["boot.secureboot"], "grace_hours": 72, "notify": true, "lock_after_hours": 0, "unlock_when_compliant": true}`,
	TypeUpdates:    `{"mode": "security", "window": "02:00-05:00", "reboot": false}`,
	TypePackages:   `{"install": [], "remove": []}`,
	TypeServices:   `{"enable": [], "disable": []}`,
	TypeFiles:      `{"files": [{"path": "/etc/motd", "content": "...", "mode": "0644"}]}`,
	TypeFirewall:   `{"enforce": true, "allow": ["22/tcp"]}`,
	TypeOSVersion:  `{"min": {"ubuntu": "22.04", "debian": "12", "fedora": "41"}}`,
	TypeScreenLock: `{"idle_seconds": 300}`,
	TypeLogin:      `{"issuer": "https://accounts.google.com", "client_id": "", "client_secret": "", "allowed_domain": ""}`,
	TypePrivacy:    `{"network_info": false, "logged_in_users": false}`,
}

// Policy is the effective state the agent enforces, composed from declarations.
// A zero section means "not managed".
type Policy struct {
	CheckinSeconds    int               `json:"checkin_seconds"`
	Compliance        Compliance        `json:"compliance"`
	Updates           Updates           `json:"updates"`
	Packages          Packages          `json:"packages"`
	Services          Services          `json:"services"`
	Files             []File            `json:"files"`
	Firewall          Firewall          `json:"firewall"`
	MinOSVersion      map[string]string `json:"min_os_version"`
	ScreenLockSeconds int               `json:"screen_lock_seconds"`
	Login             Login             `json:"login"`
	Privacy           Privacy           `json:"privacy"`
	Extra             ExtraPolicy       `json:"extra"`
}

type agentPayload struct {
	CheckinSeconds int `json:"checkin_seconds"`
}

type Compliance struct {
	Level     int      `json:"level"`              // 1 = CIS Level 1 baseline, 2 = Level 2 strict
	Remediate bool     `json:"remediate"`          // agent fixes failing checks that have an automatic fix
	Exclude   []string `json:"exclude"`            // check IDs accepted as risk (documented exception)
	Advisory  []string `json:"advisory,omitempty"` // reported, but not counted against compliance
	// Evaluated by the server:
	GraceHours          int  `json:"grace_hours,omitempty"`      // time to fix before the device counts as non-compliant
	Notify              bool `json:"notify,omitempty"`           // call the compliance webhook when the grace period ends
	LockAfterHours      int  `json:"lock_after_hours,omitempty"` // lock the device after this long non-compliant (0 = never)
	UnlockWhenCompliant bool `json:"unlock_when_compliant,omitempty"`
}

type Updates struct {
	Mode   string `json:"mode"`   // off | security | all
	Window string `json:"window"` // local time "HH:MM-HH:MM"
	Reboot bool   `json:"reboot"` // reboot inside the window when required
}

type Packages struct {
	Install []string `json:"install"`
	Remove  []string `json:"remove"`
}

type Services struct {
	Enable  []string `json:"enable"`
	Disable []string `json:"disable"`
}

type filesPayload struct {
	Files []File `json:"files"`
}

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"` // octal, default 0644
}

type Firewall struct {
	Enforce bool     `json:"enforce"`
	Allow   []string `json:"allow"` // "22/tcp", "60000:61000/udp"
}

type osPayload struct {
	Min map[string]string `json:"min"` // os-release ID -> minimum VERSION_ID
}

type screenLockPayload struct {
	IdleSeconds int `json:"idle_seconds"`
}

// Login configures desktop login with an OIDC provider (Google Workspace or any
// provider supporting the device authorization grant).
type Login struct {
	Enabled       bool   `json:"enabled"`
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	AllowedDomain string `json:"allowed_domain"` // Google "hd" claim, or email domain
}

// Privacy controls which personal data leaves the device. Default: none of it.
type Privacy struct {
	NetworkInfo   bool `json:"network_info"`    // IP addresses
	LoggedInUsers bool `json:"logged_in_users"` // usernames of active sessions
}

var (
	pkgRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._:-]{0,127}$`)
	unitRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._:-]{0,127}$`)
	portRe    = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?/(tcp|udp)$`)
	userRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	windowRe  = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`)
	versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	identRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
)

func strict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// apply decodes and validates one declaration into p. Anything that could be
// abused as a command line option or path traversal is rejected; server
// validates on save, agent again before applying.
func (d Declaration) apply(p *Policy) error {
	if !identRe.MatchString(d.Identifier) {
		return fmt.Errorf("invalid identifier %q", d.Identifier)
	}
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	switch d.Type {
	case TypeAgent:
		var v agentPayload
		if err := strict(d.Payload, &v); err != nil {
			return err
		}
		if v.CheckinSeconds < 30 || v.CheckinSeconds > 86400 {
			bad("checkin_seconds must be 30..86400")
		}
		p.CheckinSeconds = v.CheckinSeconds
	case TypeCompliance:
		if err := strict(d.Payload, &p.Compliance); err != nil {
			return err
		}
		c := p.Compliance
		if c.Level != 1 && c.Level != 2 {
			bad("level must be 1 or 2")
		}
		if c.GraceHours < 0 || c.GraceHours > 2160 || c.LockAfterHours < 0 || c.LockAfterHours > 2160 {
			bad("grace_hours and lock_after_hours must be 0..2160")
		}
		if c.LockAfterHours > 0 && c.LockAfterHours < c.GraceHours {
			bad("lock_after_hours must not be shorter than grace_hours")
		}
		for _, id := range append(slices.Clone(c.Exclude), c.Advisory...) {
			if !identRe.MatchString(id) {
				bad("invalid check ID %q", id)
			}
		}
	case TypeUpdates:
		if err := strict(d.Payload, &p.Updates); err != nil {
			return err
		}
		switch p.Updates.Mode {
		case "off", "security", "all":
		default:
			bad("mode must be off, security or all")
		}
		if p.Updates.Mode != "off" && !windowRe.MatchString(p.Updates.Window) {
			bad("window must be HH:MM-HH:MM")
		}
	case TypePackages:
		if err := strict(d.Payload, &p.Packages); err != nil {
			return err
		}
		for _, n := range slices.Concat(p.Packages.Install, p.Packages.Remove) {
			if !pkgRe.MatchString(n) {
				bad("invalid package name %q", n)
			}
		}
	case TypeServices:
		if err := strict(d.Payload, &p.Services); err != nil {
			return err
		}
		for _, n := range slices.Concat(p.Services.Enable, p.Services.Disable) {
			if !unitRe.MatchString(n) {
				bad("invalid service name %q", n)
			}
		}
	case TypeFiles:
		var v filesPayload
		if err := strict(d.Payload, &v); err != nil {
			return err
		}
		for _, f := range v.Files {
			if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || f.Path == "/" {
				bad("file path must be absolute and clean: %q", f.Path)
			}
			if _, err := f.FileMode(); err != nil {
				bad("file %s: %v", f.Path, err)
			}
		}
		p.Files = v.Files
	case TypeFirewall:
		if err := strict(d.Payload, &p.Firewall); err != nil {
			return err
		}
		for _, a := range p.Firewall.Allow {
			if !portRe.MatchString(a) {
				bad("invalid firewall rule %q", a)
			}
		}
	case TypeOSVersion:
		var v osPayload
		if err := strict(d.Payload, &v); err != nil {
			return err
		}
		for id, ver := range v.Min {
			if !versionRe.MatchString(ver) {
				bad("%s: invalid version %q", id, ver)
			}
		}
		p.MinOSVersion = v.Min
	case TypeScreenLock:
		var v screenLockPayload
		if err := strict(d.Payload, &v); err != nil {
			return err
		}
		if v.IdleSeconds < 30 || v.IdleSeconds > 3600 {
			bad("idle_seconds must be 30..3600")
		}
		p.ScreenLockSeconds = v.IdleSeconds
	case TypeLogin:
		if err := strict(d.Payload, &p.Login); err != nil {
			return err
		}
		p.Login.Enabled = true
		if !strings.HasPrefix(p.Login.Issuer, "https://") || p.Login.ClientID == "" {
			bad("login needs https issuer and client_id")
		}
	case TypePrivacy:
		if err := strict(d.Payload, &p.Privacy); err != nil {
			return err
		}
	default:
		if ok, err := d.applyExtra(p); ok {
			return err
		}
		return fmt.Errorf("unknown declaration type %q", d.Type)
	}
	return errors.Join(errs...)
}

// Token is a stable hash of a declaration's content.
func (d Declaration) Token() string {
	var buf bytes.Buffer
	json.Compact(&buf, d.Payload)
	h := sha256.Sum256([]byte(d.Type + "\x00" + d.Identifier + "\x00" + buf.String()))
	return hex.EncodeToString(h[:8])
}

// DefaultDeclarations is the baseline an agent enforces before its first sync.
func DefaultDeclarations() []Declaration {
	d, err := Merge(DefaultLibrary())
	if err != nil {
		panic(err) // static data, covered by tests
	}
	return d
}

// DeclarationsToken summarises a set of declarations for change detection.
func DeclarationsToken(decls []Declaration) string {
	h := sha256.New()
	for _, d := range decls {
		fmt.Fprintf(h, "%s=%s\n", d.Identifier, d.Token())
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Compose builds the effective policy. Invalid declarations are skipped and
// reported in the returned status.
func Compose(decls []Declaration) (Policy, []DeclarationStatus) {
	var p Policy
	var st []DeclarationStatus
	for _, d := range decls {
		s := DeclarationStatus{Identifier: d.Identifier, Type: d.Type, ServerToken: d.Token(), Valid: true, Active: true}
		trial := p
		if err := d.apply(&trial); err != nil {
			s.Valid, s.Active, s.Reasons = false, false, []string{err.Error()}
		} else {
			p = trial
		}
		st = append(st, s)
	}
	return p, st
}

// DeclarationStatus is what the agent reports per declaration.
type DeclarationStatus struct {
	Identifier  string   `json:"identifier"`
	Type        string   `json:"type"`
	ServerToken string   `json:"server_token"`
	Valid       bool     `json:"valid"`
	Active      bool     `json:"active"`
	Reasons     []string `json:"reasons,omitempty"`
}

func (f File) FileMode() (uint32, error) {
	if f.Mode == "" {
		return 0o644, nil
	}
	m, err := strconv.ParseUint(f.Mode, 8, 32)
	if err != nil || m > 0o7777 {
		return 0, fmt.Errorf("invalid mode %q", f.Mode)
	}
	return uint32(m), nil
}

// User is a person allowed to log in on a device with the desktop OIDC login.
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Admin    bool   `json:"admin"` // member of sudo/wheel
}

func (u User) Validate() error {
	if !userRe.MatchString(u.Username) || u.Username == "root" {
		return fmt.Errorf("invalid username %q", u.Username)
	}
	if !strings.Contains(u.Email, "@") || strings.ContainsAny(u.Email, " :\n") {
		return fmt.Errorf("invalid email %q", u.Email)
	}
	return nil
}

// ---- enrollment (TLS, pinned CA) and renewal (mTLS) ----

type EnrollRequest struct {
	Token     string `json:"token"`
	CSR       string `json:"csr"` // PEM, key generated on the device and never leaves it
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id"`
}

type EnrollResponse struct {
	DeviceID string `json:"device_id"`
	Cert     string `json:"cert"` // PEM client certificate, CN = device ID
}

type RenewRequest struct {
	CSR string `json:"csr"`
}

// ---- status channel ----

type Inventory struct {
	Source      string `json:"source"` // "osquery 5.x" or "native"
	Hostname    string `json:"hostname"`
	MachineID   string `json:"machine_id"`
	OSID        string `json:"os_id"`
	OSVersion   string `json:"os_version"`
	OSName      string `json:"os_name"`
	OSCodename  string `json:"os_codename,omitempty"`
	Kernel      string `json:"kernel"`
	Arch        string `json:"arch"`
	CPU         string `json:"cpu"`
	CPUCores    int    `json:"cpu_cores,omitempty"`
	CPUThreads  int    `json:"cpu_threads,omitempty"`
	MemoryMB    uint64 `json:"memory_mb"`
	SwapMB      uint64 `json:"swap_mb,omitempty"`
	DiskGB      uint64 `json:"disk_gb"` // root filesystem
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	Serial      string `json:"serial"`
	BIOSVendor  string `json:"bios_vendor,omitempty"`
	BIOSVersion string `json:"bios_version,omitempty"`
	BootTime    int64  `json:"boot_time"`
	// Desktop environment and display manager, empty on servers.
	Desktop        string    `json:"desktop,omitempty"`
	DisplayManager string    `json:"display_manager,omitempty"`
	Disks          []Disk    `json:"disks,omitempty"`
	Volumes        []Volume  `json:"volumes,omitempty"`
	Accounts       []Account `json:"accounts,omitempty"`        // local login accounts and admin rights
	Repos          []Repo    `json:"repos,omitempty"`           // configured package sources
	Interfaces     []NIC     `json:"interfaces,omitempty"`      // only with privacy.network_info
	IPs            []string  `json:"ips,omitempty"`             // only with privacy.network_info
	Users          []string  `json:"logged_in_users,omitempty"` // only with privacy.logged_in_users
}

type Account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	Shell string `json:"shell,omitempty"`
	Admin bool   `json:"admin"` // uid 0 or member of sudo, wheel or admin
}

// Repo is one package source. Signed reports signed-by (apt) or gpgcheck=1 (dnf).
type Repo struct {
	Type    string `json:"type"` // deb | rpm
	Name    string `json:"name"`
	URL     string `json:"url"`
	Suites  string `json:"suites,omitempty"`
	Enabled bool   `json:"enabled"`
	Signed  bool   `json:"signed"`
	File    string `json:"file"`
}

type Disk struct {
	Name   string `json:"name"`
	Model  string `json:"model,omitempty"`
	SizeGB uint64 `json:"size_gb"`
	Type   string `json:"type,omitempty"` // ssd | hdd | nvme | virtual
}

type Volume struct {
	Device    string `json:"device"`
	Mount     string `json:"mount"`
	FS        string `json:"fs"`
	SizeGB    uint64 `json:"size_gb"`
	FreeGB    uint64 `json:"free_gb"`
	Encrypted bool   `json:"encrypted"`
}

type NIC struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	IPs  []string `json:"ips,omitempty"`
}

type Package struct {
	Name    string `json:"n"`
	Version string `json:"v"`
	Arch    string `json:"a,omitempty"`
}

// Refs maps a check to the frameworks it provides evidence for.
type Refs struct {
	CIS []string `json:"cis,omitempty"` // CIS Benchmark recommendation titles
	BSI []string `json:"bsi,omitempty"` // IT-Grundschutz modules / requirements
	ISO []string `json:"iso,omitempty"` // ISO/IEC 27001:2022 Annex A controls
}

type CheckResult struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Level      int    `json:"level"`
	Status     string `json:"status"` // pass | fail | na | excepted
	Detail     string `json:"detail"`
	Remediated bool   `json:"remediated"`
	Refs       Refs   `json:"refs"`
}

// Status is the full status report. The agent only sends it when its hash
// changed or the server asks for it.
type Status struct {
	Inventory    Inventory           `json:"inventory"`
	Checks       []CheckResult       `json:"checks"`
	Declarations []DeclarationStatus `json:"declarations"`
}

type Command struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"` // see CommandTypes
	Payload string `json:"payload,omitempty"`
}

// CommandTypes are the one off actions an admin can send.
var CommandTypes = []string{"sync", "update", "reboot", "shutdown", "lock", "unlock", "script"}

type CommandResult struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type CheckinRequest struct {
	AgentVersion      string          `json:"agent_version"`
	Arch              string          `json:"arch"`
	DeclarationsToken string          `json:"declarations_token"`
	Status            *Status         `json:"status,omitempty"`
	StatusHash        string          `json:"status_hash"`
	Packages          []Package       `json:"packages,omitempty"`
	PackagesHash      string          `json:"packages_hash"`
	Results           []CommandResult `json:"results,omitempty"`
	Metrics           *Metrics        `json:"metrics,omitempty"`       // sent every check in, outside the status hash
	RecoveryKeys      []RecoveryKey   `json:"recovery_keys,omitempty"` // new LUKS recovery keys to escrow
	Events            []string        `json:"events,omitempty"`
}

// Metrics are point in time measurements for history charts.
type Metrics struct {
	MemUsedMB   uint64  `json:"mem_used_mb"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	RootUsedPct float64 `json:"root_used_pct"`
	Load1       float64 `json:"load1"`
}

type CheckinResponse struct {
	DeclarationsToken string        `json:"declarations_token"`
	Declarations      []Declaration `json:"declarations,omitempty"` // only when the token differs
	Users             []User        `json:"users"`
	Commands          []Command     `json:"commands,omitempty"`
	NeedStatus        bool          `json:"need_status"`
	NeedPackages      bool          `json:"need_packages"`
	AgentUpdate       *Release      `json:"agent_update,omitempty"`
	ServerTime        time.Time     `json:"server_time"`
	// RecoveryRotate carries escrowed keys the agent should replace (after
	// they were viewed); the current key unlocks the slot for the new one.
	RecoveryRotate []RecoveryKey `json:"recovery_rotate,omitempty"`
}

// ---- signed agent releases ----

// Release describes a signed agent binary. The signature is made offline with
// the release key; agents only accept binaries signed by the key compiled into them.
type Release struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig"` // hex ed25519 over SignedBytes()
}

func (r Release) SignedBytes() []byte {
	return []byte("limdm-agent\n" + r.Version + "\n" + r.Arch + "\n" + r.SHA256)
}

func (r Release) Verify(pub ed25519.PublicKey) error {
	sig, err := hex.DecodeString(r.Sig)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, r.SignedBytes(), sig) {
		return errors.New("release signature invalid")
	}
	return nil
}

// NewerVersion reports whether a is a higher dotted numeric version than b.
func NewerVersion(a, b string) bool { return CompareVersions(a, b) > 0 }

// CompareVersions compares dotted numeric versions; a leading "v" and any
// suffix after "-", "+" or "~" are ignored.
func CompareVersions(a, b string) int {
	norm := func(s string) []string {
		s = strings.TrimPrefix(s, "v")
		if i := strings.IndexAny(s, "-+~"); i >= 0 {
			s = s[:i]
		}
		return strings.Split(s, ".")
	}
	pa, pb := norm(a), norm(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}
