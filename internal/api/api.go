// Package api holds the wire protocol shared by server and agent.
//
// The model follows Apple's Declarative Device Management: the server publishes
// declarations (desired state), grouped in blueprints. The agent converges to
// them autonomously, also while offline, and reports status per declaration
// plus status items. Imperative commands exist only for one off actions.
package api

import (
	"bytes"
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
	TypeLogin:      `{"issuer": "https://accounts.google.com", "client_id": "", "client_secret": "", "allowed_domain": "", "mode": "session", "reverify_hours": 720, "grace_hours": 168}`,
	TypePrivacy:    `{"network_info": true, "logged_in_users": true}`,
}

// Policy is the effective state the agent enforces, composed from declarations.
// A zero section means "not managed".
type Policy struct {
	CheckinSeconds    int               `json:"checkin_seconds"`
	OfflineLockHours  int               `json:"offline_lock_hours"` // lock the device when the server was unreachable this long, 0 = off
	Compliance        Compliance        `json:"compliance"`
	Updates           Updates           `json:"updates"`
	Packages          Packages          `json:"packages"`
	Services          Services          `json:"services"`
	Files             []File            `json:"files"`
	Firewall          Firewall          `json:"firewall"`
	MinOSVersion      map[string]string `json:"min_os_version"`
	ScreenLockSeconds int               `json:"screen_lock_seconds"`
	ScreenLock        ScreenLock        `json:"screen_lock"`
	Login             Login             `json:"login"`
	Privacy           Privacy           `json:"privacy"`
	Extra             ExtraPolicy       `json:"extra"`
}

type agentPayload struct {
	CheckinSeconds   int `json:"checkin_seconds"`
	OfflineLockHours int `json:"offline_lock_hours,omitempty"`
}

type Compliance struct {
	Level     int      `json:"level"`              // 1 = CIS Level 1 baseline, 2 = Level 2 strict
	Remediate bool     `json:"remediate"`          // agent fixes failing checks that have an automatic fix
	Exclude   []string `json:"exclude"`            // check IDs excluded by policy; risk exceptions recorded on the server are merged in
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
	// Days limits the window to these weekdays (mon..sun); empty is every
	// day. A window across midnight belongs to the day it starts on.
	Days []string `json:"days,omitempty"`
	// Hold keeps these packages at their installed version (apt-mark hold,
	// dnf excludepkgs, pacman IgnorePkg).
	Hold []string `json:"hold,omitempty"`
	// Autoremove removes packages no longer needed, old kernels included,
	// after each update run.
	Autoremove bool `json:"autoremove,omitempty"`
	// SnapRefresh controls snapd where it exists: "hold" stops automatic
	// refreshes, "window" moves them into the update window; empty leaves
	// snapd alone.
	SnapRefresh string `json:"snap_refresh,omitempty"`
	// Reboot deferral, see RebootDefer.
	RebootDefer
}

// RebootDefer lets desktop users postpone a scheduled reboot: up to
// MaxDefers times, each for DeferMinutes; the reboot is announced
// NoticeMinutes ahead. MaxDefers 0 allows no deferral.
type RebootDefer struct {
	NoticeMinutes int `json:"reboot_notice_minutes,omitempty"` // 5 when unset, at most 120
	MaxDefers     int `json:"reboot_max_defers,omitempty"`     // at most 5
	DeferMinutes  int `json:"reboot_defer_minutes,omitempty"`  // 60 when unset, 15..480
}

// Weekdays are the values of Updates.Days, in time.Weekday order.
var Weekdays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

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
	Mode    string `json:"mode"`            // octal, default 0644
	Owner   string `json:"owner,omitempty"` // user name, default root
	Group   string `json:"group,omitempty"` // group name, default root
	// Template renders Content per device on the server (TemplateVars). A
	// file still marked when it reaches the agent could not be rendered and
	// is left as it is.
	Template bool `json:"template,omitempty"`
}

type Firewall struct {
	Enforce bool           `json:"enforce"`
	Allow   []string       `json:"allow"`           // "22/tcp", "60000:61000/udp"
	Rules   []FirewallRule `json:"rules,omitempty"` // allow rules limited to source networks
	// Zones open ports for traffic from given interfaces or networks only:
	// firewalld zones, ufw and nftables rules matching interface and source.
	Zones []FirewallZone `json:"zones,omitempty"`
	// Outbound filters traffic the device sends; nil leaves it alone.
	Outbound *FirewallOutbound `json:"outbound,omitempty"`
	// Template renders every rule text per device on the server
	// (TemplateVars). A payload still marked when it reaches the agent could
	// not be rendered; the agent then leaves the firewall as it is.
	Template bool `json:"template,omitempty"`
}

// FirewallZone binds interfaces and source networks to a zone and opens
// ports in it.
type FirewallZone struct {
	Name       string   `json:"name"`                 // firewalld zone, for example internal or trusted
	Interfaces []string `json:"interfaces,omitempty"` // for example wg0
	Sources    []string `json:"sources,omitempty"`    // CIDR or address
	Allow      []string `json:"allow,omitempty"`      // ports as in Firewall.Allow
}

// FirewallOutbound is the policy for traffic the device sends. With policy
// deny only the listed destinations, DNS, DHCP and the LiMDM server are
// reachable.
type FirewallOutbound struct {
	Policy string           `json:"policy"` // allow | deny
	Allow  []FirewallEgress `json:"allow,omitempty"`
}

// FirewallEgress allows traffic to a destination, a port or both.
type FirewallEgress struct {
	To   string `json:"to,omitempty"`   // CIDR or address, empty is any
	Port string `json:"port,omitempty"` // as in Firewall.Allow, empty is any
}

// Walk calls fn for every rule text of f (what a template can fill).
func (f *Firewall) Walk(fn func(*string)) {
	for i := range f.Allow {
		fn(&f.Allow[i])
	}
	for i := range f.Rules {
		fn(&f.Rules[i].Port)
		fn(&f.Rules[i].From)
	}
	for i := range f.Zones {
		z := &f.Zones[i]
		for _, l := range [][]string{z.Interfaces, z.Sources, z.Allow} {
			for j := range l {
				fn(&l[j])
			}
		}
	}
	if f.Outbound != nil {
		for i := range f.Outbound.Allow {
			fn(&f.Outbound.Allow[i].To)
			fn(&f.Outbound.Allow[i].Port)
		}
	}
}

// FirewallRule allows a port only from a source network.
type FirewallRule struct {
	Port string `json:"port"` // as in Allow
	From string `json:"from"` // CIDR or address
}

// FirewallRules is the effective set of allow rules: Allow without a source
// plus Rules.
func (f Firewall) FirewallRules() []FirewallRule {
	out := make([]FirewallRule, 0, len(f.Allow)+len(f.Rules))
	for _, a := range f.Allow {
		out = append(out, FirewallRule{Port: a})
	}
	for _, r := range f.Rules {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

type osPayload struct {
	Min map[string]string `json:"min"` // os-release ID -> minimum VERSION_ID
}

// screenLockPayload: the login screen keys are optional. A declaration
// without them (every declaration written before they existed) leaves the
// login manager alone; agents before 0.9.2 reject them as unknown keys.
type screenLockPayload struct {
	IdleSeconds    int   `json:"idle_seconds"`
	HideUsers      *bool `json:"hide_users,omitempty"`      // login screen asks for the user name instead of listing users
	AllowAutologin *bool `json:"allow_autologin,omitempty"` // false switches automatic login off
}

// ScreenLock is the effective login screen policy. ManageLogin is set when
// the declaration has one of the login screen keys.
type ScreenLock struct {
	ManageLogin    bool `json:"manage_login,omitempty"`
	HideUsers      bool `json:"hide_users,omitempty"`
	AllowAutologin bool `json:"allow_autologin,omitempty"`
}

// Login configures desktop login with an OIDC provider (Google Workspace or any
// provider supporting the device authorization grant).
type Login struct {
	Enabled       bool   `json:"enabled"`
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	AllowedDomain string `json:"allowed_domain"` // Google "hd" claim, or email domain
	// Mode "session" (default), like Platform SSO and Passport: the first
	// login binds the account with SSO and MFA, afterwards the local password
	// works on every login and lock screen, also offline. Every ReverifyHours
	// (default 720) the desktop app asks to confirm the company account in the
	// session; GraceHours (default 168) after that, while online, the local
	// password locks until SSO is done at the login screen. Accounts disabled
	// in the directory lock at the next poll.
	// Mode "login": SSO at the login screen every ReverifyHours (strict).
	Mode string `json:"mode,omitempty"`
	// LocalPassword (login mode): after an SSO confirmation the password typed
	// at that login becomes the local password until ReverifyHours have passed.
	LocalPassword bool `json:"local_password,omitempty"`
	ReverifyHours int  `json:"reverify_hours,omitempty"`
	GraceHours    int  `json:"grace_hours,omitempty"` // session mode
	// OfflineGraceHours (login mode): while the device cannot reach the
	// LiMDM server, a due confirmation waits this long on top (default 72).
	OfflineGraceHours int `json:"offline_grace_hours,omitempty"`
}

// Session reports the default session mode.
func (l Login) Session() bool { return l.Mode != "login" }

// Grace is the offline grace period of login mode.
func (l Login) Grace() time.Duration {
	if l.OfflineGraceHours <= 0 {
		return 72 * time.Hour
	}
	return time.Duration(l.OfflineGraceHours) * time.Hour
}

// Privacy controls which personal data leaves the device. Without a privacy
// declaration everything is collected; a declaration can switch items off.
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
		if v.OfflineLockHours < 0 || v.OfflineLockHours > 8760 {
			bad("offline_lock_hours must be 0 (off) up to 8760")
		}
		p.CheckinSeconds, p.OfflineLockHours = v.CheckinSeconds, v.OfflineLockHours
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
		u := p.Updates
		if (u.Mode != "off" || u.SnapRefresh == "window") && !windowRe.MatchString(u.Window) {
			bad("window must be HH:MM-HH:MM")
		}
		for i, d := range u.Days {
			if !slices.Contains(Weekdays, d) || slices.Contains(u.Days[:i], d) {
				bad("days: %q is not one of mon, tue, wed, thu, fri, sat, sun (each once)", d)
			}
		}
		if len(u.Hold) > 200 {
			bad("hold: at most 200 packages")
		}
		for _, n := range u.Hold {
			if !pkgRe.MatchString(n) {
				bad("hold: invalid package name %q", n)
			}
		}
		switch u.SnapRefresh {
		case "", "hold", "window":
		default:
			bad("snap_refresh must be hold or window")
		}
		if u.NoticeMinutes < 0 || u.NoticeMinutes > 120 || u.MaxDefers < 0 || u.MaxDefers > 5 ||
			u.DeferMinutes != 0 && (u.DeferMinutes < 15 || u.DeferMinutes > 480) {
			bad("reboot_notice_minutes 0..120, reboot_max_defers 0..5, reboot_defer_minutes 15..480")
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
			if f.Template {
				if _, err := ParseTemplate(f.Content); err != nil {
					bad("file %s: template: %v", f.Path, err)
				}
			}
			if userWritable(f.Path) {
				bad("file %s: directories writable by users cannot be managed (symlink attacks)", f.Path)
			}
			for _, n := range []string{f.Owner, f.Group} {
				if n != "" && !userRe.MatchString(n) {
					bad("file %s: invalid owner or group %q", f.Path, n)
				}
			}
		}
		p.Files = v.Files
	case TypeFirewall:
		if err := strict(d.Payload, &p.Firewall); err != nil {
			return err
		}
		errs = append(errs, p.Firewall.validate()...)
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
		p.ScreenLock = ScreenLock{ManageLogin: v.HideUsers != nil || v.AllowAutologin != nil,
			HideUsers: v.HideUsers != nil && *v.HideUsers, AllowAutologin: v.AllowAutologin == nil || *v.AllowAutologin}
	case TypeLogin:
		var v struct {
			Login
			Enabled *bool `json:"enabled"` // false switches SSO off, e.g. for servers below a desktop blueprint
		}
		if err := strict(d.Payload, &v); err != nil {
			return err
		}
		if v.Enabled != nil && !*v.Enabled {
			p.Login = Login{} // off: the agent removes its PAM hook, local logins work as before
			break
		}
		p.Login = v.Login
		p.Login.Enabled = true
		if p.Login.Mode == "" {
			// items from before 0.11 have no mode but local_password: they meant
			// SSO at every login, and keep that instead of turning into sessions
			var keys map[string]json.RawMessage
			if json.Unmarshal(d.Payload, &keys) == nil {
				// reverify_hours above 2160 only ever validated in session mode:
				// such an item was written for sessions, not before 0.11
				if _, legacy := keys["local_password"]; legacy && p.Login.ReverifyHours <= 2160 {
					p.Login.Mode = "login"
				}
			}
		}
		if !strings.HasPrefix(p.Login.Issuer, "https://") || p.Login.ClientID == "" {
			bad("login needs https issuer and client_id")
		}
		switch p.Login.Mode {
		case "", "session":
			p.Login.Mode, p.Login.LocalPassword = "session", true
			if p.Login.ReverifyHours == 0 {
				p.Login.ReverifyHours = 720
			}
			if p.Login.GraceHours == 0 {
				p.Login.GraceHours = 168
			}
			if p.Login.ReverifyHours < 1 || p.Login.ReverifyHours > 8760 || p.Login.GraceHours < 1 || p.Login.GraceHours > 2160 {
				bad("reverify_hours 1..8760 and grace_hours 1..2160")
			}
		case "login":
			if p.Login.LocalPassword && (p.Login.ReverifyHours < 1 || p.Login.ReverifyHours > 2160) {
				bad("local_password needs reverify_hours 1..2160")
			}
			if p.Login.OfflineGraceHours < 0 || p.Login.OfflineGraceHours > 720 {
				bad("offline_grace_hours: 0..720")
			}
		default:
			bad("mode is session or login")
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
	h := sha256.Sum256([]byte(d.Type + "\x00" + d.Identifier + "\x00" + string(unescapeHTML(buf.Bytes()))))
	return hex.EncodeToString(h[:8])
}

// unescapeHTML undoes the escapes json.Marshal adds for <, >, &, U+2028 and
// U+2029. The same payload comes back escaped or not depending on who encoded
// it last (the agent's state file, an older server), and the token must not
// change with that.
func unescapeHTML(b []byte) []byte {
	repl := map[string]string{"003c": "<", "003e": ">", "0026": "&", "2028": "\u2028", "2029": "\u2029"}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+1 < len(b) {
			if b[i+1] == 'u' && i+6 <= len(b) {
				if r, ok := repl[strings.ToLower(string(b[i+2:i+6]))]; ok {
					out = append(out, r...)
					i += 5
					continue
				}
			}
			out = append(out, b[i], b[i+1]) // any other escape, \\ included, stays as it is
			i++
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// validPortRule checks "port/proto" and "low:high/proto" beyond the syntax:
// ufw and firewalld reject 0, 99999 or reversed ranges, and the firewall
// would then never be enabled.
func validPortRule(r string) bool {
	if !portRe.MatchString(r) {
		return false
	}
	ports, _, _ := strings.Cut(r, "/")
	lo, hi, isRange := strings.Cut(ports, ":")
	l, errL := strconv.Atoi(lo)
	h := l
	var errH error
	if isRange {
		h, errH = strconv.Atoi(hi)
	}
	return errL == nil && errH == nil && l >= 1 && h <= 65535 && l <= h && (!isRange || l < h)
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
	p := Policy{Privacy: Privacy{NetworkInfo: true, LoggedInUsers: true}}
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
	if err != nil || m > 0o777 {
		return 0, fmt.Errorf("invalid mode %q (0000..0777, no setuid, setgid or sticky bits)", f.Mode)
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
	Desktop        string              `json:"desktop,omitempty"`
	DisplayManager string              `json:"display_manager,omitempty"`
	Disks          []Disk              `json:"disks,omitempty"`
	Volumes        []Volume            `json:"volumes,omitempty"`
	Accounts       []Account           `json:"accounts,omitempty"`        // local login accounts and admin rights
	Repos          []Repo              `json:"repos,omitempty"`           // configured package sources
	Flatpaks       []FlatpakApp        `json:"flatpaks,omitempty"`        // installed Flatpak applications, system and per user
	FlatpakRemotes []FlatpakRemoteInfo `json:"flatpak_remotes,omitempty"` // Flatpak remotes, system and per user
	Snaps          []SnapApp           `json:"snaps,omitempty"`           // installed snaps
	AppImages      []AppImage          `json:"appimages,omitempty"`       // AppImage files found in homes, /opt and /usr/local/bin
	Certificates   []CertInfo          `json:"certificates,omitempty"`    // CA certificates installed by LiMDM
	Apps           []AppState          `json:"apps,omitempty"`            // software catalog state
	Interfaces     []NIC               `json:"interfaces,omitempty"`      // addresses only with privacy.network_info
	DNS            []DNSConfig         `json:"dns,omitempty"`             // only with privacy.network_info
	Routes         []Route             `json:"routes,omitempty"`          // only with privacy.network_info
	VPNs           []VPN               `json:"vpns,omitempty"`
	WireGuardKeys  []WireGuardKey      `json:"wireguard_keys,omitempty"` // public keys of LiMDM managed WireGuard profiles
	Groups         []Group             `json:"groups,omitempty"`
	IPs            []string            `json:"ips,omitempty"`             // only with privacy.network_info
	Users          []string            `json:"logged_in_users,omitempty"` // only with privacy.logged_in_users
	TPM            *TPMInfo            `json:"tpm,omitempty"`
}

type Account struct {
	Name   string `json:"name"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid,omitempty"`
	Home   string `json:"home,omitempty"`
	Gecos  string `json:"gecos,omitempty"`
	Source string `json:"source,omitempty"` // local (/etc/passwd) or nss (sssd, LDAP, systemd-homed, DynamicUser, winbind)
	System bool   `json:"system,omitempty"` // service account: uid below 1000 or no login shell
	Shell  string `json:"shell,omitempty"`
	Admin  bool   `json:"admin"` // uid 0 or member of sudo, wheel or admin
	// SSO: centrally managed account; LastSSO is its last SSO confirmation.
	SSO       bool       `json:"sso,omitempty"`
	LastSSO   *time.Time `json:"last_sso,omitempty"`
	PwdLocked bool       `json:"pwd_locked,omitempty"` // local password refused until the next SSO confirmation
}

// FlatpakApp is an installed Flatpak application. Installation is "system"
// or the name of the user it is installed for.
type FlatpakApp struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Branch       string `json:"branch,omitempty"`
	Origin       string `json:"origin,omitempty"`
	Installation string `json:"installation"`
}

type FlatpakRemoteInfo struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	Title        string `json:"title,omitempty"`
	Installation string `json:"installation"` // system or a user name
	Disabled     bool   `json:"disabled,omitempty"`
}

// Repo is one package source. Signed reports signed-by (apt) or gpgcheck=1 (dnf).
type Repo struct {
	Type       string `json:"type"` // deb | rpm
	Name       string `json:"name"`
	URL        string `json:"url"`
	Suites     string `json:"suites,omitempty"`
	Components string `json:"components,omitempty"`
	KeyFile    string `json:"key_file,omitempty"` // keyring the source is pinned to
	Enabled    bool   `json:"enabled"`
	Signed     bool   `json:"signed"`
	File       string `json:"file"`
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
	// Encryption names the method: LUKS2, LUKS1, LUKS2 hw-opal, plain dm-crypt,
	// TCRYPT, BITLK, ZFS native, eCryptfs.
	Encryption string `json:"encryption,omitempty"`
}

type NIC struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	Kind  string   `json:"kind,omitempty"`  // ethernet, wifi, wireguard, tun, bridge, vlan, virtual
	State string   `json:"state,omitempty"` // up, down, unknown
	MTU   int      `json:"mtu,omitempty"`
	VPN   string   `json:"vpn,omitempty"` // provider when the interface belongs to a VPN client
}

// DNSConfig is one resolver scope: "global" or a link name.
type DNSConfig struct {
	Scope   string   `json:"scope"`
	Servers []string `json:"servers,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

type Route struct {
	Dst     string `json:"dst"` // "default" for the default route
	Gateway string `json:"gateway,omitempty"`
	Dev     string `json:"dev,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Metric  int    `json:"metric,omitempty"`
	Family  string `json:"family"` // inet, inet6
}

// VPN is an installed or running VPN client.
type VPN struct {
	Name      string `json:"name"` // WireGuard, OpenVPN, Tailscale, NetBird, Mullvad, ...
	Service   string `json:"service,omitempty"`
	Active    bool   `json:"active"`
	Interface string `json:"interface,omitempty"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
	Source  string   `json:"source"` // local (/etc/group) or nss (sssd, LDAP, systemd, winbind, ...)
	System  bool     `json:"system,omitempty"`
}

type Package struct {
	Name    string `json:"n"`
	Version string `json:"v"`
	Arch    string `json:"a,omitempty"`
}

// Refs maps a check to the frameworks it provides evidence for.
type Refs struct {
	CIS          []string `json:"cis,omitempty"`           // CIS Benchmark recommendation number and title
	CISBenchmark string   `json:"cis_benchmark,omitempty"` // benchmark name and version the CIS numbers refer to
	BSI          []string `json:"bsi,omitempty"`           // IT-Grundschutz modules / requirements
	ISO          []string `json:"iso,omitempty"`           // ISO/IEC 27001:2022 Annex A controls
}

type CheckResult struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Level      int    `json:"level"`
	Status     string `json:"status"` // pass | fail | na | excepted
	Detail     string `json:"detail"`
	Remediated bool   `json:"remediated"`
	Refs       Refs   `json:"refs"`
	Severity   string `json:"severity,omitempty"` // custom checks: low | medium | high | critical
}

// Status is the full status report. The agent only sends it when its hash
// changed or the server asks for it.
type Status struct {
	Inventory    Inventory           `json:"inventory"`
	Checks       []CheckResult       `json:"checks"`
	Declarations []DeclarationStatus `json:"declarations"`
	// CatalogVersion is the version of the agent's check catalog and its
	// framework mapping the Checks were made with.
	CatalogVersion string `json:"catalog_version,omitempty"`
}

type Command struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"` // see CommandTypes
	Payload   string    `json:"payload,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"` // when the admin sent it; delays count from here
	// Signature is the server's Ed25519 signature over the command as it was
	// created (CommandSigned), made with a key outside the database.
	Signature string `json:"signature,omitempty"`
	// Keys are the escrowed recovery keys a lost mode command carries; they
	// are added when the command is sent, so they are not signed.
	Keys []RecoveryKey `json:"keys,omitempty"`
}

// CommandTypes are the one off actions an admin can send.
var CommandTypes = []string{"sync", "update", "reboot", "shutdown", "lock", "unlock", "script", "lost", "found", "wipe", "allow_uninstall", "message", "app_install", "app_remove",
	"user_create", "user_admin", "user_lock", "user_unlock", "user_password", "user_delete", "software_remove", "diagnostics"}

// PollResponse answers the agent's frequent poll (POST /api/v1/poll).
type PollResponse struct {
	Pending bool `json:"pending"`
}

// Message is the payload of the "message" command: shown on the device's desktop.
type Message struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

// LostMode is the payload of the "lost" command. The server adds the escrowed
// recovery keys only when it delivers the command; they are never stored in
// the command itself.
type SnapApp struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher,omitempty"`
	Notes     string `json:"notes,omitempty"` // base, snapd, classic …
}

type AppImage struct {
	Path   string `json:"path"`
	Owner  string `json:"owner,omitempty"`
	SizeMB int64  `json:"size_mb"`
}

// UserCommand is the payload of the user_* commands for local accounts.
type UserCommand struct {
	Username string `json:"username"`
	FullName string `json:"full_name,omitempty"`
	Password string `json:"password,omitempty"` // user_create, user_password: must be changed at first login
	Admin    bool   `json:"admin,omitempty"`    // user_create, user_admin
	KeepHome bool   `json:"keep_home,omitempty"`
	// NoAdmin is set by the server for the helpdesk role: the agent refuses
	// accounts with uid 0, admin group membership or sudo rules.
	NoAdmin bool `json:"no_admin,omitempty"`
}

var localUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Validate checks a user command for its type.
func (u UserCommand) Validate(typ string) error {
	if !localUserRe.MatchString(u.Username) || u.Username == "root" {
		return errors.New("user name: lower case letters, digits, dash and underscore, not root")
	}
	if len(u.FullName) > 100 || strings.ContainsAny(u.FullName, ":\n\r\x00,") {
		return errors.New("full name: up to 100 characters, no colon or comma")
	}
	if typ == "user_create" || typ == "user_password" {
		if len(u.Password) < 12 || len(u.Password) > 256 || strings.ContainsAny(u.Password, "\n\r\x00:") {
			return errors.New("password: 12 to 256 characters, no colon or line break")
		}
	}
	return nil
}

// SoftwareRemove is the payload of software_remove.
type SoftwareRemove struct {
	Kind         string `json:"kind"`                   // package | snap | flatpak | appimage
	Name         string `json:"name"`                   // package, snap or Flatpak ID; for an AppImage its path
	Installation string `json:"installation,omitempty"` // Flatpak: system or a user name
}

var (
	pkgNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:-]{0,127}$`)
	appImagePathRe = regexp.MustCompile(`^/(home/[^/]+|opt|usr/local/bin|root)/[^\x00\n]*\.(AppImage|appimage)$`)
)

func (r SoftwareRemove) Validate() error {
	switch r.Kind {
	case "package", "snap":
		if !pkgNameRe.MatchString(r.Name) {
			return errors.New("invalid package name")
		}
	case "flatpak":
		if !flatpakIDRe.MatchString(r.Name) || (r.Installation != "system" && !localUserRe.MatchString(r.Installation)) {
			return errors.New("invalid Flatpak ID or installation")
		}
	case "appimage":
		if !appImagePathRe.MatchString(r.Name) || strings.Contains(r.Name, "/../") {
			return errors.New("an AppImage path below /home, /opt, /usr/local/bin or /root")
		}
	default:
		return errors.New("kind is package, snap, flatpak or appimage")
	}
	return nil
}

type LostMode struct {
	Message string        `json:"message"`
	Keys    []RecoveryKey `json:"keys,omitempty"`
}

type CommandResult struct {
	ID     int64         `json:"id"`
	OK     bool          `json:"ok"`
	Output string        `json:"output"`
	Script *ScriptResult `json:"script,omitempty"` // script command: structured result
	// Diagnostics is the bounded, redacted log bundle of a diagnostics command.
	Diagnostics string `json:"diagnostics,omitempty"`
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
	BrandingHash      string          `json:"branding_hash,omitempty"`
	UpdateResult      *UpdateResult   `json:"update_result,omitempty"` // outcome of the last agent update
	Events            []string        `json:"events,omitempty"`
	CatalogHash       string          `json:"catalog_hash,omitempty"`
	AppRequests       []AppRequest    `json:"app_requests,omitempty"`   // self service requests of users
	ScriptResults     []ScriptResult  `json:"script_results,omitempty"` // runs of recurring scripts
	// CommandKey is the command key the agent has pinned (hex), so the
	// console can show how far a key rotation has reached the fleet.
	CommandKey string `json:"command_key,omitempty"`
	// CAHash is the SHA-256 (hex) of the agent's trusted device CA file; the
	// server sends DeviceCAs when it differs.
	CAHash string `json:"ca_hash,omitempty"`
}

// Branding is the company name and PNG logo shown by the desktop helper.
type Branding struct {
	Name string `json:"name"`
	Logo []byte `json:"logo,omitempty"`
	Hash string `json:"hash"`
}

// Metrics are point in time measurements for history charts.
type Metrics struct {
	MemUsedMB   uint64  `json:"mem_used_mb"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	RootUsedPct float64 `json:"root_used_pct"`
	Load1       float64 `json:"load1"`
}

type CheckinResponse struct {
	// CommandKey is the public key commands are signed with (hex); the agent
	// pins it on first sight and runs only commands signed with it.
	CommandKey        string        `json:"command_key,omitempty"`
	DeclarationsToken string        `json:"declarations_token"`
	Declarations      []Declaration `json:"declarations,omitempty"` // only when the token differs
	Users             []User        `json:"users"`
	Commands          []Command     `json:"commands,omitempty"`
	NeedStatus        bool          `json:"need_status"`
	NeedPackages      bool          `json:"need_packages"`
	AgentUpdate       *AgentUpdate  `json:"agent_update,omitempty"`
	ServerTime        time.Time     `json:"server_time"`
	// RecoveryRotate carries escrowed keys the agent should replace (after
	// they were viewed); the current key unlocks the slot for the new one.
	RecoveryRotate []RecoveryKey `json:"recovery_rotate,omitempty"`
	// Branding is sent when it differs from the agent's BrandingHash.
	Branding *Branding `json:"branding,omitempty"`
	// Catalog is sent when it differs from the agent's CatalogHash.
	Catalog *Catalog `json:"catalog,omitempty"`
	// FallbackDNS allows the agent to ask public DNS over HTTPS resolvers
	// when the system resolver fails (server setting, default off).
	FallbackDNS bool `json:"fallback_dns,omitempty"`
	// CommandKeyRollover announces CommandKey while the previous key is
	// being retired, signed with that previous key.
	CommandKeyRollover *KeyRollover `json:"command_key_rollover,omitempty"`
	// DeviceCAs is the PEM bundle of the device CAs the agent should trust
	// (both during a CA rotation), sent when the agent's CAHash differs.
	DeviceCAs string `json:"device_cas,omitempty"`
	// RenewCert asks the agent to renew its client certificate now (it was
	// issued by a device CA that is being retired).
	RenewCert bool `json:"renew_cert,omitempty"`
	// RenewNetworkCert does the same for the EAP-TLS certificate.
	RenewNetworkCert bool `json:"renew_network_cert,omitempty"`
	// SignedData: this server signs catalog apps, managed remotes and the
	// device user list (SignedUsers). An agent with a pinned command key
	// then refuses entries without a valid signature.
	SignedData  bool         `json:"signed_data,omitempty"`
	SignedUsers *SignedUsers `json:"signed_users,omitempty"`
}

// ---- signed agent releases ----

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

// safeFiles and safeDirs (trailing slash) are where a files declaration
// may write on devices enrolled without allow_scripts: plain text that no
// program runs as code. Everything else (cron, systemd, sudoers, profiles,
// PAM, the dynamic linker, D-Bus, binaries, the agent …) needs allow_scripts,
// the same opt in remote scripts need. An allowlist, because a denylist of
// code loading paths is never complete.
var (
	safeFiles = []string{"/etc/motd", "/etc/issue", "/etc/issue.net"}
	safeDirs  = []string{"/etc/motd.d/", "/srv/", "/etc/opt/", "/var/opt/"}
)

// SafeFilePath reports whether p (absolute and clean) may be written by a
// files declaration on a device without allow_scripts.
func SafeFilePath(p string) bool {
	if filepath.Clean(p) != p || !filepath.IsAbs(p) {
		return false
	}
	if slices.Contains(safeFiles, p) {
		return true
	}
	for _, d := range safeDirs {
		if strings.HasPrefix(p, d) && len(p) > len(d) {
			return true
		}
	}
	return false
}

// userWritable reports paths below directories regular users can write to.
func userWritable(p string) bool {
	for _, d := range []string{"/home/", "/tmp/", "/var/tmp/", "/run/user/", "/dev/shm/", "/var/mail/", "/var/spool/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
