package api

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Device security types: disk encryption recovery key escrow, polkit rules,
// sudo rules and the boot loader password.

const (
	TypeDiskEncryption = "com.limdm.diskencryption"
	TypePolkit         = "com.limdm.polkit"
	TypeSudo           = "com.limdm.sudo"
	TypeBootloader     = "com.limdm.bootloader"
)

type DiskEncryption struct {
	Escrow          bool `json:"escrow"`            // every LUKS volume needs a recovery key stored on the server
	RotateAfterView bool `json:"rotate_after_view"` // replace a key once someone viewed it in the console
}

type PolkitRule struct {
	Name            string   `json:"name"`
	Actions         []string `json:"actions"` // action IDs, "prefix.*" matches a namespace
	Groups          []string `json:"groups"`  // empty: every user
	Result          string   `json:"result"`  // yes | no | auth_self | auth_self_keep | auth_admin | auth_admin_keep
	LocalActiveOnly bool     `json:"local_active_only"`
}

type SudoRule struct {
	Name       string   `json:"name"`
	Principals []string `json:"principals"` // user or %group
	RunAs      string   `json:"run_as"`     // empty: root
	Commands   []string `json:"commands"`   // absolute paths with optional arguments, or ALL
	NoPasswd   bool     `json:"nopasswd"`
}

type Sudo struct {
	Rules            []SudoRule `json:"rules"`
	TimestampTimeout *int       `json:"timestamp_timeout,omitempty"` // minutes, 0 asks every time
}

type Bootloader struct {
	Superuser      string `json:"superuser"`
	PasswordPBKDF2 string `json:"password_pbkdf2"`
	Unrestricted   bool   `json:"unrestricted"` // booting the default entries needs no password, editing does
}

// RecoveryKey is a LUKS recovery key the agent escrows with the server.
type RecoveryKey struct {
	UUID   string `json:"uuid"`   // LUKS header UUID
	Device string `json:"device"` // block device path, informational
	Key    string `json:"key"`
}

var (
	polkitAction = regexp.MustCompile(`^[a-z0-9]+(\.[a-zA-Z0-9_-]+){2,}(\.\*)?$`)
	groupRe      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	principalRe  = regexp.MustCompile(`^%?[a-z_][a-z0-9_.-]{0,31}$`)
	sudoNameRe   = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`) // sudoers.d ignores names with dots
	// No sudoers metacharacters (, : = \ ! *) in commands: one command per entry, no wildcards.
	sudoCmdRe     = regexp.MustCompile(`^/[A-Za-z0-9/._+-]+( [A-Za-z0-9/._+@-]+)*$`)
	grubUserRe    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	grubPBKDF2Re  = regexp.MustCompile(`^grub\.pbkdf2\.sha512\.[0-9]{4,7}\.[0-9A-F]{32,256}\.[0-9A-F]{128}$`)
	luksUUIDRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	recoveryKeyRe = regexp.MustCompile(`^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$`)
	polkitResults = []string{"yes", "no", "auth_self", "auth_self_keep", "auth_admin", "auth_admin_keep"}
)

func init() {
	Types[TypeDiskEncryption] = `{"escrow": true, "rotate_after_view": true}`
	Types[TypePolkit] = `{"rules": [{"name": "network", "actions": ["org.freedesktop.NetworkManager.*"], "groups": ["netdev"], "result": "yes", "local_active_only": true}, {"name": "printers", "actions": ["org.opensuse.cupspkhelper.mechanism.*"], "groups": [], "result": "auth_self_keep", "local_active_only": true}]}`
	Types[TypeSudo] = `{"rules": [{"name": "developers", "principals": ["%developers"], "run_as": "", "commands": ["/usr/bin/apt-get update", "/usr/bin/systemctl restart nginx"], "nopasswd": false}], "timestamp_timeout": 5}`
	Types[TypeBootloader] = `{"superuser": "bootadmin", "password": "replace with a new password, stored as PBKDF2 hash", "unrestricted": true}`
	listTypes[TypePolkit] = true
	listTypes[TypeSudo] = true
}

// Valid checks what an agent escrows.
func (k RecoveryKey) Valid() bool {
	return luksUUIDRe.MatchString(k.UUID) && recoveryKeyRe.MatchString(k.Key) && len(k.Device) < 256 && noControl(k.Device, 255)
}

// NewRecoveryKey returns a key in the systemd recovery key format: 32 random
// bytes as 64 modhex characters in groups of eight.
func NewRecoveryKey() string {
	const modhex = "cbdefghijklnrtuv"
	b := make([]byte, 32)
	rand.Read(b)
	var s strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			s.WriteByte('-')
		}
		s.WriteByte(modhex[c>>4])
		s.WriteByte(modhex[c&0xf])
	}
	return s.String()
}

// PrepareBootloader replaces a plain "password" in a boot loader payload with
// its GRUB PBKDF2 hash, so the clear text is never stored or sent to devices.
func PrepareBootloader(raw json.RawMessage) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	pw, ok := m["password"].(string)
	if !ok {
		return raw, nil
	}
	if len(pw) < 12 || len(pw) > 128 {
		return nil, errors.New("boot loader password must have 12..128 characters")
	}
	delete(m, "password")
	m["password_pbkdf2"] = GrubPBKDF2(pw)
	return json.Marshal(m)
}

// GrubPBKDF2 produces the format of grub-mkpasswd-pbkdf2.
func GrubPBKDF2(pw string) string {
	const iter = 100000
	salt := make([]byte, 64)
	rand.Read(salt)
	key, err := pbkdf2.Key(sha512.New, pw, salt, iter, 64)
	if err != nil {
		panic(err) // fixed, valid parameters
	}
	return fmt.Sprintf("grub.pbkdf2.sha512.%d.%s.%s", iter, strings.ToUpper(hex.EncodeToString(salt)), strings.ToUpper(hex.EncodeToString(key)))
}

func (d Declaration) applySecurity(p *Policy) (bool, error) {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	switch d.Type {
	case TypeDiskEncryption:
		var v DiskEncryption
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		p.Extra.DiskEncryption = &v
	case TypePolkit:
		var v struct {
			Rules []PolkitRule `json:"rules"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, r := range v.Rules {
			if !nameRe.MatchString(r.Name) || len(r.Actions) == 0 || !slices.Contains(polkitResults, r.Result) {
				bad("polkit rule %q: name, at least one action and a valid result are required", r.Name)
			}
			for _, a := range r.Actions {
				if !polkitAction.MatchString(a) {
					bad("polkit rule %q: invalid action %q", r.Name, a)
				}
				// pkexec grants a root shell; never hand it out through policy
				if strings.HasPrefix(a, "org.freedesktop.policykit.") {
					bad("polkit rule %q: org.freedesktop.policykit actions cannot be managed", r.Name)
				}
			}
			for _, g := range r.Groups {
				if !groupRe.MatchString(g) {
					bad("polkit rule %q: invalid group %q", r.Name, g)
				}
			}
			// granting without authentication to everybody, also remote, would give root like rights
			if r.Result == "yes" && len(r.Groups) == 0 && !r.LocalActiveOnly {
				bad("polkit rule %q: result yes needs groups or local_active_only", r.Name)
			}
		}
		p.Extra.Polkit = v.Rules
	case TypeSudo:
		var v Sudo
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, r := range v.Rules {
			if !sudoNameRe.MatchString(r.Name) || len(r.Principals) == 0 || len(r.Commands) == 0 {
				bad("sudo rule %q: name (a-z, 0-9, _ and -), principals and commands are required", r.Name)
			}
			for _, pr := range r.Principals {
				if !principalRe.MatchString(pr) {
					bad("sudo rule %q: invalid principal %q", r.Name, pr)
				}
			}
			if r.RunAs != "" && r.RunAs != "ALL" && !groupRe.MatchString(r.RunAs) {
				bad("sudo rule %q: invalid run_as %q", r.Name, r.RunAs)
			}
			for _, c := range r.Commands {
				if c != "ALL" && (!sudoCmdRe.MatchString(c) || len(c) > 300) {
					bad("sudo rule %q: command %q must be an absolute path with plain arguments, or ALL", r.Name, c)
				}
			}
		}
		if t := v.TimestampTimeout; t != nil && (*t < 0 || *t > 60) {
			bad("timestamp_timeout must be 0..60 minutes")
		}
		p.Extra.Sudo = &v
	case TypeBootloader:
		var v Bootloader
		if err := strict(d.Payload, &v); err != nil {
			return true, fmt.Errorf("%w (a plain password is hashed when the item is saved in the console)", err)
		}
		if !grubUserRe.MatchString(v.Superuser) || !grubPBKDF2Re.MatchString(v.PasswordPBKDF2) {
			bad("boot loader: superuser and a grub.pbkdf2.sha512 hash are required")
		}
		p.Extra.Bootloader = &v
	default:
		return false, nil
	}
	return true, errors.Join(errs...)
}

func mergeSecurity(typ string, a, b json.RawMessage) (json.RawMessage, bool, error) {
	switch typ {
	case TypePolkit:
		var x, y struct {
			Rules []PolkitRule `json:"rules"`
		}
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, true, err
		}
		out := x.Rules
		for _, r := range y.Rules {
			if i := slices.IndexFunc(out, func(e PolkitRule) bool { return e.Name == r.Name }); i >= 0 {
				out[i] = r
			} else {
				out = append(out, r)
			}
		}
		m, err := json.Marshal(map[string]any{"rules": out})
		return m, true, err
	case TypeSudo:
		var x, y Sudo
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, true, err
		}
		out := x.Rules
		for _, r := range y.Rules {
			if i := slices.IndexFunc(out, func(e SudoRule) bool { return e.Name == r.Name }); i >= 0 {
				out[i] = r
			} else {
				out = append(out, r)
			}
		}
		if y.TimestampTimeout != nil {
			x.TimestampTimeout = y.TimestampTimeout
		}
		m, err := json.Marshal(Sudo{Rules: out, TimestampTimeout: x.TimestampTimeout})
		return m, true, err
	}
	return nil, false, nil
}
