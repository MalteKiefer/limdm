package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Additional library types. Each payload is validated strictly here, on the
// server when saved and on the agent before it is applied.

const (
	TypeRepositories  = "com.limdm.repositories"
	TypeCertificates  = "com.limdm.certificates"
	TypeSysctl        = "com.limdm.sysctl"
	TypeKernelModules = "com.limdm.kernelmodules"
	TypeSSH           = "com.limdm.ssh"
	TypeBanner        = "com.limdm.banner"
	TypeDNS           = "com.limdm.dns"
	TypeNTP           = "com.limdm.ntp"
	TypeProxy         = "com.limdm.proxy"
	TypeFlatpak       = "com.limdm.flatpak"
	TypeScripts       = "com.limdm.scripts"
	TypeDconf         = "com.limdm.dconf"
	TypeLocalUsers    = "com.limdm.localusers"
)

// LocalUser is a local account that must exist. Accounts dropped from the
// declaration are locked, never deleted.
type LocalUser struct {
	Name           string   `json:"name"`
	UID            int      `json:"uid,omitempty"` // only used when the account is created
	FullName       string   `json:"full_name,omitempty"`
	Groups         []string `json:"groups,omitempty"` // supplementary groups, must exist
	Shell          string   `json:"shell,omitempty"`  // default /bin/bash
	Locked         bool     `json:"locked,omitempty"`
	AuthorizedKeys []string `json:"authorized_keys,omitempty"` // SSH public keys, one per entry, no options
}

// Dconf are GNOME (dconf) defaults for every user: key paths with GVariant
// values, and keys or directories users cannot change.
type Dconf struct {
	Settings map[string]string `json:"settings"`
	Locks    []string          `json:"locks,omitempty"`
}

type Repository struct {
	Name       string `json:"name"`
	Family     string `json:"family"` // debian | fedora
	URL        string `json:"url"`
	Suites     string `json:"suites,omitempty"`     // apt
	Components string `json:"components,omitempty"` // apt
	Key        string `json:"key,omitempty"`        // ASCII armored signing key
	KeyFile    string `json:"key_file,omitempty"`   // or a keyring already on the device (distribution keys)
	// SignedMetadata: the repository signs its metadata, not each package
	// (dnf repo_gpgcheck instead of gpgcheck; apt always checks metadata).
	SignedMetadata bool `json:"signed_metadata,omitempty"`
}

// Validate checks a package repository; unsigned ones are not allowed.
func (r Repository) Validate() error {
	if !nameRe.MatchString(r.Name) || (r.Family != "debian" && r.Family != "fedora") || !httpsURL(r.URL) {
		return fmt.Errorf("repository %q: name, family (debian|fedora) and an https URL are required", r.Name)
	}
	if !suiteRe.MatchString(r.Suites) || !suiteRe.MatchString(r.Components) || (r.Family == "debian" && r.Suites == "") {
		return fmt.Errorf("repository %q: invalid suites or components", r.Name)
	}
	armored := strings.Contains(r.Key, "BEGIN PGP PUBLIC KEY BLOCK") && len(r.Key) <= 64<<10
	if armored == (r.KeyFile != "") || (r.KeyFile != "" && !keyFileRe.MatchString(r.KeyFile)) {
		return fmt.Errorf("repository %q: either an armored signing key or a key_file in /usr/share/keyrings, /etc/apt/keyrings or /etc/pki/rpm-gpg is required; unsigned repositories are not allowed", r.Name)
	}
	return nil
}

type Certificate struct {
	Name string `json:"name"`
	PEM  string `json:"pem"`
}

// CertInfo describes a CA certificate LiMDM installed on a device.
type CertInfo struct {
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
}

type FlatpakRemote struct {
	Name     string `json:"name"`
	URL      string `json:"url"`                // .flatpakrepo file or repository URL
	Scope    string `json:"scope,omitempty"`    // system (default) or user: the installation of every regular user
	Disabled bool   `json:"disabled,omitempty"` // keep the remote but switch it off
}

// InstallationScope is "system" for an empty scope.
func (r FlatpakRemote) InstallationScope() string {
	if r.Scope == "" {
		return "system"
	}
	return r.Scope
}

type Flatpak struct {
	Remotes []FlatpakRemote `json:"remotes"`
	Install []string        `json:"install"`
	Remove  []string        `json:"remove"`
}

type Script struct {
	Name           string            `json:"name"`
	IntervalHours  int               `json:"interval_hours"`
	Body           string            `json:"body"`
	Params         map[string]string `json:"params,omitempty"`          // environment variables for the script
	TimeoutMinutes int               `json:"timeout_minutes,omitempty"` // 1..240, default 30
}

// ScriptCommand is the payload of the "script" command when it carries
// parameters or a timeout; a plain body is still accepted.
type ScriptCommand struct {
	Body           string            `json:"body"`
	Params         map[string]string `json:"params,omitempty"`
	TimeoutMinutes int               `json:"timeout_minutes,omitempty"`
}

// ScriptResult is the structured outcome of a script run. Output is
// truncated to its last MaxScriptOutput bytes per stream.
type ScriptResult struct {
	Name      string    `json:"name,omitempty"`       // recurring script, empty for a command
	CommandID int64     `json:"command_id,omitempty"` // script command
	ExitCode  int       `json:"exit_code"`            // -1: did not start or timed out
	Stdout    string    `json:"stdout,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
}

// MaxScriptOutput bounds stdout and stderr of one script result.
const MaxScriptOutput = 16 << 10

var (
	scriptParamRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	reservedEnvVars = []string{"PATH", "IFS", "HOME", "SHELL", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4", "CDPATH", "GLOBIGNORE",
		"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PERL5LIB", "PERL5OPT", "PERLLIB", "RUBYLIB", "RUBYOPT", "NODE_OPTIONS", "NODE_PATH", "TMPDIR"}
)

// ValidateScriptParams checks parameter names and values and the timeout.
// Names are environment variable names that do not change how an
// interpreter or the dynamic linker loads code.
func ValidateScriptParams(params map[string]string, timeout int) error {
	if len(params) > 50 {
		return errors.New("at most 50 parameters")
	}
	size := 0
	for k, v := range params {
		up := strings.ToUpper(k)
		if !scriptParamRe.MatchString(k) || slices.Contains(reservedEnvVars, up) || strings.HasPrefix(up, "LD_") || strings.HasPrefix(up, "LC_") || strings.HasPrefix(up, "DYLD_") {
			return fmt.Errorf("parameter %q: letters, digits and underscore, not a reserved variable (PATH, LD_*, BASH_ENV …)", k)
		}
		if strings.ContainsRune(v, 0) || len(v) > 4096 {
			return fmt.Errorf("parameter %s: up to 4096 characters, no NUL", k)
		}
		size += len(k) + len(v)
	}
	if size > 32<<10 {
		return errors.New("parameters up to 32 KiB in total")
	}
	if timeout < 0 || timeout > 240 {
		return errors.New("timeout_minutes must be 1..240 (0 for the default of 30)")
	}
	return nil
}

type Banner struct {
	Issue string `json:"issue"`
	Motd  string `json:"motd"`
}

type DNS struct {
	Servers []string `json:"servers"`
	Domains []string `json:"domains"`
	DNSSEC  bool     `json:"dnssec"`
}

type NTP struct {
	Servers []string `json:"servers"`
}

type Proxy struct {
	HTTP    string `json:"http"`
	HTTPS   string `json:"https"`
	NoProxy string `json:"no_proxy"`
}

// ExtraPolicy holds the additional sections of the effective policy.
type ExtraPolicy struct {
	Repositories  []Repository      `json:"repositories,omitempty"`
	RepoDisable   []string          `json:"repo_disable,omitempty"` // source files to switch off
	Certificates  []Certificate     `json:"certificates,omitempty"`
	Sysctl        map[string]string `json:"sysctl,omitempty"`
	KernelModules []string          `json:"kernel_modules,omitempty"`
	SSH           map[string]string `json:"ssh,omitempty"`
	Banner        *Banner           `json:"banner,omitempty"`
	DNS           *DNS              `json:"dns,omitempty"`
	NTP           *NTP              `json:"ntp,omitempty"`
	Proxy         *Proxy            `json:"proxy,omitempty"`
	Flatpak       *Flatpak          `json:"flatpak,omitempty"`
	Scripts       []Script          `json:"scripts,omitempty"`
	Dconf         *Dconf            `json:"dconf,omitempty"`
	LocalUsers    []LocalUser       `json:"local_users,omitempty"`

	DiskEncryption *DiskEncryption `json:"disk_encryption,omitempty"`
	Polkit         []PolkitRule    `json:"polkit,omitempty"`
	Sudo           *Sudo           `json:"sudo,omitempty"`
	Bootloader     *Bootloader     `json:"bootloader,omitempty"`
	SoftwareStore  *SoftwareStore  `json:"software_store,omitempty"`
}

var extraExamples = map[string]string{
	TypeRepositories:  `{"repositories": [{"name": "vendor", "family": "debian", "url": "https://repo.example.com/apt", "suites": "stable", "components": "main", "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----..."}]}`,
	TypeCertificates:  `{"certificates": [{"name": "corp-root", "pem": "-----BEGIN CERTIFICATE-----..."}]}`,
	TypeSysctl:        `{"settings": {"vm.swappiness": "10"}}`,
	TypeKernelModules: `{"block": ["firewire_core", "thunderbolt"]}`,
	TypeSSH:           `{"options": {"AllowGroups": "ssh-users", "Banner": "/etc/issue.net"}}`,
	TypeBanner:        `{"issue": "Authorized use only.", "motd": "Managed by IT."}`,
	TypeDNS:           `{"servers": ["10.0.0.53"], "domains": ["corp.example.com"], "dnssec": true}`,
	TypeNTP:           `{"servers": ["ntp1.example.com", "ntp2.example.com"]}`,
	TypeProxy:         `{"http": "http://proxy.example.com:3128", "https": "http://proxy.example.com:3128", "no_proxy": "localhost,127.0.0.1,.example.com"}`,
	TypeFlatpak:       `{"remotes": [{"name": "flathub", "url": "https://dl.flathub.org/repo/flathub.flatpakrepo"}], "install": ["org.mozilla.firefox"], "remove": []}`,
	TypeScripts:       `{"scripts": [{"name": "cleanup", "interval_hours": 24, "body": "#!/bin/sh\njournalctl --vacuum-time=30d"}]}`,
	TypeDconf:         `{"settings": {"/org/gnome/desktop/interface/clock-show-seconds": "true"}, "locks": ["/org/gnome/desktop/interface/clock-show-seconds"]}`,
	TypeLocalUsers:    `{"users": [{"name": "svc-backup", "groups": ["backup"], "shell": "/bin/bash", "locked": false, "authorized_keys": ["ssh-ed25519 AAAA... backup@example.com"]}]}`,
}

var (
	// no user:password@: proxy settings land in world readable profile files
	proxyURLRe = regexp.MustCompile(`^https?://[A-Za-z0-9.\[\]:-]+(/[A-Za-z0-9._~/-]*)?$`)
	noProxyRe  = regexp.MustCompile(`^[A-Za-z0-9.,:/*_\[\]-]*$`)
)

func init() {
	for t, ex := range extraExamples {
		Types[t] = ex
	}
	for _, t := range []string{TypeRepositories, TypeCertificates, TypeSysctl, TypeKernelModules, TypeSSH, TypeFlatpak, TypeScripts, TypeDconf, TypeLocalUsers} {
		listTypes[t] = true
	}
}

var (
	nameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sysctlKey  = regexp.MustCompile(`^[a-z0-9_]+(\.[a-zA-Z0-9_-]+)+$`)
	sysctlVal  = regexp.MustCompile(`^[A-Za-z0-9 ._:/-]{1,200}$`)
	moduleRe   = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	flatpakRef = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){2,}$`)
	hostRe     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)
	suiteRe    = regexp.MustCompile(`^[A-Za-z0-9._/ -]{0,200}$`)
	sshValRe   = regexp.MustCompile(`^[A-Za-z0-9 ,@._:/*-]{1,200}$`)
	repoFileRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,100}\.(list|sources|repo)|sources\.list)$`)
	shellRe    = regexp.MustCompile(`^/[A-Za-z0-9/_.+-]{1,100}$`)
	sshKeyRe   = regexp.MustCompile(`^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^\x00-\x1f]{0,200})?$`)
	dconfKeyRe = regexp.MustCompile(`^(/[A-Za-z0-9_.-]+)+$`)
	keyFileRe  = regexp.MustCompile(`^(/usr/share/keyrings|/etc/apt/keyrings|/etc/pki/rpm-gpg)/[A-Za-z0-9][A-Za-z0-9._-]{0,100}$`)
)

// sshAllowed are sshd options that cannot weaken the compliance baseline.
var sshAllowed = map[string]bool{
	"allowgroups": true, "allowusers": true, "denygroups": true, "denyusers": true, "banner": true,
	"maxsessions": true, "maxstartups": true, "loglevel": true, "port": true, "listenaddress": true,
	"authorizedkeysfile": true, "trustedusercakeys": true, "authorizedprincipalsfile": true,
	"ciphers": true, "macs": true, "kexalgorithms": true, "hostkeyalgorithms": true, "pubkeyacceptedalgorithms": true,
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

func hostOrIP(s string) bool { return net.ParseIP(s) != nil || hostRe.MatchString(s) }

func noControl(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

// applyExtra decodes and validates the additional types. ok is false for
// types it does not know.
func (d Declaration) applyExtra(p *Policy) (bool, error) {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	switch d.Type {
	case TypeRepositories:
		var v struct {
			Repositories []Repository `json:"repositories"`
			Disable      []string     `json:"disable,omitempty"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, f := range v.Disable {
			if !repoFileRe.MatchString(f) || strings.HasPrefix(f, "limdm-") {
				bad("disable: %q must be a source file name (.list, .sources, .repo) not managed by LiMDM", f)
			}
		}
		p.Extra.RepoDisable = v.Disable
		for _, r := range v.Repositories {
			if r.Name == "osquery" || strings.HasPrefix(r.Name, "app-") {
				bad("repository name %q: osquery and names starting with app- are reserved for the agent", r.Name)
			}
			if err := r.Validate(); err != nil {
				errs = append(errs, err)
			}
		}
		p.Extra.Repositories = v.Repositories
	case TypeCertificates:
		var v struct {
			Certificates []Certificate `json:"certificates"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, c := range v.Certificates {
			b, _ := pem.Decode([]byte(c.PEM))
			if !nameRe.MatchString(c.Name) || b == nil || b.Type != "CERTIFICATE" {
				bad("certificate %q: name and one PEM certificate are required", c.Name)
				continue
			}
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil || !cert.IsCA {
				bad("certificate %q: must be a CA certificate", c.Name)
			}
		}
		p.Extra.Certificates = v.Certificates
	case TypeSysctl:
		var v struct {
			Settings map[string]string `json:"settings"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for k, val := range v.Settings {
			if !sysctlKey.MatchString(k) || !sysctlVal.MatchString(val) {
				bad("invalid sysctl %q=%q", k, val)
			}
			if sysctlForbidden(k) {
				bad("sysctl %q runs programs as root and cannot be managed", k)
			}
		}
		p.Extra.Sysctl = v.Settings
	case TypeKernelModules:
		var v struct {
			Block []string `json:"block"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, m := range v.Block {
			if !moduleRe.MatchString(m) {
				bad("invalid module name %q", m)
			}
		}
		p.Extra.KernelModules = v.Block
	case TypeSSH:
		var v struct {
			Options map[string]string `json:"options"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for k, val := range v.Options {
			if !sshAllowed[strings.ToLower(k)] || !sshValRe.MatchString(val) {
				bad("sshd option %q is not allowed or has an invalid value", k)
			}
		}
		p.Extra.SSH = v.Options
	case TypeBanner:
		var v Banner
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		if !noControl(v.Issue, 4096) || !noControl(v.Motd, 4096) {
			bad("banner texts must be plain text up to 4096 characters")
		}
		p.Extra.Banner = &v
	case TypeDNS:
		var v DNS
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, s := range v.Servers {
			if net.ParseIP(s) == nil {
				bad("DNS server %q must be an IP address", s)
			}
		}
		for _, dom := range v.Domains {
			if !hostRe.MatchString(dom) {
				bad("invalid search domain %q", dom)
			}
		}
		p.Extra.DNS = &v
	case TypeNTP:
		var v NTP
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		if len(v.Servers) == 0 {
			bad("at least one NTP server is required")
		}
		for _, s := range v.Servers {
			if !hostOrIP(s) {
				bad("invalid NTP server %q", s)
			}
		}
		p.Extra.NTP = &v
	case TypeProxy:
		var v Proxy
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		// values end up in shell, apt and dnf config files: allowlist only
		for _, u := range []string{v.HTTP, v.HTTPS} {
			if pu, err := url.Parse(u); u != "" && (err != nil || !proxyURLRe.MatchString(u) || pu.Host == "") {
				bad("invalid proxy URL %q", u)
			}
		}
		if !noProxyRe.MatchString(v.NoProxy) {
			bad("no_proxy must be a comma separated list of hosts, domains or networks")
		}
		p.Extra.Proxy = &v
	case TypeFlatpak:
		var v Flatpak
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, r := range v.Remotes {
			if !nameRe.MatchString(r.Name) || !httpsURL(r.URL) {
				bad("flatpak remote %q needs a name and an https URL", r.Name)
			}
			if r.Scope != "" && r.Scope != "system" && r.Scope != "user" {
				bad("flatpak remote %q: scope is system or user", r.Name)
			}
		}
		for _, ref := range append(append([]string{}, v.Install...), v.Remove...) {
			if !flatpakRef.MatchString(ref) {
				bad("invalid flatpak application ID %q", ref)
			}
		}
		p.Extra.Flatpak = &v
	case TypeScripts:
		var v struct {
			Scripts []Script `json:"scripts"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for _, sc := range v.Scripts {
			if !nameRe.MatchString(sc.Name) || sc.IntervalHours < 1 || sc.IntervalHours > 24*30 || sc.Body == "" || len(sc.Body) > 64<<10 {
				bad("script %q: name, interval 1..720 hours and a body up to 64 KiB are required", sc.Name)
			}
			if err := ValidateScriptParams(sc.Params, sc.TimeoutMinutes); err != nil {
				bad("script %q: %v", sc.Name, err)
			}
		}
		p.Extra.Scripts = v.Scripts
	case TypeLocalUsers:
		var v struct {
			Users []LocalUser `json:"users"`
		}
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for i, u := range v.Users {
			if !localUserRe.MatchString(u.Name) || u.Name == "root" || slices.ContainsFunc(v.Users[:i], func(o LocalUser) bool { return o.Name == u.Name }) {
				bad("local user %q: lower case name, not root, each once", u.Name)
			}
			if u.UID < 0 || u.UID > 60000 || u.UID != 0 && u.UID < 1000 {
				bad("local user %s: uid 1000..60000 or unset", u.Name)
			}
			if len(u.FullName) > 100 || strings.ContainsAny(u.FullName, ":\n\r\x00,") {
				bad("local user %s: full name up to 100 characters, no colon or comma", u.Name)
			}
			if u.Shell != "" && (!shellRe.MatchString(u.Shell) || strings.Contains(u.Shell, "..")) {
				bad("local user %s: shell must be an absolute path", u.Name)
			}
			if len(u.Groups) > 32 || len(u.AuthorizedKeys) > 100 {
				bad("local user %s: at most 32 groups and 100 keys", u.Name)
			}
			for _, g := range u.Groups {
				if !userRe.MatchString(g) || g == "root" {
					bad("local user %s: invalid group %q", u.Name, g)
				}
			}
			for _, k := range u.AuthorizedKeys {
				if len(k) > 16<<10 || !sshKeyRe.MatchString(k) {
					bad("local user %s: authorized key must be \"type base64 [comment]\" without options", u.Name)
				}
			}
		}
		p.Extra.LocalUsers = v.Users
	case TypeDconf:
		var v Dconf
		if err := strict(d.Payload, &v); err != nil {
			return true, err
		}
		for k, val := range v.Settings {
			// a key needs a directory: /dir/key; values are GVariant text on one line
			if !dconfKeyRe.MatchString(k) || strings.Count(k, "/") < 2 || val == "" || !noControl(val, 1024) || strings.ContainsAny(val, "\n\t") {
				bad("dconf %q: key path /dir/key and a one line GVariant value up to 1024 characters", k)
			}
		}
		for _, l := range v.Locks {
			if !dconfKeyRe.MatchString(strings.TrimSuffix(l, "/")) {
				bad("dconf lock %q: a key path or a directory ending in /", l)
			}
		}
		p.Extra.Dconf = &v
	default:
		return d.applySecurity(p)
	}
	return true, errors.Join(errs...)
}

// mergeExtra merges list types of the additional library types.
func mergeExtra(typ string, a, b json.RawMessage) (json.RawMessage, bool, error) {
	byName := func(key string) (json.RawMessage, error) {
		// only the list itself: other fields of the payload (repositories'
		// "disable") have other shapes
		list := func(raw json.RawMessage) ([]map[string]any, error) {
			var m map[string]json.RawMessage
			var l []map[string]any
			if err := json.Unmarshal(raw, &m); err != nil || len(m[key]) == 0 {
				return nil, err
			}
			return l, json.Unmarshal(m[key], &l)
		}
		out, errA := list(a)
		in, errB := list(b)
		if err := errors.Join(errA, errB); err != nil {
			return nil, err
		}
		for _, it := range in {
			replaced := false
			for i, e := range out {
				if e["name"] == it["name"] {
					out[i], replaced = it, true
				}
			}
			if !replaced {
				out = append(out, it)
			}
		}
		return json.Marshal(map[string]any{key: out})
	}
	mergeMap := func(key string) (json.RawMessage, error) {
		var x, y map[string]map[string]string
		if err := errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err != nil {
			return nil, err
		}
		m := map[string]string{}
		for k, v := range x[key] {
			m[k] = v
		}
		for k, v := range y[key] {
			m[k] = v
		}
		return json.Marshal(map[string]any{key: m})
	}
	var out json.RawMessage
	var err error
	switch typ {
	case TypeRepositories:
		if out, err = byName("repositories"); err == nil {
			var x, y, o map[string]json.RawMessage
			var dx, dy []string
			err = errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y), json.Unmarshal(out, &o))
			if err == nil {
				for _, src := range []struct {
					raw json.RawMessage
					dst *[]string
				}{{x["disable"], &dx}, {y["disable"], &dy}} {
					if len(src.raw) > 0 && err == nil {
						err = json.Unmarshal(src.raw, src.dst)
					}
				}
				if d := union(dx, dy); len(d) > 0 && err == nil {
					o["disable"], _ = json.Marshal(d)
				}
				out, err = json.Marshal(o)
			}
		}
	case TypeCertificates:
		out, err = byName("certificates")
	case TypeScripts:
		out, err = byName("scripts")
	case TypeLocalUsers:
		out, err = byName("users")
	case TypeSysctl:
		out, err = mergeMap("settings")
	case TypeSSH:
		out, err = mergeMap("options")
	case TypeDconf:
		var x, y Dconf
		if err = errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err == nil {
			m := map[string]string{}
			for k, v := range x.Settings {
				m[k] = v
			}
			for k, v := range y.Settings {
				m[k] = v
			}
			out, err = json.Marshal(Dconf{Settings: m, Locks: union(x.Locks, y.Locks)})
		}
	case TypeKernelModules:
		var x, y struct {
			Block []string `json:"block"`
		}
		if err = errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err == nil {
			out, err = json.Marshal(map[string]any{"block": union(x.Block, y.Block)})
		}
	case TypeFlatpak:
		var x, y Flatpak
		if err = errors.Join(json.Unmarshal(a, &x), json.Unmarshal(b, &y)); err == nil {
			// a later item wins for the same remote, as for every other list
			remotes := slices.Clone(x.Remotes)
			for _, r := range y.Remotes {
				if i := slices.IndexFunc(remotes, func(e FlatpakRemote) bool {
					return e.Name == r.Name && e.InstallationScope() == r.InstallationScope()
				}); i >= 0 {
					remotes[i] = r
				} else {
					remotes = append(remotes, r)
				}
			}
			rm := union(x.Remove, y.Remove)
			out, err = json.Marshal(Flatpak{Remotes: remotes, Install: without(union(x.Install, y.Install), rm), Remove: rm})
		}
	default:
		return mergeSecurity(typ, a, b)
	}
	return out, true, err
}

// sysctlForbidden lists kernel parameters that name programs the kernel runs
// as root; setting them would be remote code execution outside allow_scripts.
func sysctlForbidden(key string) bool {
	switch {
	case key == "kernel.modprobe", key == "kernel.core_pattern", key == "kernel.poweroff_cmd", key == "kernel.hotplug",
		strings.HasPrefix(key, "kernel.usermodehelper."), strings.HasPrefix(key, "fs.binfmt_misc."):
		return true
	}
	return false
}
