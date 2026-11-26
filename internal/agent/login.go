package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/maltekiefer/limdm/internal/api"
)

// Desktop login with an OIDC provider (Google Workspace or any provider that
// supports the device authorization grant, RFC 8628).
//
// pam_exec runs `limdm-agent pam-auth` before pam_unix. For centrally managed
// users it shows a verification URL and code via the PAM conversation, waits for
// the user to approve on a phone or second device, then verifies the ID token
// (signature, issuer, audience, email, hosted domain) against the user mapping.
// Unmanaged local users fall through to the normal password stack.
//
// ponytail: no offline login for managed users; add a cached credential when devices are often offline.

const (
	usersFile = "/etc/limdm/users.json" // username -> email
	loginFile = "/etc/limdm/login.json" // api.Login incl. client secret, root only
	pamDebian = "/usr/share/pam-configs/limdm"
	pamMarker = "/var/lib/limdm/pam.installed"
	authPrev  = "/var/lib/limdm/authselect.prev"
)

func readUsers() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(usersFile)
	if err == nil && json.Unmarshal(b, &m) != nil {
		return map[string]string{} // corrupt mapping: nobody is managed, local passwords still work
	}
	return m
}

// applyUsers creates managed accounts, syncs admin group membership and
// locks accounts that were removed centrally (home directories are kept).
func (a *Agent) applyUsers() error {
	if !a.pol.Login.Enabled {
		return a.disableLogin()
	}
	var errs []error
	group := a.host.adminGroup()
	admins := groupMembers(group)
	prev := readUsers()
	cur := map[string]string{}
	for _, u := range a.users {
		if err := u.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		cur[u.Username] = strings.ToLower(u.Email)
		if _, err := user.Lookup(u.Username); err != nil {
			if _, err := sh("useradd", "-m", "-s", "/bin/bash", "-c", u.Email, u.Username); err != nil {
				errs = append(errs, err)
				continue
			}
			a.event("created user %s (%s)", u.Username, u.Email)
		} else if _, ok := prev[u.Username]; (!ok || accountExpired(u.Username)) && !a.state.UserLocked[u.Username] {
			if _, err := sh("usermod", "-e", "", u.Username); err != nil { // re-enable after an earlier removal
				errs = append(errs, err)
			}
		}
		isAdmin := slices.Contains(admins, u.Username)
		switch {
		case u.Admin && !isAdmin:
			if _, err := sh("usermod", "-aG", group, u.Username); err != nil {
				errs = append(errs, err)
			} else {
				a.event("granted admin to %s", u.Username)
			}
		case !u.Admin && isAdmin:
			if _, err := sh("gpasswd", "-d", u.Username, group); err != nil {
				errs = append(errs, err)
			} else {
				a.event("revoked admin from %s", u.Username)
			}
		}
	}
	// removed users: locked and forgotten; a failed lock is retried next cycle
	if a.state.RemovePending == nil {
		a.state.RemovePending = map[string]bool{}
	}
	for name := range prev {
		if _, keep := cur[name]; !keep {
			a.state.RemovePending[name] = true
		}
	}
	for name := range a.state.RemovePending {
		if _, back := cur[name]; back {
			delete(a.state.RemovePending, name)
			continue
		}
		_, _ = sh("gpasswd", "-d", name, group) // fails when not a member, that is fine
		if _, err := sh("usermod", "-L", "-e", "1", name); err != nil {
			errs = append(errs, err)
			continue
		}
		_, _ = sh("loginctl", "terminate-user", name) // disabled in the directory: running sessions end too
		forgetSSO(name)                               // coming back later must not skip the SSO confirmation
		delete(a.state.RemovePending, name)
		a.event("locked removed user %s", name)
	}
	b, _ := json.Marshal(cur)
	if _, err := writeIfChanged(usersFile, string(b), 0o600); err != nil {
		errs = append(errs, err)
	}
	lb, _ := json.Marshal(pamPolicy{Login: a.pol.Login, OfflineLockHours: a.pol.OfflineLockHours})
	if _, err := writeIfChanged(loginFile, string(lb), 0o600); err != nil {
		errs = append(errs, err)
	}
	if err := a.installPAM(); err != nil {
		errs = append(errs, err)
	}
	a.syncPasswordLocks()
	return errors.Join(errs...)
}

func accountExpired(name string) bool {
	for _, f := range shadowEntries() {
		if f[0] == name && len(f) > 7 && f[7] == "1" {
			return true
		}
	}
	return false
}

// disableLogin undoes the desktop login when its declaration is gone: the PAM
// hook, and the password locks the SSO rules set. Without this, the policy
// file left behind kept locking managed users with no SSO left to unlock them.
func (a *Agent) disableLogin() error {
	if _, ok := readPAMPolicy(); !ok && !pamInstalled() {
		return nil
	}
	err := a.removePAM()
	if deviceLocked() || a.state.OfflineLocked {
		return err // the device lock decides now; the release follows after the unlock
	}
	for user := range readUsers() {
		if passwordLocked(user) && !a.state.UserLocked[user] {
			// fails for accounts that never had a password; those need a reset
			if _, uerr := sh("usermod", "-U", user); uerr == nil {
				a.event("local password of %s unlocked: desktop login switched off", user)
			}
		}
	}
	// users.json stays: when the login comes back, people removed meanwhile
	// are still recognized as removed and locked
	if rerr := os.Remove(loginFile); rerr != nil && !os.IsNotExist(rerr) {
		err = errors.Join(err, rerr)
	}
	return err
}

func pamInstalled() bool { return exists(pamMarker) }

// pamActive checks the generated PAM stack, not just our marker, so a profile
// removed by pam-auth-update or authselect is detected and reinstalled.
func pamActive() bool {
	for _, f := range []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/base-auth"} {
		for l := range strings.SplitSeq(readFile(f), "\n") {
			if strings.Contains(l, "pam_exec.so") && strings.Contains(l, " pam-auth") {
				// older installs lack expose_authtok or the "auth" type and are replaced
				return strings.HasPrefix(strings.TrimSpace(l), "auth") && strings.Contains(l, "expose_authtok")
			}
		}
	}
	return false
}

func pamLine(exe string) string {
	return "pam_exec.so quiet stdout expose_authtok " + exe + " pam-auth"
}

func (a *Agent) installPAM() error {
	if pamInstalled() && pamActive() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if a.host.family == "debian" {
		// the profile ships with the package (/usr/share is package owned);
		// only older installs without it get it written here
		if !exists(pamDebian) {
			cfg := fmt.Sprintf("Name: LiMDM OIDC login\nDefault: no\nPriority: 300\nAuth-Type: Primary\nAuth:\n\t[success=end default=ignore]\t%s\n", pamLine(exe))
			if _, err := writeIfChanged(pamDebian, cfg, 0o644); err != nil {
				return err
			}
		}
		if _, err := sh("pam-auth-update", "--package", "--enable", "limdm"); err != nil {
			return err
		}
	} else if f := pamStackFile(a.host.family); f != "" {
		if err := editPAMStack(f, "auth       sufficient   "+pamLine(exe)); err != nil {
			return err
		}
	} else if a.host.family != "fedora" {
		return errors.New("no PAM stack found (Alpine needs linux-pam)")
	} else if err := authselectInstall(exe); err != nil {
		return err
	}
	a.event("installed PAM OIDC login")
	return os.WriteFile(pamMarker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

func (a *Agent) removePAM() error {
	if !pamInstalled() {
		return nil
	}
	if a.host.family == "debian" {
		if _, err := sh("pam-auth-update", "--package", "--remove", "limdm"); err != nil {
			return err
		}
	} else if f := pamStackFile(a.host.family); f != "" {
		if err := restorePAMStack(f); err != nil {
			return err
		}
	} else {
		prev := strings.Fields(readTrim(authPrev))
		if len(prev) == 0 {
			prev = []string{"local"}
		}
		if _, err := sh("authselect", append([]string{"select"}, append(prev, "--force")...)...); err != nil {
			return err
		}
	}
	a.event("removed PAM OIDC login")
	return os.Remove(pamMarker)
}

// authselectInstall clones the current authselect profile into custom/limdm and
// inserts the pam_exec line into system-auth and password-auth.
func authselectInstall(exe string) error {
	cur, err := sh("authselect", "current", "--raw")
	if err != nil {
		return err
	}
	fields := strings.Fields(cur)
	if len(fields) == 0 {
		return errors.New("authselect: no profile selected")
	}
	if fields[0] != "custom/limdm" {
		if err := os.WriteFile(authPrev, []byte(strings.Join(fields, " ")), 0o600); err != nil {
			return err
		}
		if !exists("/etc/authselect/custom/limdm") {
			if _, err := sh("authselect", "create-profile", "limdm", "-b", fields[0]); err != nil {
				return err
			}
		}
	}
	for _, f := range []string{"system-auth", "password-auth"} {
		p := "/etc/authselect/custom/limdm/" + f
		patched, err := insertPAMLine(readFile(p), "auth        sufficient                                   "+pamLine(exe))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if _, err := writeIfChanged(p, patched, 0o644); err != nil {
			return err
		}
	}
	_, err = sh("authselect", append([]string{"select", "custom/limdm"}, append(fields[1:], "--force")...)...)
	return err
}

// insertPAMLine puts line before the first auth module that actually
// authenticates (after pam_env, pam_faildelay and faillock preauth).
func insertPAMLine(content, line string) (string, error) {
	if strings.Contains(content, line) {
		return content, nil
	}
	lines := slices.DeleteFunc(strings.Split(content, "\n"), func(l string) bool { // drop an older version of our line
		return strings.Contains(l, "pam_exec.so") && strings.Contains(l, " pam-auth")
	})
	for i, l := range lines {
		f := strings.Fields(l)
		// "-auth" too: a line inserted after pam_systemd_home's
		// [success=2] would shift its jump onto pam_faillock authfail
		if len(f) < 3 || f[0] != "auth" && f[0] != "-auth" {
			continue
		}
		if strings.Contains(l, "pam_env.so") || strings.Contains(l, "pam_faildelay.so") || strings.Contains(l, "pam_faillock.so") {
			continue
		}
		return strings.Join(slices.Insert(lines, i, line), "\n"), nil
	}
	return "", errors.New("no auth module found")
}

// PAMAuth is the pam_exec entry point. Exit code 0 grants access; 1 hands
// over to pam_unix, which only accepts a local password the agent left unlocked.
func PAMAuth() int {
	if os.Getenv("PAM_TYPE") != "auth" {
		return 1
	}
	pw := readAuthtok()
	if !localService(os.Getenv("PAM_SERVICE"), os.Getenv("PAM_RHOST")) {
		return 1 // remote or unknown service: never start a device flow, pam_unix decides
	}
	username := os.Getenv("PAM_USER")
	email, ok := readUsers()[username]
	if !ok {
		return 1 // not centrally managed, fall through to local password
	}
	cfg, ok := readPAMPolicy()
	if !ok {
		return 1
	}
	now := time.Now()
	if s := readFile(nologinFile); s != "" {
		fmt.Print(s)
		return 1
	}
	if lastContactOverdue(cfg, now) {
		fmt.Print(offlineText)
		return 1
	}
	if !ssoLockWanted(cfg, username, now) && !passwordLocked(username) {
		return 1 // bound and not overdue: pam_unix checks the local password
	}
	if cfg.LocalPassword {
		if err := checkLocalPassword(username, pw); err != nil {
			fmt.Printf("SSO confirmation required. Enter the password you want to use on this device, then confirm on your phone: %v\n", err)
			return 1
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err := deviceLogin(ctx, cfg.Login, email)
	if err == nil && cfg.LocalPassword {
		if err = setLocalPassword(username, pw); err == nil {
			err = recordSSO(username, now)
		}
	}
	recordAuthEvent(username, email, err)
	if err != nil {
		fmt.Println("Login failed:", err)
		return 1
	}
	return 0
}

func deviceLogin(ctx context.Context, cfg api.Login, email string) error {
	flow, err := startDeviceFlow(ctx, cfg)
	if err != nil {
		return err
	}
	// the mapped email is not shown: the user is not authenticated yet
	fmt.Printf("Confirm the sign in with your company account:\nOpen %s and enter the code %s\n", flow.URI, flow.Code)
	return flow.finish(ctx, cfg, email)
}

// deviceFlow is a started OAuth device authorization: the user opens URI
// and enters Code, finish waits for the confirmation and checks the account.
type deviceFlow struct {
	URI, Code string
	provider  *oidc.Provider
	oc        oauth2.Config
	da        *oauth2.DeviceAuthResponse
}

func startDeviceFlow(ctx context.Context, cfg api.Login) (*deviceFlow, error) {
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, errors.New("identity provider unreachable")
	}
	ep := p.Endpoint()
	if ep.DeviceAuthURL == "" {
		return nil, errors.New("provider does not support the device authorization grant")
	}
	oc := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: ep,
		Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	da, err := oc.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	uri := da.VerificationURIComplete
	if uri == "" {
		uri = da.VerificationURI
	}
	return &deviceFlow{URI: uri, Code: da.UserCode, provider: p, oc: oc, da: da}, nil
}

func (f *deviceFlow) finish(ctx context.Context, cfg api.Login, email string) error {
	tok, err := f.oc.DeviceAccessToken(ctx, f.da)
	if err != nil {
		return errors.New("not confirmed")
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := f.provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return errors.New("invalid ID token")
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HD            string `json:"hd"`
	}
	if err := idt.Claims(&c); err != nil {
		return err
	}
	return checkIdentity(cfg.Issuer, c.Email, c.EmailVerified, c.HD, email, cfg.AllowedDomain)
}

func checkIdentity(issuer, gotEmail string, verified bool, hd, wantEmail, domain string) error {
	if !verified {
		return errors.New("email not verified")
	}
	if !strings.EqualFold(gotEmail, wantEmail) {
		return errors.New("account does not match this user")
	}
	if !api.DomainAllowed(issuer, gotEmail, hd, domain) {
		return errors.New("account is not in the allowed domain")
	}
	return nil
}

const authEvents = "/var/lib/limdm/auth-events.log"

func recordAuthEvent(username, email string, err error) {
	msg := fmt.Sprintf("%s login ok user=%s email=%s", time.Now().UTC().Format(time.RFC3339), username, email)
	if err != nil {
		msg = fmt.Sprintf("%s login failed user=%s email=%s: %v", time.Now().UTC().Format(time.RFC3339), username, email, err)
	}
	f, ferr := os.OpenFile(authEvents, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if ferr == nil {
		fmt.Fprintln(f, msg)
		f.Close()
	}
}

// pamServices run the SSO device flow: display managers, screen lockers, the
// text console and privilege prompts at the device. sshd and other remote
// services are excluded, so an unauthenticated network client can neither
// start a device flow (code phishing, a root process waiting on the IdP) nor
// learn which accounts are managed.
var pamServices = map[string]bool{
	"login": true, "gdm-password": true, "gdm-fingerprint": false, "lightdm": true, "sddm": true, "lxdm": true, "slim": true,
	"kde": true, "gnome-screensaver": true, "xscreensaver": true, "cinnamon-screensaver": true, "mate-screensaver": true,
	"xfce4-screensaver": true, "sudo": true, "sudo-i": true, "su": true, "su-l": true, "polkit-1": true,
	// greeters and lockers of compositors and window managers
	"greetd": true, "cosmic-greeter": true, "swaylock": true, "hyprlock": true, "gtklock": true, "waylock": true,
	"i3lock": true, "xsecurelock": true, "kscreensaver": true, "plasma-login": true, "lxqt-lockscreen": true,
}

func localService(service, rhost string) bool {
	if rhost != "" && rhost != "localhost" && rhost != "127.0.0.1" && rhost != "::1" {
		return false
	}
	return pamServices[service]
}

// pamStackFile is the shared auth stack edited directly on families without
// pam-auth-update or authselect: Arch's system-auth, Alpine's base-auth
// (with linux-pam), SUSE's common-auth. "" elsewhere. On SUSE common-auth
// links to pam-config's common-auth-pc; the target is edited so the link
// stays, and a pam-config run that drops the line is caught by pamActive.
func pamStackFile(family string) string {
	f := map[string]string{"arch": "/etc/pam.d/system-auth", "alpine": "/etc/pam.d/base-auth", "suse": "/etc/pam.d/common-auth"}[family]
	if f == "" || !exists(f) {
		return ""
	}
	if t, err := filepath.EvalSymlinks(f); err == nil {
		return t
	}
	return f
}

// editPAMStack inserts the hook before the first auth module and keeps the
// original next to the agent's state, so removal restores it exactly.
func editPAMStack(file, line string) error {
	orig := stateDir + "/pam-" + filepath.Base(file) + ".orig"
	cur := readFile(file)
	if !exists(orig) {
		if err := os.WriteFile(orig, []byte(cur), 0o600); err != nil {
			return err
		}
	}
	next, err := insertPAMLine(cur, line)
	if err != nil {
		return err
	}
	_, err = writeIfChanged(file, next, 0o644)
	return err
}

func restorePAMStack(file string) error {
	orig := stateDir + "/pam-" + filepath.Base(file) + ".orig"
	b, err := os.ReadFile(orig)
	if err != nil {
		// no backup: take only our line out
		lines := slices.DeleteFunc(strings.Split(readFile(file), "\n"), func(l string) bool {
			return strings.Contains(l, "pam_exec.so") && strings.Contains(l, " pam-auth")
		})
		_, err = writeIfChanged(file, strings.Join(lines, "\n"), 0o644)
		return err
	}
	if _, err := writeIfChanged(file, string(b), 0o644); err != nil {
		return err
	}
	return os.Remove(orig)
}
