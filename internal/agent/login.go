package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
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
		return a.removePAM()
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
		} else if _, ok := prev[u.Username]; !ok || accountExpired(u.Username) {
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
	for name := range prev {
		if _, keep := cur[name]; !keep {
			_, _ = sh("gpasswd", "-d", name, group) // fails when not a member, that is fine
			if _, err := sh("usermod", "-L", "-e", "1", name); err != nil {
				errs = append(errs, err)
			} else {
				a.event("locked removed user %s", name)
			}
		}
	}
	b, _ := json.Marshal(cur)
	if _, err := writeIfChanged(usersFile, string(b), 0o600); err != nil {
		errs = append(errs, err)
	}
	lb, _ := json.Marshal(a.pol.Login) //nolint:gosec // client secret goes to a root only 0600 file for pam-auth
	if _, err := writeIfChanged(loginFile, string(lb), 0o600); err != nil {
		errs = append(errs, err)
	}
	if err := a.installPAM(); err != nil {
		errs = append(errs, err)
	}
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

func pamInstalled() bool { return exists(pamMarker) }

// pamActive checks the generated PAM stack, not just our marker, so a profile
// removed by pam-auth-update or authselect is detected and reinstalled.
func pamActive() bool {
	for _, f := range []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth"} {
		if s := readFile(f); strings.Contains(s, "pam_exec.so") && strings.Contains(s, " pam-auth") {
			return true
		}
	}
	return false
}

func pamLine(exe string) string {
	return "pam_exec.so quiet stdout " + exe + " pam-auth"
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
		cfg := fmt.Sprintf("Name: LiMDM OIDC login\nDefault: yes\nPriority: 300\nAuth-Type: Primary\nAuth:\n\t[success=end default=ignore]\t%s\n", pamLine(exe))
		if _, err := writeIfChanged(pamDebian, cfg, 0o644); err != nil {
			return err
		}
		if _, err := sh("pam-auth-update", "--package", "--enable", "limdm"); err != nil {
			return err
		}
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
		os.Remove(pamDebian)
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
	if strings.Contains(content, "pam-auth") && strings.Contains(content, "pam_exec.so") {
		return content, nil
	}
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "auth" {
			continue
		}
		if strings.Contains(l, "pam_env.so") || strings.Contains(l, "pam_faildelay.so") || strings.Contains(l, "pam_faillock.so") {
			continue
		}
		return strings.Join(slices.Insert(lines, i, line), "\n"), nil
	}
	return "", errors.New("no auth module found")
}

// PAMAuth is the pam_exec entry point. Exit code 0 grants access.
func PAMAuth() int {
	if os.Getenv("PAM_TYPE") != "auth" {
		return 1
	}
	username := os.Getenv("PAM_USER")
	email, ok := readUsers()[username]
	if !ok {
		return 1 // not centrally managed, fall through to local password
	}
	var cfg api.Login
	b, err := os.ReadFile(loginFile)
	if err != nil || json.Unmarshal(b, &cfg) != nil || !cfg.Enabled {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err = deviceLogin(ctx, cfg, email)
	recordAuthEvent(username, email, err)
	if err != nil {
		fmt.Println("Login failed:", err)
		return 1
	}
	return 0
}

func deviceLogin(ctx context.Context, cfg api.Login, email string) error {
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return errors.New("identity provider unreachable")
	}
	ep := p.Endpoint()
	if ep.DeviceAuthURL == "" {
		return errors.New("provider does not support the device authorization grant")
	}
	oc := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: ep,
		Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	da, err := oc.DeviceAuth(ctx)
	if err != nil {
		return fmt.Errorf("device authorization: %w", err)
	}
	uri := da.VerificationURIComplete
	if uri == "" {
		uri = da.VerificationURI
	}
	fmt.Printf("Sign in as %s:\nOpen %s and enter the code %s\n", email, uri, da.UserCode)
	tok, err := oc.DeviceAccessToken(ctx, da)
	if err != nil {
		return errors.New("not confirmed")
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
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
	return checkIdentity(c.Email, c.EmailVerified, c.HD, email, cfg.AllowedDomain)
}

func checkIdentity(gotEmail string, verified bool, hd, wantEmail, domain string) error {
	if !verified {
		return errors.New("email not verified")
	}
	if !strings.EqualFold(gotEmail, wantEmail) {
		return errors.New("account does not match this user")
	}
	if domain != "" && !strings.EqualFold(hd, domain) && !strings.HasSuffix(strings.ToLower(gotEmail), "@"+strings.ToLower(domain)) {
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
