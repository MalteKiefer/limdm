package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"os/user"
	"syscall"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// Remote support shell: the signed "shell" command makes the agent open an
// outbound mTLS request to the server and run a login shell on a PTY behind
// it. No port is opened on the device. Only when the device's policy allows
// it (com.limdm.agent remote_shell) or, from older enrollments, the local
// allow_remote_shell; one session at a time.

const supportUser = "limdm-support"

type runningShell struct {
	cancel context.CancelCauseFunc
	info   string // shown in the desktop status
}

// startShell checks the command and starts the session in the background.
func (a *Agent) startShell(c api.Command) (string, error) {
	if !a.pol.RemoteShell && !a.cfg.AllowRemoteShell {
		return "", errors.New("remote shells are not allowed by the device's policy (Agent: remote shell)")
	}
	if a.state.CommandKey == "" { // unsigned commands run before a key is pinned; a shell never does
		return "", errors.New("remote shells need a pinned command signing key")
	}
	if time.Since(c.CreatedAt) > 10*time.Minute {
		return "", errors.New("the session request is older than 10 minutes")
	}
	var sc api.ShellCommand
	dec := json.NewDecoder(bytes.NewReader([]byte(c.Payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return "", fmt.Errorf("invalid shell command: %w", err)
	}
	if err := sc.Validate(); err != nil {
		return "", err
	}
	account, err := shellAccount(sc.User, sc.AllowRoot)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	rs := &runningShell{cancel: cancel, info: fmt.Sprintf("%s, user %s, since %s", sc.By, account, time.Now().Format("15:04"))}
	if !a.shell.CompareAndSwap(nil, rs) {
		cancel(nil)
		return "", errors.New("a remote shell session is already running")
	}
	company := a.company()
	go a.runShell(ctx, rs, sc, account, company)
	return "remote shell session started as " + account, nil
}

// shellAccount resolves the local account; empty means the support account,
// created on first use (system account, locked password).
func shellAccount(name string, allowRoot bool) (string, error) {
	if name == "" {
		name = supportUser
		if _, err := user.Lookup(name); err != nil {
			if _, err := sh("useradd", "--system", "--create-home", "--home-dir", "/var/lib/"+supportUser,
				"--shell", "/bin/bash", "--comment", "LiMDM remote support", supportUser); err != nil {
				return "", fmt.Errorf("create the support account: %w", err)
			}
		}
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("no local account %q", name)
	}
	// without AllowRoot no account that reaches root: uid 0 under any name,
	// admin groups and sudo rules (NOPASSWD included)
	if why := privileged(u.Username); why != "" && !allowRoot {
		return "", errors.New("root shells are not allowed: " + why)
	}
	return name, nil
}

func (a *Agent) runShell(ctx context.Context, rs *runningShell, sc api.ShellCommand, account, company string) {
	defer a.shell.CompareAndSwap(rs, nil)
	ctx, cancel := context.WithTimeoutCause(ctx, time.Duration(sc.MaxMinutes)*time.Minute, errors.New("maximum duration reached"))
	defer cancel()
	a.event("remote shell as %s opened by %s", account, sc.By)
	notifyAs(company, urgent, "Remote support session started",
		"%s (%s) opened a terminal on this device as %s. It ends after at most %d minutes. To end it now, run: limdm support end",
		company, sc.By, account, sc.MaxMinutes)
	err := a.relayShell(ctx, rs.cancel, sc, account)
	if err == nil {
		err = context.Cause(ctx)
	}
	a.event("remote shell as %s opened by %s ended: %v", account, sc.By, err)
	notifyAs(company, normal, "Remote support session ended", "The terminal opened by %s has ended.", sc.By)
}

// relayShell runs the login shell and copies between the PTY and the server
// until ctx ends or one side closes.
func (a *Agent) relayShell(ctx context.Context, stop context.CancelCauseFunc, sc api.ShellCommand, account string) error {
	master, slave, err := openPTY()
	if err != nil {
		return err
	}
	defer master.Close()
	cmd := exec.CommandContext(ctx, "runuser", "-l", account)
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP) } // the whole session, see below
	cmd.Env = []string{"TERM=xterm-256color", "LANG=C.UTF-8", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true} // Ctty 0: stdin
	if err := cmd.Start(); err != nil {
		slave.Close()
		return fmt.Errorf("start the shell: %w", err)
	}
	slave.Close()
	exited := make(chan struct{})
	go func() {
		err := cmd.Wait()
		stop(fmt.Errorf("the shell exited: %w", err))
		close(exited)
	}()
	defer func() {
		// the whole session: the shell and what it started (setsid made its pid the group)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-exited
		}
	}()

	pr, pw := io.Pipe()
	go func() { // PTY output → server
		_, err := io.Copy(pw, master)
		pw.CloseWithError(err)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/api/v1/shell/"+sc.Session, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	// no client timeout: the session lasts up to MaxMinutes, ctx bounds it
	resp, err := (&http.Client{Transport: a.client.Transport}).Do(req) //nolint:bodyclose // closed by the defer below
	if err != nil {
		return fmt.Errorf("connect to the server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiError("/api/v1/shell", resp)
	}
	idle := time.Duration(sc.IdleMinutes) * time.Minute
	idleT := time.AfterFunc(idle, func() { stop(errors.New("idle timeout")) })
	defer idleT.Stop()
	go func() { // server → PTY
		for {
			typ, p, err := api.ReadShellFrame(resp.Body)
			if err != nil {
				stop(errors.New("the session was ended by the server or in the console"))
				return
			}
			switch typ {
			case api.ShellInput:
				idleT.Reset(idle)
				if _, err := master.Write(p); err != nil {
					stop(err)
					return
				}
			case api.ShellResize:
				_ = setWinsize(master, uint16(p[0])<<8|uint16(p[1]), uint16(p[2])<<8|uint16(p[3]))
			}
		}
	}()
	<-ctx.Done()
	return nil
}

// endShell ends the running session, if any (desktop user, limdm support end).
func (a *Agent) endShell(reason string) bool {
	rs := a.shell.Load()
	if rs == nil {
		return false
	}
	rs.cancel(errors.New(reason))
	return true
}

// shellInfo describes the running session for the desktop status.
func (a *Agent) shellInfo() string {
	if rs := a.shell.Load(); rs != nil {
		return rs.info
	}
	return ""
}
