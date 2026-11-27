package server

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/maltekiefer/limdm/internal/api"
)

// Remote shell for support. A console user starts a session on the device
// page; the server stores it, sends the signed "shell" command and relays
// between the console (WebSocket on the console listener) and the agent
// (POST /api/v1/shell/{id} over mTLS, opened by the device). Every session is
// audited and its output is kept as a transcript. With several server
// instances, console and device may reach other instances than the one
// holding the session; those relay to it (shellrelay.go).

const (
	shellTranscriptCap = 1 << 20         // bytes of output kept per session
	shellConnectWait   = 3 * time.Minute // the device polls every minute
)

// RemoteShellSettings are the server side switches of the remote shell. A
// device additionally needs allow_remote_shell at enrollment.
type RemoteShellSettings struct {
	Enabled     bool `json:"enabled,omitempty"`
	Helpdesk    bool `json:"helpdesk,omitempty"`   // the helpdesk role may start sessions
	AllowRoot   bool `json:"allow_root,omitempty"` // sessions may run as root
	MaxMinutes  int  `json:"max_minutes,omitempty"`
	IdleMinutes int  `json:"idle_minutes,omitempty"`
}

// Limits returns the effective maximum duration and idle timeout in minutes.
func (r RemoteShellSettings) Limits() (maxM, idleM int) {
	maxM, idleM = r.MaxMinutes, r.IdleMinutes
	if maxM == 0 {
		maxM = 60
	}
	if idleM == 0 {
		idleM = min(15, maxM)
	}
	return maxM, idleM
}

func (r RemoteShellSettings) validate() error {
	maxM, idleM := r.Limits()
	if maxM < 5 || maxM > 480 || idleM < 1 || idleM > 120 || idleM > maxM {
		return errors.New("remote shell: maximum duration 5 to 480 minutes, idle timeout 1 to 120 minutes and not longer than the maximum")
	}
	return nil
}

// allows reports whether a console role may start sessions.
func (r RemoteShellSettings) allows(role string) bool {
	return r.Enabled && (role == "admin" || role == "helpdesk" && r.Helpdesk)
}

// errAwaitingApproval: the action was requested and waits for a second admin.
var errAwaitingApproval = errors.New("the action waits for approval")

// requireApproval applies four eyes approval (approvals.go) to a remote
// shell when the setting asks for it. The approval names the local user, so
// an approval for one account never opens a shell as another. It returns the
// approved request for useApproval (0 when no approval is needed); otherwise
// a request is filed (once) and errAwaitingApproval returned.
func (s *Server) requireApproval(ctx context.Context, sess session, action, target, user string) (int64, error) { //nolint:unparam // the E3 hook takes the action name
	if action != "remote_shell" || !s.settings().FourEyesShell {
		return 0, nil
	}
	var id int64
	err := s.db.QueryRow(ctx, `SELECT id FROM approvals WHERE action=$1 AND target=$2 AND requested_by=$3 AND payload->>'user'=$4
		AND status='approved' AND expires_at > now() ORDER BY id DESC LIMIT 1`, action, target, sess.Email, user).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	var pending bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM approvals WHERE action=$1 AND target=$2 AND requested_by=$3
		AND payload->>'user'=$4 AND status='pending' AND expires_at > now())`, action, target, sess.Email, user).Scan(&pending); err != nil {
		return 0, err
	}
	if !pending {
		if _, err := s.requestApproval(ctx, sess, action, target, map[string]string{"user": user}, ""); err != nil {
			return 0, err
		}
	}
	return 0, errAwaitingApproval
}

// useApproval marks an approved request as used in the transaction that
// starts the action, so a failed start keeps the approval.
func useApproval(ctx context.Context, tx pgx.Tx, id int64) error {
	if id == 0 {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE approvals SET status='used' WHERE id=$1 AND status='approved' AND expires_at > now()`, id)
	if err == nil && tag.RowsAffected() != 1 {
		err = errAwaitingApproval
	}
	return err
}

type shellHub struct {
	mu   sync.Mutex
	live map[string]*liveShell
}

type liveShell struct {
	id, device, owner string
	cmdID             int64
	inR               *io.PipeReader // frames for the agent
	inW               *io.PipeWriter
	outR              *io.PipeReader // terminal output for the console
	outW              *io.PipeWriter
	agentUp           chan struct{} // closed when the device connected
	done              chan struct{} // closed when the session ended
	activity          chan struct{} // console input, resets the idle timer
	stored            chan struct{} // closed once the end is in the database

	mu             sync.Mutex
	agent, console bool
	transcript     []byte
	truncated      bool
	reason         string
}

func newLiveShell(id, device, owner string, cmdID int64) *liveShell {
	l := &liveShell{id: id, device: device, owner: owner, cmdID: cmdID,
		agentUp: make(chan struct{}), done: make(chan struct{}), activity: make(chan struct{}, 1), stored: make(chan struct{})}
	l.inR, l.inW = io.Pipe()
	l.outR, l.outW = io.Pipe()
	return l
}

// end stops the session once; the first reason wins.
func (l *liveShell) end(reason string) {
	l.mu.Lock()
	if l.reason != "" {
		l.mu.Unlock()
		return
	}
	l.reason = reason
	l.mu.Unlock()
	close(l.done)
	_ = l.inW.Close()
	_ = l.inR.Close()
	_ = l.outW.Close()
	_ = l.outR.Close()
}

func (l *liveShell) record(p []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := shellTranscriptCap - len(l.transcript); room < len(p) {
		p, l.truncated = p[:max(room, 0)], true
	}
	l.transcript = append(l.transcript, p...)
}

func (h *shellHub) get(id string) *liveShell {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.live[id]
}

func (h *shellHub) put(l *liveShell) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.live == nil {
		h.live = map[string]*liveShell{}
	}
	h.live[l.id] = l
}

func (h *shellHub) remove(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.live, id)
}

// refused ends the session of a shell command the device did not run, if
// this instance holds it.
func (h *shellHub) refused(cmdID int64, reason string) bool {
	h.mu.Lock()
	var hit *liveShell
	for _, l := range h.live {
		if l.cmdID == cmdID {
			hit = l
		}
	}
	h.mu.Unlock()
	if hit != nil {
		hit.end(reason)
	}
	return hit != nil
}

func (s *Server) shellRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /shell/{sid}/ws", s.shellWS)
}

func (s *Server) shellAgentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/shell/{sid}", s.deviceAuth(s.shellAgent, false))
}

type shellRow struct {
	ID, Device, Hostname, By, User, Reason, State string
	Created                                       time.Time
	Connected, Ended                              *time.Time
	Bytes                                         int
	Truncated                                     bool
}

const shellCols = `s.id, s.device_id, d.hostname, s.requested_by, s.local_user, s.end_reason, s.created_at, s.connected_at, s.ended_at,
	octet_length(s.transcript), s.truncated,
	coalesce((SELECT i.seen_at > now() - interval '` + instanceAlive + `' FROM server_instances i WHERE i.id = s.instance), false)`

func (s *Server) scanShell(row pgx.Row) (shellRow, error) {
	var r shellRow
	var alive bool // the instance holding the session runs
	err := row.Scan(&r.ID, &r.Device, &r.Hostname, &r.By, &r.User, &r.Reason, &r.Created, &r.Connected, &r.Ended, &r.Bytes, &r.Truncated, &alive)
	switch {
	case r.Ended != nil:
		r.State = "ended"
	case s.shells.get(r.ID) == nil && !alive:
		r.State = "interrupted" // the server instance stopped while it ran
	case r.Connected != nil:
		r.State = "active"
	default:
		r.State = "waiting for the device"
	}
	return r, err
}

// shellErrors are shown after a refused start; only the key travels in the URL.
var shellErrors = map[string]string{
	"user": "Invalid user name.", "root": "Root sessions are not allowed in the settings.", "approval": "The session waits for approval.",
	"admin": privilegedShellAccount,
}

// startShell starts a remote shell session on a device for the caller and
// returns its id. A refused start names its key in shellErrors ("approval":
// the session waits for four eyes approval and was requested).
func (s *Server) startShell(ctx context.Context, sess session, id, localUser string) (sid, refused string, err error) {
	set := s.settings().RemoteShell
	if !set.allows(sess.Role) {
		return "", "", &userError{http.StatusForbidden, "remote shell is not enabled for your role"}
	}
	var retired bool
	if err := s.db.QueryRow(ctx, `SELECT retired FROM devices WHERE id=$1`, id).Scan(&retired); err != nil || retired || !s.inScope(ctx, sess, id) {
		return "", "", errNotFound
	}
	if ok, err := s.policyAllowsShell(ctx, id); err != nil {
		return "", "", err
	} else if !ok {
		return "", "", &userError{http.StatusConflict, shellPolicyOff}
	}
	maxM, idleM := set.Limits()
	cmd := api.ShellCommand{Session: randToken(32), User: strings.TrimSpace(localUser), AllowRoot: set.AllowRoot,
		By: sess.Email, MaxMinutes: maxM, IdleMinutes: idleM}
	if cmd.User == "root" && !set.AllowRoot {
		return "", "root", nil
	}
	if cmd.Validate() != nil {
		return "", "user", nil
	}
	if !set.AllowRoot && cmd.User != "" && s.accountPrivileged(ctx, id, cmd.User) { // the agent checks again
		return "", "admin", nil
	}
	user := cmd.User
	if user == "" {
		user = "limdm-support"
	}
	approvalID, err := s.requireApproval(ctx, sess, "remote_shell", id, user)
	if errors.Is(err, errAwaitingApproval) {
		return "", "approval", nil
	} else if err != nil {
		return "", "", err
	}
	payload, _ := json.Marshal(cmd)
	var cmdID int64
	err = s.auditAction(ctx, sess.Email, "shell.start", id, "session "+cmd.Session+" as "+user, func(tx pgx.Tx) error {
		if err := useApproval(ctx, tx, approvalID); err != nil {
			return err
		}
		var err error
		if cmdID, err = s.insertCommand(ctx, tx, id, "shell", string(payload), sess.Email); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO shell_sessions(id, device_id, command_id, requested_by, local_user, instance) VALUES ($1,$2,$3,$4,$5,$6)`,
			cmd.Session, id, cmdID, sess.Email, user, s.ha.id)
		return err
	})
	if err != nil {
		return "", "", err
	}
	l := newLiveShell(cmd.Session, id, sess.Email, cmdID)
	s.shells.put(l)
	go s.homeRelay(l, s.openBox(l.id, "h"))
	go s.watchShell(l, time.Duration(maxM)*time.Minute, time.Duration(idleM)*time.Minute) //nolint:gosec // the session outlives this request
	return cmd.Session, "", nil
}

// watchShell enforces the connect wait, maximum duration and idle timeout,
// ends the session when the console account loses its access, and stores
// the result when the session ends.
func (s *Server) watchShell(l *liveShell, maxD, idleD time.Duration) {
	defer s.finishShell(l)
	wait := time.NewTimer(shellConnectWait)
	defer wait.Stop()
	select {
	case <-l.agentUp:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := s.db.Exec(ctx, `UPDATE shell_sessions SET connected_at=now() WHERE id=$1`, l.id); err != nil {
			s.log.Error("remote shell connected", "err", err)
		}
		cancel()
	case <-wait.C:
		l.end("the device did not connect")
		return
	case <-l.done:
		return
	}
	maxT, idle, check := time.NewTimer(maxD), time.NewTimer(idleD), time.NewTicker(time.Minute)
	defer maxT.Stop()
	defer idle.Stop()
	defer check.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-maxT.C:
			l.end("maximum duration reached")
		case <-idle.C:
			l.end("idle timeout")
		case <-l.activity:
			idle.Reset(idleD)
		case <-check.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			role, _ := s.account(ctx, l.owner)
			cancel()
			if role == "" || !s.settings().RemoteShell.allows(role) {
				l.end("the console user no longer has access to remote shells")
			}
		}
	}
}

func (s *Server) finishShell(l *liveShell) {
	defer close(l.stored)
	defer s.shells.remove(l.id)
	l.mu.Lock()
	reason, transcript, truncated := l.reason, l.transcript, l.truncated
	l.mu.Unlock()
	if transcript == nil {
		transcript = []byte{} // nil would be NULL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	detail := fmt.Sprintf("session %s ended: %s (%d bytes of output)", l.id, reason, len(transcript))
	err := s.auditAction(ctx, l.owner, "shell.end", l.device, detail, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE shell_sessions SET ended_at=now(), end_reason=$2, transcript=$3, truncated=$4 WHERE id=$1`,
			l.id, truncate(reason, 500), transcript, truncated); err != nil {
			return err
		}
		// a session that ended before the device picked it up must not start later
		if _, err := tx.Exec(ctx, `UPDATE commands SET status='expired', updated_at=now() WHERE id=$1 AND status='pending'`, l.cmdID); err != nil {
			return err
		}
		return nil // old transcripts: the retention job (retention.go)
	})
	if err != nil {
		s.log.Error("store remote shell session", "session", l.id, "err", err)
	}
}

// shellWS relays between the browser and the device. Cross site WebSocket
// hijacking is prevented by the session cookie (SameSite=Lax), the exact
// Origin check and the CSRF token in the URL.
func (s *Server) shellWS(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(w, r)
	if !ok {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Origin") != s.cfg.PublicURL || !hmac.Equal([]byte(r.URL.Query().Get("csrf")), []byte(s.csrfToken(sess))) {
		http.Error(w, "origin or csrf check failed", http.StatusForbidden)
		return
	}
	l := s.shells.get(r.PathValue("sid"))
	if l == nil {
		s.shellWSRemote(w, r, sess, r.PathValue("sid"))
		return
	}
	if l.owner != sess.Email || !s.settings().RemoteShell.allows(sess.Role) || !s.inScope(r.Context(), sess, l.device) {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	l.mu.Lock()
	taken := l.console
	l.console = true
	l.mu.Unlock()
	if taken {
		http.Error(w, "the session is open in another window", http.StatusConflict)
		return
	}
	ws, err := wsUpgrade(w, r)
	if err != nil {
		l.end("the console could not connect")
		return
	}
	status := func(msg string) { _ = ws.WriteFrame(wsText, []byte(msg)) }
	go func() { // browser → device
		for {
			op, msg, err := ws.ReadMessage()
			if err != nil {
				l.end("closed in the console")
				return
			}
			if op != wsText {
				continue
			}
			if err := consoleFrame(l, msg); err != nil {
				l.end("closed in the console")
				return
			}
		}
	}()
	go func() {
		select {
		case <-l.agentUp:
			status("connected")
		case <-l.done:
		}
	}()
	status("waiting")
	buf := make([]byte, 32<<10)
	for { // device → browser
		n, err := l.outR.Read(buf)
		if n > 0 {
			if werr := ws.WriteFrame(wsBinary, buf[:n]); werr != nil {
				l.end("the console connection was lost")
				break
			}
		}
		if err != nil {
			break
		}
	}
	<-l.done
	l.mu.Lock()
	reason := l.reason
	l.mu.Unlock()
	ws.Close(truncate(reason, 120))
}

// consoleFrame turns a browser message into a frame for the device:
// {"i":"keys"} or {"r":[cols,rows]}.
func consoleFrame(l *liveShell, msg []byte) error {
	var m struct {
		I string    `json:"i"`
		R [2]uint16 `json:"r"`
	}
	if err := json.Unmarshal(msg, &m); err != nil {
		return err
	}
	if m.I != "" {
		select {
		case l.activity <- struct{}{}:
		default:
		}
		return api.WriteShellFrame(l.inW, api.ShellInput, []byte(m.I))
	}
	if m.R[0] > 0 && m.R[1] > 0 {
		return api.WriteShellFrame(l.inW, api.ShellResize, api.ResizePayload(min(m.R[0], 1000), min(m.R[1], 1000)))
	}
	return nil
}

// shellAgent is the device side of the relay: the request body is the
// terminal output, the response streams input frames.
func (s *Server) shellAgent(w http.ResponseWriter, r *http.Request) {
	device := r.Context().Value(deviceKey).(string)
	l := s.shells.get(r.PathValue("sid"))
	if l == nil {
		s.shellAgentRemote(w, r, r.PathValue("sid"), device)
		return
	}
	if l.device != device {
		problem(w, http.StatusNotFound, "no such session")
		return
	}
	l.mu.Lock()
	taken := l.agent
	l.agent = true
	l.mu.Unlock()
	if taken {
		problem(w, http.StatusConflict, "session already connected")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{}) // the listener's timeouts are for short requests
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.EnableFullDuplex() // HTTP/1.1; HTTP/2 always streams both ways
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		l.end("the device connection failed")
		return
	}
	close(l.agentUp)
	go func() { // device → console
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				l.record(buf[:n])
				if _, werr := l.outW.Write(buf[:n]); werr != nil {
					return // ended
				}
			}
			if err != nil {
				l.end("the session ended on the device")
				return
			}
		}
	}()
	go func() {
		select {
		case <-r.Context().Done():
			l.end("the device connection was lost")
		case <-l.done:
		}
	}()
	buf := make([]byte, 32<<10)
	for { // console → device
		n, err := l.inR.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil || rc.Flush() != nil {
				l.end("the device connection was lost")
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// shellPolicyOff is the answer when the device's policy does not allow
// remote shells.
const shellPolicyOff = "remote shells are not allowed by this device's policy: switch on Remote shell in the Agent settings of its blueprint"

// policyAllowsShell reports whether the resolved policy of a device allows
// remote shell sessions (com.limdm.agent remote_shell). The agent checks again.
func (s *Server) policyAllowsShell(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) // read only
	res, err := resolveDevice(ctx, tx, id)
	if err != nil {
		return false, err
	}
	pol, _ := api.Compose(res.Decls)
	return pol.RemoteShell, nil
}
