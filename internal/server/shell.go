package server

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
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
// audited and its output is kept as a transcript.
//
// ponytail: the relay lives in this process; with several server instances
// console and agent must reach the same one (sticky routing) or the session
// waits until it times out.

const (
	shellTranscriptCap = 1 << 20         // bytes of output kept per session
	shellConnectWait   = 3 * time.Minute // the device polls every minute
	shellRetention     = "365 days"      // like device events
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

func remoteShellForm(r *http.Request) RemoteShellSettings {
	maxM, _ := strconv.Atoi(r.FormValue("shell_max_minutes"))
	idleM, _ := strconv.Atoi(r.FormValue("shell_idle_minutes"))
	return RemoteShellSettings{Enabled: r.FormValue("shell_enabled") == "on", Helpdesk: r.FormValue("shell_helpdesk") == "on",
		AllowRoot: r.FormValue("shell_root") == "on", MaxMinutes: maxM, IdleMinutes: idleM}
}

// errAwaitingApproval: the action was requested and waits for a second admin.
var errAwaitingApproval = errors.New("the action waits for approval")

// requireApproval applies four eyes approval (approvals.go) to a remote
// shell when the setting asks for it: an approved request of this user for
// this device is used up and the action runs; otherwise a request is filed
// (once) and errAwaitingApproval returned. Other actions run.
func (s *Server) requireApproval(ctx context.Context, sess session, action, target string) error {
	if action != "remote_shell" || !s.settings().FourEyesShell {
		return nil
	}
	tag, err := s.db.Exec(ctx, `UPDATE approvals SET status='used' WHERE id = (SELECT id FROM approvals
		WHERE action=$1 AND target=$2 AND requested_by=$3 AND status='approved' AND expires_at > now() ORDER BY id DESC LIMIT 1)`, action, target, sess.Email)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var pending bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM approvals WHERE action=$1 AND target=$2 AND requested_by=$3
		AND status='pending' AND expires_at > now())`, action, target, sess.Email).Scan(&pending); err != nil {
		return err
	}
	if !pending {
		if _, err := s.requestApproval(ctx, sess, action, target, map[string]string{}, ""); err != nil {
			return err
		}
	}
	return errAwaitingApproval
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

// refused ends the session of a shell command the device did not run.
func (h *shellHub) refused(cmdID int64, output string) {
	h.mu.Lock()
	var hit *liveShell
	for _, l := range h.live {
		if l.cmdID == cmdID {
			hit = l
		}
	}
	h.mu.Unlock()
	if hit != nil {
		hit.end("the device refused the session: " + truncate(strings.TrimSpace(output), 300))
	}
}

func (s *Server) shellRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /devices/{id}/shell", s.page(s.shellPage))
	mux.HandleFunc("POST /devices/{id}/shell", s.helpdeskPage(s.shellStart))
	mux.HandleFunc("GET /shell/{sid}", s.page(s.shellView))
	mux.HandleFunc("POST /shell/{sid}/end", s.helpdeskPage(s.shellEnd))
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
	octet_length(s.transcript), s.truncated`

func (s *Server) scanShell(row pgx.Row) (shellRow, error) {
	var r shellRow
	err := row.Scan(&r.ID, &r.Device, &r.Hostname, &r.By, &r.User, &r.Reason, &r.Created, &r.Connected, &r.Ended, &r.Bytes, &r.Truncated)
	switch {
	case r.Ended != nil:
		r.State = "ended"
	case s.shells.get(r.ID) == nil:
		r.State = "interrupted" // the server restarted while it ran
	case r.Connected != nil:
		r.State = "active"
	default:
		r.State = "waiting for the device"
	}
	return r, err
}

func (s *Server) shellPage(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	var host string
	var retired bool
	if err := s.db.QueryRow(r.Context(), `SELECT hostname, retired FROM devices WHERE id=$1`, id).Scan(&host, &retired); err != nil || !s.inScope(r.Context(), sess, id) {
		http.NotFound(w, r)
		return
	}
	q := `SELECT ` + shellCols + ` FROM shell_sessions s JOIN devices d ON d.id=s.device_id WHERE s.device_id=$1`
	args := []any{id}
	if sess.Role == "helpdesk" { // transcripts are for admins and auditors; helpdesk sees its own sessions
		q += ` AND s.requested_by=$2`
		args = append(args, sess.Email)
	}
	rows, err := s.db.Query(r.Context(), q+` ORDER BY s.created_at DESC LIMIT 100`, args...)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	var list []shellRow
	for rows.Next() {
		sr, err := s.scanShell(rows)
		if err != nil {
			s.fail(w, err)
			return
		}
		list = append(list, sr)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, err)
		return
	}
	set := s.settings().RemoteShell
	maxM, idleM := set.Limits()
	s.render(w, r, sess, "shell", map[string]any{"DeviceID": id, "Hostname": host, "Sessions": list,
		"CanStart": set.allows(sess.Role) && !retired, "Enabled": set.Enabled, "AllowRoot": set.AllowRoot, "Max": maxM, "Idle": idleM,
		"Error": shellErrors[r.URL.Query().Get("err")]})
}

// shellErrors are shown after a refused start; only the key travels in the URL.
var shellErrors = map[string]string{
	"user": "Invalid user name.", "root": "Root sessions are not allowed in the settings.", "approval": "The session waits for approval.",
}

func (s *Server) shellStart(w http.ResponseWriter, r *http.Request, sess session) {
	ctx, id := r.Context(), r.PathValue("id")
	set := s.settings().RemoteShell
	if !set.allows(sess.Role) {
		s.errorPage(w, r, sess, http.StatusForbidden, "remote shell is not enabled for your role")
		return
	}
	back := func(code string) {
		http.Redirect(w, r, "/devices/"+id+"/shell?err="+code, http.StatusSeeOther)
	}
	var retired bool
	if err := s.db.QueryRow(ctx, `SELECT retired FROM devices WHERE id=$1`, id).Scan(&retired); err != nil || retired || !s.inScope(ctx, sess, id) {
		http.NotFound(w, r)
		return
	}
	maxM, idleM := set.Limits()
	cmd := api.ShellCommand{Session: randToken(32), User: strings.TrimSpace(r.FormValue("user")), AllowRoot: set.AllowRoot,
		By: sess.Email, MaxMinutes: maxM, IdleMinutes: idleM}
	if cmd.User == "root" && !set.AllowRoot {
		back("root")
		return
	}
	if cmd.Validate() != nil {
		back("user")
		return
	}
	if err := s.requireApproval(ctx, sess, "remote_shell", id); errors.Is(err, errAwaitingApproval) {
		back("approval")
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	payload, _ := json.Marshal(cmd)
	user := cmd.User
	if user == "" {
		user = "limdm-support"
	}
	var cmdID int64
	err := s.auditAction(ctx, sess.Email, "shell.start", id, "session "+cmd.Session+" as "+user, func(tx pgx.Tx) error {
		var err error
		if cmdID, err = s.insertCommand(ctx, tx, id, "shell", string(payload), sess.Email); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO shell_sessions(id, device_id, command_id, requested_by, local_user) VALUES ($1,$2,$3,$4,$5)`,
			cmd.Session, id, cmdID, sess.Email, user)
		return err
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	l := newLiveShell(cmd.Session, id, sess.Email, cmdID)
	s.shells.put(l)
	go s.watchShell(l, time.Duration(maxM)*time.Minute, time.Duration(idleM)*time.Minute) //nolint:gosec // the session outlives this request
	http.Redirect(w, r, "/shell/"+cmd.Session, http.StatusSeeOther)
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
		_, err := tx.Exec(ctx, `DELETE FROM shell_sessions WHERE created_at < now() - interval '`+shellRetention+`'`)
		return err
	})
	if err != nil {
		s.log.Error("store remote shell session", "session", l.id, "err", err)
	}
}

// shellView shows the live terminal to the user who started the session and
// the transcript to admins and auditors.
func (s *Server) shellView(w http.ResponseWriter, r *http.Request, sess session) {
	sid := r.PathValue("sid")
	sr, err := s.scanShell(s.db.QueryRow(r.Context(), `SELECT `+shellCols+` FROM shell_sessions s JOIN devices d ON d.id=s.device_id WHERE s.id=$1`, sid))
	if err != nil || !s.inScope(r.Context(), sess, sr.Device) {
		http.NotFound(w, r)
		return
	}
	l := s.shells.get(sid)
	live := l != nil && sr.By == sess.Email
	if !live && sess.Role != "admin" && sess.Role != "auditor" {
		s.errorPage(w, r, sess, http.StatusForbidden, "transcripts are available to admins and auditors")
		return
	}
	var text string
	if !live && sr.Ended != nil {
		var raw []byte
		if err := s.db.QueryRow(r.Context(), `SELECT transcript FROM shell_sessions WHERE id=$1`, sid).Scan(&raw); err != nil {
			s.fail(w, err)
			return
		}
		text = terminalText(raw)
	}
	_, vendorErr := fs.Stat(staticFS, "static/vendor/xterm/xterm.js")
	s.render(w, r, sess, "shellsession", map[string]any{"S": sr, "Live": live, "Transcript": text, "Terminal": vendorErr == nil,
		"Running": l != nil, "CanEnd": l != nil && (sr.By == sess.Email || sess.Role == "admin")})
}

func (s *Server) shellEnd(w http.ResponseWriter, r *http.Request, sess session) {
	sid := r.PathValue("sid")
	l := s.shells.get(sid)
	if l == nil {
		http.Redirect(w, r, "/shell/"+sid, http.StatusSeeOther)
		return
	}
	if l.owner != sess.Email && sess.Role != "admin" {
		s.errorPage(w, r, sess, http.StatusForbidden, "only the user who started the session or an admin can end it")
		return
	}
	l.end("ended in the console by " + sess.Email)
	select { // the page after the redirect shows the stored end
	case <-l.stored:
	case <-time.After(5 * time.Second):
	}
	http.Redirect(w, r, "/shell/"+sid, http.StatusSeeOther)
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
	if l == nil || l.owner != sess.Email || !s.settings().RemoteShell.allows(sess.Role) || !s.inScope(r.Context(), sess, l.device) {
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
	if l == nil || l.device != device {
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

// ansiRe matches terminal control sequences: CSI, OSC and two byte escapes.
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-Z\\-_]`)

// terminalText makes a transcript readable: control sequences removed,
// carriage returns resolved, other control characters dropped.
func terminalText(raw []byte) string {
	s := strings.ToValidUTF8(ansiRe.ReplaceAllString(string(raw), ""), "�")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
