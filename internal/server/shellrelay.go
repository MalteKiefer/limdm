package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Remote shell relay between server instances. A session lives on the
// instance that started it (its home: watcher, timeouts, transcript). The
// device and the console may reach any instance behind the load balancer;
// an instance without the session relays its leg to the home instance over
// PostgreSQL notifications (channel limdm_shell), so instances need no
// connection to each other. Messages of one direction are sent one after
// the other, which keeps their order (PostgreSQL delivers notifications in
// commit order).

// relayMsg is one relay message. To names the receiver: "h" the home
// instance, "a" the instance with the device connection, "c" the instance
// with the console WebSocket. Kinds to the home instance: "a" device
// attach (D = device ID), "w" console attach, "o" device output, "k"
// console message, "e" end (D = reason). Kinds to a leg: "y"/"x" attach
// accepted or refused, "i" input frames for the device, "c" output for the
// console, "u" the device connected, "e" end.
type relayMsg struct {
	S  string `json:"s"`
	To string `json:"t"`
	K  string `json:"k"`
	D  []byte `json:"d,omitempty"`
}

const (
	relayChunk = 4096 // bytes per message: base64 and JSON stay below the 8000 byte NOTIFY limit
	relayQueue = 1024 // messages buffered per receiver before the session ends
)

const relayBehind = "the relay between server instances fell behind"

func (s *Server) relaySend(sid, to, kind string, d []byte) error {
	b, err := json.Marshal(relayMsg{S: sid, To: to, K: kind, D: d})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = s.db.Exec(ctx, `SELECT pg_notify('limdm_shell', $1)`, string(b))
	return err
}

// relayPump sends everything read from r, in order, until r ends.
func (s *Server) relayPump(r io.Reader, sid, to, kind string) error {
	buf := make([]byte, relayChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if serr := s.relaySend(sid, to, kind, buf[:n]); serr != nil {
				return serr
			}
		}
		if err != nil {
			return nil
		}
	}
}

// relayDispatch hands a notification to its mailbox; it runs on the
// listener and never blocks. A receiver that fell behind loses its
// mailbox (closed), which ends its side of the session.
func (s *Server) relayDispatch(payload string) {
	var m relayMsg
	if json.Unmarshal([]byte(payload), &m) != nil {
		return
	}
	key := m.S + "/" + m.To
	s.ha.mu.Lock()
	defer s.ha.mu.Unlock()
	box, ok := s.ha.boxes[key]
	if !ok {
		return
	}
	select {
	case box <- m:
	default:
		delete(s.ha.boxes, key)
		close(box)
	}
}

func (s *Server) openBox(sid, role string) chan relayMsg {
	s.ha.mu.Lock()
	defer s.ha.mu.Unlock()
	if s.ha.boxes == nil {
		s.ha.boxes = map[string]chan relayMsg{}
	}
	box := make(chan relayMsg, relayQueue)
	s.ha.boxes[sid+"/"+role] = box
	return box
}

func (s *Server) closeBox(sid, role string, box chan relayMsg) {
	s.ha.mu.Lock()
	defer s.ha.mu.Unlock()
	if s.ha.boxes[sid+"/"+role] == box {
		delete(s.ha.boxes, sid+"/"+role)
	}
}

// homeRelay serves the legs of a session that reached other instances,
// until the session ends.
func (s *Server) homeRelay(l *liveShell, box chan relayMsg) {
	defer s.closeBox(l.id, "h", box)
	var legs sync.WaitGroup
	var remoteAgent, remoteConsole bool
	toConsole, toAgent := make(chan []byte, relayQueue), make(chan []byte, relayQueue)
	go func() { // device output of a remote device leg
		for p := range toConsole {
			l.record(p)
			if _, err := l.outW.Write(p); err != nil {
				return
			}
		}
	}()
	go func() { // console messages of a remote console leg
		for msg := range toAgent {
			if err := consoleFrame(l, msg); err != nil {
				l.end("closed in the console")
				return
			}
		}
	}()
	pump := func(r io.Reader, to, kind string) {
		legs.Add(1)
		go func() {
			defer legs.Done()
			if s.relayPump(r, l.id, to, kind) != nil {
				l.end("the relay between server instances failed")
			}
		}()
	}
	queue := func(q chan []byte, p []byte) {
		select {
		case q <- p:
		default:
			l.end(relayBehind)
		}
	}
	for {
		select {
		case <-l.done:
			legs.Wait() // the last output is sent before the end
			reason := l.endReason()
			if remoteAgent {
				_ = s.relaySend(l.id, "a", "e", []byte(reason))
			}
			if remoteConsole {
				_ = s.relaySend(l.id, "c", "e", []byte(reason))
			}
			close(toConsole)
			close(toAgent)
			return
		case m, ok := <-box:
			if !ok {
				l.end(relayBehind)
				box = nil
				continue
			}
			switch m.K {
			case "a":
				l.mu.Lock()
				accept := !l.agent && l.device == string(m.D)
				l.agent = l.agent || accept
				l.mu.Unlock()
				if !accept {
					_ = s.relaySend(l.id, "a", "x", nil)
					continue
				}
				remoteAgent = true
				if s.relaySend(l.id, "a", "y", nil) != nil {
					l.end("the device connection failed")
					continue
				}
				pump(l.inR, "a", "i")
				close(l.agentUp)
			case "w":
				l.mu.Lock()
				accept := !l.console
				l.console = true
				l.mu.Unlock()
				if !accept {
					_ = s.relaySend(l.id, "c", "x", nil)
					continue
				}
				remoteConsole = true
				if s.relaySend(l.id, "c", "y", nil) != nil {
					l.end("the console could not connect")
					continue
				}
				pump(l.outR, "c", "c")
				legs.Add(1)
				go func() {
					defer legs.Done()
					select {
					case <-l.agentUp:
						_ = s.relaySend(l.id, "c", "u", nil)
					case <-l.done:
					}
				}()
			case "o":
				if remoteAgent {
					queue(toConsole, m.D)
				}
			case "k":
				if remoteConsole {
					queue(toAgent, m.D)
				}
			case "e":
				l.end(string(m.D))
			}
		}
	}
}

func (l *liveShell) endReason() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reason
}

func (h *shellHub) all() []*liveShell {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*liveShell, 0, len(h.live))
	for _, l := range h.live {
		out = append(out, l)
	}
	return out
}

// remoteShell finds a session that runs on another live instance.
func (s *Server) remoteShell(ctx context.Context, sid string) (device, owner string, ok bool) {
	err := s.db.QueryRow(ctx, `SELECT s.device_id, s.requested_by FROM shell_sessions s JOIN server_instances i ON i.id = s.instance
		WHERE s.id=$1 AND s.ended_at IS NULL AND s.instance <> $2 AND i.seen_at > now() - interval '`+instanceAlive+`'`, sid, s.ha.id).Scan(&device, &owner)
	return device, owner, err == nil
}

// relayAccepted waits for the home instance to accept an attach.
func relayAccepted(box chan relayMsg) bool {
	select {
	case m, ok := <-box:
		return ok && m.K == "y"
	case <-time.After(10 * time.Second):
		return false
	}
}

// relayLeg runs a leg on this instance until the session ends: messages of
// the home instance go to deliver. It returns the end reason. The leg also
// ends when deliver fails (its own connection is lost), when the home
// instance stops and when this instance shuts down.
func (s *Server) relayLeg(sid string, box chan relayMsg, deliver func(relayMsg) bool, lost string) string {
	check := time.NewTicker(15 * time.Second)
	defer check.Stop()
	end := func(reason string) string {
		_ = s.relaySend(sid, "h", "e", []byte(reason))
		return reason
	}
	for {
		select {
		case <-s.ha.stopping:
			return end("the server instance relaying the session shut down")
		case <-check.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, _, ok := s.remoteShell(ctx, sid)
			cancel()
			if !ok {
				return "the server instance holding the session stopped"
			}
		case m, ok := <-box:
			switch {
			case !ok:
				return end(relayBehind)
			case m.K == "e":
				return string(m.D)
			case !deliver(m):
				return end(lost)
			}
		}
	}
}

// shellAgentRemote relays a device connection for a session held by
// another instance.
func (s *Server) shellAgentRemote(w http.ResponseWriter, r *http.Request, sid, device string) {
	if d, _, ok := s.remoteShell(r.Context(), sid); !ok || d != device {
		problem(w, http.StatusNotFound, "no such session")
		return
	}
	box := s.openBox(sid, "a")
	defer s.closeBox(sid, "a", box)
	if err := s.relaySend(sid, "h", "a", []byte(device)); err != nil {
		problem(w, http.StatusServiceUnavailable, "relay unavailable")
		return
	}
	if !relayAccepted(box) {
		problem(w, http.StatusConflict, "session already connected")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.EnableFullDuplex()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		_ = s.relaySend(sid, "h", "e", []byte("the device connection failed"))
		return
	}
	go func() { // device → home instance
		if s.relayPump(r.Body, sid, "h", "o") == nil {
			_ = s.relaySend(sid, "h", "e", []byte("the session ended on the device"))
		}
	}()
	s.relayLeg(sid, box, func(m relayMsg) bool {
		if m.K != "i" {
			return true
		}
		_, err := w.Write(m.D)
		return err == nil && rc.Flush() == nil
	}, "the device connection was lost")
}

// shellWSRemote relays a console WebSocket for a session held by another
// instance; the checks match shellWS.
func (s *Server) shellWSRemote(w http.ResponseWriter, r *http.Request, sess session, sid string) {
	device, owner, ok := s.remoteShell(r.Context(), sid)
	if !ok || owner != sess.Email || !s.settings().RemoteShell.allows(sess.Role) || !s.inScope(r.Context(), sess, device) {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	box := s.openBox(sid, "c")
	defer s.closeBox(sid, "c", box)
	if err := s.relaySend(sid, "h", "w", nil); err != nil {
		http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
		return
	}
	if !relayAccepted(box) {
		http.Error(w, "the session is open in another window", http.StatusConflict)
		return
	}
	ws, err := wsUpgrade(w, r)
	if err != nil {
		_ = s.relaySend(sid, "h", "e", []byte("the console could not connect"))
		return
	}
	status := func(msg string) bool { return ws.WriteFrame(wsText, []byte(msg)) == nil }
	status("waiting")
	go func() { // browser → home instance
		for {
			op, msg, err := ws.ReadMessage()
			if err != nil {
				_ = s.relaySend(sid, "h", "e", []byte("closed in the console"))
				return
			}
			if op == wsText && s.relaySend(sid, "h", "k", msg) != nil {
				return
			}
		}
	}()
	reason := s.relayLeg(sid, box, func(m relayMsg) bool {
		switch m.K {
		case "c":
			return ws.WriteFrame(wsBinary, m.D) == nil
		case "u":
			return status("connected")
		}
		return true
	}, "the console connection was lost")
	ws.Close(truncate(reason, 120))
}

// shellRefused ends the session of a shell command the device did not run,
// wherever the session runs.
func (s *Server) shellRefused(ctx context.Context, cmdID int64, output string) {
	reason := "the device refused the session: " + truncate(strings.TrimSpace(output), 300)
	if s.shells.refused(cmdID, reason) {
		return
	}
	var sid string
	if err := s.db.QueryRow(ctx, `SELECT id FROM shell_sessions WHERE command_id=$1 AND ended_at IS NULL`, cmdID).Scan(&sid); err == nil {
		_ = s.relaySend(sid, "h", "e", []byte(reason))
	}
}
