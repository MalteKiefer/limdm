package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// wsClientFrame builds a masked client frame.
func wsClientFrame(fin bool, op byte, p []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	h := []byte{b0}
	switch n := len(p); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n <= 0xffff:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		h = binary.BigEndian.AppendUint64(append(h, 0x80|127), uint64(n))
	}
	mask := make([]byte, 4)
	rand.Read(mask)
	h = append(h, mask...)
	for i, c := range p {
		h = append(h, c^mask[i%4])
	}
	return h
}

func wsDial(t *testing.T, url string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	rand.Read(key)
	k := base64.StdEncoding.EncodeToString(key)
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+k+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake: %s", resp.Status)
	}
	return c, br
}

// readServerFrame reads one unmasked server frame.
func readServerFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		t.Fatal(err)
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		io.ReadFull(br, b[:])
		n = int(binary.BigEndian.Uint16(b[:]))
	}
	p := make([]byte, n)
	io.ReadFull(br, p)
	return h[0] & 0x0f, p
}

func TestWebSocket(t *testing.T) {
	got := make(chan string, 10)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := wsUpgrade(w, r)
		if err != nil {
			return
		}
		for {
			op, msg, err := ws.ReadMessage()
			if err != nil {
				got <- "err:" + err.Error()
				return
			}
			got <- string(msg)
			_ = ws.WriteFrame(op, append([]byte("echo "), msg...))
		}
	}))
	defer ts.Close()

	// a plain GET is refused
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain GET: %s", resp.Status)
	}

	c, br := wsDial(t, ts.URL)
	defer c.Close()
	c.Write(wsClientFrame(true, wsText, []byte("hello")))
	if m := <-got; m != "hello" {
		t.Fatal(m)
	}
	if op, p := readServerFrame(t, br); op != wsText || string(p) != "echo hello" {
		t.Fatalf("echo: %d %q", op, p)
	}
	// ping in the middle of a fragmented message is answered, the message reassembled
	c.Write(wsClientFrame(false, wsBinary, []byte("ab")))
	c.Write(wsClientFrame(true, wsPing, []byte("p")))
	c.Write(wsClientFrame(true, 0, []byte(strings.Repeat("c", 300))))
	if op, p := readServerFrame(t, br); op != wsPong || string(p) != "p" {
		t.Fatalf("pong: %d %q", op, p)
	}
	if m := <-got; m != "ab"+strings.Repeat("c", 300) {
		t.Fatalf("fragments: %q", m)
	}
	readServerFrame(t, br)
	// invalid UTF-8 in a text message ends the connection
	c.Write(wsClientFrame(true, wsText, []byte{0xff, 0xfe}))
	if m := <-got; !strings.HasPrefix(m, "err:") {
		t.Fatal(m)
	}

	// unmasked client frames are refused
	c2, _ := wsDial(t, ts.URL)
	defer c2.Close()
	c2.Write([]byte{0x81, 0x01, 'x'})
	if m := <-got; !strings.Contains(m, "masked") {
		t.Fatal(m)
	}
	// oversized frames are refused before reading them
	c3, _ := wsDial(t, ts.URL)
	defer c3.Close()
	c3.Write([]byte{0x82, 0x80 | 127, 0, 0, 0, 1, 0, 0, 0, 0})
	if m := <-got; !strings.Contains(m, "too large") {
		t.Fatal(m)
	}
	// a close frame is echoed
	c4, br4 := wsDial(t, ts.URL)
	defer c4.Close()
	c4.Write(wsClientFrame(true, wsClose, nil))
	if m := <-got; m != "err:"+errWSClosed.Error() {
		t.Fatal(m)
	}
	if op, _ := readServerFrame(t, br4); op != wsClose {
		t.Fatalf("close not echoed: %d", op)
	}
}

// The agent side of the relay streams both ways over one HTTP/2 request.
func TestShellRelayAgent(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	l := newLiveShell(randToken(32), "dev1", "admin@example.com", 7)
	s.shells.put(l)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/shell/{sid}", func(w http.ResponseWriter, r *http.Request) {
		s.shellAgent(w, r.WithContext(context.WithValue(r.Context(), deviceKey, r.Header.Get("X-Device"))))
	})
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	post := func(device string, body io.Reader) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/shell/"+l.id, body)
		req.Header.Set("X-Device", device)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	other := post("other", strings.NewReader(""))
	other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("other device: %s", other.Status)
	}
	pr, pw := io.Pipe()
	resp := post("dev1", pr)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("agent connect: %s %s", resp.Status, resp.Proto)
	}
	select {
	case <-l.agentUp:
	case <-time.After(5 * time.Second):
		t.Fatal("agent not marked connected")
	}
	again := post("dev1", strings.NewReader(""))
	again.Body.Close()
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("second agent: %s", again.Status)
	}

	go pw.Write([]byte("login: ok\r\n"))
	buf := make([]byte, 64)
	n, err := l.outR.Read(buf)
	if err != nil || string(buf[:n]) != "login: ok\r\n" {
		t.Fatalf("output: %q %v", buf[:n], err)
	}
	if err := consoleFrame(l, []byte(`{"i":"ls\r"}`)); err != nil {
		t.Fatal(err)
	}
	if typ, p, err := api.ReadShellFrame(resp.Body); err != nil || typ != api.ShellInput || string(p) != "ls\r" {
		t.Fatalf("input frame: %c %q %v", typ, p, err)
	}
	go consoleFrame(l, []byte(`{"r":[120,40]}`))
	if typ, p, err := api.ReadShellFrame(resp.Body); err != nil || typ != api.ShellResize || binary.BigEndian.Uint16(p) != 120 {
		t.Fatalf("resize frame: %c %v %v", typ, p, err)
	}
	select {
	case <-l.activity:
	default:
		t.Fatal("input did not count as activity")
	}

	l.end("test over")
	if _, _, err := api.ReadShellFrame(resp.Body); err == nil {
		t.Fatal("stream still open after the end")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if string(l.transcript) != "login: ok\r\n" || l.reason != "test over" {
		t.Fatalf("transcript %q reason %q", l.transcript, l.reason)
	}
}

func TestShellTranscriptAndSettings(t *testing.T) {
	l := newLiveShell("x", "d", "o", 1)
	l.record(make([]byte, shellTranscriptCap-2))
	l.record([]byte("abcd"))
	if len(l.transcript) != shellTranscriptCap || !l.truncated {
		t.Fatalf("cap: %d %v", len(l.transcript), l.truncated)
	}
	if got := terminalText([]byte("\x1b[1;32muser@pc\x1b[0m:~$ ls\r\n\x1b]0;title\x07a\tb\x07\r\n")); got != "user@pc:~$ ls\na\tb\n" {
		t.Fatalf("terminalText: %q", got)
	}

	var set RemoteShellSettings
	if m, i := set.Limits(); m != 60 || i != 15 || set.validate() != nil || set.allows("admin") {
		t.Fatal("defaults")
	}
	set = RemoteShellSettings{Enabled: true}
	if !set.allows("admin") || set.allows("helpdesk") || set.allows("auditor") {
		t.Fatal("roles without helpdesk")
	}
	set.Helpdesk = true
	if !set.allows("helpdesk") || set.allows("auditor") {
		t.Fatal("roles with helpdesk")
	}
	for _, bad := range []RemoteShellSettings{{MaxMinutes: 4}, {MaxMinutes: 500}, {MaxMinutes: 10, IdleMinutes: 20}, {IdleMinutes: 121, MaxMinutes: 480}} {
		if bad.validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if (RemoteShellSettings{MaxMinutes: 5}).validate() != nil {
		t.Error("max 5 with default idle must be valid")
	}
}
