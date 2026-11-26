package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// Two server instances on one database: concurrent start, leader election,
// settings propagation, a remote shell relayed between instances and
// background notifications sent once.
func TestHighAvailabilityIntegration(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	// New sets the package wide keys; the other tests expect theirs
	ik, ipk, ak, from, sec, aks, cur := itemKey, itemPrevKey, auditKey, auditKeyedFrom, itemSecrets, auditKeys, auditKeyCur
	defer func() {
		itemKey, itemPrevKey, auditKey, auditKeyedFrom, itemSecrets, auditKeys, auditKeyCur = ik, ipk, ak, from, sec, aks, cur
	}()
	defer func(d time.Duration) { leaderRetry = d }(leaderRetry)
	leaderRetry = 200 * time.Millisecond
	cfg := Config{DatabaseURL: dsn, PublicURL: "https://mdm.test", AgentURL: "https://mdm.test:8444", CADir: t.TempDir(),
		SessionKey: bytes.Repeat([]byte{5}, 32), LocalLogin: true, StaleAfter: 24 * time.Hour}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	// both start at once: one migrates and creates the keys, the other waits
	var a, b *Server
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a, errA = New(ctx, cfg, quiet) }()
	go func() { defer wg.Done(); b, errB = New(ctx, cfg, quiet) }()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("start: %v %v", errA, errB)
	}
	defer a.Close()
	defer b.Close()
	if a.ca.Fingerprint() != b.ca.Fingerprint() {
		t.Fatal("instances run different device CAs")
	}
	// a third instance with its own, fresh CA directory is refused
	other := cfg
	other.CADir = t.TempDir()
	if c, err := New(ctx, other, quiet); err == nil || !strings.Contains(err.Error(), "same CA directory") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("separate CA directory: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1', 's', now(), 'pc1');
		INSERT INTO local_admins(name, role, password_hash, totp_secret) VALUES ('admin', 'admin', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	srvA, srvB := httptest.NewServer(a.AdminHandler()), httptest.NewServer(b.AdminHandler())
	defer srvA.Close()
	defer srvB.Close()
	eventually := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	for _, srv := range []*httptest.Server{srvA, srvB} {
		eventually("readyz", func() bool {
			resp, err := http.Get(srv.URL + "/readyz")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		})
	}

	// leader election: one instance runs the loop; when it stops the other takes over
	running := make(chan *Server, 4)
	ctxA, stopA := context.WithCancel(ctx)
	ctxB, stopB := context.WithCancel(ctx)
	defer stopB()
	loop := func(s *Server) func(context.Context) {
		return func(c context.Context) { running <- s; <-c.Done() }
	}
	go a.background(ctxA, "ha test", loop(a), true)
	go b.background(ctxB, "ha test", loop(b), true)
	first := <-running
	select {
	case s := <-running:
		t.Fatalf("two leaders: %p %p", first, s)
	case <-time.After(time.Second):
	}
	if first == a {
		stopA()
	} else {
		stopB()
	}
	select {
	case s := <-running:
		if s == first {
			t.Fatal("the stopped instance took the loop again")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no takeover")
	}
	stopA()
	stopB()

	// settings saved on one instance become active on the other; a save on
	// the other right after does not undo it
	admin := session{Email: "local:admin", Role: "admin", IAT: time.Now(), Last: time.Now()}
	post := func(srv *httptest.Server, s *Server, method, path, body string) (int, string) {
		t.Helper()
		return consoleAPI(t, s, srv.URL, admin)(method, path, body)
	}
	if code, body := post(srvA, a, "PATCH", "/api/v1/settings/remote_shell", `{"remote_shell":{"enabled":true}}`); code != http.StatusOK {
		t.Fatalf("save on A: %d %.3000s", code, body)
	}
	if code, _ := post(srvB, b, "PATCH", "/api/v1/settings/general", `{"stale_hours":48,"local_login":true}`); code != http.StatusOK {
		t.Fatal("save on B")
	}
	for _, s := range []*Server{a, b} {
		eventually("settings on both instances", func() bool {
			set := s.settings()
			return set.RemoteShell.Enabled && set.StaleHours == 48
		})
	}

	// background notifications come from the leader only
	var hooks atomic.Int32
	hook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hooks.Add(1) }))
	defer hook.Close()
	a.hooks, b.hooks = hook.Client(), hook.Client()
	var chID int64
	if err := db.QueryRow(ctx, `INSERT INTO notification_channels(name, kind) VALUES ('hook', 'webhook') RETURNING id`).Scan(&chID); err != nil {
		t.Fatal(err)
	}
	sealed, err := a.sealField(channelField(chID), hook.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE notification_channels SET secret=$2 WHERE id=$1;`, chID, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO audit_log(at, actor, action, prev, hash) VALUES (now(), 'intruder', 'forged', '\x00', '\x00')`); err != nil {
		t.Fatal(err)
	}
	hctx, stopHistory := context.WithCancel(ctx)
	go a.background(hctx, "history", a.historyLoop, true)
	go b.background(hctx, "history", b.historyLoop, true)
	eventually("audit.broken notification", func() bool { return hooks.Load() > 0 })
	time.Sleep(2 * time.Second)
	stopHistory()
	var logged int
	db.QueryRow(ctx, `SELECT count(*) FROM notification_log WHERE event='audit.broken'`).Scan(&logged)
	if hooks.Load() != 1 || logged != 1 {
		t.Fatalf("audit.broken sent %d times, logged %d", hooks.Load(), logged)
	}
	if broken, at := b.auditVerification(ctx); broken == 0 || at == nil {
		t.Fatal("the verification result is not shared")
	}

	// remote shell: the session lives on A; console and device reach different instances
	agentSrv := func(s *Server) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/v1/shell/{sid}", func(w http.ResponseWriter, r *http.Request) {
			s.shellAgent(w, r.WithContext(context.WithValue(r.Context(), deviceKey, "d1")))
		})
		ts := httptest.NewUnstartedServer(mux)
		ts.EnableHTTP2 = true
		ts.StartTLS()
		return ts
	}
	agentA, agentB := agentSrv(a), agentSrv(b)
	defer agentA.Close()
	defer agentB.Close()
	allowShellPolicy(t, db)
	for i, tc := range []struct {
		console *httptest.Server
		agent   *httptest.Server
		end     func(sid string, agentIn io.Closer)
		reason  string
	}{
		{srvB, agentA, func(sid string, _ io.Closer) { post(srvB, b, "POST", "/api/v1/shell-sessions/"+sid+"/end", "") }, "ended in the console by local:admin"},
		{srvA, agentB, func(_ string, agentIn io.Closer) { agentIn.Close() }, "the session ended on the device"},
	} {
		code, body := post(srvA, a, "POST", "/api/v1/devices/d1/shell", `{"user":"alice"}`)
		var started struct{ ID string }
		if json.Unmarshal([]byte(body), &started); code != http.StatusCreated || started.ID == "" {
			t.Fatalf("case %d start: %d %s", i, code, body)
		}
		sid := started.ID
		conn, br := wsDialConsole(t, tc.console.URL, "/shell/"+sid+"/ws?csrf="+url.QueryEscape(a.csrfToken(admin)), a.seal(admin))
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		if op, p := readServerFrame(t, br); op != wsText || string(p) != "waiting" {
			t.Fatalf("case %d console status: %d %q", i, op, p)
		}
		pr, pw := io.Pipe()
		req, _ := http.NewRequest(http.MethodPost, tc.agent.URL+"/api/v1/shell/"+sid, pr)
		resp, err := tc.agent.Client().Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("case %d agent connect: %v %v", i, err, resp)
		}
		if op, p := readServerFrame(t, br); op != wsText || string(p) != "connected" {
			t.Fatalf("case %d console status: %d %q", i, op, p)
		}
		go pw.Write([]byte("hello from pc1\r\n"))
		if op, p := readServerFrame(t, br); op != wsBinary || string(p) != "hello from pc1\r\n" {
			t.Fatalf("case %d output: %d %q", i, op, p)
		}
		if _, err := conn.Write(wsClientFrame(true, wsText, []byte(`{"i":"ls\r"}`))); err != nil {
			t.Fatal(err)
		}
		if typ, p, err := api.ReadShellFrame(resp.Body); err != nil || typ != api.ShellInput || string(p) != "ls\r" {
			t.Fatalf("case %d input: %c %q %v", i, typ, p, err)
		}
		if i == 0 {
			// a session out of the account's scope cannot end it from the other instance
			outside := session{Email: "local:help", Role: "helpdesk", Tags: []string{"elsewhere"}, IAT: time.Now(), Last: time.Now()}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/v1/shell-sessions/"+sid+"/end", nil)
			req.SetPathValue("sid", sid)
			b.apiShellEnd(rec, req, apiCaller{Name: outside.Email, Role: outside.Role, Tags: outside.Tags, Sess: &outside})
			var ended bool
			db.QueryRow(ctx, `SELECT ended_at IS NOT NULL FROM shell_sessions WHERE id=$1`, sid).Scan(&ended)
			if rec.Code != http.StatusNotFound || ended {
				t.Fatalf("out of scope end on the other instance: %d ended=%v", rec.Code, ended)
			}
		}
		tc.end(sid, pw)
		var reason string
		var transcript []byte
		eventually("session end stored", func() bool {
			return db.QueryRow(ctx, `SELECT end_reason, transcript FROM shell_sessions WHERE id=$1 AND ended_at IS NOT NULL`, sid).Scan(&reason, &transcript) == nil
		})
		if reason != tc.reason || string(transcript) != "hello from pc1\r\n" {
			t.Fatalf("case %d end: %q %q", i, reason, transcript)
		}
		resp.Body.Close()
		conn.Close()
	}
}

// wsDialConsole opens a console WebSocket with session cookie and origin.
func wsDialConsole(t *testing.T, base, path, cookie string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	rand.Read(key)
	io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: x\r\nOrigin: https://mdm.test\r\nCookie: "+sessionCookie+"="+cookie+
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+base64.StdEncoding.EncodeToString(key)+"\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("console handshake: %s", resp.Status)
	}
	return c, br
}
