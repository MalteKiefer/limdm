package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// Starting, refusing and ending remote shell sessions against PostgreSQL.
func TestRemoteShellIntegration(t *testing.T) {
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
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1', 's', now(), 'pc1');
		INSERT INTO console_users(email, role) VALUES ('admin@firma.de', 'admin'), ('help@firma.de', 'helpdesk'), ('audit@firma.de', 'auditor')`); err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", SessionKey: bytes.Repeat([]byte{7}, 32), LocalLogin: true}}
	set := Settings{LocalLogin: true, StaleHours: 24}
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	sessFor := func(email, role string) session {
		return session{Email: email, Role: role, IAT: time.Now(), Last: time.Now()}
	}
	admin, help, audit := sessFor("admin@firma.de", "admin"), sessFor("help@firma.de", "helpdesk"), sessFor("audit@firma.de", "auditor")
	ui := func(method, path string, form url.Values, sess session) (int, string, string) {
		t.Helper()
		if form != nil {
			form.Set("csrf", s.csrfToken(sess))
		}
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Location"), string(b)
	}

	// off by default, for every role
	if code, _, _ := ui("POST", "/devices/d1/shell", url.Values{}, admin); code != http.StatusForbidden {
		t.Fatalf("disabled setting: %d", code)
	}
	// the generic command form cannot queue a shell
	if code, _, _ := ui("POST", "/devices/d1/command", url.Values{"type": {"shell"}}, admin); code != http.StatusBadRequest {
		t.Fatalf("shell through /command: %d", code)
	}
	set.RemoteShell = RemoteShellSettings{Enabled: true}
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	if code, _, _ := ui("POST", "/devices/d1/shell", url.Values{}, help); code != http.StatusForbidden {
		t.Fatalf("helpdesk without the setting: %d", code)
	}
	if code, _, _ := ui("POST", "/devices/d1/shell", url.Values{}, audit); code != http.StatusForbidden {
		t.Fatalf("auditor: %d", code)
	}
	if code, loc, _ := ui("POST", "/devices/d1/shell", url.Values{"user": {"root"}}, admin); code != http.StatusSeeOther || !strings.Contains(loc, "err=root") {
		t.Fatalf("root without the setting: %d %s", code, loc)
	}
	code, loc, _ := ui("POST", "/devices/d1/shell", url.Values{"user": {"alice"}}, admin)
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/shell/") {
		t.Fatalf("start: %d %s", code, loc)
	}
	sid := strings.TrimPrefix(loc, "/shell/")

	// a signed command with the session for the device
	var c api.Command
	var sig string
	if err := db.QueryRow(ctx, `SELECT id, type, payload, created_at, signature FROM commands WHERE device_id='d1'`).Scan(&c.ID, &c.Type, &c.Payload, &c.CreatedAt, &sig); err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	var sc api.ShellCommand
	if err := json.Unmarshal([]byte(c.Payload), &sc); err != nil || c.Type != "shell" || sc.Session != sid || sc.User != "alice" || sc.By != "admin@firma.de" || sc.MaxMinutes != 60 {
		t.Fatalf("command: %+v %+v", c, sc)
	}
	if err := api.VerifyCommand(testCmdKey.Public().(ed25519.PublicKey), "d1", c); err != nil {
		t.Fatalf("signature: %v", err)
	}
	var audited int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='shell.start' AND target='d1'`).Scan(&audited)
	if audited != 1 {
		t.Fatal("start not audited")
	}
	// the live terminal belongs to the user who started it; others get the transcript view (admins, auditors)
	if code, _, body := ui("GET", "/shell/"+sid, nil, admin); code != 200 || !strings.Contains(body, "static/vendor/xterm") && !strings.Contains(body, "scripts/vendor-xterm.sh") {
		t.Fatalf("owner view: %d", code)
	}
	if code, _, body := ui("GET", "/shell/"+sid, nil, audit); code != 200 || !strings.Contains(body, "transcript is available once it ends") {
		t.Fatalf("auditor view of a running session: %d", code)
	}
	if code, _, _ := ui("GET", "/shell/"+sid, nil, help); code != http.StatusForbidden {
		t.Fatalf("helpdesk view of another user's session: %d", code)
	}
	// the WebSocket refuses foreign origins and missing CSRF tokens
	for _, h := range []map[string]string{{"Origin": "https://evil.test"}, {"Origin": "https://mdm.test"}} {
		req, _ := http.NewRequest("GET", srv.URL+"/shell/"+sid+"/ws", nil)
		for k, v := range h {
			req.Header.Set(k, v)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(admin)})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("websocket %v: %s", h, resp.Status)
		}
	}

	// the device refuses: the session ends with its reason, the transcript is stored
	l := s.shells.get(sid)
	l.record([]byte("\x1b[1mhello\x1b[0m\r\n"))
	s.shells.refused(c.ID, "remote shells are disabled on this device (allow_remote_shell)")
	select {
	case <-l.stored:
	case <-time.After(5 * time.Second):
		t.Fatal("end not stored")
	}
	var reason string
	var ended *time.Time
	var cmdStatus string
	db.QueryRow(ctx, `SELECT end_reason, ended_at FROM shell_sessions WHERE id=$1`, sid).Scan(&reason, &ended)
	db.QueryRow(ctx, `SELECT status FROM commands WHERE id=$1`, c.ID).Scan(&cmdStatus)
	if ended == nil || !strings.Contains(reason, "allow_remote_shell") || cmdStatus != "expired" {
		t.Fatalf("end: %q %v %s", reason, ended, cmdStatus)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='shell.end' AND target='d1'`).Scan(&audited)
	if audited != 1 {
		t.Fatal("end not audited")
	}
	if code, _, body := ui("GET", "/shell/"+sid, nil, audit); code != 200 || !strings.Contains(body, "hello") || strings.Contains(body, "\x1b") {
		t.Fatalf("transcript: %d", code)
	}
	if code, _, body := ui("GET", "/devices/d1/shell", nil, help); code != 200 || strings.Contains(body, sid) {
		t.Fatalf("helpdesk sees other users' sessions: %d", code)
	}
	if code, _, body := ui("GET", "/devices/d1/shell", nil, audit); code != 200 || !strings.Contains(body, sid) {
		t.Fatalf("auditor list: %d", code)
	}

	// helpdesk with the setting; ending from the console
	set.RemoteShell.Helpdesk = true
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	code, loc, _ = ui("POST", "/devices/d1/shell", url.Values{}, help)
	if code != http.StatusSeeOther {
		t.Fatalf("helpdesk start: %d", code)
	}
	sid2 := strings.TrimPrefix(loc, "/shell/")
	if code, _, _ := ui("POST", "/shell/"+sid2+"/end", url.Values{}, audit); code != http.StatusForbidden {
		t.Fatalf("auditor ended a session: %d", code)
	}
	if code, _, _ := ui("POST", "/shell/"+sid2+"/end", url.Values{}, help); code != http.StatusSeeOther {
		t.Fatalf("end: %d", code)
	}
	db.QueryRow(ctx, `SELECT end_reason, local_user FROM shell_sessions WHERE id=$1`, sid2).Scan(&reason, &cmdStatus)
	if !strings.Contains(reason, "help@firma.de") || cmdStatus != "limdm-support" {
		t.Fatalf("console end: %q %q", reason, cmdStatus)
	}
}
