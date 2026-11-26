package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestMapRoleAndMFA(t *testing.T) {
	m, err := parseRoleGroups("it-admins; admin\nsupport; helpdesk; berlin,munich\nsupport-all; helpdesk\n\naudit; auditor")
	if err != nil || len(m) != 4 || roleGroupsText(m) == "" {
		t.Fatalf("parse: %v %v", m, err)
	}
	if _, err := parseRoleGroups("x; root"); err == nil {
		t.Fatal("unknown role accepted")
	}
	if _, err := parseRoleGroups("x; admin; berlin"); err == nil {
		t.Fatal("scoped admin accepted")
	}
	for _, c := range []struct {
		groups []string
		role   string
		tags   []string
	}{
		{[]string{"audit", "support"}, "helpdesk", []string{"berlin", "munich"}},
		{[]string{"support", "support-all"}, "helpdesk", nil}, // one unlimited mapping is enough
		{[]string{"support", "it-admins"}, "admin", nil},
		{[]string{"other"}, "", nil},
	} {
		if role, tags := mapRole(m, c.groups); role != c.role || !slices.Equal(tags, c.tags) {
			t.Errorf("%v: got %s %v", c.groups, role, tags)
		}
	}
	for _, c := range []struct {
		acr  []string
		amr  []string
		got  string
		want bool
	}{
		{nil, []string{"pwd", "mfa"}, "", true},
		{nil, []string{"pwd", "otp"}, "", true},
		{nil, []string{"pwd"}, "", false},
		{nil, []string{"pwd", "kba"}, "", false},
		{nil, nil, "", false},
		{[]string{"gold"}, []string{"mfa"}, "silver", false},
		{[]string{"gold"}, nil, "gold", true},
	} {
		if mfaSatisfied(c.acr, c.amr, c.got) != c.want {
			t.Errorf("mfa %v %v %q: want %v", c.acr, c.amr, c.got, c.want)
		}
	}
}

func TestLoginSecretSealing(t *testing.T) {
	s := &Server{cfg: Config{SessionKey: bytes.Repeat([]byte{7}, 32)}}
	prev := itemSecrets
	var err error
	if itemSecrets, err = s.aead(infoItems); err != nil {
		t.Fatal(err)
	}
	defer func() { itemSecrets = prev }()
	plain := []byte(`{"client_id":"c","client_secret":"GOCSPX-secret","reverify_hours":720}`)
	sealed, changed, err := sealItemSecrets(api.TypeLogin, plain)
	if err != nil || !changed || bytes.Contains(sealed, []byte("GOCSPX")) || !bytes.Contains(sealed, []byte(sealedPrefix)) {
		t.Fatalf("not sealed: %s %v", sealed, err)
	}
	if again, changed, _ := sealItemSecrets(api.TypeLogin, sealed); changed || !bytes.Equal(again, sealed) {
		t.Fatal("sealed twice")
	}
	opened, err := openItemSecrets(api.TypeLogin, sealed)
	var got map[string]any
	if err != nil || json.Unmarshal(opened, &got) != nil || got["client_secret"] != "GOCSPX-secret" || got["reverify_hours"] != 720.0 {
		t.Fatalf("open: %s %v", opened, err)
	}
	if out, _, _ := sealItemSecrets(api.TypePackages, plain); !bytes.Equal(out, plain) {
		t.Fatal("other types must stay as they are")
	}
}

// TestGovernance covers four eyes approval, role scopes, retention and risk
// exceptions against PostgreSQL (LIMDM_TEST_DATABASE_URL; wipes the schema).
func TestGovernance(t *testing.T) {
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
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{7}, 32)}}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	must := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO console_users(email, role) VALUES ('a@x.de','admin'), ('b@x.de','admin'), ('h@x.de','helpdesk')`)
	must(`UPDATE console_users SET scope_tags='{berlin}' WHERE email='h@x.de'`)
	must(`INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags) VALUES ('d1','s',now(),'pc1','{berlin}'), ('d2','s',now(),'pc2','{munich}')`)

	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	ui := func(method, path string, form url.Values, email, role string) (int, string) {
		t.Helper()
		sess := session{Email: email, Role: role, IAT: time.Now(), Last: time.Now()}
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
		return resp.StatusCode, string(b)
	}

	// ---- role scopes ----
	if code, body := ui("GET", "/devices", nil, "h@x.de", "helpdesk"); code != 200 || !strings.Contains(body, "pc1") || strings.Contains(body, "pc2") {
		t.Fatalf("scoped device list: %d", code)
	}
	if code, _ := ui("GET", "/devices/d2", nil, "h@x.de", "helpdesk"); code != http.StatusNotFound {
		t.Fatalf("device outside the scope: %d", code)
	}
	if code, _ := ui("POST", "/devices/d2/command", url.Values{"type": {"sync"}}, "h@x.de", "helpdesk"); code != http.StatusNotFound {
		t.Fatalf("command outside the scope: %d", code)
	}
	if code, _ := ui("POST", "/devices/d1/command", url.Values{"type": {"sync"}}, "h@x.de", "helpdesk"); code != http.StatusSeeOther {
		t.Fatalf("command inside the scope: %d", code)
	}
	if code, _ := ui("GET", "/devices/d2", nil, "a@x.de", "admin"); code != 200 {
		t.Fatalf("admins are not scoped: %d", code)
	}
	if code, body := ui("GET", "/compliance/history", nil, "h@x.de", "helpdesk"); code != 200 || strings.Contains(body, "pc2") {
		t.Fatalf("scoped compliance history: %d", code)
	}
	if code, _ := ui("GET", "/compliance/history?device=d2", nil, "h@x.de", "helpdesk"); code != http.StatusNotFound {
		t.Fatalf("compliance history outside the scope: %d", code)
	}
	if code, _ := ui("GET", "/library/1/history", nil, "h@x.de", "helpdesk"); code != http.StatusForbidden {
		t.Fatalf("scoped version history: %d", code)
	}

	// ---- four eyes ----
	must(`UPDATE console_users SET disabled=true WHERE email='b@x.de'`)
	if _, body := ui("POST", "/settings", url.Values{"section": {"security"}, "four_eyes": {"on"}}, "a@x.de", "admin"); !strings.Contains(body, "two active administrators") {
		t.Fatal("four eyes enabled with a single admin")
	}
	must(`UPDATE console_users SET disabled=false WHERE email='b@x.de'`)
	if code, body := ui("POST", "/settings", url.Values{"section": {"security"}, "four_eyes": {"on"}}, "a@x.de", "admin"); code != 200 || !s.settings().FourEyes {
		t.Fatalf("enable four eyes: %d %s", code, body)
	}
	if code, _ := ui("POST", "/devices/d1/command", url.Values{"type": {"wipe"}, "confirm": {"pc1"}}, "a@x.de", "admin"); code != http.StatusSeeOther {
		t.Fatalf("wipe request: %d", code)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM commands WHERE type='wipe'`).Scan(&n)
	var id int64
	db.QueryRow(ctx, `SELECT id FROM approvals WHERE status='pending' AND action='command'`).Scan(&id)
	if n != 0 || id == 0 {
		t.Fatalf("wipe ran without approval: %d commands, approval %d", n, id)
	}
	idPath := "/approvals/" + strconv.FormatInt(id, 10)
	if _, body := ui("POST", idPath+"/approve", url.Values{}, "a@x.de", "admin"); !strings.Contains(body, "own request") {
		t.Fatal("requester approved their own request")
	}
	if code, _ := ui("POST", idPath+"/approve", url.Values{}, "b@x.de", "admin"); code != http.StatusSeeOther {
		t.Fatalf("approve: %d", code)
	}
	var by string
	db.QueryRow(ctx, `SELECT count(*), max(created_by) FROM commands WHERE type='wipe' AND device_id='d1'`).Scan(&n, &by)
	if n != 1 || by != "a@x.de" {
		t.Fatalf("approved wipe: %d by %q", n, by)
	}
	// role changes wait too, and the last two admins stay admins
	ui("POST", "/users/update", url.Values{"login": {"h@x.de"}, "role": {"auditor"}}, "a@x.de", "admin")
	if s.currentRole(ctx, "h@x.de") != "helpdesk" {
		t.Fatal("role changed without approval")
	}
	db.QueryRow(ctx, `SELECT id FROM approvals WHERE status='pending' AND action='user.update'`).Scan(&id)
	ui("POST", "/approvals/"+strconv.FormatInt(id, 10)+"/approve", url.Values{}, "b@x.de", "admin")
	if s.currentRole(ctx, "h@x.de") != "auditor" {
		t.Fatal("approved role change not applied")
	}
	must(`UPDATE approvals SET status='pending', expires_at=now() - interval '1 minute' WHERE id=$1`, id)
	if err := s.expireApprovals(ctx); err != nil {
		t.Fatal(err)
	}
	var st string
	db.QueryRow(ctx, `SELECT status FROM approvals WHERE id=$1`, id).Scan(&st)
	if st != "expired" {
		t.Fatalf("expired request: %s", st)
	}

	// ---- risk exceptions reach the compliance declaration while active ----
	must(`INSERT INTO risk_exceptions(check_id, mode, tag, reason, owner, approver, expires_at, created_by) VALUES
		('net.forwarding','exclude','berlin','r','o','p', now() + interval '1 day','a@x.de'),
		('boot.secureboot','advisory','','r','o','p', now() - interval '1 day','a@x.de')`)
	decls := []api.Declaration{{Identifier: "compliance", Type: api.TypeCompliance, Payload: json.RawMessage(`{"level":1,"exclude":[]}`)}}
	tx, _ := db.Begin(ctx)
	err = applyExceptions(ctx, tx, "d1", decls)
	tx.Rollback(ctx)
	var c api.Compliance
	if err != nil || json.Unmarshal(decls[0].Payload, &c) != nil || !slices.Equal(c.Exclude, []string{"net.forwarding"}) || len(c.Advisory) != 0 ||
		decls[0].ServerToken != decls[0].Token() {
		t.Fatalf("exceptions: %s %v", decls[0].Payload, err)
	}

	// ---- retention ----
	must(`INSERT INTO device_events(device_id, at, detail) VALUES ('d2', now(), 'x')`)
	if _, err := db.Exec(ctx, `DELETE FROM device_events`); err == nil {
		t.Fatal("device_events deletable outside the retention job")
	}
	if code, _ := ui("POST", "/devices/d2/delete", url.Values{"confirm": {"pc2"}}, "a@x.de", "admin"); code != http.StatusBadRequest {
		t.Fatalf("active device deleted: %d", code)
	}
	must(`UPDATE devices SET retired=true WHERE id='d2'`)
	if code, _ := ui("POST", "/devices/d2/delete", url.Values{"confirm": {"pc2"}}, "a@x.de", "admin"); code != http.StatusSeeOther {
		t.Fatalf("delete device: %d", code)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id='d2'`).Scan(&n)
	if n != 0 {
		t.Fatal("device not deleted")
	}
	if _, err := db.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("audit_log deletable outside the retention job")
	}
	var total int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&total)
	set := s.settings()
	set.AuditRetentionDays = 365
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})
	// entries are recent, so nothing is old enough: the prune is a no-op
	if err := s.pruneAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("chain after a no-op prune: %d %v", broken, err)
	}
	// a cut in the middle: delete the first half like the job does, then verify
	var cutID int64
	var cutHash []byte
	db.QueryRow(ctx, `SELECT id, hash FROM audit_log ORDER BY id OFFSET $1 LIMIT 1`, total/2).Scan(&cutID, &cutHash)
	err = s.retentionTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE id <= $1`, cutID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_cut(one, last_id, last_hash, mac, cut_at) VALUES (true,$1,$2,$3,now())`, cutID, cutHash, cutMAC(cutID, cutHash))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if broken, err := s.verifyAuditFrom(ctx, false); err != nil || broken != 0 {
		t.Fatalf("chain after the cut: %d %v", broken, err)
	}
	if broken, err := s.verifyAuditFrom(ctx, true); err != nil || broken != 0 {
		t.Fatalf("incremental check after the cut: %d %v", broken, err)
	}
	must(`UPDATE audit_cut SET mac='forged'`)
	if broken, _ := s.verifyAuditFrom(ctx, false); broken == 0 {
		t.Fatal("forged cut accepted")
	}
}
