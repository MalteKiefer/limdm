package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	ui := func(method, path, body, email, role string) (int, string) {
		t.Helper()
		return consoleAPI(t, s, srv.URL, session{Email: email, Role: role, IAT: time.Now(), Last: time.Now()})(method, path, body)
	}

	// ---- role scopes ----
	if code, body := ui("GET", "/api/v1/devices", "", "h@x.de", "helpdesk"); code != 200 || !strings.Contains(body, "pc1") || strings.Contains(body, "pc2") {
		t.Fatalf("scoped device list: %d", code)
	}
	if code, _ := ui("GET", "/api/v1/devices/d2", "", "h@x.de", "helpdesk"); code != http.StatusNotFound {
		t.Fatalf("device outside the scope: %d", code)
	}
	if code, _ := ui("POST", "/api/v1/devices/d2/commands", `{"type":"sync"}`, "h@x.de", "helpdesk"); code != http.StatusNotFound {
		t.Fatalf("command outside the scope: %d", code)
	}
	if code, _ := ui("POST", "/api/v1/devices/d1/commands", `{"type":"sync"}`, "h@x.de", "helpdesk"); code != http.StatusAccepted {
		t.Fatalf("command inside the scope: %d", code)
	}
	if code, _ := ui("GET", "/api/v1/devices/d2", "", "a@x.de", "admin"); code != 200 {
		t.Fatalf("admins are not scoped: %d", code)
	}
	if code, body := ui("GET", "/api/v1/compliance/history", "", "h@x.de", "helpdesk"); code != 200 || strings.Contains(body, "pc2") {
		t.Fatalf("scoped compliance history: %d", code)
	}
	if code, _ := ui("GET", "/api/v1/compliance/history?device=d2", "", "h@x.de", "helpdesk"); code != http.StatusNotFound {
		t.Fatalf("compliance history outside the scope: %d", code)
	}
	if code, _ := ui("GET", "/api/v1/config/library/1/versions", "", "h@x.de", "helpdesk"); code != http.StatusForbidden {
		t.Fatalf("scoped version history: %d", code)
	}

	// ---- four eyes ----
	must(`UPDATE console_users SET disabled=true WHERE email='b@x.de'`)
	if _, body := ui("PATCH", "/api/v1/settings/security", `{"four_eyes":true}`, "a@x.de", "admin"); !strings.Contains(body, "two active administrators") {
		t.Fatal("four eyes enabled with a single admin")
	}
	must(`UPDATE console_users SET disabled=false WHERE email='b@x.de'`)
	if code, body := ui("PATCH", "/api/v1/settings/security", `{"four_eyes":true}`, "a@x.de", "admin"); code != 200 || !s.settings().FourEyes {
		t.Fatalf("enable four eyes: %d %s", code, body)
	}
	if code, _ := ui("POST", "/api/v1/devices/d1/commands", `{"type":"wipe","params":{"confirm":"pc1"}}`, "a@x.de", "admin"); code != http.StatusAccepted {
		t.Fatalf("wipe request: %d", code)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM commands WHERE type='wipe'`).Scan(&n)
	var id int64
	db.QueryRow(ctx, `SELECT id FROM approvals WHERE status='pending' AND action='command'`).Scan(&id)
	if n != 0 || id == 0 {
		t.Fatalf("wipe ran without approval: %d commands, approval %d", n, id)
	}
	idPath := "/api/v1/approvals/" + strconv.FormatInt(id, 10)
	if _, body := ui("POST", idPath+"/approve", "", "a@x.de", "admin"); !strings.Contains(body, "own request") {
		t.Fatal("requester approved their own request")
	}
	if code, _ := ui("POST", idPath+"/approve", "", "b@x.de", "admin"); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	var by string
	db.QueryRow(ctx, `SELECT count(*), max(created_by) FROM commands WHERE type='wipe' AND device_id='d1'`).Scan(&n, &by)
	if n != 1 || by != "a@x.de" {
		t.Fatalf("approved wipe: %d by %q", n, by)
	}
	// bulk scripts wait too: one request per device
	if code, _ := ui("POST", "/api/v1/devices/bulk", `{"ids":["d1","d2"],"action":"command:script","params":{"payload":"echo hi"}}`, "a@x.de", "admin"); code != http.StatusAccepted {
		t.Fatalf("bulk script request: %d", code)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status='pending' AND action='command' AND payload->>'type'='script'`).Scan(&n)
	var scripts int
	db.QueryRow(ctx, `SELECT count(*) FROM commands WHERE type='script'`).Scan(&scripts)
	if n != 2 || scripts != 0 {
		t.Fatalf("bulk script under four eyes: %d requests, %d commands", n, scripts)
	}
	// remote shells wait when the setting asks for it; an approval is used once
	shellSet := s.settings()
	shellSet.FourEyesShell = true
	s.rt.Store(&runtimeState{set: shellSet, auth: &oidcAuth{}})
	asA := session{Email: "a@x.de", Role: "admin"}
	if _, err := s.requireApproval(ctx, asA, "remote_shell", "d1", "alice"); !errors.Is(err, errAwaitingApproval) {
		t.Fatalf("shell without approval: %v", err)
	}
	s.requireApproval(ctx, asA, "remote_shell", "d1", "alice") // no second request while one is pending
	var shellID int64
	db.QueryRow(ctx, `SELECT count(*), max(id) FROM approvals WHERE action='remote_shell' AND status='pending'`).Scan(&n, &shellID)
	if n != 1 {
		t.Fatalf("shell requests: %d", n)
	}
	ui("POST", "/api/v1/approvals/"+strconv.FormatInt(shellID, 10)+"/approve", "", "b@x.de", "admin")
	if _, err := s.requireApproval(ctx, asA, "remote_shell", "d1", "root"); !errors.Is(err, errAwaitingApproval) {
		t.Fatal("an approval for alice opened a shell as root")
	}
	aid, err := s.requireApproval(ctx, asA, "remote_shell", "d1", "alice")
	if err != nil || aid != shellID {
		t.Fatalf("approved shell: %d %v", aid, err)
	}
	use := func() error {
		tx, err := db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if err := useApproval(ctx, tx, aid); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := use(); err != nil {
		t.Fatalf("use approval: %v", err)
	}
	if err := use(); !errors.Is(err, errAwaitingApproval) {
		t.Fatal("a shell approval was used twice")
	}
	// role changes wait too, and the last two admins stay admins
	ui("PATCH", "/api/v1/users/h@x.de", `{"role":"auditor"}`, "a@x.de", "admin")
	if s.currentRole(ctx, "h@x.de") != "helpdesk" {
		t.Fatal("role changed without approval")
	}
	db.QueryRow(ctx, `SELECT id FROM approvals WHERE status='pending' AND action='user.update'`).Scan(&id)
	ui("POST", "/api/v1/approvals/"+strconv.FormatInt(id, 10)+"/approve", "", "b@x.de", "admin")
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

	// ---- account management cannot get around four eyes ----
	ui("POST", "/api/v1/users", `{"kind":"local","login":"second","role":"admin"}`, "a@x.de", "admin")
	if s.currentRole(ctx, "local:second") != "" {
		t.Fatal("an admin account was created without approval")
	}
	var addID int64
	db.QueryRow(ctx, `SELECT id FROM approvals WHERE status='pending' AND action='user.add'`).Scan(&addID)
	if code, body := ui("POST", "/api/v1/approvals/"+strconv.FormatInt(addID, 10)+"/approve", "", "b@x.de", "admin"); code != http.StatusOK || !strings.Contains(body, "otpauth://") {
		t.Fatalf("approved admin account: %d, credentials not shown to the approver", code)
	}
	if s.currentRole(ctx, "local:second") != "admin" {
		t.Fatal("approved admin account not created")
	}
	ui("POST", "/api/v1/users/local:second/reset", "", "a@x.de", "admin")
	var resetN int
	db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE status='pending' AND action='user.reset' AND target='local:second'`).Scan(&resetN)
	if resetN != 1 {
		t.Fatal("an admin's credentials were reset without approval")
	}
	ui("PATCH", "/api/v1/users/local:second", `{"role":"admin","disabled":true}`, "a@x.de", "admin")
	var disabled bool
	db.QueryRow(ctx, `SELECT disabled FROM local_admins WHERE name='second'`).Scan(&disabled)
	if disabled {
		t.Fatal("an admin was disabled without approval")
	}
	// a request through an API token counts as its creator's
	must(`INSERT INTO api_tokens(name, prefix, token_hash, role, read_only, created_by, expires_at) VALUES ('t','p','h-own','admin',false,'a@x.de', now() + interval '1 day')`)
	var tokID int64
	db.QueryRow(ctx, `SELECT id FROM api_tokens WHERE token_hash='h-own'`).Scan(&tokID)
	tokReq, err := s.requestApproval(ctx, apiCaller{ID: tokID, Name: "t", Role: "admin"}.sess(), "command", "d1", commandApproval{Type: "sync", Payload: "{}"}, "")
	if err != nil {
		t.Fatal(err)
	}
	ui("POST", "/api/v1/approvals/"+strconv.FormatInt(tokReq, 10)+"/approve", "", "a@x.de", "admin")
	db.QueryRow(ctx, `SELECT status FROM approvals WHERE id=$1`, tokReq).Scan(&st)
	if st != "pending" {
		t.Fatalf("the token creator approved their own request: %s", st)
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
	if code, _ := ui("DELETE", "/api/v1/devices/d2?confirm=pc2", "", "a@x.de", "admin"); code != http.StatusConflict {
		t.Fatalf("active device deleted: %d", code)
	}
	must(`UPDATE devices SET retired=true WHERE id='d2'`)
	if code, _ := ui("DELETE", "/api/v1/devices/d2?confirm=pc2", "", "a@x.de", "admin"); code != http.StatusNoContent {
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
