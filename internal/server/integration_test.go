package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

// End to end test against a real PostgreSQL:
//
//	LIMDM_TEST_DATABASE_URL=postgres://limdm@127.0.0.1:55432/limdm go test ./internal/server
//
// It wipes the public schema of that database.
func TestIntegration(t *testing.T) {
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
	if err := migrate(ctx, db); err != nil {
		t.Fatal("schema must be idempotent: ", err)
	}
	ca, err := loadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db, cmdKey: testCmdKey, ca: ca, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", AgentURL: "https://127.0.0.1:8444", StaleAfter: 24 * time.Hour,
		SessionKey: bytes.Repeat([]byte{7}, 32), Admins: []string{"admin@firma.de"}, Auditors: []string{"audit@firma.de"}, LocalLogin: true,
	}}

	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	// removing someone from LIMDM_AUDITORS revokes them at the next start
	s.cfg.Auditors = nil
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	var auditorDisabled bool
	db.QueryRow(ctx, `SELECT disabled FROM console_users WHERE email='audit@firma.de'`).Scan(&auditorDisabled)
	if !auditorDisabled {
		t.Fatal("auditor removed from the environment stays enabled")
	}
	db.Exec(ctx, `UPDATE console_users SET disabled=false WHERE email='audit@firma.de'`)
	s.cfg.Auditors = []string{"audit@firma.de"}
	// OIDC "configured" without network discovery: sessions of OIDC users stay valid
	s.rt.Store(&runtimeState{set: Settings{LocalLogin: true, StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})

	// ---- admin UI with a forged, validly signed session ----
	admin := httptest.NewServer(s.AdminHandler())
	defer admin.Close()
	adminSess := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	ui := func(method, path string, form url.Values, sess session) (int, string) {
		t.Helper()
		if form != nil {
			form.Set("csrf", s.csrfToken(sess))
		}
		req, _ := http.NewRequest(method, admin.URL+path, strings.NewReader(form.Encode()))
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

	if code, _ := ui("GET", "/", nil, session{}); code != http.StatusFound {
		t.Fatalf("anonymous must be redirected to login, got %d", code)
	}
	code, body := ui("POST", "/tokens", url.Values{"note": {"test"}, "uses": {"2"}, "days": {"1"}, "blueprint_id": {"0"}}, adminSess)
	token := regexp.MustCompile(`lmt_[A-Za-z0-9_-]+`).FindString(body)
	if code != 200 || token == "" || !strings.Contains(body, ca.Fingerprint()) {
		t.Fatalf("token page: %d", code)
	}
	_, body2 := ui("POST", "/tokens", url.Values{"note": {"revoke-me"}, "uses": {"1"}, "days": {"1"}, "blueprint_id": {"0"}}, adminSess)
	revID := hex.EncodeToString(sha(regexp.MustCompile(`lmt_[A-Za-z0-9_-]+`).FindString(body2)))
	if code, _ := ui("POST", "/tokens/"+revID+"/revoke", url.Values{}, adminSess); code != http.StatusSeeOther && code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := ui("POST", "/tokens/"+revID+"/revoke", url.Values{}, adminSess); code != http.StatusNotFound {
		t.Fatalf("revoked token still present: %d", code)
	}
	auditor := session{Email: "audit@firma.de", Role: "auditor", IAT: time.Now(), Last: time.Now()}
	if code, _ := ui("POST", "/tokens", url.Values{"uses": {"1"}, "days": {"1"}}, auditor); code != http.StatusForbidden {
		t.Fatalf("auditor must be read only, got %d", code)
	}
	for _, path := range []string{"/software/import", "/software/apps", "/software/settings", "/software/requests/1/approve", "/software/apps/firefox/delete"} {
		if code, _ := ui("POST", path, url.Values{"flatpak": {"org.example.App"}}, auditor); code != http.StatusForbidden {
			t.Fatalf("auditor must not change the catalog: %s %d", path, code)
		}
	}
	bad := url.Values{"uses": {"1"}, "days": {"1"}}
	if code, _ := ui("POST", "/tokens", bad, adminSess); code != 200 {
		t.Fatal("sanity")
	}
	// a browser form post carries the real Origin; it must pass
	okReq := url.Values{"uses": {"1"}, "days": {"1"}, "csrf": {s.csrfToken(adminSess)}}
	req0, _ := http.NewRequest("POST", admin.URL+"/tokens", strings.NewReader(okReq.Encode()))
	req0.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req0.Header.Set("Origin", s.cfg.PublicURL)
	req0.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(adminSess)})
	resp0, err := http.DefaultClient.Do(req0)
	if err != nil {
		t.Fatal(err)
	}
	resp0.Body.Close()
	if resp0.StatusCode != 200 {
		t.Fatalf("form post with matching Origin rejected: %d", resp0.StatusCode)
	}
	hr, err := http.Get(admin.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	hr.Body.Close()
	if hr.Header.Get("Referrer-Policy") == "no-referrer" {
		t.Fatal("no-referrer makes browsers send Origin: null and breaks every form")
	}
	bad.Set("csrf", "wrong")
	req, _ := http.NewRequest("POST", admin.URL+"/tokens", strings.NewReader(bad.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(adminSess)})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf not enforced: %d", resp.StatusCode)
	}

	// ---- agent API over mTLS ----
	tc, err := s.AgentTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	agentSrv := httptest.NewUnstartedServer(s.AgentHandler())
	agentSrv.TLS = tc
	agentSrv.StartTLS()
	defer agentSrv.Close()

	newIdentity := func() (*ecdsa.PrivateKey, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}
	clientFor := func(key *ecdsa.PrivateKey, certPEM string) *http.Client {
		tcfg := &tls.Config{RootCAs: ca.pool(), MinVersion: tls.VersionTLS13}
		if key != nil {
			kb, _ := x509.MarshalECPrivateKey(key)
			pair, err := tls.X509KeyPair([]byte(certPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
			if err != nil {
				t.Fatal(err)
			}
			tcfg.Certificates = []tls.Certificate{pair}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: tcfg}}
	}
	call := func(c *http.Client, path string, in, out any) int {
		t.Helper()
		b, _ := json.Marshal(in)
		resp, err := c.Post(agentSrv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil && resp.StatusCode == 200 {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}

	key, csr := newIdentity()
	var er api.EnrollResponse
	if code := call(clientFor(nil, ""), "/api/v1/enroll", api.EnrollRequest{Token: "lmt_wrong", CSR: csr}, nil); code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", code)
	}
	if code := call(clientFor(nil, ""), "/api/v1/enroll", api.EnrollRequest{Token: token, CSR: csr, Hostname: "laptop1"}, &er); code != 200 || er.DeviceID == "" {
		t.Fatalf("enroll: %d", code)
	}
	dev := clientFor(key, er.Cert)
	if code := call(clientFor(nil, ""), "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("checkin without client cert: %d", code)
	}

	status := &api.Status{
		Inventory: api.Inventory{Hostname: "laptop1", OSID: "debian", OSVersion: "12", OSName: "Debian GNU/Linux 12", Arch: "amd64", MemoryMB: 16384, Desktop: "GNOME 43",
			Disks:   []api.Disk{{Name: "/dev/nvme0n1", Model: "Test SSD", SizeGB: 512, Type: "nvme"}},
			Volumes: []api.Volume{{Device: "/dev/mapper/root", Mount: "/", FS: "ext4", SizeGB: 500, FreeGB: 40, Encrypted: true}}},
		Checks: []api.CheckResult{
			{ID: "disk.encryption", Title: "LUKS", Level: 1, Status: "fail", Detail: "=evil", Refs: api.Refs{BSI: []string{"CON.1"}, ISO: []string{"A.8.24"}}},
			{ID: "firewall.active", Title: "FW", Level: 1, Status: "pass", Refs: api.Refs{ISO: []string{"A.8.20"}}},
		},
	}
	var cr api.CheckinResponse
	if code := call(dev, "/api/v1/checkin", api.CheckinRequest{AgentVersion: "1.0.0", Status: status, StatusHash: "s1",
		Packages: []api.Package{{Name: "openssl", Version: "3"}}, PackagesHash: "p1"}, &cr); code != 200 {
		t.Fatalf("checkin: %d", code)
	}
	if len(cr.Declarations) == 0 || cr.DeclarationsToken == "" || cr.NeedStatus || cr.NeedPackages {
		t.Fatalf("first checkin response: %+v", cr)
	}
	firstToken := cr.DeclarationsToken
	cr = api.CheckinResponse{}
	call(dev, "/api/v1/checkin", api.CheckinRequest{DeclarationsToken: firstToken, StatusHash: "s1", PackagesHash: "p1"}, &cr)
	if cr.Declarations != nil {
		t.Fatal("unchanged token must not resend declarations")
	}
	cr = api.CheckinResponse{}
	call(dev, "/api/v1/checkin", api.CheckinRequest{DeclarationsToken: firstToken, StatusHash: "s2", PackagesHash: "p1"}, &cr)
	if !cr.NeedStatus {
		t.Fatal("unknown status hash must request full status")
	}

	// library items and a blueprint with a condition, inheriting from default
	itemID := func(name string) string {
		var id string
		db.QueryRow(ctx, `SELECT id::text FROM library_items WHERE name=$1`, name).Scan(&id)
		return id
	}
	saveItem := func(name, typ, payload string) (int, string) {
		return ui("POST", "/library", url.Values{"name": {name}, "type": {typ}, "payload": {payload}}, adminSess)
	}
	if code, body := saveItem("CIS Level 2", api.TypeCompliance, `{"level":2,"remediate":true,"exclude":[]}`); code != http.StatusSeeOther {
		t.Fatalf("library save: %d %s", code, body)
	}
	if code, _ := saveItem("Debian tools", api.TypePackages, `{"install":["htop"],"remove":[]}`); code != http.StatusSeeOther {
		t.Fatal("library save packages")
	}
	if code, body := saveItem("evil", api.TypePackages, `{"install":["--evil"]}`); code != 200 || !strings.Contains(body, "invalid package") {
		t.Fatal("invalid library item must be rejected")
	}
	var defID string
	db.QueryRow(ctx, `SELECT id::text FROM blueprints WHERE name='default'`).Scan(&defID)
	tree := `[{"kind":"assign","items":[` + itemID("CIS Level 2") + `]},
		{"kind":"if","branches":[{"match":"all","rules":[{"field":"os.id","op":"eq","value":"debian"},{"field":"tag","op":"has","value":"lab"}],
		"nodes":[{"kind":"assign","items":[` + itemID("Debian tools") + `]}]}],"else":[]}]`
	if code, body := ui("POST", "/blueprints", url.Values{"name": {"strict"}, "parent_id": {defID}, "tree": {tree}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("blueprint save: %d %s", code, body)
	}
	if code, body := ui("POST", "/blueprints", url.Values{"name": {"bad"}, "tree": {`[{"kind":"assign","items":[99999]}]`}}, adminSess); code != 200 || !strings.Contains(body, "does not exist") {
		t.Fatal("blueprint with unknown item must be rejected")
	}
	if code, body := ui("POST", "/blueprints", url.Values{"id": {defID}, "name": {"renamed"}, "tree": {"[]"}}, adminSess); code != 200 || !strings.Contains(body, "cannot be renamed") {
		t.Fatalf("renaming default must be refused: %d", code)
	}
	var bpID string
	db.QueryRow(ctx, `SELECT id::text FROM blueprints WHERE name='strict'`).Scan(&bpID)
	ui("POST", "/blueprints", url.Values{"name": {"child"}, "parent_id": {bpID}, "tree": {"[]"}}, adminSess)
	var childID string
	db.QueryRow(ctx, `SELECT id::text FROM blueprints WHERE name='child'`).Scan(&childID)
	if code, body := ui("POST", "/blueprints", url.Values{"id": {bpID}, "name": {"strict"}, "parent_id": {childID}, "tree": {tree}}, adminSess); code != 200 || !strings.Contains(body, "cycle") {
		t.Fatal("inheritance cycle must be refused")
	}
	if code, _ := ui("POST", "/library/"+itemID("Debian tools")+"/delete", url.Values{}, adminSess); code != http.StatusConflict {
		t.Fatal("deleting an item in use must be refused")
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/assign", url.Values{"blueprint_id": {bpID}, "tags": {"Lab, berlin"}, "users": {"mm max@firma.de admin"}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("assign: %d", code)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/assign", url.Values{"tags": {"no spaces allowed"}}, adminSess); code != http.StatusBadRequest {
		t.Fatal("invalid tag accepted")
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"rm -rf"}}, adminSess); code != http.StatusBadRequest {
		t.Fatalf("unknown command type accepted: %d", code)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"sync"}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("command: %d", code)
	}
	cr = api.CheckinResponse{}
	call(dev, "/api/v1/checkin", api.CheckinRequest{DeclarationsToken: firstToken, StatusHash: "s1", PackagesHash: "p1"}, &cr)
	pol, _ := api.Compose(cr.Declarations)
	if cr.DeclarationsToken == firstToken || pol.Compliance.Level != 2 || len(cr.Users) != 1 || len(cr.Commands) != 1 {
		t.Fatalf("after assignment: level=%d users=%v cmds=%v", pol.Compliance.Level, cr.Users, cr.Commands)
	}
	if !slices.Contains(pol.Packages.Install, "htop") || pol.Updates.Mode != "security" {
		t.Fatalf("condition (debian + tag lab) or inherited default not applied: %+v", pol)
	}
	call(dev, "/api/v1/checkin", api.CheckinRequest{DeclarationsToken: cr.DeclarationsToken, StatusHash: "s1", PackagesHash: "p1",
		Results: []api.CommandResult{{ID: cr.Commands[0].ID, OK: true, Output: "ok"}}, Events: []string{"remediated kernel.aslr"}}, nil)

	// every admin page renders
	pages := []string{"/", "/devices", "/devices?status=non-compliant&q=laptop", "/compliance", "/compliance?state=failing&level=1&framework=iso&sort=fail&q=luks", "/blueprints", "/blueprints/" + bpID, "/blueprints/new", "/library", "/library/new?type=com.limdm.packages", "/library/" + itemID("Debian tools"), "/tokens", "/audit"}
	for _, tab := range []string{"overview", "hardware", "network", "software", "software&sub=sources", "accounts", "accounts&sub=groups&system=1", "compliance", "declarations", "commands&type=reboot"} {
		pages = append(pages, "/devices/"+er.DeviceID+"?tab="+tab+"&q=open&page=2")
	}
	pages = append(pages, "/profile", "/profile?tab=password", "/profile?tab=recovery")
	for _, p := range pages {
		if code, body := ui("GET", p, nil, auditor); code != 200 {
			t.Fatalf("GET %s: %d %s", p, code, body)
		}
	}
	if _, body := ui("GET", "/audit", nil, auditor); !strings.Contains(body, "intact") {
		t.Fatal("audit chain must verify")
	}
	_, body = ui("GET", "/export/compliance.csv", nil, auditor)
	if !strings.Contains(body, "disk.encryption") || !strings.Contains(body, "'=evil") || !strings.Contains(body, "A.8.24") {
		t.Fatalf("compliance export:\n%s", body)
	}
	if _, body := ui("GET", "/devices/"+er.DeviceID+"?tab=declarations", nil, auditor); !strings.Contains(body, "com.limdm.compliance") {
		t.Fatal("device page must list declarations")
	}

	// ---- directory: SCIM provisioning and group based blueprint assignment ----
	_, body = ui("POST", "/directory/scim-token", url.Values{}, adminSess)
	scimTok := regexp.MustCompile(`lms_[A-Za-z0-9_-]+`).FindString(body)
	if scimTok == "" {
		t.Fatal("no SCIM token shown")
	}
	scim := func(method, path, tok string, in any, out any) int {
		t.Helper()
		var rd io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, admin.URL+"/scim/v2"+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	if code := scim("GET", "/Users", "wrong", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("SCIM without valid token: %d", code)
	}
	var created struct{ ID string }
	if code := scim("POST", "/Users", scimTok, map[string]any{"schemas": []string{scimUserSchema}, "userName": "max@firma.de", "externalId": "ext-1",
		"name": map[string]string{"givenName": "Max", "familyName": "Muster"}, "emails": []map[string]any{{"value": "Max@Firma.de", "primary": true}},
		scimEnterprise: map[string]string{"department": "Finance"}}, &created); code != http.StatusCreated || created.ID == "" {
		t.Fatalf("SCIM create user: %d", code)
	}
	if code := scim("POST", "/Users", scimTok, map[string]any{"userName": "max@firma.de", "emails": []map[string]any{{"value": "max@firma.de"}}}, nil); code != http.StatusConflict {
		t.Fatalf("duplicate SCIM user: %d", code)
	}
	var list struct{ TotalResults int }
	scim("GET", `/Users?filter=userName+eq+%22max@firma.de%22`, scimTok, nil, &list)
	if list.TotalResults != 1 {
		t.Fatalf("SCIM filter: %d", list.TotalResults)
	}
	var grp struct{ ID string }
	if code := scim("POST", "/Groups", scimTok, map[string]any{"displayName": "finance-laptops", "members": []map[string]string{}}, &grp); code != http.StatusCreated {
		t.Fatalf("SCIM create group: %d", code)
	}
	if code := scim("PATCH", "/Groups/"+grp.ID, scimTok, map[string]any{"schemas": []string{scimPatch}, "Operations": []map[string]any{
		{"op": "Add", "path": "members", "value": []map[string]string{{"value": created.ID}}}}}, nil); code != 200 {
		t.Fatalf("SCIM add member: %d", code)
	}
	var gid string
	db.QueryRow(ctx, `SELECT id::text FROM dir_groups WHERE name='finance-laptops'`).Scan(&gid)
	ui("POST", "/directory/groups", url.Values{"group_id": {gid}, "blueprint_id": {childID}, "priority": {"5"}}, adminSess)
	// clear the explicit blueprint, set the primary user: the group's blueprint must win over default
	if code, body := ui("POST", "/devices/"+er.DeviceID+"/assign", url.Values{"blueprint_id": {"0"}, "primary_user": {"max@firma.de"}, "tags": {"lab"}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("assign primary user: %d %s", code, body)
	}
	tx0, _ := db.Begin(ctx)
	resGroup, err := resolveDevice(ctx, tx0, er.DeviceID)
	tx0.Rollback(ctx)
	if err != nil || resGroup.Chain[len(resGroup.Chain)-1].Name != "child" {
		t.Fatalf("group assignment not applied: %v %+v", err, resGroup.Chain)
	}
	txf, _ := db.Begin(ctx)
	facts, _, _ := deviceFacts(ctx, txf, er.DeviceID)
	txf.Rollback(ctx) // an open transaction would block later schema DDL
	if len(facts.Groups) != 1 || facts.Department != "Finance" {
		t.Fatalf("directory facts: %+v", facts)
	}
	// Entra deactivates with a string boolean; the device loses the group blueprint
	if code := scim("PATCH", "/Users/"+created.ID, scimTok, map[string]any{"schemas": []string{scimPatch}, "Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}}}, nil); code != 200 {
		t.Fatalf("SCIM deactivate: %d", code)
	}
	tx1, _ := db.Begin(ctx)
	resGroup, _ = resolveDevice(ctx, tx1, er.DeviceID)
	tx1.Rollback(ctx)
	if resGroup.Chain[len(resGroup.Chain)-1].Name != "default" {
		t.Fatalf("inactive user must not bring a group blueprint: %+v", resGroup.Chain)
	}
	if code, _ := ui("GET", "/directory", nil, auditor); code != 200 {
		t.Fatal("directory page")
	}

	// tamper events mark the device and are audited separately
	if code := call(dev, "/api/v1/checkin", api.CheckinRequest{Events: []string{"2026-11-25T08:00:00Z tamper: watchdog: limdm-agent.service was disabled, enabled again"}}, nil); code != 200 {
		t.Fatalf("checkin with tamper event: %d", code)
	}
	var tamperedAt *time.Time
	var tamperAudits int
	db.QueryRow(ctx, `SELECT tampered_at FROM devices WHERE id=$1`, er.DeviceID).Scan(&tamperedAt)
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='agent.tamper'`).Scan(&tamperAudits)
	if tamperedAt == nil || tamperAudits != 1 {
		t.Fatalf("tamper event: tampered_at=%v audits=%d", tamperedAt, tamperAudits)
	}
	// routine events go to device_events, not into the chained audit log
	if code := call(dev, "/api/v1/checkin", api.CheckinRequest{Events: []string{"2026-11-25T08:01:00Z created user anna", "no timestamp"}}, nil); code != 200 {
		t.Fatalf("checkin with events: %d", code)
	}
	var routine, routineAudits int
	db.QueryRow(ctx, `SELECT count(*) FROM device_events WHERE device_id=$1 AND detail IN ('created user anna','no timestamp')`, er.DeviceID).Scan(&routine)
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE detail LIKE '%created user anna%'`).Scan(&routineAudits)
	if routine != 2 || routineAudits != 0 {
		t.Fatalf("routine events: stored=%d audited=%d", routine, routineAudits)
	}
	if _, err := db.Exec(ctx, `UPDATE device_events SET detail='x'`); err == nil {
		t.Fatal("device_events must be append only")
	}
	// renewal: the old certificate stays valid until the new one is used (a lost
	// response must not lock the device out), then it is revoked
	key2, csr2 := newIdentity()
	var rr api.EnrollResponse
	if code := call(dev, "/api/v1/renew", api.RenewRequest{CSR: csr2}, &rr); code != 200 {
		t.Fatalf("renew: %d", code)
	}
	if code := call(dev, "/api/v1/checkin", api.CheckinRequest{}, nil); code != 200 {
		t.Fatalf("old certificate rejected before the new one was used: %d", code)
	}
	dev2 := clientFor(key2, rr.Cert)
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != 200 {
		t.Fatalf("renewed certificate rejected: %d", code)
	}
	if code := call(dev, "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusForbidden {
		t.Fatalf("old certificate still accepted after the new one was used: %d", code)
	}

	// a certificate the device CA did not issue is rejected, even with a registered serial
	issue := func(signer *x509.Certificate, signerKey any, pub any, notAfter time.Time) (*x509.Certificate, string) {
		tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: er.DeviceID},
			NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if signer == nil {
			tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, tmpl.KeyUsage|x509.KeyUsageCertSign
			signer = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	setSerial := func(c *x509.Certificate) {
		if _, err := db.Exec(ctx, `UPDATE devices SET cert_serial=$2 WHERE id=$1`, er.DeviceID, c.SerialNumber.Text(16)); err != nil {
			t.Fatal(err)
		}
	}
	foreign, foreignPEM := issue(nil, key2, &key2.PublicKey, time.Now().Add(time.Hour))
	setSerial(foreign)
	if code := call(clientFor(key2, foreignPEM), "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("foreign CA accepted: %d", code)
	}
	if code := call(clientFor(key2, foreignPEM), "/api/v1/renew", api.RenewRequest{CSR: csr2}, nil); code != http.StatusUnauthorized {
		t.Fatalf("foreign CA accepted for renewal: %d", code)
	}

	// an expired certificate may renew within the grace period, but not check in
	// expired 30 minutes ago: the test CA itself is only one hour old
	expiredCert, expiredPEM := issue(ca.cert, ca.key, &key2.PublicKey, time.Now().Add(-30*time.Minute))
	setSerial(expiredCert)
	devExpired := clientFor(key2, expiredPEM)
	if code := call(devExpired, "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("expired certificate accepted for check in: %d", code)
	}
	key3, csr3 := newIdentity()
	var rr3 api.EnrollResponse
	if code := call(devExpired, "/api/v1/renew", api.RenewRequest{CSR: csr3}, &rr3); code != 200 {
		t.Fatalf("expired certificate within grace could not renew: %d", code)
	}
	dev2 = clientFor(key3, rr3.Cert)
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != 200 {
		t.Fatalf("certificate renewed from expired one rejected: %d", code)
	}
	ancient, ancientPEM := issue(ca.cert, ca.key, &key3.PublicKey, time.Now().Add(-expiredRenewGrace-time.Hour))
	setSerial(ancient)
	if code := call(clientFor(key3, ancientPEM), "/api/v1/renew", api.RenewRequest{CSR: csr3}, nil); code != http.StatusUnauthorized {
		t.Fatalf("certificate beyond grace accepted for renewal: %d", code)
	}

	// retiring revokes access
	_, freshPEM := issue(ca.cert, ca.key, &key3.PublicKey, time.Now().Add(time.Hour))
	fresh, _ := x509.ParseCertificate(func() []byte { b, _ := pem.Decode([]byte(freshPEM)); return b.Bytes }())
	setSerial(fresh)
	dev2 = clientFor(key3, freshPEM)
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != 200 {
		t.Fatalf("fresh certificate rejected: %d", code)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/retire", url.Values{}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("retire: %d", code)
	}
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusForbidden {
		t.Fatalf("retired device still accepted: %d", code)
	}

	// ---- local admin with password and TOTP ----
	creds, err := LocalAdmin(ctx, dsn, "add", "breakglass", "admin")
	if err != nil {
		t.Fatal(err)
	}
	field := func(k string) string {
		for _, l := range strings.Split(creds, "\n") {
			if v, ok := strings.CutPrefix(l, k+":"); ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	pw := field("password")
	secret := regexp.MustCompile(`secret=([A-Z2-7]+)`).FindStringSubmatch(creds)[1]
	if _, err := LocalAdmin(ctx, dsn, "add", "breakglass", "admin"); err == nil {
		t.Fatal("duplicate local admin accepted")
	}
	localLogin := func(user, password, code string) (int, *http.Cookie) {
		t.Helper()
		form := url.Values{"csrf": {"tok"}, "username": {user}, "password": {password}, "totp": {code}}
		req, _ := http.NewRequest("POST", admin.URL+"/login/local", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: loginCookie, Value: "tok"})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		for _, c := range resp.Cookies() {
			if c.Name == sessionCookie && c.Value != "" {
				return resp.StatusCode, c
			}
		}
		return resp.StatusCode, nil
	}
	code1, _ := totpCode(secret, time.Now().Unix()/30)
	if st, c := localLogin("breakglass", pw+"x", code1); c != nil || st != 200 {
		t.Fatalf("wrong password accepted: %d", st)
	}
	if _, c := localLogin("breakglass\nforged log line", pw, code1); c != nil {
		t.Fatal("malformed username accepted")
	}
	var invalidAudited int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE actor='local:(invalid)'`).Scan(&invalidAudited)
	if invalidAudited != 1 {
		t.Fatalf("malformed username must be audited as (invalid), got %d", invalidAudited)
	}
	st, sessCookie := localLogin("breakglass", pw, code1)
	if st != http.StatusSeeOther || sessCookie == nil {
		t.Fatalf("local login failed: %d", st)
	}
	if _, c := localLogin("breakglass", pw, code1); c != nil {
		t.Fatal("replayed TOTP code accepted")
	}
	getWith := func(c *http.Cookie) int {
		req, _ := http.NewRequest("GET", admin.URL+"/", nil)
		req.AddCookie(c)
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if getWith(sessCookie) != 200 {
		t.Fatal("local admin session rejected")
	}
	if _, err := LocalAdmin(ctx, dsn, "disable", "breakglass", "admin"); err != nil {
		t.Fatal(err)
	}
	if getWith(sessCookie) != http.StatusFound {
		t.Fatal("session of a disabled local admin still valid")
	}
	if _, err := LocalAdmin(ctx, dsn, "enable", "breakglass", "admin"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxFailures; i++ {
		localLogin("breakglass", "wrong", "000000")
	}
	code2, _ := totpCode(secret, time.Now().Unix()/30+1)
	if _, c := localLogin("breakglass", pw, code2); c != nil {
		t.Fatal("locked account accepted a correct login")
	}
	var lockedFailures int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='login.local.failed'`).Scan(&lockedFailures)
	if lockedFailures < maxFailures+2 {
		t.Fatalf("failed local logins not audited: %d", lockedFailures)
	}

	// ---- roles: helpdesk may send commands but no scripts and no configuration ----
	db.Exec(ctx, `INSERT INTO console_users(email, role) VALUES ('help@firma.de', 'helpdesk')`)
	help := session{Email: "help@firma.de", Role: "helpdesk", IAT: time.Now(), Last: time.Now()}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"reboot"}}, help); code != http.StatusSeeOther {
		t.Fatalf("helpdesk command: %d", code)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"shutdown"}, "minutes": {"5000"}}, help); code != http.StatusBadRequest {
		t.Fatalf("delay out of range accepted: %d", code)
	}
	// lost mode and wipe: admins only, confirmed with the host name
	var host string
	db.QueryRow(ctx, `SELECT hostname FROM devices WHERE id=$1`, er.DeviceID).Scan(&host)
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"wipe"}, "confirm": {host}}, help); code != http.StatusForbidden {
		t.Fatalf("helpdesk wipe: %d", code)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"wipe"}, "confirm": {"wrong"}}, adminSess); code != http.StatusBadRequest {
		t.Fatalf("wipe without confirmation: %d", code)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"lost"}, "confirm": {host}, "message": {"call IT"}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("lost mode: %d", code)
	}
	var pl string
	ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"reboot"}, "minutes": {"0"}}, help)
	db.QueryRow(ctx, `SELECT payload FROM commands WHERE type='reboot' ORDER BY id DESC LIMIT 1`).Scan(&pl)
	if pl != "0" {
		t.Fatalf("reboot now payload %q", pl)
	}
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/command", url.Values{"type": {"script"}, "payload": {"id"}}, help); code != http.StatusForbidden {
		t.Fatalf("helpdesk script must be refused: %d", code)
	}
	if code, _ := ui("POST", "/tokens", url.Values{"uses": {"1"}, "days": {"1"}}, help); code != http.StatusForbidden {
		t.Fatalf("helpdesk configuration must be refused: %d", code)
	}
	if code, _ := ui("GET", "/settings", nil, help); code != http.StatusForbidden {
		t.Fatal("settings must be hidden from helpdesk")
	}

	// ---- user management ----
	if code, body := ui("POST", "/users", url.Values{"kind": {"oidc"}, "login": {"Neu@Firma.de"}, "role": {"auditor"}}, adminSess); code != 200 || !strings.Contains(body, "neu@firma.de") {
		t.Fatalf("add oidc user: %d", code)
	}
	if code, body := ui("POST", "/users", url.Values{"kind": {"local"}, "login": {"ops"}, "role": {"helpdesk"}}, adminSess); code != 200 || !strings.Contains(body, "otpauth://totp/") {
		t.Fatalf("add local user must show credentials once: %d", code)
	}
	if _, body := ui("POST", "/users/update", url.Values{"login": {"admin@firma.de"}, "role": {"auditor"}}, adminSess); !strings.Contains(body, "your own account") {
		t.Fatal("self demotion must be refused")
	}
	other := session{Email: "neu@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	db.Exec(ctx, `UPDATE console_users SET role='admin' WHERE email='neu@firma.de'`)
	db.Exec(ctx, `UPDATE local_admins SET disabled=true`)
	if _, body := ui("POST", "/users/update", url.Values{"login": {"admin@firma.de"}, "role": {"admin"}, "disabled": {"on"}}, other); strings.Contains(body, "must remain") {
		t.Fatal("disabling one of two admins must be allowed")
	}
	if code, _ := ui("GET", "/", nil, adminSess); code != http.StatusFound {
		t.Fatalf("session of a disabled OIDC admin must end: %d", code)
	}
	if _, body := ui("POST", "/users/update", url.Values{"login": {"neu@firma.de"}, "role": {"auditor"}}, other); !strings.Contains(body, "your own account") {
		t.Fatal("the last admin demoting themselves must be refused")
	}
	db.Exec(ctx, `UPDATE console_users SET disabled=false, role='admin' WHERE email='admin@firma.de'`)
	if code, _ := ui("GET", "/", nil, adminSess); code != http.StatusFound {
		t.Fatalf("a session revoked by disabling must stay invalid after re-enabling: %d", code)
	}
	db.QueryRow(ctx, `SELECT session_gen FROM console_users WHERE email='admin@firma.de'`).Scan(&adminSess.Gen) // signs in again

	// ---- settings ----
	if _, body := ui("POST", "/settings", url.Values{"section": {"general"}, "stale_hours": {"24"}}, adminSess); !strings.Contains(body, "Settings saved") {
		t.Fatal("an OIDC admin may switch off local login while OIDC works")
	}
	if _, body := ui("POST", "/settings", url.Values{"section": {"sso"}}, adminSess); !strings.Contains(body, "can only be disabled") {
		t.Fatal("removing OIDC while local login is off must be refused")
	}
	if _, body := ui("POST", "/settings", url.Values{"section": {"monitoring"}, "webhook_url": {"http://plain"}}, adminSess); !strings.Contains(body, "must be https") {
		t.Fatal("plain http webhook accepted")
	}
	if code, _ := ui("POST", "/settings", url.Values{"section": {"bogus"}}, adminSess); code != http.StatusBadRequest {
		t.Fatalf("unknown section: %d", code)
	}
	if _, body := ui("POST", "/settings", url.Values{"section": {"general"}, "stale_hours": {"48"}, "local_login": {"on"}}, adminSess); !strings.Contains(body, "Settings saved") {
		t.Fatalf("general settings not saved: %s", body)
	}
	if _, body := ui("POST", "/settings", url.Values{"section": {"sso"}}, adminSess); !strings.Contains(body, "Settings saved") {
		t.Fatalf("clearing OIDC: %s", body)
	}
	if s.settings().StaleHours != 48 || s.oidc() != nil {
		t.Fatalf("settings not active: %+v", s.settings())
	}
	if code, _ := ui("GET", "/", nil, adminSess); code != http.StatusFound {
		t.Fatal("OIDC sessions must end once OIDC is removed")
	}
	s.rt.Store(&runtimeState{set: Settings{LocalLogin: true, StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})

	// audit log is append only and chained
	if _, err := db.Exec(ctx, `UPDATE audit_log SET detail='x'`); err == nil {
		t.Fatal("audit_log update must fail")
	}
	if _, err := db.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("audit_log delete must fail")
	}
	if broken, err := s.verifyAudit(ctx); err != nil || broken != 0 {
		t.Fatalf("chain broken at %d: %v", broken, err)
	}
}

// TestMigrationFromPriorityBlueprints converts the first data model.
func TestMigrationFromPriorityBlueprints(t *testing.T) {
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
	if _, err := db.Exec(ctx, schema); err != nil {
		t.Fatal(err)
	}
	// turn the fresh schema back into the legacy shape
	legacy := `ALTER TABLE blueprints DROP COLUMN tree, DROP COLUMN parent_id,
		ADD COLUMN priority INT NOT NULL DEFAULT 100, ADD COLUMN declarations JSONB NOT NULL DEFAULT '[]';
		CREATE TABLE device_blueprints (device_id TEXT REFERENCES devices(id), blueprint_id BIGINT REFERENCES blueprints(id));
		INSERT INTO blueprints(name, priority, declarations) VALUES
		  ('default', 1000, '[{"identifier":"compliance","type":"com.limdm.compliance","payload":{"level":1,"remediate":true}}]'),
		  ('strict', 10, '[{"identifier":"strict","type":"com.limdm.compliance","payload":{"level":2,"remediate":true}}]'),
		  ('loose', 50, '[]');
		INSERT INTO devices(id, cert_serial, cert_not_after) VALUES ('dev1', 's', now());
		INSERT INTO device_blueprints SELECT 'dev1', id FROM blueprints WHERE name IN ('strict', 'loose');`
	if _, err := db.Exec(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	tx, _ := db.Begin(ctx)
	res, err := resolveDevice(ctx, tx, "dev1")
	tx.Rollback(ctx) // release table locks before the next migrate runs DDL
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := api.Compose(res.Decls)
	if len(res.Chain) != 2 || res.Chain[0].Name != "default" || res.Chain[1].Name != "strict" || pol.Compliance.Level != 2 {
		t.Fatalf("migrated chain %v level %d", res.Chain, pol.Compliance.Level)
	}
	var legacyTable bool
	db.QueryRow(ctx, `SELECT to_regclass('device_blueprints') IS NOT NULL`).Scan(&legacyTable)
	if legacyTable {
		t.Fatal("device_blueprints must be dropped")
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatal("migrations must be idempotent: ", err)
	}
}

// TestCompliancePolicy walks a device through grace, notification, lock and unlock.
func TestCompliancePolicy(t *testing.T) {
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
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, failing) VALUES ('d1', 's', now(), 'pc1', 2)`)
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{PublicURL: "https://mdm.test", SessionKey: bytes.Repeat([]byte{1}, 32)}}
	pol := api.Compliance{Level: 1, GraceHours: 1, Notify: true, LockAfterHours: 2, UnlockWhenCompliant: true}
	t0 := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	step := func(at time.Time) *webhookEvent {
		t.Helper()
		tx, _ := db.Begin(ctx)
		ev, err := s.enforceCompliance(ctx, tx, "d1", pol, at)
		if err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
		return ev
	}
	commands := func() []string {
		rows, _ := db.Query(ctx, `SELECT type FROM commands WHERE device_id='d1' ORDER BY id`)
		out, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		return out
	}
	if ev := step(t0); ev != nil {
		t.Fatal("no webhook inside the grace period")
	}
	if ev := step(t0.Add(30 * time.Minute)); ev != nil {
		t.Fatal("still in grace")
	}
	ev := step(t0.Add(61 * time.Minute))
	if ev == nil || ev.Failing != 2 || !ev.Since.Equal(t0) {
		t.Fatalf("webhook after grace: %+v", ev)
	}
	if step(t0.Add(70*time.Minute)) != nil {
		t.Fatal("webhook must be sent once per episode")
	}
	if len(commands()) != 0 {
		t.Fatal("no lock before lock_after_hours")
	}
	step(t0.Add(2 * time.Hour))
	step(t0.Add(3 * time.Hour))
	if got := commands(); !slices.Equal(got, []string{"lock"}) {
		t.Fatalf("lock queued once: %v", got)
	}
	db.Exec(ctx, `UPDATE devices SET failing=0 WHERE id='d1'`)
	step(t0.Add(4 * time.Hour))
	var since *time.Time
	var locked bool
	db.QueryRow(ctx, `SELECT noncompliant_since, auto_locked FROM devices WHERE id='d1'`).Scan(&since, &locked)
	if got := commands(); !slices.Equal(got, []string{"lock", "unlock"}) || since != nil || locked {
		t.Fatalf("after recovery: cmds=%v since=%v locked=%v", got, since, locked)
	}
	var audited int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE actor='policy'`).Scan(&audited)
	if audited != 3 {
		t.Fatalf("notify, lock and unlock must be audited, got %d", audited)
	}
	// a removed lock action lifts an automatic lock even while failing
	db.Exec(ctx, `UPDATE devices SET failing=1, auto_locked=true WHERE id='d1'`)
	pol.LockAfterHours = 0
	step(t0.Add(5 * time.Hour))
	db.QueryRow(ctx, `SELECT auto_locked FROM devices WHERE id='d1'`).Scan(&locked)
	if got := commands(); got[len(got)-1] != "unlock" || locked {
		t.Fatalf("lock policy removed: cmds=%v locked=%v", got, locked)
	}
}

func TestWebhookSignature(t *testing.T) {
	got := make(chan *http.Request, 1)
	bodies := make(chan []byte, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r
		bodies <- b
	}))
	defer ts.Close()
	s := &Server{cfg: Config{SessionKey: bytes.Repeat([]byte{2}, 32)}, hooks: ts.Client(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.rt.Store(&runtimeState{set: Settings{WebhookURL: ts.URL}})
	s.sendWebhook(&webhookEvent{Type: "device.noncompliant", DeviceID: "d1"})
	select {
	case r := <-got:
		body := <-bodies
		mac := hmac.New(sha256.New, s.webhookKey())
		mac.Write([]byte(r.Header.Get("X-LiMDM-Timestamp") + "."))
		mac.Write(body)
		if r.Header.Get("X-LiMDM-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("signature does not verify")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook not delivered")
	}
}

func TestHistory(t *testing.T) {
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
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1', 's', now(), 'pc1')`)
	rec := func(m *api.Metrics) {
		t.Helper()
		tx, _ := db.Begin(ctx)
		if err := recordMetrics(ctx, tx, "d1", m); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	rec(&api.Metrics{MemUsedMB: 900, MemTotalMB: 100}) // implausible, ignored
	rec(&api.Metrics{MemUsedMB: 1000, MemTotalMB: 4000, RootUsedPct: 40, Load1: 0.5})
	rec(&api.Metrics{MemUsedMB: 2000, MemTotalMB: 4000, RootUsedPct: 41, Load1: 0.7}) // within 15 min, dropped
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM device_metrics`).Scan(&n)
	if n != 1 {
		t.Fatalf("want 1 sample, got %d", n)
	}
	db.Exec(ctx, `UPDATE device_metrics SET at = at - interval '1 hour'`)
	rec(&api.Metrics{MemUsedMB: 2000, MemTotalMB: 4000, RootUsedPct: 41, Load1: 0.7})
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	charts, err := s.deviceCharts(ctx, "d1")
	if err != nil || len(charts) != 3 || !strings.Contains(string(charts[0]), "<polyline") {
		t.Fatalf("device charts: %v %d", err, len(charts))
	}
	if err := s.snapshotFleet(ctx); err != nil {
		t.Fatal(err)
	}
	db.Exec(ctx, `INSERT INTO fleet_history VALUES (current_date - 1, 3, 1, 0, 0, 0)`)
	chart, err := s.fleetChart(ctx)
	if err != nil || !strings.Contains(string(chart), `class="line bad"`) {
		t.Fatalf("fleet chart: %v", err)
	}
}

func TestRecoveryEscrow(t *testing.T) {
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
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1', 's', now(), 'pc1')`)
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{SessionKey: bytes.Repeat([]byte{7}, 32)}}
	k := api.RecoveryKey{UUID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", Device: "/dev/sda3", Key: api.NewRecoveryKey()}
	tx, _ := db.Begin(ctx)
	if err := s.escrowKeys(ctx, tx, "d1", []api.RecoveryKey{k}); err != nil {
		t.Fatal(err)
	}
	if err := s.escrowKeys(ctx, tx, "d1", []api.RecoveryKey{{UUID: k.UUID, Device: "x", Key: "plain"}}); err == nil {
		t.Fatal("invalid key accepted")
	}
	tx.Rollback(ctx)
	tx, _ = db.Begin(ctx)
	s.escrowKeys(ctx, tx, "d1", []api.RecoveryKey{k})
	tx.Commit(ctx)
	var sealed []byte
	db.QueryRow(ctx, `SELECT sealed FROM recovery_keys`).Scan(&sealed)
	if bytes.Contains(sealed, []byte(k.Key)) {
		t.Fatal("key stored in clear")
	}
	if _, err := s.openRecovery("d2", k.UUID, sealed); err == nil {
		t.Fatal("sealed key opens for another device")
	}
	tx, _ = db.Begin(ctx)
	rot, err := s.rotations(ctx, tx, "d1")
	tx.Rollback(ctx)
	if err != nil || len(rot) != 0 {
		t.Fatalf("unexpected rotation: %v %v", rot, err)
	}
	db.Exec(ctx, `UPDATE recovery_keys SET rotate=true, viewed_at=now()`)
	tx, _ = db.Begin(ctx)
	rot, err = s.rotations(ctx, tx, "d1")
	tx.Rollback(ctx)
	if err != nil || len(rot) != 1 || rot[0].Key != k.Key {
		t.Fatalf("rotation: %v %v", rot, err)
	}
	// the replacement clears the rotation and the view
	tx, _ = db.Begin(ctx)
	s.escrowKeys(ctx, tx, "d1", []api.RecoveryKey{{UUID: k.UUID, Device: k.Device, Key: api.NewRecoveryKey()}})
	tx.Commit(ctx)
	var rotate bool
	var viewed *time.Time
	db.QueryRow(ctx, `SELECT rotate, viewed_at FROM recovery_keys`).Scan(&rotate, &viewed)
	if rotate || viewed != nil {
		t.Fatal("rotation not cleared")
	}
	// lost mode: the escrowed key is attached at delivery, not stored in the command
	cmds := []api.Command{{ID: 1, Type: "lost", Payload: `{"message":"call +49 1"}`}, {ID: 2, Type: "sync"}}
	tx, _ = db.Begin(ctx)
	err = s.attachRecoveryKeys(ctx, tx, "d1", cmds)
	tx.Rollback(ctx)
	var lm api.LostMode
	if err != nil || json.Unmarshal([]byte(cmds[0].Payload), &lm) != nil || lm.Message != "call +49 1" || len(lm.Keys) != 0 ||
		len(cmds[0].Keys) != 1 || !cmds[0].Keys[0].Valid() || len(cmds[1].Keys) != 0 {
		t.Fatalf("lost mode keys beside the signed payload: %v %s %d", err, cmds[0].Payload, len(cmds[0].Keys))
	}
	// commands are signed with the command key over what was created
	tx, _ = db.Begin(ctx)
	if err := s.insertCommand(ctx, tx, "d1", "lock", "", "admin@firma.de"); err != nil {
		t.Fatal(err)
	}
	var signed api.Command
	tx.QueryRow(ctx, `SELECT id, type, payload, created_at, signature FROM commands WHERE device_id='d1' ORDER BY id DESC LIMIT 1`).Scan(&signed.ID, &signed.Type, &signed.Payload, &signed.CreatedAt, &signed.Signature)
	tx.Rollback(ctx)
	pub := testCmdKey.Public().(ed25519.PublicKey)
	if err := api.VerifyCommand(pub, "d1", signed); err != nil {
		t.Fatalf("signature: %v %+v", err, signed)
	}
	forged := signed
	forged.Type = "wipe"
	if api.VerifyCommand(pub, "d1", forged) == nil || api.VerifyCommand(pub, "d2", signed) == nil {
		t.Fatal("a changed command or another device verified")
	}
	// package source templates from the inventory
	db.Exec(ctx, `UPDATE devices SET inventory=$1 WHERE id='d1'`, `{"repos":[
		{"type":"deb","name":"debian.sources","url":"http://deb.debian.org/debian/","suites":"trixie trixie-updates","components":"main","key_file":"/usr/share/keyrings/debian-archive-keyring.gpg","enabled":true,"signed":true,"file":"/etc/apt/sources.list.d/debian.sources"},
		{"type":"deb","name":"debian.sources","url":"http://deb.debian.org/debian-security/","suites":"trixie-security","components":"main","key_file":"/usr/share/keyrings/debian-archive-keyring.gpg","enabled":true,"signed":true,"file":"/etc/apt/sources.list.d/debian.sources"},
		{"type":"deb","name":"limdm-osquery.sources","url":"https://pkg.osquerypackages.com/deb","file":"/etc/apt/sources.list.d/limdm-osquery.sources"}]}`)
	for _, mode := range []string{"disable", "edit"} {
		it, err := s.sourceTemplate(ctx, "d1", "/etc/apt/sources.list.d/debian.sources", mode)
		if err != nil {
			t.Fatal(err)
		}
		if err := it.Validate(); err != nil {
			t.Fatalf("%s template invalid: %v\n%s", mode, err, it.Payload)
		}
		if mode == "edit" && !strings.Contains(string(it.Payload), `"debian-2"`) {
			t.Fatalf("edit must keep both entries: %s", it.Payload)
		}
	}
	if _, err := s.sourceTemplate(ctx, "d1", "/etc/apt/sources.list.d/limdm-osquery.sources", "disable"); err == nil {
		t.Fatal("managed source offered")
	}
	// directory deactivation removes device accounts
	db.Exec(ctx, `INSERT INTO dir_users(source, user_name, email, active) VALUES ('scim','gone','Gone@Example.com',false),('scim','here','here@example.com',true)`)
	tx, _ = db.Begin(ctx)
	us, err := activeUsers(ctx, tx, []api.User{{Username: "gone", Email: "gone@example.com"}, {Username: "here", Email: "here@example.com"}, {Username: "local", Email: "local@example.com"}})
	tx.Rollback(ctx)
	if err != nil || len(us) != 2 || us[0].Username != "here" {
		t.Fatalf("active users: %+v %v", us, err)
	}
	// deleted from the directory (SCIM DELETE) counts like deactivated; provisioning again restores
	db.Exec(ctx, `DELETE FROM dir_users WHERE email='here@example.com'`)
	tx, _ = db.Begin(ctx)
	us, _ = activeUsers(ctx, tx, []api.User{{Username: "here", Email: "here@example.com"}})
	tx.Rollback(ctx)
	if len(us) != 0 {
		t.Fatalf("deleted directory user kept: %+v", us)
	}
	db.Exec(ctx, `INSERT INTO dir_users(source, user_name, email, active) VALUES ('scim','here','here@example.com',true)`)
	tx, _ = db.Begin(ctx)
	us, _ = activeUsers(ctx, tx, []api.User{{Username: "here", Email: "here@example.com"}})
	tx.Rollback(ctx)
	if len(us) != 1 {
		t.Fatal("reprovisioned user still dropped")
	}
}

func TestRecoveryCodeLogin(t *testing.T) {
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
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tx, _ := db.Begin(ctx)
	creds, err := localAdd(ctx, tx, "alice", "admin")
	if err != nil {
		t.Fatal(err)
	}
	code := newRecoveryCode()
	tx.Exec(ctx, `INSERT INTO local_recovery_codes(name, hash) VALUES ('alice', $1)`, hashCode(code))
	tx.Commit(ctx)
	var pw string
	for _, l := range strings.Split(creds, "\n") {
		if v, ok := strings.CutPrefix(l, "password: "); ok {
			pw = strings.TrimSpace(v)
		}
	}
	if role, err := s.checkLocal(ctx, "alice", pw, strings.ToUpper(code), "127.0.0.1"); err != nil || role != "admin" {
		t.Fatalf("recovery code login: %q %v", role, err)
	}
	if _, err := s.checkLocal(ctx, "alice", pw, code, "127.0.0.1"); err == nil {
		t.Fatal("recovery code worked twice")
	}
	if _, err := s.checkLocal(ctx, "alice", "wrong", newRecoveryCode(), "127.0.0.1"); err == nil {
		t.Fatal("wrong password accepted")
	}
	// sign out ends every session of the account
	_, gen0 := s.account(ctx, "local:alice")
	if err := s.revokeSessions(ctx, db, "local:alice"); err != nil {
		t.Fatal(err)
	}
	if _, gen1 := s.account(ctx, "local:alice"); gen1 != gen0+1 {
		t.Fatalf("session generation not bumped: %d -> %d", gen0, gen1)
	}
	// the profile password check honours the lockout
	for range maxFailures {
		tx, _ := db.Begin(ctx)
		s.checkCurrent(ctx, tx, "alice", "wrong")
		tx.Commit(ctx)
	}
	tx, _ = db.Begin(ctx)
	err = s.checkCurrent(ctx, tx, "alice", pw)
	tx.Rollback(ctx)
	if !errors.Is(err, errLocked) {
		t.Fatalf("locked account accepted the password: %v", err)
	}
	if !strings.Contains(string(qrSVG(totpURI("alice", newTOTPSecret()))), "<path") {
		t.Fatal("no QR code")
	}
}

func TestAgentUpdates(t *testing.T) {
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
	s := &Server{db: db, cmdKey: testCmdKey, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for i, id := range []string{"d1", "d2", "d3", "d4"} {
		tags := "{}"
		if i == 0 {
			tags = "{pilot}"
		}
		if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, tags) VALUES ($1, $1, now(), $1, $2)`, id, tags); err != nil {
			t.Fatal(err)
		}
	}
	sums := strings.Repeat("a", 64) + "  " + api.PackageName("1.1.0", "amd64", "deb") + "\n"
	db.Exec(ctx, `INSERT INTO agent_releases(version, published_at, sums) VALUES ('1.1.0', now(), $1), ('1.2.0', now(), $1)`, sums)
	offer := func(id string) *api.AgentUpdate {
		t.Helper()
		tx, _ := db.Begin(ctx)
		defer tx.Rollback(ctx)
		u, err := s.offerUpdate(ctx, tx, id, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
		return u
	}
	db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('agent_updates', '{"auto":true,"delay_days":7,"pilot_tag":"pilot"}')`)
	if u := offer("d1"); u != nil {
		t.Fatalf("unapproved version offered: %+v", u)
	}
	db.Exec(ctx, `UPDATE agent_releases SET approved_at=now() WHERE version='1.1.0'`)
	if u := offer("d1"); u == nil || u.Version != "1.1.0" {
		t.Fatalf("pilot device: %+v", u)
	}
	if u := offer("d2"); u != nil {
		t.Fatal("delay ignored")
	}
	db.Exec(ctx, `UPDATE devices SET update_requested=true WHERE id='d2'`)
	if u := offer("d2"); u == nil {
		t.Fatal("requested update not offered")
	}
	db.Exec(ctx, `UPDATE agent_releases SET approved_at=now() - interval '8 days' WHERE version='1.1.0'`)
	if u := offer("d3"); u == nil {
		t.Fatal("due update not offered")
	}

	report := func(id string, res api.UpdateResult) {
		t.Helper()
		tx, _ := db.Begin(ctx)
		defer tx.Rollback(ctx)
		if err := s.recordUpdateResult(ctx, tx, id, &res); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	report("d1", api.UpdateResult{From: "1.0.0", To: "1.1.0", RolledBack: true})
	report("d2", api.UpdateResult{From: "1.0.0", To: "1.1.0", RolledBack: true})
	var blocked, requested bool
	db.QueryRow(ctx, `SELECT blocked FROM agent_releases WHERE version='1.1.0'`).Scan(&blocked)
	db.QueryRow(ctx, `SELECT update_requested FROM devices WHERE id='d2'`).Scan(&requested)
	if blocked || requested {
		t.Fatalf("blocked=%v requested=%v after two failures", blocked, requested)
	}
	report("d3", api.UpdateResult{From: "1.0.0", To: "1.1.0", Detail: "dpkg failed"})
	db.QueryRow(ctx, `SELECT blocked FROM agent_releases WHERE version='1.1.0'`).Scan(&blocked)
	if !blocked {
		t.Fatal("version not blocked after three failures")
	}
	if u := offer("d4"); u != nil {
		t.Fatalf("blocked version offered: %+v", u)
	}

	// poll: nothing pending, then a queued command
	pollOf := func(id string) bool {
		t.Helper()
		rec := httptest.NewRecorder()
		s.poll(rec, httptest.NewRequest("POST", "/api/v1/poll", nil).WithContext(context.WithValue(ctx, deviceKey, id)))
		var pr api.PollResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &pr) != nil {
			t.Fatalf("poll: %d", rec.Code)
		}
		return pr.Pending
	}
	if pollOf("d3") {
		t.Fatal("nothing should be pending")
	}
	db.Exec(ctx, `INSERT INTO commands(device_id, type, payload, created_by) VALUES ('d3', 'reboot', '5', 'admin')`)
	if !pollOf("d3") {
		t.Fatal("queued command not reported by poll")
	}

	// privacy: no public address or location without network_info
	db.Exec(ctx, `UPDATE devices SET external_ip='203.0.113.7', geo='{"ip":"203.0.113.7","country":"Germany"}', geo_at=now() WHERE id='d3'`)
	tx, _ := db.Begin(ctx)
	if err := forgetPublicAddress(ctx, tx, "d3"); err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	var ip string
	var geo []byte
	db.QueryRow(ctx, `SELECT external_ip, geo FROM devices WHERE id='d3'`).Scan(&ip, &geo)
	if ip != "" || geo != nil {
		t.Fatalf("public address kept: %q %s", ip, geo)
	}

	// an admin picks an unapproved version for one device
	db.Exec(ctx, `UPDATE devices SET update_requested=true, update_target='1.2.0' WHERE id='d4'`)
	if u := offer("d4"); u == nil || u.Version != "1.2.0" {
		t.Fatalf("picked version not offered: %+v", u)
	}
	if u := offer("d3"); u != nil && u.Version == "1.2.0" {
		t.Fatal("picked version leaked to another device")
	}
	// package download: only approved versions and files listed in the sums
	s.cfg.ReleaseDir = t.TempDir()
	db.Exec(ctx, `UPDATE agent_releases SET blocked=false WHERE version='1.1.0'`)
	os.MkdirAll(filepath.Join(s.cfg.ReleaseDir, "1.1.0"), 0o755)
	os.WriteFile(filepath.Join(s.cfg.ReleaseDir, "1.1.0", api.PackageName("1.1.0", "amd64", "deb")), []byte("pkg"), 0o644)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /p/{version}/{file}", s.agentPackage)
	os.MkdirAll(filepath.Join(s.cfg.ReleaseDir, "1.2.0"), 0o755)
	os.WriteFile(filepath.Join(s.cfg.ReleaseDir, "1.2.0", api.PackageName("1.2.0", "amd64", "deb")), []byte("pkg"), 0o644)
	db.Exec(ctx, `UPDATE agent_releases SET sums=$1 WHERE version='1.2.0'`, strings.Repeat("b", 64)+"  "+api.PackageName("1.2.0", "amd64", "deb")+"\n")
	rec := httptest.NewRecorder()
	mux0 := http.NewServeMux()
	mux0.HandleFunc("GET /p/{version}/{file}", s.agentPackage)
	mux0.ServeHTTP(rec, httptest.NewRequest("GET", "/p/1.2.0/"+api.PackageName("1.2.0", "amd64", "deb"), nil).WithContext(context.WithValue(ctx, deviceKey, "d4")))
	if rec.Code != 200 {
		t.Fatalf("device with a picked version must get the package: %d", rec.Code)
	}
	for path, want := range map[string]int{
		"/p/1.1.0/" + api.PackageName("1.1.0", "amd64", "deb"): 200,
		"/p/1.1.0/" + api.PackageName("1.1.0", "arm64", "deb"): 404, // not in sums
		"/p/1.2.0/" + api.PackageName("1.2.0", "amd64", "deb"): 404, // not approved
		"/p/1.1.0/" + api.PackageName("1.2.0", "amd64", "deb"): 404, // version mismatch
		"/p/1.1.0/limdm-server_1.1.0_linux_amd64.deb":          404,
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil).WithContext(context.WithValue(ctx, deviceKey, "d3")))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}

	// poll reports a due agent update, but not while it installs or after it failed here
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, agent_version) VALUES ('d5', 'd5', now(), 'd5', '1.0.0')`)
	db.Exec(ctx, `UPDATE agent_releases SET approved_at=now() - interval '30 days', blocked=false WHERE version='1.2.0'`)
	if !pollOf("d5") {
		t.Fatal("due update not reported by poll")
	}
	db.Exec(ctx, `UPDATE devices SET update_state='offered', update_version='1.2.0', update_at=now() WHERE id='d5'`)
	if pollOf("d5") {
		t.Fatal("an update being installed must not trigger check ins")
	}
	db.Exec(ctx, `UPDATE devices SET update_state='rolled_back' WHERE id='d5'`)
	if u := offer("d5"); u != nil && u.Version == "1.2.0" {
		t.Fatal("a version that rolled back must not be offered again by policy")
	}
	db.Exec(ctx, `UPDATE devices SET update_requested=true WHERE id='d5'`)
	if !pollOf("d5") {
		t.Fatal("an admin request must retry the update")
	}

	// software catalog: 78 seeded apps, scope by blueprint, requests
	var seeded int
	db.QueryRow(ctx, `SELECT count(*) FROM catalog_apps`).Scan(&seeded)
	if seeded != len(defaultCatalog)+len(moreCatalog) {
		t.Fatalf("seeded catalog: %d", seeded)
	}
	db.Exec(ctx, `UPDATE catalog_apps SET mode='request' WHERE slug='slack'`)
	db.Exec(ctx, `UPDATE catalog_apps SET scope='{999}' WHERE slug='zoom'`)
	db.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('software', '{"restrict_flathub":true}') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`)
	ctx2 := ctx
	tx2, _ := db.Begin(ctx2)
	cat, err := s.deviceCatalog(ctx2, tx2, "d3", []blueprintRec{{ID: 1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Apps) != seeded-1 || !cat.RestrictFlathub || cat.Hash == "" {
		t.Fatalf("catalog: %d apps, restrict=%v", len(cat.Apps), cat.RestrictFlathub)
	}
	reqs := []api.AppRequest{{App: "slack", User: "bob", Note: "team chat"}, {App: "slack", User: "bob"}, {App: "firefox", User: "bob"}}
	if err := recordAppRequests(ctx2, tx2, "d3", reqs, cat); err != nil {
		t.Fatal(err)
	}
	tx2.Commit(ctx2)
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM catalog_requests WHERE device_id='d3'`).Scan(&n)
	if n != 1 {
		t.Fatalf("one request for the request mode app expected, got %d", n)
	}
	tx3, _ := db.Begin(ctx)
	cat, _ = s.deviceCatalog(ctx, tx3, "d3", []blueprintRec{{ID: 999}}, &api.SoftwareStore{StoresReadOnly: true})
	tx3.Rollback(ctx)
	var slack, zoom bool
	for _, a := range cat.Apps {
		slack = slack || (a.ID == "slack" && a.Request == "pending")
		zoom = zoom || a.ID == "zoom"
	}
	if !slack || !zoom {
		t.Fatalf("request state or scoped app missing: slack=%v zoom=%v", slack, zoom)
	}
	if cat.RestrictFlathub || !cat.StoresReadOnly {
		t.Fatalf("the device's store policy must override the default: %+v", cat)
	}

	// import Flatpaks installed on devices into the catalog
	db.Exec(ctx, `UPDATE devices SET inventory='{"flatpaks":[{"id":"com.github.wwmm.easyeffects","name":"Easy Effects","installation":"system"},{"id":"org.mozilla.firefox","name":"Firefox","installation":"system"}]}' WHERE id='d3'`)
	fleet, err := s.fleetFlatpaks(ctx)
	if err != nil || len(fleet) != 1 || fleet[0].ID != "com.github.wwmm.easyeffects" {
		t.Fatalf("fleet flatpaks outside the catalog: %v %+v", err, fleet)
	}
	form := url.Values{"flatpak": {"com.github.wwmm.easyeffects", "org.unknown.App"}}
	ireq := httptest.NewRequest("POST", "/software/import", strings.NewReader(form.Encode()))
	ireq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ireq.ParseForm()
	rec = httptest.NewRecorder()
	s.appImport(rec, ireq, session{Email: "admin@firma.de", Role: "admin"})
	var imported string
	db.QueryRow(ctx, `SELECT slug FROM catalog_apps WHERE sources @> '[{"flatpak":"com.github.wwmm.easyeffects"}]'`).Scan(&imported)
	if rec.Code != http.StatusSeeOther || imported != "easy-effects" {
		t.Fatalf("import: %d %q", rec.Code, imported)
	}
	if fleet, _ := s.fleetFlatpaks(ctx); len(fleet) != 0 {
		t.Fatalf("imported app still listed: %+v", fleet)
	}

	// remotes: Flathub managed from the start, take over a found one as blocked, only managed per policy
	db.Exec(ctx, `UPDATE devices SET inventory='{"flatpak_remotes":[{"name":"flathub","url":"https://dl.flathub.org/repo/","installation":"system"},{"name":"flatpark","url":"https://dl.flatpark.org/","installation":"bob"}]}' WHERE id='d3'`)
	post := func(path string, form url.Values) int {
		t.Helper()
		rq := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rq.ParseForm()
		rc := httptest.NewRecorder()
		mux := http.NewServeMux()
		mux.HandleFunc("POST /software/remotes", func(w http.ResponseWriter, r *http.Request) {
			s.remoteSave(w, r, session{Email: "admin@firma.de", Role: "admin"})
		})
		mux.HandleFunc("POST /software/remotes/{name}/{op}", func(w http.ResponseWriter, r *http.Request) {
			s.remoteOp(w, r, session{Email: "admin@firma.de", Role: "admin"})
		})
		mux.ServeHTTP(rc, rq)
		return rc.Code
	}
	if code := post("/software/remotes", url.Values{"name": {"flatpark"}, "url": {"https://dl.flatpark.org/"}, "state": {"blocked"}}); code != http.StatusSeeOther {
		t.Fatalf("take over: %d", code)
	}
	if code := post("/software/remotes/flatpark/allow", nil); code != http.StatusSeeOther {
		t.Fatalf("allow: %d", code)
	}
	tx4, _ := db.Begin(ctx)
	cat, _ = s.deviceCatalog(ctx, tx4, "d3", nil, &api.SoftwareStore{OnlyManagedRemotes: true})
	tx4.Rollback(ctx)
	names := map[string]string{}
	for _, r := range cat.Remotes {
		names[r.Name] = r.State
	}
	if names["flathub"] != "allowed" || names["flatpark"] != "allowed" || !cat.OnlyManagedRemotes {
		t.Fatalf("catalog remotes: %+v only=%v", cat.Remotes, cat.OnlyManagedRemotes)
	}

	// requests for apps outside the catalog: recorded once, approved for everyone as a new app
	tx5, _ := db.Begin(ctx)
	cat, _ = s.deviceCatalog(ctx, tx5, "d3", nil, nil)
	newReqs := []api.AppRequest{{Flatpak: "org.example.Notes", Name: "Notes", User: "bob"}, {Flatpak: "org.example.Notes", User: "bob"},
		{Flatpak: "org.mozilla.firefox", User: "bob"}, {Flatpak: "bad id", User: "bob"}, {Flatpak: "org.example.Other", Remote: "nowhere", User: "bob"}}
	if err := recordAppRequests(ctx, tx5, "d3", newReqs, cat); err != nil {
		t.Fatal(err)
	}
	tx5.Commit(ctx)
	var reqID int64
	db.QueryRow(ctx, `SELECT count(*), max(id) FROM catalog_requests WHERE device_id='d3' AND flatpak<>''`).Scan(&n, &reqID)
	if n != 1 {
		t.Fatalf("one request for the unknown Flatpak expected, got %d", n)
	}
	mux = http.NewServeMux()
	mux.HandleFunc("POST /software/requests/{id}/{op}", func(w http.ResponseWriter, r *http.Request) {
		s.requestDecide(w, r, session{Email: "admin@firma.de", Role: "admin"})
	})
	rq := httptest.NewRequest("POST", fmt.Sprintf("/software/requests/%d/approve-all", reqID), nil)
	rc := httptest.NewRecorder()
	mux.ServeHTTP(rc, rq)
	var mode, linked string
	db.QueryRow(ctx, `SELECT a.mode, q.app FROM catalog_requests q JOIN catalog_apps a ON a.slug=q.app WHERE q.id=$1`, reqID).Scan(&mode, &linked)
	if rc.Code != http.StatusSeeOther || mode != "available" || linked != "notes" {
		t.Fatalf("approve for everyone: %d mode=%q app=%q", rc.Code, mode, linked)
	}

	// an app from a vendor repository keeps its repository through the editor
	save := func(form url.Values) (int, string) {
		rq := httptest.NewRequest("POST", "/software/apps", strings.NewReader(form.Encode()))
		rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rq.ParseForm()
		rc := httptest.NewRecorder()
		s.appSave(rc, rq, session{Email: "admin@firma.de", Role: "admin"})
		return rc.Code, rc.Body.String()
	}
	if code, body := save(url.Values{"new": {"1"}, "id": {"vendor-vpn"}, "name": {"Vendor VPN"}, "mode": {"available"}, "enabled": {"on"},
		"debian": {"vendor-vpn"}, "deb_repo_url": {"https://repo.example.com/apt"}, "deb_repo_suite": {"stable"}, "deb_repo_components": {"main"},
		"deb_repo_key": {"-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----"}}); code != http.StatusSeeOther {
		t.Fatalf("save app with repository: %d %s", code, body)
	}
	var srcJSON string
	db.QueryRow(ctx, `SELECT sources::text FROM catalog_apps WHERE slug='vendor-vpn'`).Scan(&srcJSON)
	if !strings.Contains(srcJSON, `"url": "https://repo.example.com/apt"`) || !strings.Contains(srcJSON, `"name": "vendor-vpn"`) {
		t.Fatalf("repository not stored: %s", srcJSON)
	}
	unsigned := api.CatalogApp{ID: "unsigned", Name: "Unsigned", Mode: api.AppAvailable, Sources: []api.AppSource{{Kind: "package", Debian: "x",
		Repos: []api.Repository{{Name: "unsigned", Family: "debian", URL: "https://repo.example.com/apt", Suites: "stable"}}}}}
	if err := unsigned.Validate(); err == nil || !strings.Contains(err.Error(), "unsigned repositories are not allowed") {
		t.Fatalf("unsigned repository accepted: %v", err)
	}

	// bulk actions on the device list: tag two devices, install an app, filter by tag
	bulk := func(form url.Values, role string) int {
		rq := httptest.NewRequest("POST", "/devices/bulk", strings.NewReader(form.Encode()))
		rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rc := httptest.NewRecorder()
		s.devicesBulk(rc, rq, session{Email: "admin@firma.de", Role: role})
		return rc.Code
	}
	if code := bulk(url.Values{"id": {"d3", "d5"}, "action": {"tag-add"}, "tag": {"Finance"}}, "admin"); code != http.StatusSeeOther {
		t.Fatalf("bulk tag: %d", code)
	}
	if code := bulk(url.Values{"id": {"d3"}, "action": {"tag-add"}, "tag": {"finance"}}, "helpdesk"); code != http.StatusForbidden {
		t.Fatalf("helpdesk must not tag: %d", code)
	}
	if code := bulk(url.Values{"id": {"d3", "d5"}, "action": {"command:app_install"}, "app": {"firefox"}}, "admin"); code != http.StatusSeeOther {
		t.Fatalf("bulk install: %d", code)
	}
	if code := bulk(url.Values{"id": {"d3"}, "action": {"command:wipe"}, "confirm": {"x"}}, "admin"); code != http.StatusBadRequest {
		t.Fatalf("wipe must not run in bulk: %d", code)
	}
	if code := bulk(url.Values{"id": {"d3", "nope"}, "action": {"command:sync"}}, "admin"); code != http.StatusBadRequest {
		t.Fatalf("unknown device accepted: %d", code)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM commands WHERE type='app_install' AND payload='firefox' AND device_id IN ('d3','d5')`).Scan(&n)
	if n != 2 {
		t.Fatalf("app install commands: %d", n)
	}
	// a new local user's password never reaches the audit log
	if err := s.queueCommand(ctx, "admin@firma.de", "d3", "user_create", `{"username":"anna","password":"correct horse battery"}`); err != nil {
		t.Fatal(err)
	}
	var auditDetail string
	db.QueryRow(ctx, `SELECT detail FROM audit_log WHERE action='command.user_create' ORDER BY id DESC LIMIT 1`).Scan(&auditDetail)
	if strings.Contains(auditDetail, "horse") || !strings.Contains(auditDetail, "anna") {
		t.Fatalf("audit detail: %s", auditDetail)
	}
	for _, f := range deviceFilters {
		if f.Key == "tag" {
			tagged, err := s.listDevicesWhere(ctx, f.Where, "finance")
			if err != nil || len(tagged) != 2 {
				t.Fatalf("tag filter: %v %d", err, len(tagged))
			}
		} else if _, err := s.listDevicesWhere(ctx, f.Where, "x"); err != nil {
			t.Fatalf("filter %s: %v", f.Key, err)
		}
	}
}

var testCmdKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
