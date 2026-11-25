package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

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
	s := &Server{db: db, ca: ca, log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{
		PublicURL: "https://mdm.test", AgentURL: "https://127.0.0.1:8444", StaleAfter: 24 * time.Hour,
		SessionKey: bytes.Repeat([]byte{7}, 32), Admins: []string{"admin@firma.de"}, Auditors: []string{"audit@firma.de"}, LocalLogin: true,
	}}

	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
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
	auditor := session{Email: "audit@firma.de", Role: "auditor", IAT: time.Now(), Last: time.Now()}
	if code, _ := ui("POST", "/tokens", url.Values{"uses": {"1"}, "days": {"1"}}, auditor); code != http.StatusForbidden {
		t.Fatalf("auditor must be read only, got %d", code)
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
	for _, tab := range []string{"overview", "hardware", "software", "compliance", "declarations", "commands"} {
		pages = append(pages, "/devices/"+er.DeviceID+"?tab="+tab+"&q=open&page=2")
	}
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
	if code := scim("PATCH", "/Users/"+created.ID, scimTok, map[string]any{"Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}}}, nil); code != 200 {
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

	// certificate renewal revokes the old certificate
	key2, csr2 := newIdentity()
	var rr api.EnrollResponse
	if code := call(dev, "/api/v1/renew", api.RenewRequest{CSR: csr2}, &rr); code != 200 {
		t.Fatalf("renew: %d", code)
	}
	if code := call(dev, "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("old certificate still accepted: %d", code)
	}
	dev2 := clientFor(key2, rr.Cert)
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != 200 {
		t.Fatalf("renewed certificate rejected: %d", code)
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
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusUnauthorized {
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

	// ---- settings ----
	if _, body := ui("POST", "/settings", url.Values{"stale_hours": {"48"}}, adminSess); !strings.Contains(body, "can only be disabled") {
		t.Fatal("disabling local login without OIDC must be refused")
	}
	if _, body := ui("POST", "/settings", url.Values{"stale_hours": {"48"}, "local_login": {"on"}, "webhook_url": {"http://plain"}}, adminSess); !strings.Contains(body, "must be https") {
		t.Fatal("plain http webhook accepted")
	}
	if _, body := ui("POST", "/settings", url.Values{"stale_hours": {"48"}, "local_login": {"on"}}, adminSess); !strings.Contains(body, "Settings saved") {
		t.Fatalf("settings save failed:\n%s", body)
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
