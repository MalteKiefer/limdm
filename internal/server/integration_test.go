package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
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
		SessionKey: bytes.Repeat([]byte{7}, 32), Admins: []string{"admin@firma.de"}, Auditors: []string{"audit@firma.de"},
	}}

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
		Inventory: api.Inventory{Hostname: "laptop1", OSName: "Debian GNU/Linux 12", Arch: "amd64"},
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

	// blueprint with stricter compliance, assigned to the device
	strict := `[{"identifier":"strict","type":"com.limdm.compliance","payload":{"level":2,"remediate":true,"exclude":[]}}]`
	if code, body := ui("POST", "/blueprints", url.Values{"name": {"strict"}, "priority": {"10"}, "doc": {strict}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("blueprint save: %d %s", code, body)
	}
	if code, body := ui("POST", "/blueprints", url.Values{"name": {"bad"}, "priority": {"10"}, "doc": {`[{"identifier":"p","type":"com.limdm.packages","payload":{"install":["--evil"]}}]`}}, adminSess); code != 200 || !strings.Contains(body, "invalid package") {
		t.Fatal("invalid blueprint must be rejected")
	}
	var bpID string
	db.QueryRow(ctx, `SELECT id::text FROM blueprints WHERE name='strict'`).Scan(&bpID)
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/assign", url.Values{"blueprint": {bpID}, "users": {"mm max@firma.de admin"}}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("assign: %d", code)
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
	call(dev, "/api/v1/checkin", api.CheckinRequest{DeclarationsToken: cr.DeclarationsToken, StatusHash: "s1", PackagesHash: "p1",
		Results: []api.CommandResult{{ID: cr.Commands[0].ID, OK: true, Output: "ok"}}, Events: []string{"remediated kernel.aslr"}}, nil)

	// every admin page renders
	for _, p := range []string{"/", "/devices/" + er.DeviceID, "/compliance", "/blueprints", "/blueprints/" + bpID, "/blueprints/new", "/tokens", "/audit"} {
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
	if _, body := ui("GET", "/devices/"+er.DeviceID, nil, auditor); !strings.Contains(body, "com.limdm.compliance") {
		t.Fatal("device page must list declarations")
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

	// retiring revokes access
	if code, _ := ui("POST", "/devices/"+er.DeviceID+"/retire", url.Values{}, adminSess); code != http.StatusSeeOther {
		t.Fatalf("retire: %d", code)
	}
	if code := call(dev2, "/api/v1/checkin", api.CheckinRequest{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("retired device still accepted: %d", code)
	}

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
