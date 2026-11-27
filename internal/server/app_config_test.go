package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestComplianceImpact(t *testing.T) {
	got := complianceImpact([]byte(`{"level":1,"exclude":["a"]}`), []byte(`{"level":2,"exclude":["b"],"advisory":["c"]}`))
	codes := []string{}
	for _, i := range got {
		codes = append(codes, i.Code+"="+strings.Join(i.Values, ","))
	}
	if strings.Join(codes, " ") != "level=1,2 excluded_added=b excluded_removed=a advisory_added=c" {
		t.Fatalf("impact: %v", codes)
	}
}

// TestAppConfigAPI runs the configuration area of the console app against
// a database: overviews, review, versions, rollback, four eyes, the software
// catalog and the package repository.
func TestAppConfigAPI(t *testing.T) {
	dsn := os.Getenv("LIMDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("LIMDM_TEST_DATABASE_URL not set")
	}
	t.Setenv("LIMDM_ARTIFACT_DIR", t.TempDir())
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
		PublicURL: "https://mdm.test", StaleAfter: 24 * time.Hour, SessionKey: bytes.Repeat([]byte{3}, 32),
		Admins: []string{"admin@firma.de", "second@firma.de"}, Auditors: []string{"audit@firma.de"},
	}}
	if err := s.seedConsoleUsers(ctx); err != nil {
		t.Fatal(err)
	}
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname, inventory, tags, last_seen, checks, failing, agent_version) VALUES
		('d1', 's', now(), 'alpha', '{"os_name":"Ubuntu 24.04"}', '{prod}', now(), '[]', 0, '0.17.0')`); err != nil {
		t.Fatal(err)
	}
	admin := session{Email: "admin@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	auditor := session{Email: "audit@firma.de", Role: "auditor", IAT: time.Now(), Last: time.Now()}
	send := func(sess session, method, path, ctype string, body io.Reader) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, body)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(sess)})
		req.Header.Set(csrfHeader, s.csrfToken(sess))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	call := func(sess session, method, path, body string) (int, string) {
		t.Helper()
		return send(sess, method, path, "application/json", strings.NewReader(body))
	}
	want := func(code int, body string, status int, part string) {
		t.Helper()
		if code != status || !strings.Contains(body, part) {
			t.Fatalf("want %d with %q, got %d: %s", status, part, code, body)
		}
	}

	is := func(status int) func(int, string) {
		return func(code int, body string) {
			t.Helper()
			if code != status {
				t.Fatalf("want %d, got %d: %s", status, code, body)
			}
		}
	}

	// schemas: annotated, in the asked language
	code, body := call(admin, "GET", "/api/v1/schemas/com.limdm.agent?lang=de", "")
	want(code, body, 200, `"Check in Intervall"`)
	code, body = call(admin, "GET", "/api/v1/schemas?lang=en", "")
	want(code, body, 200, `"four_eyes":true`)

	// a compliance item: review shows the effect, save, versions, rollback
	code, body = call(admin, "POST", "/api/v1/library-items", `{"name":"base","type":"com.limdm.compliance","payload":{"level":1,"remediate":false,"exclude":[]}}`)
	want(code, body, 201, `"id"`)
	var item struct{ ID int64 }
	_ = json.Unmarshal([]byte(body), &item)
	id := itoa(item.ID)
	code, body = call(admin, "POST", "/api/v1/config/library/preview", `{"id":`+id+`,"name":"base","type":"com.limdm.compliance","payload":{"level":2,"remediate":false,"exclude":["ssh.root"]}}`)
	want(code, body, 200, `"excluded_added"`)
	if !strings.Contains(body, `"code":"level"`) || !strings.Contains(body, `"op":"add"`) {
		t.Fatalf("preview: %s", body)
	}
	is(422)(call(admin, "POST", "/api/v1/config/library/preview", `{"name":"x","type":"com.limdm.agent","payload":{"checkin_seconds":5}}`))
	// new items start from the example payload or what a device reported
	if code, body := call(admin, "GET", "/api/v1/config/library/template?type=com.limdm.agent", ""); code != 200 || !strings.Contains(body, `"checkin_seconds":300`) {
		t.Fatalf("template: %d %s", code, body)
	}
	is(400)(call(admin, "GET", "/api/v1/config/library/template?type=nope", ""))
	is(404)(call(admin, "GET", "/api/v1/config/library/template?device=d1&remote=flathub&inst=system&mode=edit", ""))
	is(404)(call(admin, "GET", "/api/v1/config/library/template?device=nope&file=x", ""))
	is(403)(call(auditor, "GET", "/api/v1/config/library/template?type=com.limdm.agent", ""))
	code, body = call(admin, "PUT", "/api/v1/library-items/"+id, `{"name":"base","type":"com.limdm.compliance","payload":{"level":2,"remediate":false,"exclude":[]}}`)
	want(code, body, 200, `"level":2`)
	code, body = call(auditor, "GET", "/api/v1/config/library/"+id+"/versions", "")
	want(code, body, 200, `"version":2`)
	is(403)(call(auditor, "POST", "/api/v1/config/library/"+id+"/rollback", `{"version":1}`))
	code, body = call(admin, "POST", "/api/v1/config/library/"+id+"/rollback", `{"version":1}`)
	want(code, body, 200, `"saved"`)

	// a blueprint using it: overview with usage, sources and compliance
	code, body = call(admin, "POST", "/api/v1/config/blueprints/preview", `{"name":"dev","tree":[{"kind":"assign","items":[`+id+`]}]}`)
	want(code, body, 200, `"items_added"`)
	code, body = call(admin, "POST", "/api/v1/blueprints", `{"name":"dev","tree":[{"kind":"assign","items":[`+id+`]}]}`)
	want(code, body, 201, `"dev"`)
	code, body = call(auditor, "GET", "/api/v1/config/library", "")
	want(code, body, 200, `"used_by":["dev"]`)
	code, body = call(auditor, "GET", "/api/v1/config/blueprints", "")
	want(code, body, 200, `"kind":"default"`)
	if !strings.Contains(body, `"rule_fields"`) || !strings.Contains(body, `"compliant"`) && !strings.Contains(body, `"pending"`) {
		t.Fatalf("blueprints: %s", body)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/library-items/"+id, ""); code != 409 {
		t.Fatalf("delete used item: %d", code)
	}

	// deleted objects are listed and restored
	var dev int64
	_ = db.QueryRow(ctx, `SELECT id FROM blueprints WHERE name='dev'`).Scan(&dev)
	if code, _ := call(admin, "DELETE", "/api/v1/blueprints/"+itoa(dev), ""); code != 204 {
		t.Fatalf("delete blueprint: %d", code)
	}
	code, body = call(auditor, "GET", "/api/v1/config/blueprints", "")
	want(code, body, 200, `"deleted":[{"id":`+itoa(dev))
	code, body = call(admin, "POST", "/api/v1/config/blueprints/"+itoa(dev)+"/rollback", `{"version":1}`)
	want(code, body, 200, `"saved"`)

	// pilot rollout: a device moves to the pilot copy and back on promote
	if _, err := db.Exec(ctx, `UPDATE devices SET blueprint_id=$1 WHERE id='d1'`, dev); err != nil {
		t.Fatal(err)
	}
	is(422)(call(admin, "POST", "/api/v1/config/blueprints/"+itoa(dev)+"/pilot", `{"tree":[],"devices":["nope"]}`))
	code, body = call(admin, "POST", "/api/v1/config/blueprints/"+itoa(dev)+"/pilot", `{"tree":[],"devices":["d1"]}`)
	want(code, body, 201, `"devices":["d1"]`)
	is(409)(call(admin, "POST", "/api/v1/config/blueprints/"+itoa(dev)+"/pilot", `{"tree":[],"devices":["d1"]}`))
	var onPilot string
	_ = db.QueryRow(ctx, `SELECT b.name FROM devices d JOIN blueprints b ON b.id=d.blueprint_id WHERE d.id='d1'`).Scan(&onPilot)
	if onPilot != "dev.pilot" {
		t.Fatalf("device on %q", onPilot)
	}
	code, body = call(auditor, "GET", "/api/v1/config/blueprints", "")
	want(code, body, 200, `"pilot_of":`+itoa(dev))
	code, body = call(admin, "POST", "/api/v1/config/blueprints/"+itoa(dev)+"/pilot/promote", "")
	want(code, body, 200, `"promote"`)
	var tree string
	_ = db.QueryRow(ctx, `SELECT b.tree::text FROM devices d JOIN blueprints b ON b.id=d.blueprint_id WHERE d.id='d1'`).Scan(&tree)
	if tree != "[]" {
		t.Fatalf("after promote: %s", tree)
	}
	is(404)(call(admin, "POST", "/api/v1/config/blueprints/"+itoa(dev)+"/pilot/abort", ""))

	// four eyes: a root effective item waits for another admin
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, FourEyes: true, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	code, body = call(admin, "POST", "/api/v1/config/library/preview", `{"name":"k","type":"com.limdm.kernelmodules","payload":{"block":["usb-storage"]}}`)
	want(code, body, 200, `"needs_approval":false`)
	code, body = call(admin, "POST", "/api/v1/library-items", `{"name":"ops","type":"com.limdm.sudo","payload":{"rules":[{"name":"ops","principals":["%ops"],"commands":["ALL"]}]}}`)
	want(code, body, 202, `"pending"`)
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})

	// software catalog: settings, remotes, apps, requests; auditors read only
	is(200)(call(admin, "PUT", "/api/v1/software/settings", `{"restrict_flathub":true,"stores_read_only":false,"only_managed_remotes":false}`))
	code, body = call(auditor, "GET", "/api/v1/software/settings", "")
	want(code, body, 200, `"restrict_flathub":true`)
	is(403)(call(auditor, "PUT", "/api/v1/software/settings", `{}`))
	code, body = call(admin, "PUT", "/api/v1/software/remotes/corp", `{"url":"http://repo.corp/x.flatpakrepo","state":"allowed"}`)
	want(code, body, 422, "")
	code, body = call(admin, "PUT", "/api/v1/software/remotes/corp", `{"url":"https://repo.corp/x.flatpakrepo","state":"blocked"}`)
	want(code, body, 200, `"saved"`)
	code, body = call(admin, "POST", "/api/v1/software/remotes/corp/filter", "")
	want(code, body, 200, `"saved"`)
	code, body = call(auditor, "GET", "/api/v1/software/remotes", "")
	want(code, body, 200, `"catalog_only":true`)
	app := `{"id":"editor","name":"Editor","mode":"available","enabled":true,"sources":[{"kind":"flatpak","flatpak":"org.example.Editor"}]}`
	code, body = call(admin, "POST", "/api/v1/software/apps", app)
	want(code, body, 200, `"saved"`)
	is(409)(call(admin, "POST", "/api/v1/software/apps", app))
	code, body = call(auditor, "GET", "/api/v1/software/catalog", "")
	want(code, body, 200, `"org.example.Editor"`)
	if _, err := db.Exec(ctx, `INSERT INTO catalog_requests(device_id, app, app_name, username, note, status) VALUES ('d1', 'editor', 'Editor', 'anna', 'please', 'pending')`); err != nil {
		t.Fatal(err)
	}
	code, body = call(auditor, "GET", "/api/v1/software/requests", "")
	want(code, body, 200, `"pending"`)
	var reqID int64
	_ = db.QueryRow(ctx, `SELECT id FROM catalog_requests`).Scan(&reqID)
	code, body = call(admin, "POST", "/api/v1/software/requests/"+itoa(reqID)+"/deny", "")
	want(code, body, 200, `"decided"`)
	is(404)(call(admin, "POST", "/api/v1/software/requests/"+itoa(reqID)+"/deny", ""))
	if code, _ := call(admin, "DELETE", "/api/v1/software/apps/editor", ""); code != 204 {
		t.Fatalf("delete app: %d", code)
	}

	// package repository: upload, list with snippet, delete
	upload := func(sess session, name, content string) (int, string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("name", name)
		_ = mw.WriteField("version", "1.0")
		_ = mw.WriteField("kind", "script")
		fw, _ := mw.CreateFormFile("file", name+".sh")
		_, _ = fw.Write([]byte(content))
		_ = mw.Close()
		return send(sess, "POST", "/api/v1/packages", mw.FormDataContentType(), &buf)
	}
	code, body = upload(admin, "hello", "#!/bin/sh\necho hi\n")
	want(code, body, 201, `"uploaded"`)
	code, body = upload(admin, "bad", "no shebang")
	want(code, body, 422, "does not match")
	is(403)(upload(auditor, "x", "#!/bin/sh\n"))
	code, body = call(auditor, "GET", "/api/v1/packages", "")
	want(code, body, 200, `"snippet"`)
	var pid int64
	_ = db.QueryRow(ctx, `SELECT id FROM artifacts`).Scan(&pid)
	// device scoped accounts and tokens: nothing read or written
	code, body = call(admin, "POST", "/api/v1/tokens", `{"name":"desk","role":"helpdesk","days":30,"scope_tags":["prod"]}`)
	var tok struct{ Token string }
	if _ = json.Unmarshal([]byte(body), &tok); code != 201 || tok.Token == "" {
		t.Fatalf("scoped token: %d %s", code, body)
	}
	bearer := func(method, path, ctype string, body io.Reader) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set("Authorization", "Bearer "+tok.Token)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("scoped token %s %s: %d", method, path, resp.StatusCode)
		}
	}
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("name", "scoped")
	_ = mw.WriteField("kind", "script")
	fw, _ := mw.CreateFormFile("file", "s.sh")
	_, _ = fw.Write([]byte("#!/bin/sh\n"))
	_ = mw.Close()
	bearer("POST", "/api/v1/packages", mw.FormDataContentType(), &mp)
	bearer("DELETE", "/api/v1/packages/"+itoa(pid), "", nil)
	// a scoped auditor token has the role for these reads, the scope refuses them
	code, body = call(admin, "POST", "/api/v1/tokens", `{"name":"aud","role":"auditor","days":30,"scope_tags":["prod"]}`)
	if _ = json.Unmarshal([]byte(body), &tok); code != 201 {
		t.Fatalf("scoped auditor token: %d %s", code, body)
	}
	bearer("GET", "/api/v1/packages", "", nil)
	bearer("GET", "/api/v1/software/catalog", "", nil)
	bearer("GET", "/api/v1/config/library/"+id+"/versions", "", nil)
	var arts int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM artifacts`).Scan(&arts)
	if arts != 1 {
		t.Fatalf("scoped callers changed packages: %d", arts)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/packages/"+itoa(pid), ""); code != 204 {
		t.Fatalf("delete package: %d", code)
	}
	code, body = call(admin, "PUT", "/api/v1/packages/settings", `{"max_upload_mb":64,"quota_mb":1024,"quota_count":50,"store":"local"}`)
	want(code, body, 200, `"saved"`)
	is(422)(call(admin, "PUT", "/api/v1/packages/settings", `{"max_upload_mb":0,"quota_mb":1,"quota_count":1,"store":"local"}`))

	// R3-E: device attributes, template preview, rendering at check in and script results
	is(422)(call(admin, "PATCH", "/api/v1/devices/d1", `{"attributes":{"1bad":"x"}}`))
	is(200)(call(admin, "PATCH", "/api/v1/devices/d1", `{"attributes":{"site":"ber","net":"10.1.0.0/16"}}`))
	code, body = call(admin, "GET", "/api/v1/devices/d1", "")
	want(code, body, 200, `"attributes":{"net":"10.1.0.0/16","site":"ber"}`)
	tplFiles := `{"files":[{"path":"/etc/motd","content":"{{.Hostname}} at {{.Attributes.site}}","mode":"0644","template":true}]}`
	code, body = call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.files","device":"alpha","payload":`+tplFiles+`}`)
	want(code, body, 200, `"content":"alpha at ber"`)
	code, body = call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.files","device":"d1","payload":{"files":[{"path":"/etc/motd","content":"{{.Attributes.nope}}","mode":"0644","template":true}]}}`)
	want(code, body, 200, `"error":"file /etc/motd`)
	is(422)(call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.files","device":"nope","payload":`+tplFiles+`}`))
	is(422)(call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.files","device":"d1","payload":{"files":[{"path":"/etc/motd","content":"{{template \"t\"}}","mode":"0644","template":true}]}}`))
	is(403)(call(auditor, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.files","device":"d1","payload":`+tplFiles+`}`))
	var terrs []string
	items, err := renderItems(ctx, db, "d1", []api.LibraryItem{{Name: "fw", Type: api.TypeFirewall, Payload: json.RawMessage(`{"enforce":true,"allow":[],"rules":[{"port":"22/tcp","from":"{{.Attributes.net}}"}],"template":true}`)}}, &terrs)
	if err != nil || len(terrs) != 0 || !strings.Contains(string(items[0].Payload), `"from":"10.1.0.0/16"`) {
		t.Fatalf("render at check in: %v %v %s", err, terrs, items[0].Payload)
	}
	// R3-H: hostname preview from the last report and rendering at check in
	if _, err := db.Exec(ctx, `UPDATE devices SET inventory = '{"hostname":"alpha","serial":"PF2AB","hostname_info":{"ptr":"WS17.corp.example","mac":"aa:bb:cc:dd:ee:ff"}}' WHERE id = 'd1'`); err != nil {
		t.Fatal(err)
	}
	code, body = call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.hostname","device":"d1","payload":{"source":"template","template":"pc-{{lower .Serial}}-{{.Attributes.site}}","domain":"corp.example"}}`)
	want(code, body, 200, `"target":"pc-pf2ab-ber.corp.example"`)
	code, body = call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.hostname","device":"d1","payload":{"source":"rdns"}}`)
	want(code, body, 200, `"current":"alpha","target":"ws17.corp.example","source":"rdns"`)
	code, body = call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.hostname","device":"d1","payload":{"source":"dns","fallback":"keep"}}`)
	want(code, body, 200, `"error":"dns: no DNS name`)
	is(422)(call(admin, "POST", "/api/v1/config/library/render", `{"type":"com.limdm.hostname","device":"d1","payload":{"source":"fixed"}}`))
	items, err = renderItems(ctx, db, "d1", []api.LibraryItem{{Name: "hn", Type: api.TypeHostname, Payload: json.RawMessage(`{"source":"template","template":"{{.MAC}}"}`)}}, &terrs)
	if err != nil || len(terrs) != 0 || !strings.Contains(string(items[0].Payload), `"template":"aa:bb:cc:dd:ee:ff"`) {
		t.Fatalf("hostname render at check in: %v %v %s", err, terrs, items[0].Payload)
	}
	if _, err := db.Exec(ctx, `INSERT INTO script_results(device_id, name, exit_code, stdout, started_at, ended_at) VALUES
		('d1', 'cleanup', 1, 'old', now(), now()), ('d1', 'cleanup', 0, 'line1
line2', now(), now())`); err != nil {
		t.Fatal(err)
	}
	code, body = call(auditor, "GET", "/api/v1/config/scripts/results?name=cleanup", "")
	want(code, body, 200, `"exit_code":0`)
	if strings.Count(body, `"device_id"`) != 1 || !strings.Contains(body, `"output":"line1\nline2"`) {
		t.Fatalf("script results: %s", body)
	}
	is(422)(call(auditor, "GET", "/api/v1/config/scripts/results", ""))
}
