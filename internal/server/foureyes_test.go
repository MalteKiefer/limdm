package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestAdminMappings(t *testing.T) {
	m := []RoleGroup{{Group: "it", Role: "admin"}, {Group: "scim-admins", Role: "admin"}, {Group: "support", Role: "helpdesk"}}
	if role, _ := mapRole(adminMappings(m, false, []string{"scim-admins"}), []string{"scim-admins", "support"}); role != "helpdesk" {
		t.Fatalf("a SCIM only group must not grant admin: %q", role)
	}
	if role, _ := mapRole(adminMappings(m, false, nil), []string{"it"}); role != "admin" {
		t.Fatalf("OIDC claim or Google groups grant admin without four eyes: %q", role)
	}
	if role, _ := mapRole(adminMappings(m, true, nil), []string{"it", "support"}); role != "helpdesk" {
		t.Fatalf("no admin from groups while four eyes is on: %q", role)
	}
	if len(m) != 3 {
		t.Fatal("the settings must not be changed")
	}
}

// TestFourEyesDeclarations: root effective library items, required catalog
// apps and admin API tokens wait for a second admin.
func TestFourEyesDeclarations(t *testing.T) {
	s, db, ui := evidenceServer(t)
	ctx := context.Background()
	prev := itemKey
	itemKey = testCmdKey
	t.Cleanup(func() { itemKey = prev })
	db.Exec(ctx, `INSERT INTO console_users(email, role) VALUES ('second@firma.de', 'admin')`)
	set := s.settings()
	set.FourEyes = true
	s.rt.Store(&runtimeState{set: set, auth: &oidcAuth{}})

	web := httptest.NewServer(s.AdminHandler())
	t.Cleanup(web.Close)
	second := session{Email: "second@firma.de", Role: "admin", IAT: time.Now(), Last: time.Now()}
	approve := func(id string) (int, string) {
		form := url.Values{"csrf": {s.csrfToken(second)}}
		req, _ := http.NewRequest("POST", web.URL+"/approvals/"+id+"/approve", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.seal(second)})
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	lastID := func(action string) string {
		var id string
		db.QueryRow(ctx, `SELECT id::text FROM approvals WHERE action=$1 AND status='pending' ORDER BY id DESC LIMIT 1`, action).Scan(&id)
		return id
	}

	// a harmless item is saved at once, a script waits
	if code, _ := ui("POST", "/library", url.Values{"name": {"motd"}, "type": {api.TypeBanner}, "payload": {`{"motd": "hi"}`}}); code != http.StatusSeeOther {
		t.Fatalf("banner: %d", code)
	}
	script := `{"scripts": [{"name": "x", "interval_hours": 24, "body": "#!/bin/sh\ntrue"}]}`
	if code, _ := ui("POST", "/library", url.Values{"name": {"root-script"}, "type": {api.TypeScripts}, "payload": {script}}); code != http.StatusSeeOther {
		t.Fatalf("script request: %d", code)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM library_items WHERE name IN ('motd', 'root-script')`).Scan(&n)
	id := lastID("library.save")
	if n != 1 || id == "" {
		t.Fatalf("the script must wait for approval: items=%d request=%q", n, id)
	}
	if code, _ := ui("POST", "/approvals/"+id+"/approve", url.Values{}); code == http.StatusSeeOther {
		t.Fatal("the requester approved their own request")
	}
	if code, _ := approve(id); code != http.StatusSeeOther {
		t.Fatalf("approve: %d", code)
	}
	var name, typ, sig string
	var payload []byte
	if err := db.QueryRow(ctx, `SELECT name, type, payload, signature FROM library_items WHERE name='root-script'`).Scan(&name, &typ, &payload, &sig); err != nil {
		t.Fatal(err)
	}
	if !itemSignatureOK(name, typ, payload, sig) {
		t.Fatal("the approved item must be signed")
	}

	// a required catalog app waits, an available one does not
	app := url.Values{"new": {"1"}, "id": {"forced"}, "name": {"Forced"}, "mode": {"required"}, "enabled": {"on"}, "flatpak": {"org.example.Forced"}}
	if code, _ := ui("POST", "/software/apps", app); code != http.StatusSeeOther {
		t.Fatalf("app request: %d", code)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM catalog_apps WHERE slug='forced'`).Scan(&n)
	if id = lastID("catalog.save"); n != 0 || id == "" {
		t.Fatalf("a required app must wait: %d %q", n, id)
	}
	if code, _ := approve(id); code != http.StatusSeeOther {
		t.Fatalf("approve app: %d", code)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM catalog_apps WHERE slug='forced' AND mode='required' AND signature <> ''`).Scan(&n)
	if n != 1 {
		t.Fatal("approved app missing or unsigned")
	}

	// admin API tokens wait; the approver sees the token once
	if code, _ := ui("POST", "/settings/api", url.Values{"name": {"ci"}, "role": {"admin"}, "days": {"30"}}); code != http.StatusSeeOther {
		t.Fatalf("token request: %d", code)
	}
	db.QueryRow(ctx, `SELECT count(*) FROM api_tokens`).Scan(&n)
	if id = lastID("token.add"); n != 0 || id == "" {
		t.Fatalf("an admin token must wait: %d %q", n, id)
	}
	if code, body := approve(id); code != 200 || !strings.Contains(body, "lma_") {
		t.Fatalf("approver must see the token once: %d", code)
	}
	var by string
	db.QueryRow(ctx, `SELECT created_by FROM api_tokens WHERE name='ci'`).Scan(&by)
	if by != "admin@firma.de" {
		t.Fatalf("token belongs to the requester, got %q", by)
	}
}

func TestSCIMNetworkList(t *testing.T) {
	nets, err := parseNets([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.rt.Store(&runtimeState{scim: nets})
	h := s.scimAuth(func(http.ResponseWriter, *http.Request) { t.Fatal("reached the handler") })
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/scim/v2/Users", nil)
	r.RemoteAddr = "192.0.2.1:4000"
	h(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("outside the SCIM networks: %d", w.Code)
	}
	if !netsContain(nets, "10.1.2.3") || !netsContain(nets, "::ffff:10.1.2.3") || netsContain(nets, "garbage") {
		t.Fatal("netsContain")
	}
}

// TestFourEyesArtifacts: an item that installs uploaded packages as root
// needs a second admin like a script.
func TestFourEyesArtifacts(t *testing.T) {
	s := &Server{}
	s.rt.Store(&runtimeState{set: Settings{FourEyes: true}})
	if !s.itemNeedsApproval(api.LibraryItem{Type: api.TypeArtifacts, Payload: []byte(`{"artifacts": []}`)}) {
		t.Fatal("com.limdm.artifacts saved without approval")
	}
}
