package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Approvals, exceptions, tokens and tenants through the admin API, token
// scopes, Idempotency-Key, If-Match and the API reference page.
func TestAdminAPIManagement(t *testing.T) {
	db := loadTestDB(t, 8)
	s := loadTestServer(db)
	s.cfg.MultiTenant = true
	s.rt.Store(&runtimeState{set: Settings{StaleHours: 24, FourEyes: true, OIDCIssuer: "https://idp.test", OIDCClientID: "x"}, auth: &oidcAuth{}})
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1','s',now(),'pc1')`); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.AdminHandler())
	defer srv.Close()
	root := session{Email: "admin@firma.de", Role: "admin", Super: true}
	mkToken := func(name, role string, scopes ...string) string {
		t.Helper()
		// stored directly: four eyes would hold an admin token for approval
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		// each token belongs to its own person; alice2 is a second token of alice
		tok, _, _, err := insertToken(ctx, tx, tokenApproval{Name: name, Role: role, Days: 30, Scopes: scopes}, strings.TrimSuffix(name, "2")+"@firma.de")
		if err != nil || tx.Commit(ctx) != nil {
			t.Fatal(err)
		}
		return tok
	}
	type answer struct {
		StatusCode int
		Header     http.Header
	}
	call := func(tok, method, path, body string, hdr ...string) (answer, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return answer{resp.StatusCode, resp.Header}, string(b)
	}
	alice, bob := mkToken("alice", "admin"), mkToken("bob", "admin")
	if _, _, err := s.createAPIToken(ctx, root, tokenSpec{Name: "carol", Role: "admin", Days: 30}); err == nil {
		t.Fatal("admin token created without approval")
	}
	if resp, body := call(alice, "POST", "/api/v1/tokens", `{"name":"dave","role":"admin","days":30}`); resp.StatusCode != http.StatusAccepted ||
		!strings.HasPrefix(resp.Header.Get("Location"), "/api/v1/approvals/") {
		t.Fatalf("admin token via API: %d %s", resp.StatusCode, body)
	}

	// four eyes: a wipe through the API waits for approval at an API URL
	resp, body := call(alice, "POST", "/api/v1/devices/d1/commands", `{"type":"wipe","params":{"confirm":"pc1","reason":"stolen"}}`)
	if resp.StatusCode != http.StatusAccepted || !strings.HasPrefix(resp.Header.Get("Location"), "/api/v1/approvals/") {
		t.Fatalf("wipe: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	loc := resp.Header.Get("Location")
	if resp, body = call(bob, "GET", loc, ""); resp.StatusCode != 200 || !strings.Contains(body, `"status":"pending"`) {
		t.Fatalf("approval: %d %s", resp.StatusCode, body)
	}
	if resp, _ = call(alice, "POST", loc+"/approve", ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("own request approved: %d", resp.StatusCode)
	}
	if resp, _ = call(mkToken("alice2", "admin"), "POST", loc+"/approve", ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("own request approved with a second token: %d", resp.StatusCode)
	}
	if resp, body = call(bob, "POST", loc+"/approve", ""); resp.StatusCode != 200 || !strings.Contains(body, `"status":"approved"`) {
		t.Fatalf("approve: %d %s", resp.StatusCode, body)
	}
	if resp, body = call(bob, "GET", "/api/v1/approvals?status=approved", ""); resp.StatusCode != 200 || !strings.Contains(body, `"action":"command"`) {
		t.Fatalf("approval list: %d %s", resp.StatusCode, body)
	}

	// Idempotency-Key: a retried request queues one command
	cmd := `{"type":"lock","params":{"message":"x"}}`
	r1, b1 := call(alice, "POST", "/api/v1/devices/d1/commands", cmd, "Idempotency-Key", "k1")
	r2, b2 := call(alice, "POST", "/api/v1/devices/d1/commands", cmd, "Idempotency-Key", "k1")
	if r1.StatusCode != http.StatusAccepted || r2.StatusCode != r1.StatusCode || b1 != b2 || r2.Header.Get("Idempotent-Replayed") != "true" ||
		r2.Header.Get("Location") != r1.Header.Get("Location") {
		t.Fatalf("replay: %d %d %q", r1.StatusCode, r2.StatusCode, r2.Header.Get("Idempotent-Replayed"))
	}
	var locks int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM commands WHERE type='lock'`).Scan(&locks); err != nil || locks != 1 {
		t.Fatalf("commands queued: %d %v", locks, err)
	}
	if resp, _ = call(alice, "POST", "/api/v1/devices/d1/commands", `{"type":"unlock"}`, "Idempotency-Key", "k1"); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("key reused for another request: %d", resp.StatusCode)
	}

	// If-Match: a change based on an old read is refused
	resp, body = call(alice, "POST", "/api/v1/blueprints", `{"name":"lab","tree":[]}`)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("ETag") == "" {
		t.Fatalf("blueprint: %d %s", resp.StatusCode, body)
	}
	bpLoc, etag := resp.Header.Get("Location"), resp.Header.Get("ETag")
	time.Sleep(2 * time.Millisecond)
	if resp, _ = call(bob, "PUT", bpLoc, `{"name":"lab","description":"bob","tree":[]}`, "If-Match", etag); resp.StatusCode != 200 {
		t.Fatalf("put with current etag: %d", resp.StatusCode)
	}
	current := resp.Header.Get("ETag")
	if resp, _ = call(alice, "PUT", bpLoc, `{"name":"lab","description":"alice","tree":[]}`, "If-Match", etag); resp.StatusCode != http.StatusPreconditionFailed ||
		resp.Header.Get("ETag") != current {
		t.Fatalf("lost update: %d %q", resp.StatusCode, resp.Header.Get("ETag"))
	}
	// the check runs in the save transaction: a row changed after the
	// request started is still compared
	var bpID int64
	db.QueryRow(ctx, `SELECT id FROM blueprints WHERE name='lab'`).Scan(&bpID)
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE blueprints SET updated_at = updated_at + interval '1 second' WHERE id=$1`, bpID); err != nil {
			return err
		}
		return checkIfMatch(context.WithValue(ctx, ifMatchKey{}, current), tx, "blueprints", bpID)
	})
	if !errors.Is(err, errPrecondition) {
		t.Fatalf("If-Match inside the transaction: %v", err)
	}

	// exceptions
	day := time.Now().AddDate(0, 1, 0).Format(time.DateOnly)
	if resp, body = call(alice, "POST", "/api/v1/exceptions", `{"check_id":"disk.recovery","mode":"advisory","reason":"lab","owner":"cto","approver":"alice@firma.de","expires":"`+day+`"}`); resp.StatusCode == http.StatusCreated {
		t.Fatalf("token creator named as their own approver: %s", body)
	}
	resp, body = call(alice, "POST", "/api/v1/exceptions", `{"check_id":"disk.recovery","mode":"advisory","reason":"lab","owner":"cto","approver":"ciso","expires":"`+day+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("exception: %d %s", resp.StatusCode, body)
	}
	if resp, body = call(bob, "GET", "/api/v1/exceptions", ""); !strings.Contains(body, `"state":"active"`) {
		t.Fatalf("exceptions: %d %s", resp.StatusCode, body)
	}
	if resp, _ = call(bob, "DELETE", "/api/v1/exceptions/1", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke exception: %d", resp.StatusCode)
	}

	// tokens: create with scopes, a scoped token is limited, delete
	resp, body = call(alice, "POST", "/api/v1/tokens", `{"name":"reader","role":"admin","days":7,"scopes":["read"]}`)
	var created struct {
		ID    int64
		Token string
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("token: %d %s", resp.StatusCode, body)
	}
	// four eyes: the approver gets the admin token once
	var decided struct{ Credentials string }
	if resp, body = call(bob, "POST", resp.Header.Get("Location")+"/approve", ""); resp.StatusCode != 200 || json.Unmarshal([]byte(body), &decided) != nil {
		t.Fatalf("approve token: %d %s", resp.StatusCode, body)
	}
	_, created.Token, _ = strings.Cut(decided.Credentials, ": ")
	if err := db.QueryRow(ctx, `SELECT id FROM api_tokens WHERE name='reader'`).Scan(&created.ID); err != nil || !strings.HasPrefix(created.Token, "lma_") {
		t.Fatalf("approved token: %q %v", decided.Credentials, err)
	}
	if resp, _ = call(created.Token, "GET", "/api/v1/blueprints", ""); resp.StatusCode != 200 {
		t.Fatalf("scoped read: %d", resp.StatusCode)
	}
	if resp, _ = call(created.Token, "POST", "/api/v1/devices/d1/commands", `{"type":"unlock"}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("command without the commands scope: %d", resp.StatusCode)
	}
	approver := mkToken("approver", "admin", "admin")
	if resp, body = call(approver, "POST", "/api/v1/tokens", `{"name":"wider","role":"helpdesk","days":7,"scopes":[]}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a scoped token minted an unscoped one: %d %s", resp.StatusCode, body)
	}
	if resp, _ = call(alice, "POST", "/api/v1/tokens", `{"name":"x","role":"admin","days":7,"scopes":["everything"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown scope: %d", resp.StatusCode)
	}
	if resp, body = call(bob, "GET", "/api/v1/tokens", ""); resp.StatusCode != 200 || strings.Contains(body, created.Token) {
		t.Fatalf("token list: %d", resp.StatusCode)
	}
	if resp, _ = call(alice, "DELETE", "/api/v1/tokens/"+strconv.FormatInt(created.ID, 10), ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete token: %d", resp.StatusCode)
	}
	if resp, _ = call(created.Token, "GET", "/api/v1/blueprints", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted token: %d", resp.StatusCode)
	}

	// tenants: global tokens only
	if resp, body = call(alice, "POST", "/api/v1/tenants", `{"name":"Customer"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("tenant: %d %s", resp.StatusCode, body)
	}
	if resp, _ = call(alice, "POST", "/api/v1/tenants", `{"name":"Customer"}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate tenant: %d", resp.StatusCode)
	}
	if resp, body = call(bob, "GET", "/api/v1/tenants", ""); !strings.Contains(body, `"name":"Customer"`) {
		t.Fatalf("tenants: %d %s", resp.StatusCode, body)
	}

	// the reference page needs no token and no script
	ref, err := http.Get(srv.URL + "/api/v1/docs")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(ref.Body)
	ref.Body.Close()
	if ref.StatusCode != 200 || !strings.Contains(string(page), "/api/v1/devices/{id}/commands") || strings.Contains(string(page), "<script") {
		t.Fatalf("reference: %d", ref.StatusCode)
	}
}
