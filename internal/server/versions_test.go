package server

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestLineDiff(t *testing.T) {
	var got []string
	for _, l := range lineDiff("a\nb\nc\n", "a\nc\nd\n") {
		got = append(got, l.Op+":"+l.Text)
	}
	if strings.Join(got, " ") != "same:a del:b same:c add:d" {
		t.Fatalf("diff: %v", got)
	}
	if d := lineDiff("", "x"); len(d) != 2 || d[0].Op != "del" || d[1].Op != "add" {
		t.Fatalf("new object: %v", d)
	}
}

// Library items and blueprints keep every version: preview before saving,
// history with diff, rollback as a new version, and restore after delete.
func TestVersioning(t *testing.T) {
	_, db, ui := evidenceServer(t)
	ctx := context.Background()
	db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1', 's', now(), 'pc1')`)
	var defID int64
	db.QueryRow(ctx, `SELECT id FROM blueprints WHERE name='default'`).Scan(&defID)

	save := func(form url.Values) (int, string) { return ui("POST", "/library", form) }
	if code, _ := save(url.Values{"name": {"tools"}, "type": {"com.limdm.packages"}, "payload": {`{"install":["vim"]}`}}); code != http.StatusSeeOther {
		t.Fatalf("create: %d", code)
	}
	var itemID int64
	db.QueryRow(ctx, `SELECT id FROM library_items WHERE name='tools'`).Scan(&itemID)
	id := strconv.FormatInt(itemID, 10)
	// put the item into the default blueprint, which the device gets
	tree := `[{"kind":"assign","items":[` + id + `]}]`
	if code, body := ui("POST", "/blueprints", url.Values{"id": {strconv.FormatInt(defID, 10)}, "name": {"default"}, "tree": {tree}}); code != http.StatusSeeOther {
		t.Fatalf("blueprint save: %d %s", code, body)
	}

	// the preview shows the diff and the reached device, and saves nothing
	code, body := save(url.Values{"id": {id}, "name": {"tools"}, "type": {"com.limdm.packages"}, "payload": {`{"install":["vim","git"]}`}, "preview": {"1"}})
	if code != 200 || !strings.Contains(body, "pc1") || !strings.Contains(body, `class="d-add">+     &#34;git&#34;`) {
		t.Fatalf("preview: %d\n%s", code, body)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM library_item_versions WHERE item_id=$1`, itemID).Scan(&n)
	if n != 1 {
		t.Fatalf("preview must not save: %d versions", n)
	}
	if code, _ := save(url.Values{"id": {id}, "name": {"tools"}, "type": {"com.limdm.packages"}, "payload": {`{"install":["vim","git"]}`}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if code, body := ui("GET", "/library/"+id+"/history", nil); code != 200 || !strings.Contains(body, "d-add") {
		t.Fatalf("history: %d", code)
	}
	if code, _ := ui("POST", "/library/"+id+"/rollback", url.Values{"version": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("rollback: %d", code)
	}
	var payload, note string
	db.QueryRow(ctx, `SELECT payload::text FROM library_items WHERE id=$1`, itemID).Scan(&payload)
	db.QueryRow(ctx, `SELECT note FROM library_item_versions WHERE item_id=$1 AND version=3`, itemID).Scan(&note)
	if strings.Contains(payload, "git") || note != "rollback to version 1" {
		t.Fatalf("rollback did not restore version 1: %s %q", payload, note)
	}

	// delete keeps the last payload; restore brings the item back under its ID
	ui("POST", "/blueprints", url.Values{"id": {strconv.FormatInt(defID, 10)}, "name": {"default"}, "tree": {"[]"}})
	if code, _ := ui("POST", "/library/"+id+"/delete", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("delete: %d", code)
	}
	if _, body := ui("GET", "/library", nil); !strings.Contains(body, "/library/"+id+"/history") {
		t.Fatal("deleted item not listed")
	}
	if code, _ := ui("POST", "/library/"+id+"/rollback", url.Values{"version": {"3"}}); code != http.StatusSeeOther {
		t.Fatalf("restore: %d", code)
	}
	if err := db.QueryRow(ctx, `SELECT payload::text FROM library_items WHERE id=$1`, itemID).Scan(&payload); err != nil {
		t.Fatal("item not restored: ", err)
	}
	var audited int
	db.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='library.rollback'`).Scan(&audited)
	if audited != 2 {
		t.Fatalf("rollbacks audited %d times", audited)
	}

	// blueprints: rollback of the default map and restore of a deleted one
	if code, _ := ui("POST", "/blueprints/"+strconv.FormatInt(defID, 10)+"/rollback", url.Values{"version": {"2"}}); code != http.StatusSeeOther {
		t.Fatalf("blueprint rollback: %d", code)
	}
	var tr string
	db.QueryRow(ctx, `SELECT tree::text FROM blueprints WHERE id=$1`, defID).Scan(&tr)
	if !strings.Contains(tr, id) {
		t.Fatalf("blueprint rollback: %s", tr)
	}
	ui("POST", "/blueprints", url.Values{"name": {"lab"}, "tree": {"[]"}})
	var labID int64
	db.QueryRow(ctx, `SELECT id FROM blueprints WHERE name='lab'`).Scan(&labID)
	lab := strconv.FormatInt(labID, 10)
	ui("POST", "/blueprints/"+lab+"/delete", url.Values{})
	if code, _ := ui("POST", "/blueprints/"+lab+"/rollback", url.Values{"version": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("blueprint restore: %d", code)
	}
	if _, err := db.Exec(ctx, `UPDATE library_item_versions SET note='x'`); err == nil {
		t.Fatal("version history must be append only")
	}
}

// Network secrets live in library_items only: versions, diffs, the preview
// and the audit log show the mask, and a rollback takes the stored secret.
func TestNetworkSecretsNotVersioned(t *testing.T) {
	_, db, ui := evidenceServer(t)
	ctx := context.Background()
	const secret = "supersecret-psk-1"
	payload := func(ssid, psk string) string {
		return `{"profiles":[{"name":"w","type":"wifi","ssid":"` + ssid + `","security":"wpa2-personal","psk":"` + psk + `"}]}`
	}
	if code, body := ui("POST", "/library", url.Values{"name": {"wlan"}, "type": {"com.limdm.network"}, "payload": {payload("Corp", secret)}}); code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", code, body)
	}
	var itemID int64
	db.QueryRow(ctx, `SELECT id FROM library_items WHERE name='wlan'`).Scan(&itemID)
	id := strconv.FormatInt(itemID, 10)
	// the editor sends the mask back with a changed SSID
	edit := url.Values{"id": {id}, "name": {"wlan"}, "type": {"com.limdm.network"}, "payload": {payload("Corp2", "••••••")}}
	edit.Set("preview", "1")
	if code, body := ui("POST", "/library", edit); code != 200 || strings.Contains(body, secret) {
		t.Fatalf("preview shows the secret: %d", code)
	}
	edit.Del("preview")
	if code, body := ui("POST", "/library", edit); code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", code, body)
	}
	var stored string
	db.QueryRow(ctx, `SELECT payload::text FROM library_items WHERE id=$1`, itemID).Scan(&stored)
	if !strings.Contains(stored, secret) || !strings.Contains(stored, "Corp2") {
		t.Fatalf("stored secret lost: %s", stored)
	}
	var leaks int
	db.QueryRow(ctx, `SELECT (SELECT count(*) FROM library_item_versions WHERE payload::text LIKE '%'||$1||'%')
		+ (SELECT count(*) FROM audit_log WHERE detail LIKE '%'||$1||'%')`, secret).Scan(&leaks)
	if leaks != 0 {
		t.Fatalf("secret in versions or audit log: %d", leaks)
	}
	if code, body := ui("GET", "/library/"+id+"/history", nil); code != 200 || strings.Contains(body, secret) {
		t.Fatalf("history shows the secret: %d", code)
	}
	if code, body := ui("POST", "/library/"+id+"/rollback", url.Values{"version": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("rollback: %d %s", code, body)
	}
	db.QueryRow(ctx, `SELECT payload::text FROM library_items WHERE id=$1`, itemID).Scan(&stored)
	if !strings.Contains(stored, secret) || strings.Contains(stored, "Corp2") {
		t.Fatalf("rollback: %s", stored)
	}
}
