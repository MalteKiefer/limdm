package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestSignedDataRefused(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(msg []byte) string { return hex.EncodeToString(ed25519.Sign(key, msg)) }
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.cfg.DeviceID = "dev1"
	a.state.CommandKey = hex.EncodeToString(pub)

	alice := api.User{Username: "alice", Email: "a@example.com"}
	bob := api.User{Username: "bob", Email: "b@example.com"}
	signed := []api.User{alice, bob}
	su := &api.SignedUsers{Users: signed, Signature: sign(api.UsersSigned("dev1", signed))}
	resp := func(users []api.User, su *api.SignedUsers) api.CheckinResponse {
		return api.CheckinResponse{SignedData: true, Users: users, SignedUsers: su}
	}
	if u, err := a.verifyUsers(resp([]api.User{alice}, su)); err != nil || len(u) != 1 {
		t.Fatalf("a subset of the signed list (directory filter) must pass: %v %v", u, err)
	}
	if _, err := a.verifyUsers(resp([]api.User{{Username: "alice", Email: "a@example.com", Admin: true}}, su)); err == nil {
		t.Fatal("an admin flag the signed list does not have must be refused")
	}
	if _, err := a.verifyUsers(resp(signed, nil)); err == nil {
		t.Fatal("an unsigned list from a signing server must be refused")
	}
	other := &api.SignedUsers{Users: signed, Signature: sign(api.UsersSigned("dev2", signed))}
	if _, err := a.verifyUsers(resp(signed, other)); err == nil {
		t.Fatal("a list signed for another device must be refused")
	}
	if u, err := a.verifyUsers(api.CheckinResponse{Users: signed}); err != nil || len(u) != 2 {
		t.Fatal("servers that do not sign yet are trusted as before")
	}

	good := api.CatalogApp{ID: "firefox", Name: "Firefox", Mode: api.AppRequired, Sources: []api.AppSource{{Kind: "flatpak", Flatpak: "org.mozilla.firefox"}}}
	good.Signature = sign(api.CatalogAppSigned(good))
	good.Summary, good.Request = "changed by Flathub", "approved" // display only, not signed
	evil := good
	evil.ID, evil.Sources = "evil", []api.AppSource{{Kind: "package", Debian: "evil", Repos: []api.Repository{{Family: "debian"}}}}
	rem := api.CatalogRemote{Name: "flathub", URL: "https://dl.flathub.org/repo/flathub.flatpakrepo", State: "allowed"}
	rem.Signature = sign(api.CatalogRemoteSigned(rem))
	badRem := rem
	badRem.URL = "https://evil.example/repo"
	c := &api.Catalog{Apps: []api.CatalogApp{good, evil}, Remotes: []api.CatalogRemote{rem, badRem}}
	a.verifyCatalog(true, c)
	if len(c.Apps) != 1 || c.Apps[0].ID != "firefox" || len(c.Remotes) != 1 || c.Remotes[0].URL != rem.URL {
		t.Fatalf("only signed entries may stay: %+v %+v", c.Apps, c.Remotes)
	}
}
