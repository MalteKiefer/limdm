package agent

import (
	"slices"
	"testing"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestRequestDecisions(t *testing.T) {
	old := &api.Catalog{Apps: []api.CatalogApp{{ID: "slack", Name: "Slack", Request: "pending"}, {ID: "zoom", Name: "Zoom", Request: "pending"}, {ID: "gimp", Request: "approved"}},
		Requests: []api.RequestState{{Flatpak: "org.example.Notes", Name: "Notes", Status: "pending"}}}
	cur := &api.Catalog{Apps: []api.CatalogApp{{ID: "slack", Name: "Slack", Request: "approved", Install: true}, {ID: "zoom", Name: "Zoom", Request: "pending"}, {ID: "gimp", Request: "approved"}},
		Requests: []api.RequestState{{Flatpak: "org.example.Notes", Name: "Notes", Status: "denied"}}}
	got := requestDecisions(old, cur)
	want := []requestDecision{{Name: "Slack", Status: "approved", Install: true}, {Name: "Notes", Status: "denied"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
	if requestDecisions(nil, cur) != nil {
		t.Fatal("no old catalog, no decisions")
	}
	now := time.Now()
	if requestPolling(0, now) || !requestPolling(now.Add(-time.Hour).Unix(), now) || requestPolling(now.Add(-25*time.Hour).Unix(), now) {
		t.Fatal("fast polling only while a request is open, for at most a day")
	}
}
