package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateChannel(t *testing.T) {
	ok := []channel{
		{Name: "ops", Kind: "slack", Secret: "https://hooks.slack.com/services/T0/B0/xyz"},
		{Name: "ops", Kind: "discord", Secret: "https://discord.com/api/webhooks/1/abc", Events: []string{"device.tamper"}},
		{Name: "ops", Kind: "webhook", Secret: "https://siem.example.com/limdm"},
		{Name: "ops", Kind: "email", Config: channelConfig{Host: "smtp.example.com", Port: 587, TLS: "starttls", From: "LiMDM <mdm@example.com>", To: []string{"it@example.com"}}},
	}
	for _, c := range ok {
		if err := validateChannel(c); err != nil {
			t.Errorf("%s: %v", c.Kind, err)
		}
	}
	bad := []channel{
		{Name: "x", Kind: "slack", Secret: "https://evil.example/hooks.slack.com/"},
		{Name: "x", Kind: "discord", Secret: "https://discord.com.evil.example/api/webhooks/1"},
		{Name: "x", Kind: "discord", Secret: "http://discord.com/api/webhooks/1/a"},
		{Name: "x", Kind: "webhook", Secret: "http://siem.example.com"},
		{Name: "x", Kind: "email", Config: channelConfig{Host: "smtp.example.com", Port: 25, TLS: "", From: "a@b.c", To: []string{"d@e.f"}}},
		{Name: "x", Kind: "email", Config: channelConfig{Host: "smtp.example.com", Port: 587, TLS: "starttls", From: "a@b.c", To: []string{"not an address"}}},
		{Name: "x", Kind: "slack", Secret: "https://hooks.slack.com/x", Events: []string{"device.unknown"}},
		{Name: "x", Kind: "teams", Secret: "https://example.com"},
	}
	for _, c := range bad {
		if validateChannel(c) == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestNotificationFormats(t *testing.T) {
	n := notice{Type: "device.tamper", Severity: "critical", Title: "Tamper attempt on pinetree", Text: "agent stopped @everyone",
		URL: "https://mdm.example.com/devices/d1", At: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
	b, _ := discordBody(n)
	var d struct {
		Embeds []struct {
			Title string `json:"title"`
			Color int    `json:"color"`
		} `json:"embeds"`
		Mentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if json.Unmarshal(b, &d) != nil || d.Embeds[0].Title != n.Title || d.Embeds[0].Color != 0xE01B24 || d.Mentions.Parse == nil || len(d.Mentions.Parse) != 0 {
		t.Fatalf("discord: %s", b)
	}
	inj2 := n
	inj2.Text = "<!channel> <https://evil.example|click>"
	b, _ = slackBody(inj2)
	var sl struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(b, &sl) != nil || !strings.Contains(sl.Text, "<https://mdm.example.com/devices/d1|Open in LiMDM>") ||
		strings.Contains(sl.Text, "<!channel>") || strings.Contains(sl.Text, "<https://evil.example") {
		t.Fatalf("slack: %s", sl.Text)
	}
	inj := n
	inj.Title = "x\r\nBcc: victim@example.com"
	m := string(emailMessage("mdm@example.com", []string{"it@example.com"}, inj))
	head, _, _ := strings.Cut(m, "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") || !strings.Contains(head, "Subject: =?utf-8?") {
		t.Fatalf("header injection possible:\n%s", head)
	}
}

func TestDeliverWebhookKinds(t *testing.T) {
	var got []string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Header.Get("X-LiMDM-Signature")+" "+string(b))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	s := &Server{hooks: ts.Client(), cfg: Config{SessionKey: []byte("0123456789abcdef0123456789abcdef")}}
	n := notice{Type: "device.enrolled", Title: "Device enrolled", Text: "x", At: time.Now()}
	for _, kind := range []string{"slack", "discord", "webhook"} {
		if err := s.deliver(context.Background(), channel{Kind: kind, Secret: ts.URL}, n); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	if len(got) != 3 || strings.HasPrefix(got[0], "sha256=") || !strings.HasPrefix(got[2], "sha256=") {
		t.Fatalf("deliveries: %q", got)
	}
}
