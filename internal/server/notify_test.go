package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// device controlled text: no masked links, formatting or bare links
	md := n
	md.Text = "[click](https://evil.example) **bold** `x`"
	b, _ = discordBody(md)
	var dd struct {
		Embeds []struct {
			Description string `json:"description"`
		} `json:"embeds"`
	}
	if json.Unmarshal(b, &dd) != nil || strings.Contains(dd.Embeds[0].Description, "[click](") || strings.Contains(dd.Embeds[0].Description, "**") ||
		strings.Contains(dd.Embeds[0].Description, "https://") {
		t.Fatalf("discord markdown not escaped: %s", dd.Embeds[0].Description)
	}
	inj2 := n
	inj2.Text = "<!channel> <https://evil.example|click> *bold*"
	b, _ = slackBody("en", inj2)
	if !strings.Contains(string(b), "https://mdm.example.com/devices/d1|Open in LiMDM") {
		t.Fatalf("slack: console link missing: %s", b)
	}
	var sl struct {
		Text   string `json:"text"`
		Blocks []struct {
			Type string `json:"type"`
			Text struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"text"`
		} `json:"blocks"`
	}
	if json.Unmarshal(b, &sl) != nil || len(sl.Blocks) < 2 || sl.Blocks[1].Text.Type != "plain_text" || strings.Contains(sl.Blocks[1].Text.Text, "https://") ||
		strings.Contains(sl.Text, "<!channel>") {
		t.Fatalf("slack: device text must be plain: %s", b)
	}
	inj := n
	inj.Title = "x\r\nBcc: victim@example.com"
	m := string(emailMessage("mdm@example.com", []string{"it@example.com"}, inj))
	head, _, _ := strings.Cut(m, "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") || !strings.Contains(head, "\r\nSubject: [LiMDM] x Bcc: victim@example.com\r\n") {
		t.Fatalf("header injection possible:\n%s", head)
	}
	// addresses are written by net/mail, never raw: a forged recipient stays out
	m = string(emailMessage("LiMDM <mdm@example.com>", []string{"it@example.com\r\nBcc: victim@example.com"}, n))
	head, _, _ = strings.Cut(m, "\r\n\r\n")
	if strings.Contains(head, "victim") || !strings.Contains(head, "From: \"LiMDM\" <mdm@example.com>\r\n") {
		t.Fatalf("address headers:\n%s", head)
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

func TestNotifyRefusesLocalTargets(t *testing.T) {
	private := withPrivate(context.Background(), true)
	for _, target := range []string{"https://127.0.0.1:9/x", "https://[::1]:9/x", "https://169.254.169.254/latest/meta-data"} {
		s := &Server{} // the real client with the guarded dialer
		if err := s.postJSON(private, target, []byte("{}"), false, nil); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: %v", target, err)
		}
	}
	// private networks only for global channels with the setting on
	for _, target := range []string{"https://10.0.0.1:9/x", "https://192.168.1.1:9/x", "https://100.100.100.200/x", "https://[fd00:ec2::254]/x"} {
		s := &Server{}
		if err := s.postJSON(context.Background(), target, []byte("{}"), false, nil); err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: %v", target, err)
		}
	}
	if !targetAllowed(private, net.ParseIP("10.1.2.3")) || targetAllowed(context.Background(), net.ParseIP("10.1.2.3")) {
		t.Fatal("withPrivate")
	}
}

func TestTenantWebhookSignature(t *testing.T) {
	s := &Server{whKey: bytes.Repeat([]byte{1}, 32)}
	a, b := s.tenantWebhookKey(2), s.tenantWebhookKey(3)
	if bytes.Equal(a, b) || bytes.Equal(a, s.webhookKey()) {
		t.Fatal("each tenant needs its own secret")
	}
	var sig, tenant, at string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig, tenant, at = r.Header.Get("X-LiMDM-Signature"), r.Header.Get("X-LiMDM-Tenant"), r.Header.Get("X-LiMDM-Timestamp")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	s.hooks = ts.Client()
	two := int64(2)
	if err := s.postJSON(context.Background(), ts.URL, []byte("{}"), true, &two); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, a)
	fmt.Fprintf(mac, "%s.2.{}", at)
	if tenant != "2" || sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("tenant header %q, signature %q", tenant, sig)
	}
}

// a pooled connection would skip the private network check of the dialer
func TestNotifyClientNoPooling(t *testing.T) {
	if tr, ok := notifyClient.Transport.(pinnedTransport); !ok || !tr.DisableKeepAlives {
		t.Fatal("notification transport keeps idle connections")
	}
}

// Through a proxy the target is resolved and checked here and the tunnel
// goes to the checked address, so the proxy cannot resolve it again to a
// refused one (DNS rebinding).
func TestDialPinnedThroughProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err == nil {
				seen <- req.Method + " " + req.Host + " " + req.Header.Get("Proxy-Authorization")
				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			}
			c.Close()
		}
	}()
	proxy, _ := url.Parse("http://u:p@" + ln.Addr().String())
	ctx := context.WithValue(context.Background(), proxyKey{}, proxy)
	if _, err := dialPinned(ctx, "tcp", "localhost:443", safeDialer.DialContext); err == nil {
		t.Fatal("a name resolving to loopback was tunneled")
	}
	c, err := dialPinned(withPrivate(ctx, true), "tcp", "203.0.113.7:443", safeDialer.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := <-seen; got != "CONNECT 203.0.113.7:443 Basic dTpw" {
		t.Fatalf("proxy saw %q", got)
	}
	select {
	case got := <-seen:
		t.Fatalf("refused target reached the proxy: %q", got)
	default:
	}
}
