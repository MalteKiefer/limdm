package server

import (
	"net/http/httptest"
	"testing"
)

// X-Forwarded-For counts from loopback and the configured load balancers only.
func TestTrustedProxies(t *testing.T) {
	if _, err := parseProxies("10.0.0.0/8, nonsense"); err == nil {
		t.Fatal("invalid entry accepted")
	}
	list, err := parseProxies(" 10.1.0.0/16 , 192.0.2.7,2001:db8::/32")
	if err != nil || len(list) != 3 {
		t.Fatalf("parse: %v %v", list, err)
	}
	defer func() { trustedProxies = nil }()
	trustedProxies = list
	for peer, want := range map[string]string{
		"10.1.2.3:4000":       "203.0.113.9",
		"192.0.2.7:4000":      "203.0.113.9",
		"[2001:db8::1]:4000":  "203.0.113.9",
		"[::ffff:10.1.2.3]:1": "203.0.113.9",
		"127.0.0.1:4000":      "203.0.113.9",
		"192.0.2.8:4000":      "192.0.2.8", // not a proxy: the header is ignored
		"10.2.0.1:4000":       "10.2.0.1",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9")
		if got := clientIP(r); got != want {
			t.Errorf("%s: %s, want %s", peer, got, want)
		}
	}
}
