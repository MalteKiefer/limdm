package agent

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestParseDoH(t *testing.T) {
	b := []byte(`{"Status":0,"Answer":[{"name":"mdm.example.com","type":5,"TTL":300,"data":"edge.example.net."},
		{"name":"edge.example.net","type":1,"TTL":120,"data":"203.0.113.7"},{"type":1,"TTL":20,"data":"127.0.0.1"},
		{"type":28,"TTL":3600,"data":"2001:db8::7"}]}`)
	ips, ttl, err := parseDoH(b)
	if err != nil || len(ips) != 2 || ips[0] != "203.0.113.7" || ips[1] != "2001:db8::7" || ttl != 120*time.Second {
		t.Fatalf("%v %v %v", ips, ttl, err)
	}
	if _, _, err := parseDoH([]byte(`{"Status":3}`)); err == nil {
		t.Fatal("NXDOMAIN accepted")
	}
}

// TestDoHLive asks the real resolvers; run with LIMDM_LIVE_DNS=1.
func TestDoHLive(t *testing.T) {
	if os.Getenv("LIMDM_LIVE_DNS") == "" {
		t.Skip("set LIMDM_LIVE_DNS=1")
	}
	ips, err := resolveDoH(context.Background(), "github.com")
	if err != nil || len(ips) == 0 || net.ParseIP(ips[0]) == nil {
		t.Fatalf("%v %v", ips, err)
	}
	// a name the system resolver cannot resolve falls back, and fails cleanly
	if _, err := fallbackDial()(context.Background(), "tcp", "does-not-exist.invalid:443"); err == nil {
		t.Fatal("dial to an invalid name succeeded")
	}
}
