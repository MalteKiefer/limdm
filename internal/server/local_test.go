package server

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890")) // RFC 6238 appendix B, SHA-1
	for _, c := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := totpCode(secret, c.unix/30)
		if err != nil || got != c.want {
			t.Errorf("T=%d: got %s want %s (%v)", c.unix, got, c.want, err)
		}
	}
}

func TestVerifyTOTPReplayAndWindow(t *testing.T) {
	secret := newTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	code, _ := totpCode(secret, now.Unix()/30)
	step, ok := verifyTOTP(secret, code, now, 0)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := verifyTOTP(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	old, _ := totpCode(secret, now.Unix()/30-3)
	if _, ok := verifyTOTP(secret, old, now, 0); ok {
		t.Fatal("code outside the window accepted")
	}
	if _, ok := verifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestPasswordHash(t *testing.T) {
	h := hashPassword("correct horse")
	if !checkPassword(h, "correct horse") || checkPassword(h, "correct horsf") || checkPassword("garbage", "x") {
		t.Fatal("argon2id verification wrong")
	}
	if a, b := hashPassword("same"), hashPassword("same"); a == b {
		t.Fatal("salt missing")
	}
}

func TestLimiter(t *testing.T) {
	var l limiter
	for i := 0; i < 3; i++ {
		if !l.allow("a", 3, time.Minute) {
			t.Fatal("blocked too early")
		}
	}
	if l.allow("a", 3, time.Minute) || !l.allow("b", 3, time.Minute) {
		t.Fatal("limit not per key")
	}
	// idle keys are dropped
	l.mu.Lock()
	l.hits["old"] = []time.Time{time.Now().Add(-2 * limiterTTL)}
	l.swept = time.Time{}
	l.mu.Unlock()
	l.allow("c", 3, time.Minute)
	if _, ok := l.hits["old"]; ok {
		t.Fatal("idle key kept")
	}
	// IPv6 clients share the budget of their /64
	r1, r2 := httptest.NewRequest("GET", "/", nil), httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr, r2.RemoteAddr = "[2001:db8:1:2::1]:4000", "[2001:db8:1:2::ffff]:4000"
	if rateKey(r1) != rateKey(r2) || rateKey(r1) != "2001:db8:1:2::/64" {
		t.Fatalf("rate keys %s %s", rateKey(r1), rateKey(r2))
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/login/local", nil)
	r.RemoteAddr = "203.0.113.9:4000"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("header from a non proxy peer trusted: %s", got)
	}
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("loopback proxy: got %s", got)
	}
}

func TestSecretSealing(t *testing.T) {
	s := &Server{cfg: Config{SessionKey: []byte("0123456789abcdef0123456789abcdef")}}
	enc, err := s.sealField("settings.oidc_client_secret", "client-secret")
	if err != nil || enc == "" || strings.Contains(enc, "client-secret") {
		t.Fatalf("seal: %q %v", enc, err)
	}
	if got, err := s.openField("settings.oidc_client_secret", enc); err != nil || got != "client-secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	other := &Server{cfg: Config{SessionKey: []byte("ffffffffffffffffffffffffffffffff")}}
	if _, err := other.openField("settings.oidc_client_secret", enc); err == nil {
		t.Fatal("secret opened with a different key")
	}
	// bound to the field: a sealed OIDC secret cannot be read as another field
	if _, err := s.openField("settings.google_service_account_key", enc); err == nil {
		t.Fatal("sealed value opened for another field")
	}
	// values sealed before per field binding stay readable
	a, _ := s.aead(infoSettings)
	legacy := base64.StdEncoding.EncodeToString(seal(a, []byte("old"), []byte(legacyAD)))
	if got, err := s.openField("settings.google_service_account_key", legacy); err != nil || got != "old" {
		t.Fatalf("legacy value: %q %v", got, err)
	}
}
