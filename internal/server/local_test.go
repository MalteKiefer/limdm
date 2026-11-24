package server

import (
	"net/http/httptest"
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
