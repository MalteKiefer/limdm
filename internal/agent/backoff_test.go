package agent

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestBusyBackoff(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Retry-After": {"120"}}}
	err := busyOf("/api/v1/checkin", resp)
	var be busyError
	if !errors.As(err, &be) || be.after < 120*time.Second || be.after > 151*time.Second {
		t.Fatalf("Retry-After not honored: %v", err)
	}
	if busyOf("x", &http.Response{StatusCode: http.StatusInternalServerError}) != nil {
		t.Fatal("500 is no busy answer")
	}
	if err := busyOf("x", &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"999999"}}}); !errors.As(err, &be) || be.after > maxRetryAfter*5/4+time.Second {
		t.Fatalf("Retry-After not capped: %v", err)
	}
	var b backoff
	if b.wait(time.Second) != time.Second {
		t.Fatal("wait without backoff")
	}
	b.note(busyError{after: time.Hour})
	b.note(busyError{after: time.Minute}) // never shortens
	if w := b.wait(time.Second); w < 59*time.Minute {
		t.Fatalf("backoff not kept: %v", w)
	}
}

func TestCheckinWait(t *testing.T) {
	if w := checkinWait(5*time.Minute, 0); w < 5*time.Minute || w > 5*time.Minute+30*time.Second {
		t.Fatalf("normal: %v", w)
	}
	if w := checkinWait(5*time.Minute, 1); w < 10*time.Minute || w > 15*time.Minute {
		t.Fatalf("first failure: %v", w)
	}
	if w := checkinWait(5*time.Minute, 9); w < 15*time.Minute || w > 22*time.Minute+30*time.Second {
		t.Fatalf("capped: %v", w)
	}
	if w := checkinWait(time.Hour, 3); w < time.Hour {
		t.Fatalf("never shorter than the interval: %v", w)
	}
}
