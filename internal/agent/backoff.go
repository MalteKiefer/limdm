package agent

import (
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// busyError is a server answer of 503 or 429: it is overloaded (too many
// check ins or package downloads at once, a lock it could not get in time)
// and asks the device to come back after a while. It is no failure of the
// request itself: an agent update is not marked failed for it.
type busyError struct {
	what  string
	after time.Duration
}

func (e busyError) Error() string {
	return fmt.Sprintf("%s: server busy, retry in %s", e.what, e.after.Round(time.Second))
}

// maxRetryAfter caps what a server can ask for: a device must not go quiet
// for long because of one answer.
const maxRetryAfter = 30 * time.Minute

// busyOf returns a busyError for 503 and 429 answers, else nil. Retry-After
// in seconds is honored (default one minute); jitter spreads the fleet.
func busyOf(what string, resp *http.Response) error {
	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusTooManyRequests {
		return nil
	}
	d := time.Minute
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
		d = time.Duration(s) * time.Second
	}
	d = min(d, maxRetryAfter)
	return busyError{what: what, after: d + time.Duration(mrand.Int64N(int64(d/4)+int64(time.Second)))} //nolint:gosec // jitter, not a secret
}

// backoff is when the device may talk to the server again (unix nanos).
type backoff struct{ until atomic.Int64 }

// note records a busy answer; it never shortens a running backoff.
func (b *backoff) note(err error) {
	var be busyError
	if !errors.As(err, &be) {
		return
	}
	t := time.Now().Add(be.after).UnixNano()
	for {
		cur := b.until.Load()
		if cur >= t || b.until.CompareAndSwap(cur, t) {
			return
		}
	}
}

// wait stretches d to the end of a running backoff.
func (b *backoff) wait(d time.Duration) time.Duration {
	return max(d, time.Until(time.Unix(0, b.until.Load())))
}

// checkinWait is the pause before the next check in: the interval plus up to
// 10 % jitter; after failed check ins the interval doubles per failure up to
// 15 minutes with up to 50 % jitter, so a fleet does not return all at once
// when the server is back after an outage.
func checkinWait(interval time.Duration, failures int) time.Duration {
	jitter := interval / 10
	if failures > 0 {
		interval = max(interval, min(interval<<min(failures, 4), 15*time.Minute))
		jitter = interval / 2
	}
	return interval + time.Duration(mrand.Int64N(int64(jitter)+1)) //nolint:gosec // scheduling jitter, not a secret
}
