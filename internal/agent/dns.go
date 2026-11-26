package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Fallback name resolution for the LiMDM server.
//
// When the system resolver cannot resolve the server's name, or none of the
// addresses it returns answers (a broken or hijacked local DNS, a captive
// resolver, a stale entry), the agent asks Cloudflare and Google over DNS
// over HTTPS, by IP address (no DNS needed to reach them) and with their
// certificates checked against the system roots. Plain port 53 queries are
// never used: they can be answered by anyone on the path.
//
// A wrong answer cannot redirect the agent: TLS to the LiMDM server still
// checks the server's certificate against the pinned device CA for the
// server's name, and the server checks the device certificate.

var dohResolvers = []struct{ name, url string }{
	{"cloudflare", "https://1.1.1.1/dns-query"},
	{"google", "https://8.8.8.8/resolve"},
	{"cloudflare", "https://1.0.0.1/dns-query"},
	{"google", "https://8.8.4.4/resolve"},
}

type dohEntry struct {
	ips     []string
	expires time.Time
}

// fallbackDNS is opt in: the server setting turns it on (remembered in the
// state for the next start), "no_fallback_dns": true in agent.json keeps it
// off on a device whatever the server says.
var fallbackDNS atomic.Bool

var (
	dohMu    sync.Mutex
	dohCache = map[string]dohEntry{}
	// dohClient trusts the system roots: the resolvers' certificates carry
	// their IP addresses.
	dohClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}}
)

// dohAnswer is the JSON format of both Cloudflare and Google.
type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// parseDoH returns the A and AAAA addresses and the shortest TTL.
func parseDoH(b []byte) ([]string, time.Duration, error) {
	var a dohAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, 0, err
	}
	if a.Status != 0 {
		return nil, 0, fmt.Errorf("DNS status %d", a.Status)
	}
	var ips []string
	ttl := time.Hour
	for _, r := range a.Answer {
		if r.Type != 1 && r.Type != 28 { // A, AAAA; CNAME records are followed by the resolver
			continue
		}
		if ip := net.ParseIP(r.Data); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			ips = append(ips, ip.String())
			ttl = min(ttl, time.Duration(max(r.TTL, 60))*time.Second)
		}
	}
	if len(ips) == 0 {
		return nil, 0, errors.New("no address")
	}
	return ips, ttl, nil
}

// resolveDoH asks the public resolvers in turn; answers are cached for their TTL.
func resolveDoH(ctx context.Context, host string) ([]string, error) {
	dohMu.Lock()
	if e, ok := dohCache[host]; ok && time.Now().Before(e.expires) {
		dohMu.Unlock()
		return e.ips, nil
	}
	dohMu.Unlock()
	var errs []error
	for _, r := range dohResolvers {
		var ips []string
		var ttl time.Duration
		for _, typ := range []string{"A", "AAAA"} {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url+"?name="+url.QueryEscape(host)+"&type="+typ, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/dns-json")
			resp, err := dohClient.Do(req)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r.name, err))
				break
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				errs = append(errs, fmt.Errorf("%s: %s", r.name, resp.Status))
				break
			}
			if got, t, err := parseDoH(b); err == nil {
				ips = append(ips, got...)
				if ttl == 0 || t < ttl {
					ttl = t
				}
			}
		}
		if len(ips) > 0 {
			dohMu.Lock()
			dohCache[host] = dohEntry{ips: ips, expires: time.Now().Add(ttl)}
			dohMu.Unlock()
			return ips, nil
		}
	}
	return nil, fmt.Errorf("fallback DNS for %s: %w", host, errors.Join(errs...))
}

// fallbackDial dials with the system resolver first and, if that fails,
// with addresses from the public resolvers. TLS on top still verifies the
// server's name against the pinned CA.
func fallbackDial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, addr)
		if err == nil || !fallbackDNS.Load() {
			return conn, err
		}
		host, port, serr := net.SplitHostPort(addr)
		if serr != nil || net.ParseIP(host) != nil {
			return nil, err // an IP address needs no name resolution
		}
		ips, derr := resolveDoH(ctx, host)
		if derr != nil {
			return nil, errors.Join(err, derr)
		}
		for _, ip := range ips {
			if c, cerr := d.DialContext(ctx, network, net.JoinHostPort(ip, port)); cerr == nil {
				return c, nil
			}
		}
		return nil, fmt.Errorf("%w; fallback DNS answered %v, none reachable", err, ips)
	}
}
