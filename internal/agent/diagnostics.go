package agent

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// maxDiagnostics bounds a diagnostics bundle; each section keeps its newest lines.
const (
	maxDiagnostics = 512 << 10
	maxSection     = 240 << 10
)

var (
	pemPrivate   = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	secretAssign = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:secret|passw(?:or)?d|passphrase|token|api[_-]?key|private[_-]?key|credential|psk|otp|cookie|session[_-]?id)[a-z0-9_.-]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)`)
	authHeader   = regexp.MustCompile(`(?i)\b((?:authorization:\s*)?(?:bearer|basic)\s+|authorization:\s*)[A-Za-z0-9._~+/=-]{6,}`)
	urlCreds     = regexp.MustCompile(`(://)[^/\s:@]+:[^/\s@]+@`)
	recoveryKey  = regexp.MustCompile(`\b[0-9A-Za-z]{4,8}(-[0-9A-Za-z]{4,8}){5,}\b`) // LiMDM and BitLocker style recovery keys
)

// redact masks what may be a credential in log text: private keys,
// key=value pairs with secret names, authorization headers, user info in
// URLs and recovery keys.
func redact(s string) string {
	s = pemPrivate.ReplaceAllString(s, "[private key removed]")
	s = secretAssign.ReplaceAllString(s, "${1}"+masked)
	s = authHeader.ReplaceAllString(s, "${1}"+masked)
	s = urlCreds.ReplaceAllString(s, "${1}"+masked+"@")
	return recoveryKey.ReplaceAllString(s, masked)
}

// tail keeps the last n bytes of s, cut at a line start.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return "[earlier lines cut]\n" + s
}

// collectDiagnostics returns a bounded, redacted text bundle: the agent's
// journal and recent warnings of the system, for support.
func (a *Agent) collectDiagnostics() string {
	var b strings.Builder
	fmt.Fprintf(&b, "LiMDM diagnostics\nagent %s, %s, collected %s\n", Version, a.host.Name, time.Now().UTC().Format(time.RFC3339))
	for _, sec := range []struct {
		title string
		args  []string
	}{
		{"agent journal (limdm-agent, limdm-watchdog, last 2000 lines)", []string{"-u", agentUnit, "-u", "limdm-watchdog.service", "-n", "2000"}},
		{"system warnings and errors (this boot, last 1000 lines)", []string{"-b", "-p", "warning", "-n", "1000"}},
	} {
		out, err := run(time.Minute, "journalctl", append(sec.args, "-o", "short-iso", "--no-pager", "-q")...)
		if err != nil {
			out += "\n" + err.Error()
		}
		fmt.Fprintf(&b, "\n===== %s =====\n%s\n", sec.title, tail(redact(out), maxSection))
	}
	return tail(b.String(), maxDiagnostics)
}
