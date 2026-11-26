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
	secretAssign = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:secret|passw(?:or)?d|passphrase|token|api[_-]?key|private[_-]?key|preshared[_-]?key|credential|psk|otp|cookie|session[_-]?id)[a-z0-9_.-]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)`)
	authHeader   = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization"?\s*[:=]\s*)[^\r\n"']+`)
	authScheme   = regexp.MustCompile(`(?i)\b((?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{12,}`)
	urlCreds     = regexp.MustCompile(`(://)[^/\s:@]+:[^/\s@]+@`)
	urlToken     = regexp.MustCompile(`(://)[^/\s:@]{16,}@`) // a token as URL user (https://TOKEN@host)
	queryToken   = regexp.MustCompile(`(?i)([?&](?:key|sig|signature|auth|code|state|access_token|id_token|x-amz-signature|x-amz-credential|x-goog-signature)=)[^&\s"'#]+`)
	knownToken   = regexp.MustCompile(`\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})`)
	recoveryKey  = regexp.MustCompile(`\b[0-9A-Za-z]{4,8}(-[0-9A-Za-z]{4,8}){5,}\b`) // LiMDM and BitLocker style recovery keys

	// authFailure marks lines of failed logins. Their user fields hold what
	// was typed as the user name, often a password typed one field early.
	authFailure = regexp.MustCompile(`(?i)authentication failure|failed password|failed (?:publickey|keyboard-interactive|none) for|invalid user|failed login|user unknown|not known to the underlying|incorrect password|could not identify password|unknown user|illegal user`)
	authUser    = regexp.MustCompile(`(?i)(\b(?:r?user|logname|account)=)\S*|((?:invalid|illegal|unknown) user\s+)\S+|(failed (?:password|publickey|keyboard-interactive/pam|none) for\s+)(?:invalid user\s+)?\S+|(\bFOR\s+'?)[^',\s]+|(password for \[)[^\]]*`)
)

// redact masks what may be a credential in log text: private keys,
// key=value pairs with secret names, authorization headers, tokens in URLs
// and well known token formats, recovery keys, and the user fields of failed
// logins (pam_unix, sshd, login, sudo).
func redact(s string) string {
	s = pemPrivate.ReplaceAllString(s, "[private key removed]")
	s = secretAssign.ReplaceAllString(s, "${1}"+masked)
	s = authHeader.ReplaceAllString(s, "${1}"+masked)
	s = authScheme.ReplaceAllString(s, "${1}"+masked)
	s = urlCreds.ReplaceAllString(s, "${1}"+masked+"@")
	s = urlToken.ReplaceAllString(s, "${1}"+masked+"@")
	s = queryToken.ReplaceAllString(s, "${1}"+masked)
	s = knownToken.ReplaceAllString(s, masked)
	s = recoveryKey.ReplaceAllString(s, masked)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if authFailure.MatchString(l) {
			lines[i] = authUser.ReplaceAllString(l, "${1}${2}${3}${4}${5}"+masked)
		}
	}
	return strings.Join(lines, "\n")
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
