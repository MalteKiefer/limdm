package agent

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maltekiefer/limdm/internal/api"
)

// What the desktop app shows besides the status: the declarations in force
// with their settings (like the profiles list on macOS), the CA
// certificates LiMDM installed, and the agent's journal.

// DesktopProfile is one declaration as the user sees it. Secrets are masked.
type DesktopProfile struct {
	Identifier string   `json:"identifier"`
	Type       string   `json:"type"`
	Active     bool     `json:"active"`
	Reasons    []string `json:"reasons,omitempty"`
	Settings   string   `json:"settings"` // indented JSON
}

// DesktopLogLine is one journal entry of the agent or its watchdog.
type DesktopLogLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // error | warning | info
	Text  string    `json:"text"`
}

var secretWords = []string{"secret", "password", "passphrase", "token", "private"}

// maskSecrets replaces values of secret looking keys, at any depth.
func maskSecrets(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			lk := strings.ToLower(k)
			secret := false
			for _, w := range secretWords {
				secret = secret || strings.Contains(lk, w)
			}
			if s, ok := x.(string); secret && ok && s != "" {
				t[k] = "••••••"
			} else {
				t[k] = maskSecrets(x)
			}
		}
	case []any:
		for i := range t {
			t[i] = maskSecrets(t[i])
		}
	}
	return v
}

func (a *Agent) desktopProfiles() []DesktopProfile {
	status := map[string]api.DeclarationStatus{}
	for _, s := range a.declStatus {
		status[s.Identifier] = s
	}
	var out []DesktopProfile
	for _, d := range a.state.Declarations {
		var v any
		settings := ""
		if json.Unmarshal(d.Payload, &v) == nil {
			b, _ := json.MarshalIndent(maskSecrets(v), "", "  ")
			settings = string(b)
		}
		st := status[d.Identifier]
		out = append(out, DesktopProfile{Identifier: d.Identifier, Type: d.Type, Active: st.Active, Reasons: st.Reasons, Settings: settings})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out
}

// certInfo describes the CA certificates LiMDM installs.
func certInfo(certs []api.Certificate) []api.CertInfo {
	var out []api.CertInfo
	for _, c := range certs {
		b, _ := pem.Decode([]byte(c.PEM))
		if b == nil {
			continue
		}
		x, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(x.Raw)
		out = append(out, api.CertInfo{Name: c.Name, Subject: x.Subject.String(), Issuer: x.Issuer.String(),
			NotBefore: x.NotBefore, NotAfter: x.NotAfter, SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}

// agentJournal returns the latest entries of the agent and its watchdog.
func agentJournal(n int) []DesktopLogLine {
	out, err := run(10*time.Second, "journalctl", "-u", agentUnit, "-u", "limdm-watchdog.service",
		"-n", strconv.Itoa(n), "-o", "json", "--no-pager", "-q")
	if err != nil {
		return nil
	}
	var lines []DesktopLogLine
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var e struct {
			Realtime string `json:"__REALTIME_TIMESTAMP"`
			Priority string `json:"PRIORITY"`
			Message  any    `json:"MESSAGE"`
		}
		if json.Unmarshal([]byte(l), &e) != nil {
			continue
		}
		msg, ok := e.Message.(string)
		if !ok {
			continue // binary message
		}
		us, _ := strconv.ParseInt(e.Realtime, 10, 64)
		line := DesktopLogLine{Time: time.UnixMicro(us), Level: "info", Text: msg}
		switch p, _ := strconv.Atoi(e.Priority); {
		case p <= 3:
			line.Level = "error"
		case p == 4:
			line.Level = "warning"
		}
		// the agent logs JSON (slog): show the message and its attributes
		if strings.HasPrefix(msg, "{") {
			var j map[string]any
			if json.Unmarshal([]byte(msg), &j) == nil {
				if lv, _ := j["level"].(string); lv == "ERROR" {
					line.Level = "error"
				} else if lv == "WARN" {
					line.Level = "warning"
				}
				var b bytes.Buffer
				fmt.Fprint(&b, j["msg"])
				keys := make([]string, 0, len(j))
				for k := range j {
					if k != "msg" && k != "time" && k != "level" {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(&b, " %s=%v", k, j[k])
				}
				line.Text = b.String()
			}
		}
		if len(line.Text) > 600 {
			line.Text = line.Text[:600]
		}
		lines = append(lines, line)
	}
	return lines
}
