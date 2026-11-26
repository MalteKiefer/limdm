package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Remote shell for support. The console starts a session; the server sends
// the signed "shell" command; the agent opens POST /api/v1/shell/{session}
// over mTLS. The request body carries the terminal output, the response body
// carries frames with keyboard input and window sizes.

// ShellCommand is the payload of the "shell" command.
type ShellCommand struct {
	Session     string `json:"session"`              // random ID, also the relay path
	User        string `json:"user,omitempty"`       // local account; empty: the support account
	AllowRoot   bool   `json:"allow_root,omitempty"` // the server setting permits root
	By          string `json:"by"`                   // console user, shown on the device
	MaxMinutes  int    `json:"max_minutes"`
	IdleMinutes int    `json:"idle_minutes"`
}

var shellSessionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)

// ValidShellSession reports whether s can be a session ID.
func ValidShellSession(s string) bool { return shellSessionRe.MatchString(s) }

func (c ShellCommand) Validate() error {
	switch {
	case !ValidShellSession(c.Session):
		return errors.New("invalid session")
	case c.User != "" && !localUserRe.MatchString(c.User):
		return errors.New("user name: lower case letters, digits, dash and underscore")
	case c.User == "root" && !c.AllowRoot:
		return errors.New("root shells are not allowed")
	case c.MaxMinutes < 1 || c.MaxMinutes > 480 || c.IdleMinutes < 1 || c.IdleMinutes > c.MaxMinutes:
		return errors.New("max_minutes 1..480 and idle_minutes 1..max_minutes")
	case len(c.By) > 320 || !noControl(c.By, 320):
		return errors.New("invalid requester")
	}
	return nil
}

// Shell frames from the server to the agent: one type byte, a big endian
// uint16 length and the payload.
const (
	ShellInput  = 'i' // keyboard input
	ShellResize = 'r' // columns and rows, two big endian uint16
)

// WriteShellFrame writes one frame; payloads above 65535 bytes are refused.
func WriteShellFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > 0xffff {
		return errors.New("shell frame too large")
	}
	buf := make([]byte, 3+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload))) //nolint:gosec // at most 0xffff, checked above
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadShellFrame reads one frame.
func ReadShellFrame(r io.Reader) (byte, []byte, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0] != ShellInput && h[0] != ShellResize {
		return 0, nil, fmt.Errorf("unknown shell frame %q", h[0])
	}
	p := make([]byte, binary.BigEndian.Uint16(h[1:]))
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if h[0] == ShellResize && len(p) != 4 {
		return 0, nil, errors.New("invalid resize frame")
	}
	return h[0], p, nil
}

// ResizePayload encodes a window size.
func ResizePayload(cols, rows uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, cols)
	binary.BigEndian.PutUint16(b[2:], rows)
	return b
}
