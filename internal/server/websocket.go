package server

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // RFC 6455 defines the handshake with SHA-1; it is not used for security
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// A minimal RFC 6455 WebSocket server for the console terminal: no
// extensions, no subprotocols, messages up to wsMaxMessage. Only the server
// side exists; client frames must be masked.

const (
	wsText   = 0x1
	wsBinary = 0x2
	wsClose  = 0x8
	wsPing   = 0x9
	wsPong   = 0xA

	wsMaxMessage = 64 << 10
)

var errWSClosed = errors.New("websocket closed")

type wsConn struct {
	c   net.Conn
	r   *bufio.Reader
	wmu sync.Mutex // frames from several goroutines (data, pong, close) must not interleave
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// wsUpgrade checks the handshake and takes over the connection. The caller
// has already authenticated the request and checked its Origin.
func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 16 || r.Method != http.MethodGet ||
		!headerHas(r.Header, "Connection", "upgrade") || !headerHas(r.Header, "Upgrade", "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "websocket handshake expected", http.StatusBadRequest)
		return nil, errors.New("bad websocket handshake")
	}
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return nil, err
	}
	// the server's read and write timeouts stay on a hijacked connection
	_ = c.SetDeadline(time.Time{})
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // see import
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n"
	if _, err := c.Write([]byte(resp)); err != nil {
		c.Close()
		return nil, err
	}
	return &wsConn{c: c, r: brw.Reader}, nil
}

// readFrame reads one frame and unmasks it.
func (ws *wsConn) readFrame() (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(ws.r, h[:]); err != nil {
		return
	}
	fin, op = h[0]&0x80 != 0, h[0]&0x0f
	if h[0]&0x70 != 0 {
		return false, 0, nil, errors.New("websocket: reserved bits set")
	}
	if h[1]&0x80 == 0 {
		return false, 0, nil, errors.New("websocket: client frames must be masked")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(ws.r, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(ws.r, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if op >= wsClose && (n > 125 || !fin) {
		return false, 0, nil, errors.New("websocket: invalid control frame")
	}
	if n > wsMaxMessage {
		return false, 0, nil, errors.New("websocket: frame too large")
	}
	var mask [4]byte
	if _, err = io.ReadFull(ws.r, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(ws.r, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return fin, op, payload, nil
}

// ReadMessage returns the next text or binary message. Pings are answered,
// a close frame is echoed and ends the connection with errWSClosed.
func (ws *wsConn) ReadMessage() (byte, []byte, error) {
	var op byte
	var msg []byte
	for {
		fin, fop, p, err := ws.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch fop {
		case wsPing:
			if err := ws.WriteFrame(wsPong, p); err != nil {
				return 0, nil, err
			}
			continue
		case wsPong:
			continue
		case wsClose:
			_ = ws.WriteFrame(wsClose, nil)
			return 0, nil, errWSClosed
		case wsText, wsBinary:
			if op != 0 {
				return 0, nil, errors.New("websocket: new message inside a fragmented one")
			}
			op = fop
		case 0: // continuation
			if op == 0 {
				return 0, nil, errors.New("websocket: continuation without a message")
			}
		default:
			return 0, nil, errors.New("websocket: unknown opcode")
		}
		if len(msg)+len(p) > wsMaxMessage {
			return 0, nil, errors.New("websocket: message too large")
		}
		msg = append(msg, p...)
		if fin {
			if op == wsText && !utf8.Valid(msg) {
				return 0, nil, errors.New("websocket: invalid UTF-8 in a text message")
			}
			return op, msg, nil
		}
	}
}

// WriteFrame sends one unmasked, final frame.
func (ws *wsConn) WriteFrame(op byte, p []byte) error {
	h := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		h = append(h, byte(n))
	case n <= 0xffff:
		h = append(h, 126, byte(n>>8), byte(n)) //nolint:gosec // n <= 0xffff
	default:
		h = binary.BigEndian.AppendUint64(append(h, 127), uint64(n))
	}
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	_ = ws.c.SetWriteDeadline(time.Now().Add(30 * time.Second)) // a stalled browser must not block the relay forever
	if _, err := ws.c.Write(append(h, p...)); err != nil {
		return err
	}
	return nil
}

// Close sends a close frame with a reason and closes the connection.
func (ws *wsConn) Close(reason string) {
	if len(reason) > 120 {
		reason = reason[:120]
	}
	_ = ws.WriteFrame(wsClose, append([]byte{0x03, 0xe8}, reason...)) // 1000 normal closure
	ws.c.Close()
}
