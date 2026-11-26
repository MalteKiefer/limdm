package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// PROXY protocol version 2 on the agent listener. Behind a load balancer in
// TCP passthrough mode (mTLS ends at LiMDM) every connection comes from the
// balancer; with the PROXY header it names the device's address, so the
// public address, its location and the per address limits (enrollment) see
// the device. Only connections from the configured sources must and may send
// the header (LIMDM_AGENT_PROXY_PROTOCOL); from anywhere else it would let a
// client choose its own address.

var proxySig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyListener reads the PROXY v2 header of connections from the sources
// trusted returns at the moment of the connection (Settings, Operations).
type proxyListener struct {
	net.Listener
	trusted func() []netip.Prefix
}

// AgentListener listens for the agent API, with PROXY protocol v2 for the
// load balancers named in Settings, Operations (LIMDM_AGENT_PROXY_PROTOCOL
// is the initial value).
func (s *Server) AgentListener(addr string) (net.Listener, error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return ln, err
	}
	return proxyListener{ln, s.proxySources}, nil
}

func (l proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil || !containsAddr(l.trusted(), ap.Addr().Unmap()) {
		return c, nil
	}
	return &proxyConn{Conn: c}, nil
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// proxyConn parses the header on first use: in Accept it would let one slow
// balancer connection stall all others.
type proxyConn struct {
	net.Conn
	once   sync.Once
	remote net.Addr
	err    error
}

func (c *proxyConn) init() {
	c.once.Do(func() {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		c.remote, c.err = readProxyHeader(c.Conn)
		_ = c.SetReadDeadline(time.Time{})
		if c.err != nil {
			_ = c.Close()
		}
		if c.remote == nil { // LOCAL: the balancer's own health check
			c.remote = c.Conn.RemoteAddr()
		}
	})
}

func (c *proxyConn) Read(b []byte) (int, error) {
	if c.init(); c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}

func (c *proxyConn) RemoteAddr() net.Addr {
	c.init()
	return c.remote
}

// readProxyHeader reads a PROXY v2 header: the client address for PROXY
// over TCP, nil for LOCAL and other families.
func readProxyHeader(r io.Reader) (net.Addr, error) {
	var h [16]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, fmt.Errorf("proxy header: %w", err)
	}
	if !bytes.Equal(h[:12], proxySig) || h[12]>>4 != 2 {
		return nil, errors.New("proxy header: missing or not version 2")
	}
	n := int(binary.BigEndian.Uint16(h[14:]))
	if n > 1024 {
		return nil, errors.New("proxy header: too long")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("proxy header: %w", err)
	}
	if h[12]&0x0f == 0 { // LOCAL
		return nil, nil
	}
	if h[12]&0x0f != 1 {
		return nil, errors.New("proxy header: unknown command")
	}
	switch h[13] {
	case 0x11: // TCP over IPv4
		if n < 12 {
			return nil, errors.New("proxy header: short address")
		}
		return &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:]))}, nil
	case 0x21: // TCP over IPv6
		if n < 36 {
			return nil, errors.New("proxy header: short address")
		}
		return &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:]))}, nil
	}
	return nil, nil // UDP, unix sockets: keep the balancer's address
}
