package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
)

func proxyV2(src netip.AddrPort) []byte {
	b := append([]byte{}, proxySig...)
	b = append(b, 0x21, 0x11, 0, 12)
	b = append(b, src.Addr().AsSlice()...)
	b = append(b, 192, 0, 2, 1)
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, 8444)
}

func TestProxyProtocol(t *testing.T) {
	accept := func(trusted string, send []byte) (net.Conn, string) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		pl := proxyListener{ln, func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(trusted)} }}
		go func() {
			c, err := net.Dial("tcp", ln.Addr().String())
			if err == nil {
				_, _ = c.Write(send)
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}
		}()
		c, err := pl.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c, c.RemoteAddr().String()
	}
	hello := []byte("hello")
	c, addr := accept("127.0.0.0/8", append(proxyV2(netip.MustParseAddrPort("203.0.113.7:4444")), hello...))
	if addr != "203.0.113.7:4444" {
		t.Fatalf("remote address %s", addr)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("payload after the header: %q %v", got, err)
	}
	// a trusted source must send the header
	c, _ = accept("127.0.0.0/8", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if _, err := c.Read(got); err == nil {
		t.Fatal("connection without header accepted")
	}
	// anyone else cannot choose an address
	c, addr = accept("10.0.0.0/8", append(proxyV2(netip.MustParseAddrPort("203.0.113.7:4444")), hello...))
	if addr == "203.0.113.7:4444" {
		t.Fatal("untrusted source chose its address")
	}
	if _, err := io.ReadFull(c, got[:1]); err != nil || got[0] != '\r' {
		t.Fatal("untrusted connection changed")
	}
}
