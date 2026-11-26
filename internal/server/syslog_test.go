package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tcp+tls verifies the collector against the configured CA and frames the
// messages with octet counting (RFC 5425).
func TestSyslogTLS(t *testing.T) {
	ts := httptest.NewTLSServer(nil) // only for its certificate (127.0.0.1)
	ts.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: ts.TLS.Certificates, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString(']')
			c.Close()
			if line != "" { // a refused handshake reads nothing
				got <- line
			}
		}
	}()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	u, _ := url.Parse("tcp+tls://" + ln.Addr().String())
	if _, err := syslogDialer(u, "no certificate"); err == nil {
		t.Fatal("a CA without a certificate accepted")
	}
	// without the CA the self signed collector is refused
	dial, err := syslogDialer(u, "")
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dial(context.Background()); err == nil {
		c.Close()
		t.Fatal("collector with an unknown CA accepted")
	}
	if dial, err = syslogDialer(u, ca); err != nil {
		t.Fatal(err)
	}
	c, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("5 <13>1]")); err != nil {
		t.Fatal(err)
	}
	if line := <-got; !strings.HasPrefix(line, "5 <13>1") {
		t.Fatalf("collector got %q", line)
	}
}

// Device events become visible in id order: a check in that inserts its
// events first but commits last must not leave a smaller id behind the
// syslog cursor.
func TestDeviceEventsCommitOrder(t *testing.T) {
	db := loadTestDB(t, 4)
	s := loadTestServer(db)
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO devices(id, cert_serial, cert_not_after, hostname) VALUES ('d1','s',now(),'a'), ('d2','s',now(),'b')`); err != nil {
		t.Fatal(err)
	}
	slow := &auditTx{Tx: mustBegin(t, db)}
	if _, err := s.storeEvents(ctx, slow, "d1", []string{"slow event"}); err != nil {
		t.Fatal(err)
	}
	fast := &auditTx{Tx: mustBegin(t, db)}
	if _, err := s.storeEvents(ctx, fast, "d2", []string{"fast event"}); err != nil {
		t.Fatal(err)
	}
	if err := fast.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var first string
	if err := db.QueryRow(ctx, `SELECT device_id FROM device_events ORDER BY id LIMIT 1`).Scan(&first); err != nil || first != "d2" {
		t.Fatalf("first id belongs to %q, committed later: %v", first, err)
	}
}
