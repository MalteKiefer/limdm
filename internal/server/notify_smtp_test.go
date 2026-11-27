package server

import (
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"
)

// smtpData speaks DATA like smtp.Client.Data: 354, the dot encoded message, 250.
func TestSMTPData(t *testing.T) {
	cli, srv := net.Pipe()
	got := make(chan string, 1)
	go func() {
		tp := textproto.NewConn(srv)
		defer tp.Close()
		_ = tp.PrintfLine("220 test")
		if l, _ := tp.ReadLine(); l != "DATA" {
			got <- "command " + l
			return
		}
		_ = tp.PrintfLine("354 go ahead")
		body, err := tp.ReadDotBytes()
		if err != nil {
			got <- err.Error()
			return
		}
		_ = tp.PrintfLine("250 queued")
		got <- string(body)
	}()
	c, err := smtp.NewClient(cli, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := smtpData(c, []byte("Subject: x\r\n\r\n.leading dot\r\n")); err != nil {
		t.Fatal(err)
	}
	if b := <-got; !strings.Contains(b, "Subject: x\n\n.leading dot") {
		t.Fatalf("server got %q", b)
	}
	_ = c.Close()
}
