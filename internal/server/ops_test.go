package server

import (
	"strings"
	"testing"
)

func TestOpsSettingsValidate(t *testing.T) {
	ok := OpsSettings{}.withDefaults()
	if _, err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]OpsSettings{
		"level":   {LogLevel: "loud"},
		"reads":   {AuditAPIReads: "some"},
		"limit":   {MaxCheckins: 10001},
		"syslog":  {Syslog: "http://siem:514"},
		"no port": {Syslog: "tcp://siem"},
		"ca":      {Syslog: "tcp+tls://siem:6514", SyslogCA: "not a certificate"},
		"proxy":   {AgentProxyFrom: []string{"10.0.0.0/33"}},
	} {
		if _, err := o.withDefaults().validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	p, err := OpsSettings{AgentProxyFrom: []string{"10.0.0.5", "192.0.2.0/24"}}.withDefaults().validate()
	if err != nil || len(p) != 2 || !strings.HasSuffix(p[0].String(), "/32") {
		t.Fatalf("proxies: %v %v", p, err)
	}
}

func TestSlotsResize(t *testing.T) {
	s := newSlots(2)
	old := s.get()
	old <- struct{}{}
	s.resize(2)
	if s.get() != old {
		t.Fatal("same size must keep the channel")
	}
	s.resize(5)
	if cap(s.get()) != 5 || len(s.get()) != 0 {
		t.Fatal("resize")
	}
	<-old // a holder of the old channel releases into it
	var none *slots
	none.resize(3)
	if none.get() != nil {
		t.Fatal("nil slots must stay unlimited")
	}
}
