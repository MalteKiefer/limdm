package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestSyslogMessage(t *testing.T) {
	at := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	m := syslogMessage(5, at, "mdm host", "audit", [][2]string{{"id", "7"}, {"target", `pc"] x`}}, "line1\n<13>1 forged")
	want := `<109>1 2026-11-26T08:00:00.000000Z mdmhost limdm-server - audit [limdm@32473 id="7" target="pc\"\] x"] line1 <13>1 forged`
	if m != want {
		t.Fatalf("got  %s\nwant %s", m, want)
	}
}

// A chain with plain entries, the switch, and keyed entries verifies from a
// JSON Lines export; a changed entry, a keyed entry rehashed without the key
// (downgrade) and a wrong key are all detected.
func TestAuditExportVerify(t *testing.T) {
	key := AuditKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)))
	const keyedFrom = 3
	build := func(mutate func(i int, l *auditLine)) []byte {
		var out bytes.Buffer
		prev := make([]byte, 32)
		at := time.Unix(1700000000, 123000).UTC()
		for i := 1; i <= 5; i++ {
			l := auditLine{ID: int64(i), AtUS: at.UnixMicro(), Actor: "admin@x", Action: "library.save", Target: "t", Detail: "d"}
			if mutate != nil {
				mutate(i, &l)
			}
			k := []byte(nil)
			if i >= keyedFrom {
				k = key
			}
			if l.Scheme == "downgrade" {
				k = nil
			}
			h := auditHash(k, prev, time.UnixMicro(l.AtUS), l.Actor, l.Action, l.Target, l.Detail)
			l.Prev, l.Hash = hex.EncodeToString(prev), hex.EncodeToString(h)
			b, _ := json.Marshal(l)
			out.Write(append(b, '\n'))
			prev = h
		}
		return out.Bytes()
	}
	n, first, last, broken, err := VerifyAuditExport(bytes.NewReader(build(nil)), key, keyedFrom)
	if err != nil || n != 5 || first != 1 || last != 5 || broken != 0 {
		t.Fatalf("intact chain: n=%d first=%d last=%d broken=%d err=%v", n, first, last, broken, err)
	}
	// rewrite one detail after the fact
	tampered := bytes.Replace(build(nil), []byte(`"id":4,"at":"","at_us":1700000000000123,"actor":"admin@x","action":"library.save","target":"t","detail":"d"`),
		[]byte(`"id":4,"at":"","at_us":1700000000000123,"actor":"admin@x","action":"library.save","target":"t","detail":"x"`), 1)
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(tampered), key, keyedFrom); broken != 4 {
		t.Fatalf("changed entry not detected: %d", broken)
	}
	downgraded := build(func(i int, l *auditLine) {
		if i == 4 {
			l.Scheme = "downgrade"
		}
	})
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(downgraded), key, keyedFrom); broken != 4 {
		t.Fatalf("keyed entry hashed without the key not detected: %d", broken)
	}
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(build(nil)), make([]byte, 32), keyedFrom); broken != keyedFrom {
		t.Fatalf("wrong key not detected: %d", broken)
	}
	// an export of a date range starts in the middle of the chain
	lines := bytes.SplitAfter(build(nil), []byte("\n"))
	if _, first, _, broken, err := VerifyAuditExport(bytes.NewReader(bytes.Join(lines[2:], nil)), key, keyedFrom); err != nil || first != 3 || broken != 0 {
		t.Fatalf("partial export: first=%d broken=%d err=%v", first, broken, err)
	}
}
