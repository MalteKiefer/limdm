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
	keys := AuditKeys{{From: keyedFrom, Key: key}}
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
	n, first, last, broken, err := VerifyAuditExport(bytes.NewReader(build(nil)), keys)
	if err != nil || n != 5 || first != 1 || last != 5 || broken != 0 {
		t.Fatalf("intact chain: n=%d first=%d last=%d broken=%d err=%v", n, first, last, broken, err)
	}
	// rewrite one detail after the fact
	tampered := bytes.Replace(build(nil), []byte(`"id":4,"at":"","at_us":1700000000000123,"actor":"admin@x","action":"library.save","target":"t","detail":"d"`),
		[]byte(`"id":4,"at":"","at_us":1700000000000123,"actor":"admin@x","action":"library.save","target":"t","detail":"x"`), 1)
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(tampered), keys); broken != 4 {
		t.Fatalf("changed entry not detected: %d", broken)
	}
	downgraded := build(func(i int, l *auditLine) {
		if i == 4 {
			l.Scheme = "downgrade"
		}
	})
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(downgraded), keys); broken != 4 {
		t.Fatalf("keyed entry hashed without the key not detected: %d", broken)
	}
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(build(nil)), AuditKeys{{From: keyedFrom, Key: make([]byte, 32)}}); broken != keyedFrom {
		t.Fatalf("wrong key not detected: %d", broken)
	}
	// an export of a date range starts in the middle of the chain
	lines := bytes.SplitAfter(build(nil), []byte("\n"))
	if _, first, _, broken, err := VerifyAuditExport(bytes.NewReader(bytes.Join(lines[2:], nil)), keys); err != nil || first != 3 || broken != 0 {
		t.Fatalf("partial export: first=%d broken=%d err=%v", first, broken, err)
	}
}

// After a command key rotation the chain has two keyed segments; each
// entry verifies with the key of its segment.
func TestAuditKeySegments(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	keys := AuditKeys{{From: 2, Key: k1}, {From: 4, Key: k2}}
	if keys.keyFor(1) != nil || !bytes.Equal(keys.keyFor(3), k1) || !bytes.Equal(keys.keyFor(9), k2) {
		t.Fatal("keyFor picks the wrong segment")
	}
	var out bytes.Buffer
	prev := make([]byte, 32)
	at := time.Unix(1700000000, 0).UTC()
	for i := int64(1); i <= 5; i++ {
		h := auditHash(keys.keyFor(i), prev, at, "a", "b", "c", "d")
		b, _ := json.Marshal(auditLine{ID: i, AtUS: at.UnixMicro(), Actor: "a", Action: "b", Target: "c", Detail: "d",
			Prev: hex.EncodeToString(prev), Hash: hex.EncodeToString(h)})
		out.Write(append(b, '\n'))
		prev = h
	}
	if _, _, _, broken, err := VerifyAuditExport(bytes.NewReader(out.Bytes()), keys); err != nil || broken != 0 {
		t.Fatalf("two segments: broken=%d err=%v", broken, err)
	}
	if _, _, _, broken, _ := VerifyAuditExport(bytes.NewReader(out.Bytes()), keys[:1]); broken != 4 {
		t.Fatalf("missing second segment not detected: %d", broken)
	}
}

// The segment file round trips and rejects a key that does not match its id.
func TestAuditKeyLines(t *testing.T) {
	dir := t.TempDir()
	k := bytes.Repeat([]byte{5}, 32)
	in := []auditKeyLine{{from: 3, id: auditKeyID(k), key: k}, {from: 9, id: "00112233aabbccdd"}}
	if err := writeAuditKeyLines(dir, in); err != nil {
		t.Fatal(err)
	}
	got, err := readAuditKeyLines(dir)
	if err != nil || len(got) != 2 || got[1].from != 9 || !bytes.Equal(got[0].key, k) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	in[0].id = "ffffffffffffffff"
	_ = writeAuditKeyLines(dir, in)
	if _, err := readAuditKeyLines(dir); err == nil {
		t.Fatal("a key that does not match its id was accepted")
	}
}
