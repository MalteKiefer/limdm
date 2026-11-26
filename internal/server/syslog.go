package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Audit entries and device events go to a SIEM as RFC 5424 syslog messages
// when LIMDM_SYSLOG names a target (udp://host:514 or tcp://host:514). A
// copy outside the database anchors the audit chain externally. Forwarding
// starts with the entries written after the server started and retries
// unsent ones; the loop runs on one instance only.

const syslogSDID = "limdm@32473" // 32473: the IANA example enterprise number (RFC 5612)

// syslogMessage formats one RFC 5424 message (facility 13, log audit).
func syslogMessage(severity int, at time.Time, host, msgid string, params [][2]string, msg string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 %s %s limdm-server - %s [%s", 13*8+severity, at.UTC().Format("2006-01-02T15:04:05.000000Z"), syslogToken(host), msgid, syslogSDID)
	for _, p := range params {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(syslogClean(p[1]))
		fmt.Fprintf(&b, ` %s="%s"`, p[0], v)
	}
	b.WriteString("] ")
	b.WriteString(truncate(syslogClean(msg), 2000))
	return b.String()
}

// syslogClean replaces line breaks and other control characters, which a
// device could put into a detail to forge further messages.
func syslogClean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// syslogToken is a header field: printable ASCII without spaces, or "-".
func syslogToken(s string) string {
	s = strings.Map(func(r rune) rune {
		if r <= 0x20 || r >= 0x7f {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	return truncate(s, 255)
}

func (s *Server) syslogLoop(ctx context.Context) {
	target := s.cfg.Syslog
	if target == "" {
		<-ctx.Done()
		return
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "udp" && u.Scheme != "tcp") || u.Host == "" {
		s.log.Error("LIMDM_SYSLOG must be udp://host:port or tcp://host:port")
		<-ctx.Done()
		return
	}
	host, _ := os.Hostname()
	// continue where the last leader stopped (high availability); the first
	// start begins with new entries
	var lastAudit, lastEvent int64
	if err := s.db.QueryRow(ctx, `SELECT coalesce((SELECT last_id FROM syslog_cursor WHERE stream='audit'), (SELECT max(id) FROM audit_log), 0),
		coalesce((SELECT last_id FROM syslog_cursor WHERE stream='events'), (SELECT max(id) FROM device_events), 0)`).Scan(&lastAudit, &lastEvent); err != nil {
		s.log.Error("syslog start", "err", err)
		return
	}
	var conn net.Conn
	send := func(m string) error {
		if conn == nil {
			c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, u.Scheme, u.Host)
			if err != nil {
				return err
			}
			conn = c
		}
		if u.Scheme == "tcp" { // octet counting framing (RFC 6587)
			m = strconv.Itoa(len(m)) + " " + m
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(m)); err != nil {
			conn.Close()
			conn = nil
			return err
		}
		return nil
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		prevAudit, prevEvent := lastAudit, lastEvent
		if err := s.forwardAudit(ctx, host, &lastAudit, send); err != nil {
			s.log.Warn("syslog forwarding", "err", err)
		} else if err := s.forwardEvents(ctx, host, &lastEvent, send); err != nil {
			s.log.Warn("syslog forwarding", "err", err)
		}
		if lastAudit != prevAudit || lastEvent != prevEvent {
			if _, err := s.db.Exec(ctx, `INSERT INTO syslog_cursor(stream, last_id) VALUES ('audit', $1), ('events', $2)
				ON CONFLICT (stream) DO UPDATE SET last_id = EXCLUDED.last_id`, lastAudit, lastEvent); err != nil {
				s.log.Warn("syslog position", "err", err)
			}
		}
	}
}

// forwardAudit sends audit entries after *last; *last only moves past sent ones.
func (s *Server) forwardAudit(ctx context.Context, host string, last *int64, send func(string) error) error {
	rows, err := s.db.Query(ctx, `SELECT id, at, actor, action, target, detail, encode(hash, 'hex') FROM audit_log WHERE id > $1 ORDER BY id LIMIT 500`, *last)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var at time.Time
		var actor, action, target, detail, hash string
		if err := rows.Scan(&id, &at, &actor, &action, &target, &detail, &hash); err != nil {
			return err
		}
		m := syslogMessage(5, at, host, "audit", [][2]string{{"id", strconv.FormatInt(id, 10)}, {"actor", actor}, {"action", action}, {"target", target}, {"hash", hash}}, detail)
		if err := send(m); err != nil {
			return err
		}
		*last = id
	}
	return rows.Err()
}

// forwardEvents sends device events after *last.
func (s *Server) forwardEvents(ctx context.Context, host string, last *int64, send func(string) error) error {
	rows, err := s.db.Query(ctx, `SELECT id, at, device_id, detail FROM device_events WHERE id > $1 ORDER BY id LIMIT 500`, *last)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var at time.Time
		var device, detail string
		if err := rows.Scan(&id, &at, &device, &detail); err != nil {
			return err
		}
		if err := send(syslogMessage(6, at, host, "event", [][2]string{{"id", strconv.FormatInt(id, 10)}, {"device", device}}, detail)); err != nil {
			return err
		}
		*last = id
	}
	return rows.Err()
}
